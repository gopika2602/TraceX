"""Owner-scoped deterministic evidence intake and review.

Uploaded content is untrusted data. This module only parses text/CSV/JSON and
never interprets document contents as instructions or executes uploaded files.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from ..auth import get_current_user
from ..db import get_database
from ..models import CaseIntake, IntakeEvidence

router = APIRouter(prefix="/cases/extractions", tags=["evidence extraction"])
MAX_FILE_BYTES = 3 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 500
SUPPORTED = {".csv", ".json", ".txt", ".log"}
EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")


class ReviewEvent(BaseModel):
    event_id: str
    status: Literal["approved", "rejected", "unreviewed"]
    fields: dict[str, Any] = Field(default_factory=dict)


class ReviewRequest(BaseModel):
    events: list[ReviewEvent] = Field(min_length=1, max_length=MAX_EVENTS)


def _timestamp(value: Any) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def _field(row: dict, *names: str) -> str | None:
    normalized = {str(key).strip().lower().replace(" ", "_"): value for key, value in row.items()}
    for name in names:
        value = normalized.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()[:4000]
    return None


def _normalize_row(row: dict, source: str, reference: str, method: str, raw_text: str) -> dict:
    timestamp_raw = _field(row, "timestamp", "time", "event_time", "@timestamp")
    if timestamp_raw is None:
        match = TIMESTAMP.search(raw_text)
        timestamp_raw = match.group(0) if match else None
    timestamp = _timestamp(timestamp_raw)
    description = _field(row, "description", "message", "summary", "event", "action", "details") or raw_text.strip()
    kind = _field(row, "event_type", "type", "event_name", "category")
    if not kind:
        text = description.lower()
        # Specific event classification is keyword-driven. Unknown remains unknown.
        kind = next((term for term in ("suspicious_login", "login", "token_reuse", "token_issued", "oauth_token_issued", "api_access", "data_read", "privileged_action", "network_connection") if term.replace("_", " ") in text or term in text), "observed_event")
    reference_label = reference[:500]
    return {
        "event_id": uuid4().hex,
        "evidence_type": kind[:100],
        "timestamp": timestamp,
        "timestamp_source": "explicit_source_timestamp" if timestamp else None,
        "source": source[:500],
        "evidence_source": source[:500],
        "raw_event_reference": reference_label,
        "extraction_method": method,
        "confidence": 0.8 if timestamp and kind != "observed_event" else 0.55 if timestamp else 0.3,
        "verification_status": "unreviewed",
        "identity": _field(row, "identity", "user", "user_name", "account", "email", "principal") or (EMAIL.search(description).group(0) if EMAIL.search(description) else None),
        "source_ip": _field(row, "source_ip", "src_ip", "client_ip", "ip") or (IP.search(description).group(0) if IP.search(description) else None),
        "destination_ip": _field(row, "destination_ip", "dest_ip", "dst_ip"),
        "device_id": _field(row, "device_id", "device", "host", "hostname"),
        "api_service": _field(row, "api_service", "application", "service", "app"),
        "resource": _field(row, "resource", "target", "destination", "asset"),
        "permission": _field(row, "permission", "scope", "role"),
        "session_id": _field(row, "session_id", "session"),
        "token_id": _field(row, "token_id", "token"),
        "user_agent": _field(row, "user_agent", "useragent"),
        "description": description[:4000] or None,
        "warnings": [] if timestamp else ["A full timezone-aware timestamp is missing; add one before approving this event."],
    }


def _parse_file(filename: str, content: str) -> list[tuple[dict, str]]:
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if suffix not in SUPPORTED:
        raise HTTPException(status_code=415, detail=f"Unsupported evidence format. Supported formats: {', '.join(sorted(SUPPORTED))}.")
    try:
        if suffix == ".csv":
            rows = list(csv.DictReader(io.StringIO(content)))
            if not rows:
                raise ValueError("CSV has no data rows or header.")
            return [(row, f"{filename}:row:{index + 2}") for index, row in enumerate(rows)]
        if suffix == ".json":
            parsed = json.loads(content)
            rows = parsed if isinstance(parsed, list) else parsed.get("events", parsed.get("records", [parsed])) if isinstance(parsed, dict) else None
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise ValueError("JSON must be an object, an array of objects, or contain an events/records array.")
            return [(row, f"{filename}:record:{index + 1}") for index, row in enumerate(rows)]
        lines = [(index, line.strip()) for index, line in enumerate(content.splitlines(), start=1) if line.strip()]
        if not lines:
            raise ValueError("Text file is empty.")
        return [({"description": line}, f"{filename}:line:{number}") for number, line in lines]
    except (json.JSONDecodeError, csv.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse {filename}: {exc}") from exc


def _owned(database, extraction_id: str, owner_id: str) -> dict:
    document = database.extractions.find_one({"_id": extraction_id, "owner_id": owner_id})
    if not document:
        raise HTTPException(status_code=404, detail="Extraction not found.")
    return document


def _response(doc: dict) -> dict:
    return {"id": doc["_id"], "status": doc["status"], "created_at": doc["created_at"].isoformat(),
            "extraction_method": "deterministic_rules", "ai_provider": None,
            "sources": [{key: value for key, value in source.items() if key != "content"} for source in doc["sources"]],
            "events": doc["events"], "warnings": doc["warnings"]}


def _audit(database, user: dict, action: str, extraction_id: str, counts: dict | None = None) -> None:
    # Deliberately excludes story text, evidence values, and credentials.
    database.audit_events.insert_one({"actor_id": user["id"], "action": action, "target_type": "evidence_extraction",
                                      "target_id": extraction_id, "details": counts or {}, "created_at": datetime.now(timezone.utc)})


@router.post("/preview", status_code=201)
async def preview_extraction(story: str = Form(default=""), files: list[UploadFile] = File(default=[]), user: dict = Depends(get_current_user), database=Depends(get_database)):
    if len(story.encode("utf-8")) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="Incident story exceeds the 3 MiB limit.")
    sources: list[dict] = []
    candidates: list[tuple[dict, str, str, str]] = []
    total = len(story.encode("utf-8"))
    if story.strip():
        for number, line in enumerate((line.strip() for line in story.splitlines()), start=1):
            if line:
                candidates.append(({"description": line}, "Pasted incident story", f"story:line:{number}", line))
        sources.append({"name": "Pasted incident story", "kind": "story", "size_bytes": total, "content": story})
    for file in files:
        name = (file.filename or "evidence").replace("\\", "/").split("/")[-1][:200]
        suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if suffix not in SUPPORTED:
            raise HTTPException(status_code=415, detail=f"Unsupported file type for {name}; accepted: CSV, JSON, TXT, LOG.")
        raw = await file.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail=f"{name} exceeds the 3 MiB per-file limit.")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise HTTPException(status_code=413, detail="Combined story and files exceed the 8 MiB request limit.")
        try:
            content = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"{name} must be UTF-8 text.") from exc
        source_name = name
        sources.append({"name": source_name, "kind": suffix[1:], "size_bytes": len(raw), "content": content})
        for row, reference in _parse_file(name, content):
            candidates.append((row, source_name, reference, json.dumps(row, ensure_ascii=False, sort_keys=True)))
    if not candidates:
        raise HTTPException(status_code=422, detail="Paste an incident description or select a supported evidence file.")
    if len(candidates) > MAX_EVENTS:
        raise HTTPException(status_code=413, detail=f"At most {MAX_EVENTS} records may be extracted at once.")
    events = [_normalize_row(row, source, reference, "deterministic_rules", raw) for row, source, reference, raw in candidates]
    fingerprints: dict[str, list[str]] = {}
    for event in events:
        digest = hashlib.sha256(json.dumps({key: event.get(key) for key in ("timestamp", "evidence_type", "identity", "source_ip", "description")}, sort_keys=True).encode()).hexdigest()
        fingerprints.setdefault(digest, []).append(event["event_id"])
    duplicate_ids = {event_id for same in fingerprints.values() if len(same) > 1 for event_id in same}
    for event in events:
        if event["event_id"] in duplicate_ids:
            event["warnings"].append("Possible duplicate: another submitted record has matching normalized fields. Review before import.")
    source_identity = json.dumps({"story": story, "sources": [{"name": item["name"], "content": item.get("content", "")} for item in sources]}, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(source_identity.encode("utf-8")).hexdigest()
    document = {"_id": uuid4().hex, "owner_id": user["id"], "content_hash": digest,
                "status": "needs_review", "created_at": datetime.now(timezone.utc),
                "sources": sources, "events": events,
                "warnings": ["Extraction uses deterministic field/keyword rules; no AI provider is configured or called.",
                             "Extracted statements are unverified evidence. Review and approve records before importing."],
                "story": story[:MAX_FILE_BYTES]}
    try:
        database.extractions.insert_one(document)
    except DuplicateKeyError:
        existing = database.extractions.find_one({"owner_id": user["id"], "content_hash": digest})
        _audit(database, user, "extraction_preview_reused", existing["_id"], {"event_count": len(existing["events"])})
        return _response(existing)
    _audit(database, user, "extraction_preview_created", document["_id"], {"event_count": len(events), "source_count": len(sources)})
    return _response(document)


@router.get("/{extraction_id}")
def get_extraction(extraction_id: str, user: dict = Depends(get_current_user), database=Depends(get_database)):
    return _response(_owned(database, extraction_id, user["id"]))


@router.put("/{extraction_id}/review")
def review_extraction(extraction_id: str, payload: ReviewRequest, user: dict = Depends(get_current_user), database=Depends(get_database)):
    doc = _owned(database, extraction_id, user["id"])
    if doc["status"] == "imported":
        raise HTTPException(status_code=409, detail="This extraction has already been imported and is read-only.")
    by_id = {event["event_id"]: event for event in doc["events"]}
    updates = {entry.event_id: entry for entry in payload.events}
    if set(updates) != set(by_id):
        raise HTTPException(status_code=422, detail="Review must include each extracted event exactly once.")
    editable = {"evidence_type", "timestamp", "identity", "source_ip", "destination_ip", "device_id", "api_service", "resource", "permission", "session_id", "token_id", "user_agent", "description"}
    reviewed = []
    for event_id, old in by_id.items():
        update = updates[event_id]
        event = dict(old)
        for key, value in update.fields.items():
            if key not in editable:
                raise HTTPException(status_code=422, detail=f"Field {key} cannot be edited in review.")
            event[key] = value
        if update.status == "approved":
            if not event.get("timestamp") or not _timestamp(event["timestamp"]):
                raise HTTPException(status_code=422, detail=f"Event {event_id} needs a complete timezone-aware timestamp before approval.")
            if not event.get("evidence_type") or not event.get("description"):
                raise HTTPException(status_code=422, detail=f"Event {event_id} needs an event type and description before approval.")
            event["timestamp"] = _timestamp(event["timestamp"])
        event["verification_status"] = update.status
        reviewed.append(event)
    database.extractions.update_one({"_id": extraction_id, "owner_id": user["id"]}, {"$set": {"events": reviewed, "status": "reviewed"}})
    _audit(database, user, "extraction_review_saved", extraction_id, {"approved": sum(event["verification_status"] == "approved" for event in reviewed), "rejected": sum(event["verification_status"] == "rejected" for event in reviewed)})
    return _response({**doc, "events": reviewed, "status": "reviewed"})


@router.post("/{extraction_id}/import", status_code=201)
def import_extraction(extraction_id: str, case_name: str = Form(min_length=1, max_length=200), user: dict = Depends(get_current_user), database=Depends(get_database)):
    doc = _owned(database, extraction_id, user["id"])
    if doc["status"] == "imported":
        return {"status": "already_imported", "case_id": doc["case_id"], "analysis_status": doc.get("analysis_status", "pending")}
    if doc["status"] not in {"reviewed"}:
        raise HTTPException(status_code=409, detail="Review and save this extraction before importing it.")
    approved = [event for event in doc["events"] if event.get("verification_status") == "approved"]
    if not approved:
        raise HTTPException(status_code=409, detail="Approve at least one extracted event before importing.")
    try:
        evidence = [IntakeEvidence.model_validate({key: value for key, value in event.items() if key not in {"event_id", "warnings"}}) for event in approved]
        payload = CaseIntake(case_name=case_name.strip(), description=doc.get("story") or "Imported reviewed evidence.", evidence=evidence)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Approved records are incomplete. Review their required fields.") from exc
    claimed = database.extractions.find_one_and_update(
        {"_id": extraction_id, "owner_id": user["id"], "status": "reviewed"},
        {"$set": {"status": "importing", "importing_started_at": datetime.now(timezone.utc)}},
        return_document=ReturnDocument.AFTER,
    )
    if not claimed:
        current = _owned(database, extraction_id, user["id"])
        if current["status"] == "imported":
            return {"status": "already_imported", "case_id": current["case_id"], "analysis_status": current.get("analysis_status", "pending")}
        raise HTTPException(status_code=409, detail="This extraction is already being imported. Refresh its status and try again.")
    from .cases import create_intake
    try:
        result = create_intake(payload, current_user=user, database=database)
    except Exception:
        database.extractions.update_one({"_id": extraction_id, "owner_id": user["id"], "status": "importing"}, {"$set": {"status": "reviewed"}, "$unset": {"importing_started_at": ""}})
        raise
    analysis_status = "analyzed"
    try:
        # Use the normal case analysis operation immediately so imported events
        # flow through the same deterministic engine as manually collected ones.
        from .cases import analyze_case
        analyze_case(result["case_id"], current_user=user, database=database)
    except Exception:
        # The evidence and case are already persisted. Preserve the import and
        # report the analysis as pending rather than fabricating a result.
        analysis_status = "pending"
        database.cases.update_one({"_id": result["case_id"], "created_by": user["id"]}, {"$set": {"status": "Draft"}})
    database.extractions.update_one({"_id": extraction_id, "owner_id": user["id"], "status": "importing"}, {"$set": {"status": "imported", "case_id": result["case_id"], "analysis_status": analysis_status, "imported_at": datetime.now(timezone.utc)}, "$unset": {"importing_started_at": ""}})
    _audit(database, user, "extraction_imported", extraction_id, {"case_id": result["case_id"], "event_count": len(approved)})
    return {"status": "imported", "analysis_status": analysis_status, **result}
