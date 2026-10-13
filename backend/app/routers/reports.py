"""Authenticated read-only generation and delivery of investigation reports."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from io import BytesIO
import logging
import re
from typing import Literal
from uuid import uuid4

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from gridfs import GridFSBucket
from pydantic import BaseModel, Field

from ..auth import get_current_user
from ..data import read_environment
from ..db import get_database
from ..reporting import (MAX_REPORT_BYTES, SECTION_LABELS, generate_pdf,
    generate_powerpoint, make_report_model)
from .cases import _case_events, _find_case

router = APIRouter(tags=["investigation reports"])
logger = logging.getLogger(__name__)


class GenerateReportRequest(BaseModel):
    format: Literal["pdf", "powerpoint", "both"]
    sections: list[str] = Field(min_length=1, max_length=12)


def _load_report_model(case_id: str, user: dict, database):
    case = _find_case(database, case_id, user)
    analysis_doc = database.analyses.find_one({"case_id": case_id})
    evidence_rows = list(database.evidence.find({"case_id": case_id}).sort("record.timestamp", 1))
    events = _case_events(database, case)
    environment = read_environment(database, case["dataset_id"], 1)
    analysis = analysis_doc.get("result") if analysis_doc else None
    return make_report_model(case, analysis, events, evidence_rows, environment)


def _summary(model: dict) -> dict:
    counts = model["evidence_counts"]
    return {
        "case": {"id": model["case_id"], "title": model["title"], "status": model["status"]},
        "counts": {"evidence_records": counts["total"], "approved": counts["approved"],
                   "rejected": counts["rejected"], "awaiting_review": counts["awaiting_review"],
                   "timeline_events": model["event_count"]},
        "analysis_available": model["analysis_available"],
        "composition_mode": model["composition_mode"],
        "disclosure": model["composition_disclosure"],
        "sections": [{"key": key, "label": label,
                      "available": bool(model["available_sections"].get(key)),
                      "reason": None if model["available_sections"].get(key) else "Required persisted data is not available; the report will not invent it."}
                     for key, label in SECTION_LABELS.items()],
    }


def _public_report(document: dict) -> dict:
    return {"id": document["_id"], "case_id": document["case_id"], "status": document["status"],
            "generated_at": document["generated_at"].isoformat(), "sections": document["sections"],
            "composition_mode": document["composition_mode"], "errors": document.get("errors", []),
            "files": [{"format": item["format"], "filename": item["filename"],
                       "size_bytes": item["size_bytes"], "sha512": item["sha512"],
                       "download_url": f"/reports/{document['_id']}/{item['format']}/download"}
                      for item in document["files"]]}


@router.get("/cases/{case_id}/reports/readiness")
def report_readiness(case_id: str, user: dict = Depends(get_current_user), database=Depends(get_database)):
    model = _load_report_model(case_id, user, database)
    return _summary(model)


@router.get("/cases/{case_id}/reports")
def list_reports(case_id: str, user: dict = Depends(get_current_user), database=Depends(get_database)):
    _find_case(database, case_id, user)
    docs = database.reports.find({"case_id": case_id}).sort("generated_at", -1)
    return {"reports": [_public_report(doc) for doc in docs]}


@router.post("/cases/{case_id}/reports", status_code=201)
def generate_report(case_id: str, payload: GenerateReportRequest,
                    user: dict = Depends(get_current_user), database=Depends(get_database)):
    if len(set(payload.sections)) != len(payload.sections):
        raise HTTPException(status_code=422, detail="Report sections must not be repeated.")
    unknown = sorted(set(payload.sections) - set(SECTION_LABELS))
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown report section: {unknown[0]}.")
    model = _load_report_model(case_id, user, database)
    generated_at = datetime.now(timezone.utc)
    model["generated_at"] = generated_at.isoformat()
    formats = ["pdf", "powerpoint"] if payload.format == "both" else [payload.format]
    output: list[tuple[str, bytes, str]] = []
    errors: list[dict[str, str]] = []
    case_label = re.sub(r"[^A-Za-z0-9_-]", "-", case_id)[:80]
    report_id = uuid4().hex
    for report_format in formats:
        try:
            data = generate_pdf(model, payload.sections) if report_format == "pdf" else generate_powerpoint(model, payload.sections)
            if not data or len(data) > MAX_REPORT_BYTES:
                raise ValueError("Generated output did not pass size validation.")
            extension = "pdf" if report_format == "pdf" else "pptx"
            filename = f"TraceX-{case_label}-{report_id}.{extension}"
            output.append((report_format, data, filename))
        except Exception as exc:
            logger.error("Report %s generation failed (%s).", report_format, type(exc).__name__)
            errors.append({"format": report_format, "message": f"The {report_format} report could not be generated. You can retry this format."})
    if not output:
        raise HTTPException(status_code=500, detail="Report generation failed for all requested formats. No report file was saved.")

    bucket = GridFSBucket(database, bucket_name="tracex_reports")
    stored_files = []
    try:
        for report_format, data, filename in output:
            file_id = bucket.upload_from_stream(filename, BytesIO(data), metadata={
                "report_id": report_id, "case_id": case_id, "owner_id": user["id"], "format": report_format,
            })
            stored_files.append({"format": report_format, "filename": filename, "gridfs_id": str(file_id),
                                 "size_bytes": len(data), "sha512": hashlib.sha512(data).hexdigest()})
        status = "ready" if not errors else "partial"
        document = {"_id": report_id, "case_id": case_id, "owner_id": user["id"],
                    "status": status, "generated_at": generated_at, "sections": payload.sections,
                    "composition_mode": "deterministic", "files": stored_files, "errors": errors,
                    "source_event_ids": [str(event.get("event_id", event.get("id", ""))) for event in model["events"]],
                    "source_evidence_ids": [item["id"] for item in model["evidence"]]}
        database.reports.insert_one(document)
    except Exception as exc:
        logger.error("Report persistence failed (%s).", type(exc).__name__)
        for item in stored_files:
            try:
                bucket.delete(ObjectId(item["gridfs_id"]))
            except Exception:
                pass
        raise HTTPException(status_code=503, detail="The generated report could not be saved. Check database availability and retry.") from exc
    return {"readiness": _summary(model), "report": _public_report(document)}


@router.get("/reports/{report_id}/{report_format}/download")
def download_report(report_id: str, report_format: Literal["pdf", "powerpoint"],
                    user: dict = Depends(get_current_user), database=Depends(get_database)):
    if not re.fullmatch(r"[a-f0-9]{32}", report_id):
        raise HTTPException(status_code=404, detail="Report not found.")
    document = database.reports.find_one({"_id": report_id})
    if not document:
        raise HTTPException(status_code=404, detail="Report not found.")
    _find_case(database, document["case_id"], user)
    item = next((value for value in document.get("files", []) if value.get("format") == report_format), None)
    if not item:
        raise HTTPException(status_code=404, detail=f"No {report_format} file is available for this report.")
    try:
        data = GridFSBucket(database, bucket_name="tracex_reports").open_download_stream(ObjectId(item["gridfs_id"])).read()
    except Exception as exc:
        logger.error("Stored report download failed (%s).", type(exc).__name__)
        raise HTTPException(status_code=503, detail="The saved report file is temporarily unavailable.") from exc
    if len(data) != item["size_bytes"] or hashlib.sha512(data).hexdigest() != item["sha512"]:
        raise HTTPException(status_code=503, detail="The saved report did not pass integrity validation.")
    media_type = "application/pdf" if report_format == "pdf" else "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    return Response(data, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{item["filename"]}"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"})
