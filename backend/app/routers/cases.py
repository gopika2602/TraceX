"""Case analysis, evidence, origin tracing and remediation routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from attackpath import analyze, apply_remediation, explain, verify
from attackpath.origin import trace_backward

from ..auth import get_current_user, require_admin
from ..data import read_environment, read_events
from ..db import get_database
from ..models import CaseCreate, CaseIntake, InvestigatorNotes
from ..data import persist_dataset, validate_environment

router = APIRouter(tags=["cases"])


def _case_filter(user: dict) -> dict:
    return {} if user.get("role") == "admin" else {"created_by": user["id"]}


def _find_case(database, case_id: str, user: dict) -> dict:
    case = database.cases.find_one({"_id": case_id, **_case_filter(user)})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


def _latest_case(database, user: dict) -> dict | None:
    return database.cases.find_one(_case_filter(user), sort=[("created_at", -1)])


def _analysis(database, case: dict) -> dict:
    record = database.analyses.find_one({"case_id": case["_id"]})
    if not record:
        raise HTTPException(status_code=404, detail="Case analysis not found.")
    return record["result"]


def _case_events(database, case: dict) -> list[dict]:
    return read_events(database, case["dataset_id"])


def _case_environment(database, case: dict, version: int = 1) -> dict:
    environment = read_environment(database, case["dataset_id"], version)
    if environment is None:
        raise HTTPException(status_code=404, detail=f"Environment version {version} not found.")
    return environment


def _summary(result: dict, case_id: str, created_at: datetime, events: list[dict]) -> dict:
    root = result.get("root_cause", {})
    first_step = (result.get("attack_path", {}).get("steps") or [{}])[0]
    raw_time = first_step.get("timestamp")
    detected = raw_time or created_at.isoformat()
    try:
        detected = datetime.fromisoformat(str(detected).replace("Z", "+00:00")).strftime("%H:%M:%S UTC")
    except ValueError:
        pass
    identity = root.get("compromised_identity") or first_step.get("identity")
    event_by_id = {str(item.get("event_id", item.get("id"))): item for item in events}
    evidence = event_by_id.get(str((first_step.get("event_ids") or [""])[0]), {})
    source = str(evidence.get("event_type", evidence.get("type", "Correlated telemetry"))).replace("_", " ").title()
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    severities = [str(item.get("severity", "")).lower() for item in events]
    reported_severities = [item for item in severities if item in severity_rank]
    severity = max(reported_severities, key=severity_rank.get) if reported_severities else "unknown"
    return {
        "id": case_id,
        "title": f"Observed identity activity: {identity}" if identity else "Correlated security activity",
        "identity": identity or "Unknown identity",
        "severity": severity,
        "status": "Investigating",
        "detected": detected,
        "source": source,
        "synthetic": bool(result.get("synthetic", False)),
    }


def _intake_event(item, event_id: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": item.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": item.evidence_type,
        "permission": item.permission,
        "identity": item.identity or "unknown",
        "token_id": item.token_id or "unknown",
        "session_id": item.session_id or "unknown",
        "device_id": item.device_id or "unknown",
        "source": {"ip": item.source_ip or "unknown", "device_id": item.device_id or "unknown",
                   "session_id": item.session_id or "unknown", "user_agent": item.user_agent or "unknown"},
        "destination": {"ip": item.destination_ip or "unknown", "application": item.api_service or "unknown",
                        "resource": item.resource or item.api_service or "unknown"},
        "summary": item.description or "Investigator supplied evidence record.",
        "metadata": {"source_label": item.source, "process": item.process,
                     "authentication": item.authentication, "network_connection": item.network_connection},
    }


def _intake_environment(items, supplied_environment: dict[str, Any] | None = None) -> dict[str, Any]:
    if supplied_environment is not None:
        return validate_environment(supplied_environment)
    nodes: dict[str, dict[str, str]] = {}
    for item in items:
        for value, kind in ((item.source_ip, "ip"), (item.destination_ip, "ip"), (item.device_id, "device"),
                            (item.identity, "identity"), (item.session_id, "session"), (item.token_id, "token"),
                            (item.api_service, "service"), (item.resource, "resource")):
            if value:
                nodes.setdefault(value, {"id": value, "type": kind})
    return {"nodes": list(nodes.values()), "edges": [], "relationships": "No access edges are inferred from co-occurrence alone."}


@router.post("/cases/intake", status_code=201)
def create_intake(payload: CaseIntake, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    """Persist investigator intake and evidence, then analyze those exact records."""
    case_id = payload.case_id or f"CASE-{uuid4().hex[:8].upper()}"
    if database.cases.find_one({"_id": case_id}):
        raise HTTPException(status_code=409, detail="That case ID is already in use.")
    now = datetime.now(timezone.utc)
    events: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    for item in payload.evidence:
        record = item.model_dump(mode="json", exclude_none=True)
        event_id = f"evidence-{uuid4().hex}"
        events.append(_intake_event(item, event_id))
        evidence_rows.append({"_id": event_id, "case_id": case_id, "owner_id": current_user["id"],
                              "created_at": now, "record": record, "event_id": event_id})
    environment = _intake_environment(payload.evidence, payload.environment)
    dataset = persist_dataset(database, events, environment, name=payload.case_name, owner_id=current_user["id"])
    summary = {"id": case_id, "title": payload.case_name, "identity": "Unknown identity", "severity": "unknown",
               "status": "Draft", "detected": payload.incident_at.isoformat() if payload.incident_at else now.isoformat(),
               "source": "Investigator submitted evidence", "synthetic": False, "dataset_id": dataset["id"]}
    case = {
        "_id": case_id, "dataset_id": dataset["id"], "created_by": current_user["id"],
        "created_at": now, "status": "Investigating", "summary": summary,
        "case_information": {"case_name": payload.case_name, "organization": payload.organization,
                             "incident_at": payload.incident_at, "description": payload.description,
                             "investigator_name": payload.investigator_name,
                             "investigator_notes": payload.investigator_notes},
        "applied_remediation_ids": [],
    }
    database.cases.insert_one(case)
    database.evidence.insert_many(evidence_rows)
    return {"case_id": case_id, "case": {**summary, "dataset_id": dataset["id"]},
            "evidence_count": len(evidence_rows), "synthetic": False, "status": "Draft"}


@router.post("/cases/{case_id}/analyze")
def analyze_case(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _find_case(database, case_id, current_user)
    events = _case_events(database, case)
    if not events:
        raise HTTPException(status_code=409, detail="Add at least one evidence record before analysis.")
    environment = _case_environment(database, case, 1)
    result = analyze(events, environment)
    result["synthetic"] = False
    summary = _summary(result, case_id, case["created_at"], events)
    info = case.get("case_information", {})
    summary.update({"title": info.get("case_name", summary["title"]), "dataset_id": case["dataset_id"], "synthetic": False})
    database.cases.update_one({"_id": case_id}, {"$set": {"summary": summary, "status": "Investigating"}})
    database.analyses.replace_one({"_id": case_id}, {"_id": case_id, "case_id": case_id,
        "dataset_id": case["dataset_id"], "result": result, "created_at": datetime.now(timezone.utc)}, upsert=True)
    return {"case_id": case_id, "status": "analyzed", "event_count": len(events), "analysis": summary}


def _stored_evidence_response(document: dict) -> dict:
    return {"id": document["_id"], **document["record"], "event_id": document["event_id"]}


@router.get("/cases/{case_id}/collected-evidence")
def list_collected_evidence(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _find_case(database, case_id, current_user)
    return [_stored_evidence_response(row) for row in database.evidence.find({"case_id": case_id}).sort("record.timestamp", 1)]


@router.patch("/cases/{case_id}/notes")
def update_case_notes(case_id: str, payload: InvestigatorNotes, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _find_case(database, case_id, current_user)
    database.cases.update_one({"_id": case_id}, {"$set": {"case_information.investigator_notes": payload.notes}})
    return {"case_id": case_id, "investigator_notes": payload.notes}


def _path_response(result: dict, events: list[dict], case_id: str) -> dict:
    by_id = {str(item.get("event_id", item.get("id"))): item for item in events}
    stages = result.get("attack_path", {}).get("steps", [])
    steps = []
    previous_target: str | None = None
    for index, raw in enumerate(stages, start=1):
        event_id = str((raw.get("event_ids") or [""])[0])
        event = by_id.get(event_id, {})
        destination = event.get("destination") if isinstance(event.get("destination"), dict) else {}
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        stage = raw.get("stage", "observed_activity")
        identity = str(raw.get("identity") or "unknown identity")
        token = str(raw.get("token_id") or "unknown token")
        application = str(raw.get("application") or destination.get("application") or "unknown application")
        resource = str(raw.get("resource") or destination.get("resource") or application)
        if stage == "initial_compromise":
            source_id, target_id = str(source.get("ip") or identity), identity
        elif stage == "token_abuse":
            source_id, target_id = identity, token
        elif stage == "application_access":
            source_id, target_id = token, application
        elif stage == "token_created":
            source_id, target_id = application, token
        elif stage in {"privilege_escalation", "data_access"}:
            source_id, target_id = previous_target or token, resource
        else:
            source_id, target_id = token, resource
        permission = str(event.get("permission") or "observed")
        timestamp = str(raw.get("timestamp") or event.get("timestamp") or event.get("time") or "")
        steps.append({
            "step": index,
            "source": source_id,
            "target": target_id,
            "permission": permission,
            "stage": stage,
            "summary": str(raw.get("summary") or event.get("summary") or event.get("event_type") or stage),
            "event_ids": [event_id] if event_id else [],
            "timestamp": timestamp,
        })
        previous_target = target_id
    return {"case_id": case_id, "steps": steps}


def _root_cause_response(result: dict) -> dict:
    root = result.get("root_cause", {})
    codes = {
        "TOKEN_NOT_BOUND_TO_DEVICE": "Credential not bound to observed device",
        "EXCESSIVE_OAUTH_SCOPE": "Excessive OAuth permissions",
        "NO_STEP_UP_AUTH": "No step-up authentication",
    }
    factors = [{"code": item.get("code", "OBSERVED_FACTOR"), "title": codes.get(item.get("code"), "Contributing factor"), "detail": item.get("description", "")}
               for item in root.get("contributing_factors", [])]
    immediate = root.get("immediate_breakpoint", {})
    structural = root.get("structural_breakpoint", {})
    breakpoints = []
    for kind, data in (("immediate", immediate), ("structural", structural)):
        if data:
            breakpoints.append({
                "type": kind,
                "step": data.get("breaks_at_step", 0),
                "action": "Revoke compromised credential" if kind == "immediate" else "Remove excessive permission",
                "reason": f"{data.get('action', 'remediate')} {data.get('token_id', data.get('permission', 'access'))} to interrupt the observed path.",
            })
    return {
        "initial_compromise": root.get("compromised_identity") or "Unknown identity",
        "affected_device": root.get("affected_device"),
        "abused_credential": root.get("abused_credential") or "Unknown credential",
        "summary": root.get("summary", "The analysis did not establish a root cause."),
        "evidence_event_ids": root.get("evidence_event_ids", []),
        "related_event_ids": [str(event_id) for step in result.get("attack_path", {}).get("steps", []) for event_id in step.get("event_ids", [])],
        "confidence": None,
        "contributing_factors": factors,
        "breakpoints": breakpoints,
    }


def _blast_radius_response(result: dict) -> dict:
    blast = result.get("blast_radius", {})
    summary = blast.get("summary", {})
    assets = [{
        "name": item.get("node_id", "unknown"),
        "category": item.get("tags", ["resource"])[0] if isinstance(item.get("tags"), list) and item.get("tags") else item.get("type", "resource"),
        "sensitivity": str(item.get("sensitivity", "low")).title(),
        "hops": item.get("hops", 0),
    } for item in blast.get("reachable_nodes", [])]
    return {
        "reachable_resources": summary.get("reachable_resources", 0),
        "sensitive_assets": summary.get("sensitive_assets", 0),
        "critical_systems": summary.get("critical_systems", 0),
        "financial_apis": summary.get("financial_apis", 0),
        "customer_data_systems": summary.get("customer_data_systems", 0),
        "other_identities": summary.get("other_identities", 0),
        "assets": assets,
        "synthetic": bool(result.get("synthetic", False)),
    }


def _remediation_response(result: dict, case: dict) -> list[dict]:
    applied = set(case.get("applied_remediation_ids", []))
    priorities = {"revoke_token": "Critical", "reduce_scope": "High", "require_step_up_auth": "Medium"}
    titles = {"revoke_token": "Revoke compromised token", "reduce_scope": "Remove excessive OAuth scope", "require_step_up_auth": "Require step-up authentication"}
    items = []
    for raw in result.get("remediations", []):
        remediation_id = raw.get("remediation_id", raw.get("id", ""))
        action = raw.get("action", "review")
        collateral = raw.get("collateral", {})
        if isinstance(collateral, dict):
            count = collateral.get("users_affected", 0)
            collateral_text = f"{count} users affected" if isinstance(count, int) else str(count)
        else:
            collateral_text = str(collateral)
        items.append({
            "id": remediation_id,
            "title": titles.get(action, action.replace("_", " ").title()),
            "description": raw.get("description", ""),
            "action": action,
            "priority": priorities.get(action, "Medium"),
            "expected_paths_broken": raw.get("expected_paths_broken", []),
            "collateral": collateral_text,
            "status": "applied" if remediation_id in applied else "recommended",
        })
    return items


def _origin_assessment(result: dict, case_id: str) -> dict:
    origin = result.get("attack_origin", {})
    likely = origin.get("likely_origin")
    candidates = origin.get("candidate_origins", [])
    top = next((item for item in candidates if item.get("entity_id") == (likely or {}).get("entity_id")), None) or (candidates[0] if candidates else None)
    selected = likely or top
    score = (selected or {}).get("confidence_score")
    suspect = None
    likely_origin = None
    status = "inconclusive"
    if selected:
        kind = selected.get("entity_type", "unknown")
        label = str(selected.get("entity_id", "Unknown"))
        is_likely = bool(likely and selected.get("entity_id") == likely.get("entity_id"))
        status = "likely-origin" if is_likely else "inconclusive"
        candidate_state = selected.get("status", "unknown")
        state = {
            "likely_attack_origin": "likely-origin",
            "suspected_origin": "suspected-origin",
            "potential_victim": "potential-victim",
            "suspected_compromised_device": "suspected-compromised-device",
        }.get(candidate_state, "unknown")
        suspect = {"id": label, "label": label, "kind": kind, "state": state, "reason": selected.get("reason", "")}
        if is_likely:
            likely_origin = {"id": label, "label": label, "kind": kind}
    limitations = origin.get("limitations", [])
    summary = (selected or {}).get("reason") or (limitations[0] if limitations else "Available telemetry did not establish an origin.")
    return {
        "case_id": case_id,
        "status": status,
        "suspect": suspect,
        "likely_origin": likely_origin,
        "confidence": {"score": max(0, min(1, float(score or 0) / 100)), "label": (selected or {}).get("confidence_level", "UNKNOWN")},
        "summary": summary,
        "attribution_confirmed": False,
    }


def _evidence_response(result: dict, events: list[dict]) -> list[dict]:
    attack_event_ids = {str(event_id) for step in result.get("attack_path", {}).get("steps", []) for event_id in step.get("event_ids", [])}
    evidence_event_ids = {
        str(item.get("event_id"))
        for candidate in result.get("attack_origin", {}).get("candidate_origins", [])
        for item in candidate.get("supporting_evidence", [])
        if item.get("event_id")
    }
    items = []
    for event in events:
        event_id = str(event.get("event_id", event.get("id", "unknown")))
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        destination = event.get("destination") if isinstance(event.get("destination"), dict) else {}
        destination_label = destination.get("resource") or destination.get("application")
        items.append({
            "id": event_id,
            "timestamp": event.get("timestamp", event.get("time", "")),
            "event_type": event.get("event_type", event.get("type", "Unknown event")),
            "source": str(source.get("ip")) if source.get("ip") else None,
            "destination": str(destination_label) if destination_label else None,
            "device": str(event.get("device_id")) if event.get("device_id") else None,
            "user": str(event.get("identity")) if event.get("identity") else None,
            "ip": str(source.get("ip")) if source.get("ip") else None,
            "reason": str(event.get("summary") or "Observed telemetry record from the ingested dataset."),
            "strength": "strong" if event_id in evidence_event_ids else "suspected" if event_id in attack_event_ids else "unknown",
        })
    return items


def _case_with_analysis(case_id: str, database, user: dict) -> tuple[dict, dict, list[dict]]:
    case = _find_case(database, case_id, user)
    result = _analysis(database, case)
    events = _case_events(database, case)
    return case, result, events


@router.get("/cases")
def list_cases(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    return [row["summary"] for row in database.cases.find(_case_filter(current_user)).sort("created_at", -1)]


@router.get("/cases.json")
def list_cases_legacy(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    return list_cases(current_user, database)


@router.post("/cases", status_code=201)
def create_case(payload: CaseCreate | None = None, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    payload = payload or CaseCreate()
    dataset = database.datasets.find_one({"_id": payload.dataset_id}) if payload.dataset_id else database.datasets.find_one({}, sort=[("created_at", -1)])
    if not dataset:
        raise HTTPException(status_code=409, detail="Load a dataset with POST /datasets/load-demo or upload one before creating a case.")
    events = read_events(database, dataset["_id"])
    environment = read_environment(database, dataset["_id"], 1)
    if environment is None:
        raise HTTPException(status_code=409, detail="The dataset does not have an original environment version.")
    result = analyze(events, environment)
    result["synthetic"] = bool(dataset.get("synthetic", False))
    now = datetime.now(timezone.utc)
    case_id = f"CASE-{uuid4().hex[:8].upper()}"
    summary = _summary(result, case_id, now, events)
    database.cases.insert_one({
        "_id": case_id, "dataset_id": dataset["_id"], "created_by": current_user["id"],
        "created_at": now, "status": "Investigating", "summary": summary,
        "applied_remediation_ids": [],
    })
    database.analyses.insert_one({"_id": case_id, "case_id": case_id, "dataset_id": dataset["_id"], "result": result, "created_at": now})
    return {"case_id": case_id, "analysis_id": case_id, "case": summary, "synthetic": bool(dataset.get("synthetic"))}


@router.get("/cases/{case_id}")
def get_case(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _find_case(database, case_id, current_user)
    return {**case["summary"], "dataset_id": case["dataset_id"], "created_at": case["created_at"].isoformat(),
            "case_information": case.get("case_information", {})}


def _event_response(events: list[dict]) -> list[dict]:
    response = []
    for item in events:
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        destination = item.get("destination") if isinstance(item.get("destination"), dict) else {}
        response.append({
            "event_id": item.get("event_id", item.get("id", "")),
            "time": item.get("timestamp", item.get("time", "")),
            "event_type": item.get("event_type", item.get("type", "Unknown")),
            "identity": item.get("identity", "unknown"),
            "token": item.get("token_id", "unknown"),
            "application": destination.get("application", "unknown"),
            "resource": destination.get("resource", "unknown"),
            "severity": item.get("severity", "unknown"),
            "source_ip": source.get("ip", "unknown"),
            "location": source.get("country", "Unknown"),
        })
    return response


@router.get("/cases/{case_id}/events")
def get_case_events(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _find_case(database, case_id, current_user)
    return _event_response(_case_events(database, case))


@router.get("/cases/{case_id}/correlation")
def get_correlation(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, _ = _case_with_analysis(case_id, database, current_user)
    return result.get("correlation", [])


@router.get("/cases/{case_id}/attack-path")
def get_attack_path(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, events = _case_with_analysis(case_id, database, current_user)
    return _path_response(result, events, case_id)


@router.get("/cases/{case_id}/root-cause")
def get_root_cause(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, _ = _case_with_analysis(case_id, database, current_user)
    return _root_cause_response(result)


@router.get("/cases/{case_id}/blast-radius")
def get_blast_radius(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, _ = _case_with_analysis(case_id, database, current_user)
    return _blast_radius_response(result)


@router.get("/cases/{case_id}/explanation")
def get_explanation(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, _ = _case_with_analysis(case_id, database, current_user)
    return {"case_id": case_id, "explanation": explain(result), "synthetic": bool(result.get("synthetic"))}


@router.get("/cases/{case_id}/remediations")
def get_remediations(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case, result, _ = _case_with_analysis(case_id, database, current_user)
    return _remediation_response(result, case)


@router.get("/cases/{case_id}/attack-origin")
def get_attack_origin(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, _ = _case_with_analysis(case_id, database, current_user)
    return _origin_assessment(result, case_id)


@router.get("/cases/{case_id}/evidence")
def get_evidence(case_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, events = _case_with_analysis(case_id, database, current_user)
    return _evidence_response(result, events)


@router.get("/cases/{case_id}/attack-origin/trace")
def get_attack_origin_trace(case_id: str, suspect_id: str = Query(min_length=1), current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    _, result, events = _case_with_analysis(case_id, database, current_user)
    candidates = result.get("attack_origin", {}).get("candidate_origins", [])
    candidate = next((item for item in candidates if str(item.get("entity_id")) == suspect_id), None)
    if not candidate:
        raise HTTPException(status_code=404, detail="Suspect was not found in this case's backend origin assessment.")
    seed_ids = [str(event_id) for step in result.get("attack_path", {}).get("steps", []) for event_id in step.get("event_ids", [])]
    trace = trace_backward(events, seed_ids)
    linked_events = [events[index] for index in trace["event_indices"]]
    nodes = []
    for event in linked_events:
        event_id = str(event.get("event_id", event.get("id", "unknown")))
        nodes.append({
            "id": event_id,
            "label": str(event.get("event_type", event.get("type", "Observed event"))).replace("_", " "),
            "kind": "event",
            "state": "likely-origin" if event.get("event_type") == "malicious_external_connection" and candidate.get("entity_type") in {"ip", "device"} else "confirmed-evidence" if event_id in seed_ids else "suspect",
            "detail": f"{event.get('timestamp', 'time unknown')} · {event.get('identity', 'identity not recorded')}",
            "event_ids": [event_id],
        })
    edges = [{
        "id": f"trace-{index + 1}", "source": link["from_event_id"], "target": link["to_event_id"],
        "label": ", ".join(link.get("relationship", [])), "event_id": link["to_event_id"],
    } for index, link in enumerate(trace["links"])
      if link["from_event_id"] in {node["id"] for node in nodes} and link["to_event_id"] in {node["id"] for node in nodes}]
    likely = result.get("attack_origin", {}).get("likely_origin")
    return {
        "case_id": case_id,
        "nodes": nodes,
        "edges": edges,
        "likely_origin_id": likely.get("entity_id") if likely else None,
        "attribution_confirmed": False,
        "limitations": trace.get("limitations", []),
    }


@router.get("/events.json")
def events_legacy(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _latest_case(database, current_user)
    if not case:
        return []
    return _event_response(_case_events(database, case))


@router.get("/attack-path.json")
def attack_path_legacy(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _latest_case(database, current_user)
    if not case:
        return {"case_id": "", "steps": []}
    return _path_response(_analysis(database, case), _case_events(database, case), case["_id"])


@router.get("/root-cause.json")
def root_cause_legacy(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _latest_case(database, current_user)
    return _root_cause_response(_analysis(database, case)) if case else {"initial_compromise": "Unknown", "abused_credential": "Unknown", "summary": "No analysis exists yet.", "contributing_factors": [], "breakpoints": []}


@router.get("/blast-radius.json")
def blast_radius_legacy(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _latest_case(database, current_user)
    return _blast_radius_response(_analysis(database, case)) if case else {"reachable_resources": 0, "sensitive_assets": 0, "critical_systems": 0, "financial_apis": 0, "customer_data_systems": 0, "other_identities": 0, "assets": [], "synthetic": True}


@router.get("/remediations.json")
def remediations_legacy(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    case = _latest_case(database, current_user)
    return _remediation_response(_analysis(database, case), case) if case else []


def _apply_case_remediation(case_id: str, remediation_id: str, database, user: dict) -> dict:
    case, result, _ = _case_with_analysis(case_id, database, user)
    remediation = next((item for item in result.get("remediations", []) if item.get("remediation_id") == remediation_id), None)
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found for this case.")
    original = _case_environment(database, case, 1)
    current = read_environment(database, case["dataset_id"], 2) or original
    try:
        updated = apply_remediation(current, remediation)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    now = datetime.now(timezone.utc)
    database.environments.replace_one({"dataset_id": case["dataset_id"], "version": 2}, {
        "_id": f"{case['dataset_id']}:v2", "dataset_id": case["dataset_id"], "version": 2,
        "data": updated, "created_at": now, "remediation_id": remediation_id,
        "synthetic": bool((database.datasets.find_one({"_id": case["dataset_id"]}) or {}).get("synthetic", False)),
    }, upsert=True)
    database.cases.update_one({"_id": case_id}, {"$addToSet": {"applied_remediation_ids": remediation_id}})
    return {"id": remediation_id, "status": "applied", "environment_version": 2}


@router.post("/cases/{case_id}/remediations/{remediation_id}/apply")
def apply_case_remediation(case_id: str, remediation_id: str, user: dict = Depends(require_admin), database=Depends(get_database)):
    return _apply_case_remediation(case_id, remediation_id, database, user)


@router.post("/remediations/{remediation_id}/apply")
def apply_remediation_legacy(remediation_id: str, user: dict = Depends(require_admin), database=Depends(get_database)):
    case = _latest_case(database, user)
    if not case:
        raise HTTPException(status_code=404, detail="No case is available for remediation.")
    return _apply_case_remediation(case["_id"], remediation_id, database, user)


def _verify_case(case_id: str, remediation_id: str | None, database, user: dict) -> dict:
    case, result, _ = _case_with_analysis(case_id, database, user)
    before = _case_environment(database, case, 1)
    after = _case_environment(database, case, 2)
    raw = verify(result.get("attack_path", {}), before, after, result.get("root_cause", {}).get("abused_credential"))
    allowed_before = [item["step_number"] for item in raw.get("steps_before", []) if item.get("allowed")]
    allowed_after = [item["step_number"] for item in raw.get("steps_after", []) if item.get("allowed")]
    verification = {
        "case_id": case_id,
        "remediation_id": remediation_id,
        "status": raw.get("result", "PATH_STILL_OPEN"),
        "broken_at_step": raw.get("first_denied_step"),
        "before_allowed_steps": allowed_before,
        "after_allowed_steps": allowed_after,
        "before_blast_radius": raw.get("blast_radius_before", {}).get("summary", {}).get("reachable_resources", 0),
        "after_blast_radius": raw.get("blast_radius_after", {}).get("summary", {}).get("reachable_resources", 0),
        "transition_count": raw.get("transition_count", 0),
        "normal_access_preserved": raw.get("normal_access_preserved"),
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "synthetic": bool((database.datasets.find_one({"_id": case["dataset_id"]}) or {}).get("synthetic", False)),
    }
    verification_id = f"{case_id}:{remediation_id or 'latest'}"
    database.verifications.replace_one({"_id": verification_id}, {"_id": verification_id, **verification}, upsert=True)
    return verification


@router.post("/cases/{case_id}/verify")
def verify_case(case_id: str, remediation_id: str | None = None, user: dict = Depends(require_admin), database=Depends(get_database)):
    return _verify_case(case_id, remediation_id, database, user)


@router.post("/remediations/{remediation_id}/verify")
def verify_legacy(remediation_id: str, user: dict = Depends(require_admin), database=Depends(get_database)):
    case = _latest_case(database, user)
    if not case:
        raise HTTPException(status_code=404, detail="No case is available for verification.")
    return _verify_case(case["_id"], remediation_id, database, user)


@router.post("/reset-demo")
def reset_demo(user: dict = Depends(require_admin), database=Depends(get_database)):
    case_ids = [case["_id"] for case in database.cases.find({"dataset_id": "demo-nimbus"}, {"_id": 1})]
    database.cases.delete_many({"dataset_id": "demo-nimbus"})
    database.analyses.delete_many({"dataset_id": "demo-nimbus"})
    if case_ids:
        database.verifications.delete_many({"case_id": {"$in": case_ids}})
    database.environments.delete_many({"dataset_id": "demo-nimbus", "version": {"$gt": 1}})
    return {"status": "ok", "deleted_cases": len(case_ids), "removed_environment_versions": True}
