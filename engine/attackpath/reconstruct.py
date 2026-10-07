"""Observed incident path reconstruction."""

from __future__ import annotations

from typing import Any

STAGES = (
    "initial_compromise", "token_abuse", "application_access", "token_created",
    "api_access", "privilege_escalation", "data_access",
)


def _classify(event: dict[str, Any]) -> str:
    kind = str(event.get("event_type", event.get("type", ""))).lower()
    app = str(event.get("destination", {}).get("application", "") if isinstance(event.get("destination"), dict) else "").lower()
    resource = str(event.get("destination", {}).get("resource", "") if isinstance(event.get("destination"), dict) else "").lower()
    text = " ".join((kind, app, resource))
    if "session_reuse" in text or "new_device" in text or "login" in kind:
        return "initial_compromise"
    if "token_use" in kind or "token_abuse" in kind:
        return "token_abuse"
    if "oauth" in text or "token_create" in text or "token_issued" in text:
        return "token_created"
    if "db_query" in text or "database" in text or "customers-db" in text:
        return "data_access"
    if "privilege" in text or "payments-svc" in text:
        return "privilege_escalation"
    if "api_call" in text or "orders-api" in text:
        return "api_access"
    if "application_access" in text or "helpdeskpro" in text:
        return "application_access"
    return "token_abuse"


def reconstruct(events: list[dict[str, Any]], group: dict[str, Any]) -> dict[str, Any]:
    by_id = {str(event.get("event_id", event.get("id"))): event for event in events}
    selected = [by_id[event_id] for event_id in group["event_ids"] if event_id in by_id]
    selected.sort(key=lambda event: str(event.get("timestamp", event.get("time", ""))))
    staged: dict[str, list[dict[str, Any]]] = {stage: [] for stage in STAGES}
    for event in selected:
        staged[_classify(event)].append(event)
    ordered = []
    for stage in STAGES:
        ordered.extend(staged[stage])
    steps = []
    graph_nodes: dict[str, dict[str, Any]] = {}
    edges = []
    for number, event in enumerate(ordered, start=1):
        stage = _classify(event)
        event_id = str(event.get("event_id", event.get("id", f"event-{number}")))
        destination = event.get("destination", {}) if isinstance(event.get("destination"), dict) else {}
        identity = event.get("identity", event.get("actor", {}).get("identity") if isinstance(event.get("actor"), dict) else None)
        token = event.get("token_id")
        app = destination.get("application")
        resource = destination.get("resource")
        steps.append({"step_number": number, "stage": stage, "event_ids": [event_id],
                      "timestamp": event.get("timestamp", event.get("time")),
                      "identity": identity, "token_id": token, "application": app,
                      "resource": resource, "summary": event.get("summary", event.get("event_type", event.get("type", stage)))})
        chain = [x for x in (identity, token, app, resource) if x]
        for value in chain:
            graph_nodes[str(value)] = {"id": str(value), "label": str(value), "type": _node_type(str(value))}
        edges.extend({"from": str(a), "to": str(b), "event_id": event_id} for a, b in zip(chain, chain[1:]))
    return {"steps": steps, "nodes": list(graph_nodes.values()), "edges": edges}


def _node_type(value: str) -> str:
    lowered = value.lower()
    if "tok-" in lowered or "oauth-" in lowered: return "token"
    if "api" in lowered: return "api"
    if "svc" in lowered: return "service"
    if "db" in lowered: return "database"
    if lowered in {"helpdeskpro", "crm", "email"}: return "application"
    return "identity"
