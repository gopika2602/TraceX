"""Validation and persistence helpers for uploaded/demo datasets."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import HTTPException


MAX_DATASET_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 100_000


def _nested(value: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def validate_events(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("events", value.get("items"))
    if not isinstance(value, list) or not value:
        raise HTTPException(status_code=422, detail="Events JSON must contain a non-empty list of event objects.")
    if len(value) > MAX_EVENTS:
        raise HTTPException(status_code=413, detail=f"A dataset may contain at most {MAX_EVENTS} events.")
    errors: list[str] = []
    seen: set[str] = set()
    for index, event in enumerate(value):
        if not isinstance(event, dict):
            errors.append(f"events[{index}] must be an object")
            continue
        required = {
            "event_id": event.get("event_id", event.get("id")),
            "timestamp": event.get("timestamp", event.get("time", event.get("occurred_at"))),
            "event_type": event.get("event_type", event.get("type")),
            "identity": event.get("identity", _nested(event, "actor", "identity")),
            "token_id": event.get("token_id", _nested(event, "source", "token_id")),
            "session_id": event.get("session_id", _nested(event, "source", "session_id")),
            "device_id": event.get("device_id", _nested(event, "source", "device_id")),
            "source.ip": _nested(event, "source", "ip"),
            "destination.application": _nested(event, "destination", "application"),
            "destination.resource": _nested(event, "destination", "resource"),
        }
        missing = [key for key, item in required.items() if item in (None, "")]
        if missing:
            errors.append(f"events[{index}] missing {', '.join(missing)}")
        event_id = str(required["event_id"] or "")
        if event_id in seen:
            errors.append(f"events[{index}] duplicates event_id {event_id}")
        if event_id:
            seen.add(event_id)
        timestamp = required["timestamp"]
        if timestamp:
            try:
                datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"events[{index}].timestamp must be an ISO 8601 timestamp")
    if errors:
        raise HTTPException(status_code=422, detail={"message": "Event contract validation failed.", "errors": errors[:50]})
    return value


def validate_environment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), list) or not isinstance(value.get("edges"), list):
        raise HTTPException(status_code=422, detail="Environment JSON must contain nodes and edges arrays.")
    node_ids: set[str] = set()
    for index, node in enumerate(value["nodes"]):
        node_id = node if isinstance(node, str) else node.get("id", node.get("node_id")) if isinstance(node, dict) else None
        if not node_id:
            raise HTTPException(status_code=422, detail=f"environment.nodes[{index}] must have an id.")
        if str(node_id) in node_ids:
            raise HTTPException(status_code=422, detail=f"environment contains duplicate node id {node_id}.")
        node_ids.add(str(node_id))
    for index, edge in enumerate(value["edges"]):
        if not isinstance(edge, dict):
            raise HTTPException(status_code=422, detail=f"environment.edges[{index}] must be an object.")
        source, target, permission = edge.get("from", edge.get("source")), edge.get("to", edge.get("target")), edge.get("permission", edge.get("permissions"))
        if source is None or target is None or permission in (None, "", []):
            raise HTTPException(status_code=422, detail=f"environment.edges[{index}] requires from, to and permission.")
        if str(source) not in node_ids or str(target) not in node_ids:
            raise HTTPException(status_code=422, detail=f"environment.edges[{index}] refers to an unknown node.")
    return value


def persist_dataset(database, events: list[dict[str, Any]], environment: dict[str, Any], *, name: str, owner_id: str, dataset_id: str | None = None, synthetic: bool = False) -> dict[str, Any]:
    dataset_id = dataset_id or uuid4().hex
    now = datetime.now(timezone.utc)
    database.events.delete_many({"dataset_id": dataset_id})
    database.environments.delete_many({"dataset_id": dataset_id})
    database.events.insert_many([
        {"_id": f"{dataset_id}:{item.get('event_id', item.get('id'))}", "dataset_id": dataset_id, "event_index": index, "payload": item}
        for index, item in enumerate(events)
    ])
    database.environments.insert_one({
        "_id": f"{dataset_id}:v1", "dataset_id": dataset_id, "version": 1,
        "data": environment, "created_at": now, "synthetic": synthetic,
    })
    database.datasets.replace_one({"_id": dataset_id}, {
        "_id": dataset_id, "name": name, "owner_id": owner_id,
        "event_count": len(events), "created_at": now, "synthetic": synthetic,
    }, upsert=True)
    return {"id": dataset_id, "name": name, "event_count": len(events), "synthetic": synthetic}


def read_events(database, dataset_id: str) -> list[dict[str, Any]]:
    return [row["payload"] for row in database.events.find({"dataset_id": dataset_id}).sort("event_index", 1)]


def read_environment(database, dataset_id: str, version: int = 1) -> dict[str, Any] | None:
    document = database.environments.find_one({"dataset_id": dataset_id, "version": version})
    return document.get("data") if document else None
