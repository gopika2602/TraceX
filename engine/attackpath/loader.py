"""JSON loading and event indexing helpers."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def _read_json(source: str | Path | dict[str, Any] | list[Any]) -> Any:
    if isinstance(source, (dict, list)):
        return source
    with Path(source).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_events(path: str | Path | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Load an event list or a JSON object containing an ``events`` list."""
    data = _read_json(path)
    if isinstance(data, dict):
        data = data.get("events", data.get("items", []))
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ValueError("events JSON must be a list of event objects")
    return data


def load_environment(path: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load and minimally validate a graph environment document."""
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("environment JSON must be an object")
    if not isinstance(data.get("nodes", []), list) or not isinstance(data.get("edges", []), list):
        raise ValueError("environment nodes and edges must be lists")
    return data


def _value(event: dict[str, Any], key: str) -> Any:
    if key in event:
        return event[key]
    for container in ("source", "actor", "principal"):
        nested = event.get(container)
        if isinstance(nested, dict) and key in nested:
            return nested[key]
    return None


def index_events(events: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Index events by token, session, device and identity."""
    indexes: dict[str, dict[str, list[dict[str, Any]]]] = {
        name: defaultdict(list) for name in ("token_id", "session_id", "device_id", "identity")
    }
    for event in events:
        for key in indexes:
            value = _value(event, key)
            if value is not None:
                indexes[key][str(value)].append(event)
    return {key: dict(value) for key, value in indexes.items()}
