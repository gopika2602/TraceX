"""Suspicious event correlation using shared identifiers and bounded time."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import networkx as nx

from .loader import index_events


def _get(event: dict[str, Any], key: str) -> Any:
    if key in event:
        return event[key]
    for parent in ("source", "actor", "principal"):
        value = event.get(parent)
        if isinstance(value, dict) and key in value:
            return value[key]
    return None


def _timestamp(event: dict[str, Any]) -> datetime | None:
    raw = event.get("timestamp", event.get("time", event.get("occurred_at")))
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _flags(event: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    flags = set(event.get("suspicion_flags", []))
    identity, device = _get(event, "identity"), _get(event, "device_id")
    if identity and device:
        known = {str(_get(other, "device_id")) for other in events
                 if _get(other, "identity") == identity and other is not event and _get(other, "device_id")}
        if known and str(device) not in known:
            flags.add("NEW_DEVICE")
    country = event.get("source", {}).get("country") if isinstance(event.get("source"), dict) else event.get("country")
    token = _get(event, "token_id")
    prior = [other for other in events if _get(other, "token_id") == token and _timestamp(other) and _timestamp(event)
             and _timestamp(other) < _timestamp(event)]
    if country and prior:
        first_country = next((other.get("source", {}).get("country") if isinstance(other.get("source"), dict)
                              else other.get("country") for other in sorted(prior, key=lambda x: _timestamp(x))), None)
        if first_country and first_country != country:
            flags.add("SESSION_REUSE_NEW_GEO")
    scopes = event.get("scopes", event.get("metadata", {}).get("scopes", []))
    if isinstance(scopes, str):
        scopes = [scopes]
    if any("admin" in str(scope).lower() for scope in scopes or []):
        flags.add("TOKEN_SCOPE_EXCESSIVE")
    if int(event.get("rows", event.get("rows_read", 0)) or 0) > 1000:
        flags.add("BULK_READ")
    return sorted(flags)


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    graph = nx.Graph()
    graph.add_nodes_from(range(len(events)))
    reasons: dict[tuple[int, int], set[str]] = defaultdict(set)
    indexes = index_events(events)
    for key, mapping in indexes.items():
        for members in mapping.values():
            for pos, left in enumerate(members):
                i = events.index(left)
                for right in members[pos + 1:]:
                    j = events.index(right)
                    if key != "device_id":
                        reasons[tuple(sorted((i, j)))].add(f"SHARED_{key.upper()}")
                    else:
                        a, b = _timestamp(left), _timestamp(right)
                        if a and b and abs((a - b).total_seconds()) <= 1800:
                            reasons[tuple(sorted((i, j)))].add("SHARED_DEVICE_WITHIN_30M")
    for j, event in enumerate(events):
        meta = event.get("metadata", {}) or {}
        for key, reason in (("issued_by_session", "OAUTH_ISSUER_SESSION"), ("issued_by_token", "OAUTH_ISSUER_TOKEN")):
            value = meta.get(key)
            for i, earlier in enumerate(events):
                if i != j and _get(earlier, "session_id" if key.endswith("session") else "token_id") == value:
                    reasons[tuple(sorted((i, j)))].add(reason)
    for pair, labels in reasons.items():
        graph.add_edge(*pair)
    groups = []
    for component in nx.connected_components(graph):
        members = sorted(component)
        group_events = [events[i] for i in members]
        flags = sorted({flag for event in group_events for flag in _flags(event, events)})
        if not flags:
            continue
        link_reasons = sorted({reason for pair, values in reasons.items()
                               if pair[0] in component and pair[1] in component for reason in values})
        ids = [str(event.get("event_id", event.get("id", f"event-{i}"))) for i, event in zip(members, group_events)]
        groups.append({"group_id": f"group-{len(groups)+1}", "event_ids": ids,
                       "link_reasons": link_reasons, "suspicion_flags": flags,
                       "confidence": round(min(0.99, 0.65 + 0.08 * len(link_reasons)), 2)})
    return groups
