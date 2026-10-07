"""Evidence-based backward tracing for likely attack origins.

This module ranks entities from observed telemetry. It never attributes activity
to a human. A device already showing compromise evidence is represented as a
potential victim/intermediary, even when later used in the attack.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


ENTITY_KEYS = {
    "identity": ("identity", "user_id", "username", "principal"),
    "device": ("device_id", "device", "hostname", "host_id"),
    "ip": ("source_ip", "src_ip", "ip_address", "ip"),
    "session": ("session_id",),
    "token": ("token_id", "credential_id"),
    "process": ("process_id", "process_name"),
}
TIME_KEYS = ("timestamp", "time", "occurred_at", "event_time")
EVIDENCE_WEIGHTS = {
    "malicious_external_connection": 30,
    "credential_theft": 30,
    "malware_or_execution": 28,
    "anomalous_authentication": 20,
    "suspicious_network_activity": 15,
    "unusual_login": 12,
    "repeated_suspicious_behavior": 10,
    "earlier_causal_evidence": 8,
}


def _nested(event: dict[str, Any], key: str) -> Any:
    if key in event:
        return event[key]
    for parent in ("source", "actor", "principal", "destination", "network", "process"):
        nested = event.get(parent)
        if isinstance(nested, dict) and key in nested:
            return nested[key]
    return None


def _timestamp(event: dict[str, Any]) -> datetime | None:
    raw = next((event.get(key) for key in TIME_KEYS if event.get(key)), None)
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def _event_id(event: dict[str, Any], index: int) -> str:
    return str(event.get("event_id", event.get("id", f"event-{index}")))


def _entity_values(event: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for entity_type, keys in ENTITY_KEYS.items():
        values = {str(value) for key in keys if (value := _nested(event, key)) not in (None, "")}
        if values:
            result[entity_type] = values
    # IPs and devices on the destination side form the next hop of a connection.
    destination = event.get("destination")
    if isinstance(destination, dict):
        for kind, names in (("ip", ("ip", "ip_address")), ("device", ("device_id", "device", "host"))):
            vals = {str(destination[name]) for name in names if destination.get(name) not in (None, "")}
            if vals:
                result.setdefault(kind, set()).update(vals)
    source = event.get("source")
    if isinstance(source, dict):
        for kind, names in (("ip", ("ip", "ip_address")), ("device", ("device_id", "device", "host"))):
            vals = {str(source[name]) for name in names if source.get(name) not in (None, "")}
            if vals:
                result.setdefault(kind, set()).update(vals)
    return result


def _event_text(event: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("event_type", "type", "action", "category", "description", "result", "status", "process_name"):
        value = event.get(key)
        if value is not None:
            parts.append(str(value))
    for key in ("evidence", "tags", "indicators", "suspicion_flags"):
        value = event.get(key)
        if value is not None:
            parts.extend(str(item) for item in (value if isinstance(value, list) else [value]))
    return " ".join(parts).lower().replace("-", "_").replace(" ", "_")


def _event_evidence(event: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    text = _event_text(event)
    evidence: list[dict[str, Any]] = []
    patterns = {
        "malicious_external_connection": ("malicious_external", "command_and_control", "c2_connection", "known_bad_ip", "threat_intel_match"),
        "credential_theft": ("credential_theft", "token_theft", "session_theft", "credential_dump", "stolen_token"),
        "malware_or_execution": ("malware", "ransomware", "payload_execution", "suspicious_process", "process_injection", "powershell_encoded"),
        "anomalous_authentication": ("impossible_travel", "mfa_bypass", "auth_anomaly", "authentication_anomaly", "session_hijack", "new_device"),
        "suspicious_network_activity": ("port_scan", "beacon", "lateral_movement", "suspicious_network", "network_scan"),
        "unusual_login": ("unusual_login", "failed_login_burst", "login_anomaly", "new_geo"),
    }
    event_id = event.get("event_id", event.get("id"))
    for evidence_type, needles in patterns.items():
        if any(needle in text for needle in needles):
            evidence.append({"event_id": event_id, "type": evidence_type,
                             "timestamp": next((event.get(key) for key in TIME_KEYS if event.get(key)), None),
                             "description": f"Event contains indicator for {evidence_type.replace('_', ' ')}."})
    # Repeated matching of a meaningful suspicious indicator adds a small,
    # explicit boost. Benign shared identifiers alone never count as evidence.
    suspicious_events = [other for other in events if other is not event and any(
        needle in _event_text(other) for needles in patterns.values() for needle in needles)]
    if len(suspicious_events) >= 2 and any(needle in text for needles in patterns.values() for needle in needles):
        evidence.append({"event_id": event_id, "type": "repeated_suspicious_behavior",
                         "timestamp": next((event.get(key) for key in TIME_KEYS if event.get(key)), None),
                         "description": "This indicator recurs across multiple events."})
    return evidence


def correlate_origin_evidence(events: list[dict[str, Any]], seed_event_ids: list[str] | None = None,
                              *, max_hops: int = 8) -> dict[str, Any]:
    """Walk from incident seed events toward earlier, causally linked events.

    Links require shared identity/session/token/device/IP or a connection where
    an earlier destination IP/device matches the later source IP/device. A
    causal link alone is not treated as malicious evidence.
    """
    id_to_index = {_event_id(event, i): i for i, event in enumerate(events)}
    if seed_event_ids:
        seeds = [id_to_index[eid] for eid in seed_event_ids if eid in id_to_index]
    else:
        seeds = [i for i, event in enumerate(events) if event.get("suspicion_flags")]
    if not seeds:
        return {"event_indices": [], "links": [], "limitations": ["No suspicious seed event was available for backward tracing."]}

    timestamps = [_timestamp(event) for event in events]
    reached = set(seeds)
    frontier = [(i, 0) for i in seeds]
    links: list[dict[str, Any]] = []
    limitations: list[str] = []
    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_hops:
            continue
        current_event = events[current]
        current_entities = _entity_values(current_event)
        current_time = timestamps[current]
        for previous, previous_event in enumerate(events):
            if previous in reached:
                continue
            previous_time = timestamps[previous]
            shared: list[str] = []
            prev_entities = _entity_values(previous_event)
            for entity_type in current_entities.keys() & prev_entities.keys():
                if current_entities[entity_type] & prev_entities[entity_type]:
                    shared.append(f"shared_{entity_type}")
            # Directional network/device continuity is useful even where the
            # source and destination values live in nested objects.
            prev_destination = previous_event.get("destination", {})
            curr_source = current_event.get("source", {})
            if isinstance(prev_destination, dict) and isinstance(curr_source, dict):
                for kind, names in (("ip", ("ip", "ip_address")), ("device", ("device_id", "device", "host"))):
                    if any(prev_destination.get(name) and prev_destination.get(name) == curr_source.get(name) for name in names):
                        shared.append(f"connection_continuity_{kind}")
            # Prefer the directional description over its duplicate shared
            # entity label when the same IP/device is the network handoff.
            for kind in ("ip", "device"):
                if f"connection_continuity_{kind}" in shared:
                    shared = [item for item in shared if item != f"shared_{kind}"]
            if not shared:
                continue
            if previous_time and current_time and previous_time < current_time:
                temporal = "earlier"
            elif previous_time and current_time and previous_time > current_time:
                temporal = "timestamp_conflict"
                limitations.append(f"Timestamp order conflicts for linked events {_event_id(previous_event, previous)} and {_event_id(current_event, current)}.")
            else:
                temporal = "timestamp_unknown"
                limitations.append(f"A timestamp is missing or invalid for linked events {_event_id(previous_event, previous)} and {_event_id(current_event, current)}.")
            # Only strictly earlier events extend the backward chain. Conflicts
            # are retained as evidence/counter-evidence but not walked backward.
            links.append({"from_event_id": _event_id(previous_event, previous),
                          "to_event_id": _event_id(current_event, current),
                          "relationship": sorted(set(shared)), "temporal_order": temporal})
            if temporal == "earlier":
                reached.add(previous)
                frontier.append((previous, depth + 1))
    return {"event_indices": sorted(reached, key=lambda i: (timestamps[i] or datetime.max.replace(tzinfo=timezone.utc), i)),
            "links": links, "limitations": sorted(set(limitations))}


def trace_backward(events: list[dict[str, Any]], suspicious_event_ids: list[str] | None = None,
                   *, max_hops: int = 8) -> dict[str, Any]:
    """Public convenience function for the evidence-linked backward walk."""
    return correlate_origin_evidence(events, suspicious_event_ids, max_hops=max_hops)


def score_origin_candidate(entity_id: str, entity_type: str, evidence_events: list[dict[str, Any]],
                           all_events: list[dict[str, Any]], *, victim: bool = False,
                           timestamp_conflict: bool = False, weak_causal_link: bool = False) -> dict[str, Any]:
    """Produce a deterministic, capped score with a per-indicator rationale."""
    matching = [event for event in evidence_events if entity_id in _entity_values(event).get(entity_type, set())]
    supporting = [item for event in matching for item in _event_evidence(event, all_events)]
    score = sum(EVIDENCE_WEIGHTS[item["type"]] for item in supporting)
    if matching and any(_timestamp(event) for event in matching):
        earliest = min((_timestamp(event) for event in matching if _timestamp(event)), default=None)
        latest_incident = max((_timestamp(event) for event in all_events if _timestamp(event)), default=None)
        if earliest and latest_incident and earliest < latest_incident:
            supporting.append({"type": "earlier_causal_evidence", "timestamp": earliest.isoformat(),
                               "description": "Evidence for this entity predates the latest observed incident event."})
            score += EVIDENCE_WEIGHTS["earlier_causal_evidence"]
    counter: list[dict[str, Any]] = []
    if victim:
        score -= 40
        counter.append({"type": "possible_compromised_victim", "description": "Earlier compromise evidence means this entity may be an intermediary victim."})
    if timestamp_conflict:
        score -= 18
        counter.append({"type": "timestamp_conflict", "description": "Linked event timestamps do not support a consistent backward order."})
    if weak_causal_link:
        score -= 12
        counter.append({"type": "weak_causal_link", "description": "The entity is connected only by a weak or incomplete relationship."})
    if not supporting:
        counter.append({"type": "missing_evidence", "description": "No direct malicious, theft, malware, or anomalous-authentication indicator was found."})
    score = max(0, min(100, score))
    if score >= 65:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "UNKNOWN"
    status = ("suspected_compromised_device" if entity_type == "device" else "potential_victim") if victim else ("suspected_origin" if score >= 35 else "unknown")
    reason = (f"Score {score}/100 from {len(supporting)} supporting indicators" if supporting else "Insufficient direct evidence to rank this entity as an origin")
    if counter:
        reason += f"; {len(counter)} confidence reduction(s) applied."
    return {"entity_id": entity_id, "entity_type": entity_type, "status": status,
            "confidence_score": score, "confidence_level": level,
            "supporting_evidence": supporting, "counter_evidence": counter,
            "reason": reason}


def analyze_attack_origin(events: list[dict[str, Any]], attack_path: dict[str, Any] | None = None,
                          correlated_groups: list[dict[str, Any]] | None = None,
                          suspicious_event_ids: list[str] | None = None,
                          *, max_hops: int = 8) -> dict[str, Any]:
    """Trace suspicious event evidence backward and rank candidate entities."""
    if suspicious_event_ids is None:
        if attack_path:
            suspicious_event_ids = [str(event_id) for step in attack_path.get("steps", [])
                                    for event_id in step.get("event_ids", [])]
        elif correlated_groups:
            suspicious_event_ids = [str(event_id) for group in correlated_groups for event_id in group.get("event_ids", [])]
    trace = trace_backward(events, suspicious_event_ids, max_hops=max_hops)
    reached_events = [events[i] for i in trace["event_indices"]]
    seed_ids = set(suspicious_event_ids or [])
    candidate_keys: set[tuple[str, str]] = set()
    for event in reached_events:
        for entity_type, values in _entity_values(event).items():
            candidate_keys.update((entity_type, value) for value in values)
    candidates = []
    for entity_type, entity_id in candidate_keys:
        entity_events = [event for event in reached_events if entity_id in _entity_values(event).get(entity_type, set())]
        evidence = [item for event in entity_events for item in _event_evidence(event, events)]
        victim = any(item["type"] in {"credential_theft", "malware_or_execution", "anomalous_authentication"} for item in evidence) and any(
            _event_id(event, i) in seed_ids for i, event in enumerate(events) if entity_id in _entity_values(event).get(entity_type, set()))
        # Suspected-origin entities must have actual indicators; shared IP or
        # token membership alone is never enough to label an origin.
        conflict = any(link["temporal_order"] == "timestamp_conflict" and
                       (link["from_event_id"] in {_event_id(e, i) for i, e in enumerate(entity_events)} or
                        link["to_event_id"] in {_event_id(e, i) for i, e in enumerate(entity_events)}) for link in trace["links"])
        weak = bool(entity_events) and not evidence
        candidate = score_origin_candidate(entity_id, entity_type, entity_events, events,
                                           victim=victim, timestamp_conflict=conflict, weak_causal_link=weak)
        candidate["backward_chain"] = [{"event_id": _event_id(event, i),
                                        "timestamp": next((event.get(key) for key in TIME_KEYS if event.get(key)), None),
                                        "event_type": event.get("event_type", event.get("type"))}
                                       for i, event in enumerate(events) if event in entity_events]
        if evidence or victim or weak:
            candidates.append(candidate)
    candidates.sort(key=lambda item: (-item["confidence_score"], item["entity_type"], item["entity_id"]))
    likely = next((candidate for candidate in candidates
                   if candidate["status"] not in {"potential_victim", "suspected_compromised_device"} and candidate["confidence_score"] >= 35), None)
    if likely:
        likely_summary = {"entity_id": likely["entity_id"], "entity_type": likely["entity_type"],
                          "status": "likely_attack_origin", "confidence_score": likely["confidence_score"],
                          "confidence_level": likely["confidence_level"]}
        likely["status"] = "likely_attack_origin"
    else:
        likely_summary = None
    limitations = list(trace["limitations"])
    if not candidates:
        limitations.append("No entities with meaningful evidence were identified; origin remains inconclusive.")
    elif likely is None:
        limitations.append("Available evidence is insufficient to determine a likely origin; attribution remains inconclusive.")
    limitations.append("Telemetry-based origin ranking does not identify or confirm a human attacker.")
    return {"candidate_origins": candidates, "likely_origin": likely_summary,
            "limitations": sorted(set(limitations)), "backward_links": trace["links"]}
