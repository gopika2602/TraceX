"""Root cause and disruption points derived from observed evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _permissions(edge: dict[str, Any]) -> list[str]:
    value = edge.get("permission", edge.get("permissions", edge.get("actions", [])))
    return [str(item) for item in value] if isinstance(value, list) else ([str(value)] if value else [])


def _timestamp(event: dict[str, Any]) -> datetime | None:
    raw = event.get("timestamp", event.get("time", event.get("occurred_at")))
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def analyze_root_cause(attack_path: dict[str, Any], events: list[dict[str, Any]],
                       environment: dict[str, Any]) -> dict[str, Any]:
    steps = attack_path.get("steps", [])
    first = steps[0] if steps else {}
    identity = first.get("identity")
    credential = first.get("token_id")
    event_id = (first.get("event_ids") or [None])[0]
    event = next((item for item in events if str(item.get("event_id", item.get("id"))) == str(event_id)), {})
    device = event.get("device_id")
    bound_devices = event.get("token_bound_devices", event.get("bound_devices", []))
    if isinstance(bound_devices, str):
        bound_devices = [bound_devices]
    factors = []
    if device and bound_devices and device not in bound_devices:
        factors.append({"code": "TOKEN_NOT_BOUND_TO_DEVICE", "description": f"Credential {credential or 'unknown'} was used from device {device}, which is not listed as bound to it."})

    path_entities = {str(value) for step in steps for value in (step.get("identity"), step.get("token_id"), step.get("application"), step.get("resource")) if value}
    structural_edge = None
    for edge in environment.get("edges", []):
        excessive = next((permission for permission in _permissions(edge) if "admin" in permission.lower()), None)
        source, target = edge.get("from", edge.get("source")), edge.get("to", edge.get("target"))
        if not excessive or str(source) not in path_entities and str(target) not in path_entities:
            continue
        structural_edge = {"source": source, "target": target, "permission": excessive}
        factors.append({"code": "EXCESSIVE_OAUTH_SCOPE", "description": f"{structural_edge['source']} has {excessive} access to {structural_edge['target']}."})
        break

    normalized_identity = str(identity or "").lower()
    incident_time = _timestamp(event)
    preceding_mfa = any(
        str(item.get("identity", "")).lower() == normalized_identity
        and "mfa" in str(item.get("event_type", item.get("type", ""))).lower()
        and _timestamp(item) is not None and incident_time is not None
        and _timestamp(item) < incident_time
        for item in events
    )
    if identity and not preceding_mfa:
        factors.append({"code": "NO_STEP_UP_AUTH", "description": f"No MFA event for {identity} is present in the supplied dataset."})

    token_step = next((step for step in steps if credential and step.get("token_id") == credential and step.get("stage") != "initial_compromise"), None)
    immediate = ({"action": "revoke_token", "token_id": credential,
                  "breaks_at_step": token_step.get("step_number") if token_step else None}
                 if credential else None)
    structural_step = next((step for step in steps if structural_edge and (
        step.get("permission") == structural_edge["permission"]
        or step.get("token_id") == structural_edge["source"]
        and step.get("resource") == structural_edge["target"]
    )), None)
    structural = ({"action": "remove_excessive_permission", **structural_edge,
                   "breaks_at_step": structural_step.get("step_number") if structural_step else None}
                  if structural_edge else None)
    return {
        "compromised_identity": identity,
        "abused_credential": credential,
        "affected_device": device,
        "evidence_event_ids": [str(event_id)] if event_id else [],
        "contributing_factors": factors,
        "immediate_breakpoint": immediate,
        "structural_breakpoint": structural,
        "summary": (f"Available evidence links {identity or 'an unknown identity'}'s credential "
                    f"{credential or 'unknown'} to the reconstructed activity path."
                    if steps else "No correlated attack path was established from the supplied evidence."),
    }
