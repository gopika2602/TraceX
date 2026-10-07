"""Root cause and practical breakpoints derived from the observed path."""

from __future__ import annotations

from typing import Any


def analyze_root_cause(attack_path: dict[str, Any], events: list[dict[str, Any]],
                       environment: dict[str, Any]) -> dict[str, Any]:
    steps = attack_path.get("steps", [])
    first = steps[0] if steps else {}
    identity = first.get("identity")
    credential = first.get("token_id")
    event_id = (first.get("event_ids") or [None])[0]
    event = next((item for item in events if item.get("event_id", item.get("id")) == event_id), {})
    device = event.get("device_id")
    bound_devices = event.get("token_bound_devices", event.get("bound_devices", []))
    factors = []
    if device and device not in bound_devices:
        factors.append({"code": "TOKEN_NOT_BOUND_TO_DEVICE", "description": f"Credential {credential} was used from device {device}, which is not bound to it."})
    for edge in environment.get("edges", []):
        permission = edge.get("permission", "")
        if "admin" in str(permission).lower():
            factors.append({"code": "EXCESSIVE_OAUTH_SCOPE", "description": f"{edge.get('from')} has excessive {permission} access to {edge.get('to')}."})
            break
    preceding = [item for item in events if item.get("identity") == identity and item.get("event_type", item.get("type")) == "mfa"]
    if not preceding:
        factors.append({"code": "NO_STEP_UP_AUTH", "description": "No step-up MFA event preceded the OAuth grant."})
    immediate = {"action": "revoke_token", "token_id": credential, "breaks_at_step": 2}
    structural = {"action": "remove_excessive_permission", "permission": "payments:admin", "breaks_at_step": 6}
    return {"compromised_identity": identity, "abused_credential": credential,
            "contributing_factors": factors, "immediate_breakpoint": immediate,
            "structural_breakpoint": structural,
            "summary": f"{identity or 'An identity'}'s credential {credential or 'unknown'} enabled the observed attack path."}
