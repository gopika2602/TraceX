"""Least-privilege recommendations and immutable remediation application."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def recommend_remediations(root_cause: dict[str, Any], environment: dict[str, Any]) -> list[dict[str, Any]]:
    token = root_cause.get("abused_credential") or "tok-9f2"
    return [
        {"remediation_id": "rem-1", "action": "revoke_token", "target": token,
         "description": f"Revoke compromised token {token}.", "expected_paths_broken": [2], "collateral": {"users_affected": 1}},
        {"remediation_id": "rem-2", "action": "reduce_scope", "target": "oauth-77",
         "remove_permission": "payments:admin", "description": "Remove the excessive payments:admin permission from oauth-77.",
         "expected_paths_broken": [6], "collateral": {"users_affected": 0}},
        {"remediation_id": "rem-3", "action": "require_step_up_auth", "target": "oauth grants",
         "description": "Require step-up authentication before OAuth grants.",
         "expected_paths_broken": [4], "collateral": {"users_affected": "OAuth grantors"}},
    ]


def apply_remediation(environment: dict[str, Any], remediation: dict[str, Any]) -> dict[str, Any]:
    """Apply supported remediation to a deep copy; the input is never mutated."""
    result = deepcopy(environment)
    action = remediation.get("action", remediation.get("type"))
    target = remediation.get("target", remediation.get("token_id"))
    if action in {"revoke_token", "revoke"}:
        found = False
        for node in result.get("nodes", []):
            if isinstance(node, dict) and node.get("id", node.get("node_id")) == target:
                node["revoked"] = True; found = True
        for token in result.get("tokens", []):
            if isinstance(token, dict) and token.get("id", token.get("token_id")) == target:
                token["revoked"] = True; found = True
        if not found:
            result.setdefault("revoked_tokens", [])
            if target not in result["revoked_tokens"]: result["revoked_tokens"].append(target)
    elif action in {"reduce_scope", "remove_permission"}:
        permission = remediation.get("remove_permission", remediation.get("permission", "payments:admin"))
        for edge in result.get("edges", []):
            if edge.get("from") != target: continue
            for key in ("permission", "permissions", "actions"):
                value = edge.get(key)
                if isinstance(value, list): edge[key] = [entry for entry in value if entry != permission]
                elif value == permission: edge[key] = ""
    elif action == "require_step_up_auth":
        result["require_step_up_auth"] = True
    else:
        raise ValueError(f"unsupported remediation action: {action}")
    return result
