"""Least-privilege recommendations and immutable remediation application."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def recommend_remediations(root_cause: dict[str, Any], environment: dict[str, Any]) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    immediate = root_cause.get("immediate_breakpoint")
    if immediate and immediate.get("token_id"):
        token = immediate["token_id"]
        recommendations.append({
            "remediation_id": "rem-1", "action": "revoke_token", "target": token,
            "description": f"Revoke the observed compromised credential {token}.",
            "expected_paths_broken": [immediate["breaks_at_step"]] if immediate.get("breaks_at_step") else [],
            "collateral": {"users_affected": 1},
        })
    structural = root_cause.get("structural_breakpoint")
    if structural and structural.get("source") and structural.get("permission"):
        permission = structural["permission"]
        recommendations.append({
            "remediation_id": "rem-2", "action": "reduce_scope", "target": structural["source"],
            "remove_permission": permission,
            "description": f"Remove the observed excessive permission {permission} from {structural['source']}.",
            "expected_paths_broken": [structural["breaks_at_step"]] if structural.get("breaks_at_step") else [],
            "collateral": {"users_affected": 0},
        })
    if any(item.get("code") == "NO_STEP_UP_AUTH" for item in root_cause.get("contributing_factors", [])):
        recommendations.append({
            "remediation_id": "rem-3", "action": "require_step_up_auth", "target": "observed identity",
            "description": "Require step-up authentication for the observed identity's token or OAuth grant flow.",
            "expected_paths_broken": [],
            "collateral": {"users_affected": "Identity and OAuth grantors"},
        })
    return recommendations


def apply_remediation(environment: dict[str, Any], remediation: dict[str, Any]) -> dict[str, Any]:
    """Apply supported remediation to a deep copy; the input is never mutated."""
    result = deepcopy(environment)
    action = remediation.get("action", remediation.get("type"))
    target = remediation.get("target", remediation.get("token_id"))
    if action in {"revoke_token", "revoke"}:
        if not target:
            raise ValueError("revoke_token requires a target token")
        for node in result.get("nodes", []):
            if isinstance(node, dict) and node.get("id", node.get("node_id")) == target:
                node["revoked"] = True
        for token in result.get("tokens", []):
            if isinstance(token, dict) and token.get("id", token.get("token_id")) == target:
                token["revoked"] = True
        result.setdefault("revoked_tokens", [])
        if target not in result["revoked_tokens"]:
            result["revoked_tokens"].append(target)
    elif action in {"reduce_scope", "remove_permission"}:
        permission = remediation.get("remove_permission", remediation.get("permission"))
        if not target or not permission:
            raise ValueError("reduce_scope requires a target and permission")
        changed = False
        for edge in result.get("edges", []):
            source = edge.get("from", edge.get("source"))
            if source != target:
                continue
            for key in ("permission", "permissions", "actions"):
                value = edge.get(key)
                if isinstance(value, list) and permission in value:
                    edge[key] = [entry for entry in value if entry != permission]
                    changed = True
                elif value == permission:
                    edge[key] = ""
                    changed = True
        if not changed:
            raise ValueError(f"permission {permission} was not present on an edge from {target}")
    elif action == "require_step_up_auth":
        result["require_step_up_auth"] = True
    else:
        raise ValueError(f"unsupported remediation action: {action}")
    return result
