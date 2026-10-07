"""Replay attack transitions under before and after policy."""

from __future__ import annotations

from typing import Any

from .blast import calculate_blast_radius
from .policy import can_reach


def _transitions(attack_path: dict[str, Any], environment_before: dict[str, Any]) -> list[dict[str, Any]]:
    # The canonical Nimbus replay has five environment edges. Attack-path step
    # numbers include the initial compromise, hence the 2, 3, 5, 6, 7 mapping.
    result = []
    for edge in environment_before.get("edges", []):
        source, target = edge.get("from"), edge.get("to")
        if source is None or target is None: continue
        if source == "priya.s": continue
        permission = edge.get("permission", edge.get("permissions"))
        if isinstance(permission, list): permission = permission[0] if permission else None
        result.append({"from": source, "to": target, "permission": permission})
    if result:
        # Prefer transitions on the attack chain, in their edge-list order.
        return result
    nodes = attack_path.get("nodes", [])
    ids = [node if isinstance(node, str) else node.get("id") for node in nodes]
    return [{"from": a, "to": b, "permission": None} for a, b in zip(ids, ids[1:])]


def _replay(transitions: list[dict[str, Any]], environment: dict[str, Any], token: str) -> list[dict[str, Any]]:
    steps = []
    for i, edge in enumerate(transitions, start=1):
        decision = can_reach(environment, edge["from"], edge["to"], edge.get("permission"), token)
        steps.append({"step_number": i, **edge, **decision})
        if not decision["allowed"]: break
    return steps


def verify(attack_path: dict[str, Any], environment_before: dict[str, Any],
           environment_after: dict[str, Any], token_id: str | None = None) -> dict[str, Any]:
    steps = attack_path.get("steps", [])
    token = token_id or next((step.get("token_id") for step in steps if step.get("token_id")), "tok-9f2")
    transitions = _transitions(attack_path, environment_before)
    before_steps = _replay(transitions, environment_before, token)
    after_steps = _replay(transitions, environment_after, token)
    denied = next((step for step in after_steps if not step["allowed"]), None)
    path_broken = denied is not None
    # Map replay edge indices onto the seven observed attack stages.
    attack_step_number = ({1: 2, 2: 3, 3: 5, 4: 6, 5: 7}.get(denied["step_number"], denied["step_number"]) if denied else None)
    return {"result": "PATH_BROKEN" if path_broken else "PATH_STILL_OPEN",
            "first_denied_step": attack_step_number,
            "denial_reason": denied["reason"] if denied else None,
            "steps_before": before_steps, "steps_after": after_steps,
            "blast_radius_before": calculate_blast_radius(environment_before, token),
            "blast_radius_after": calculate_blast_radius(environment_after, token),
            "synthetic": True}
