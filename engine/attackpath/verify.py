"""Replay observed attack transitions against before and after policy."""

from __future__ import annotations

from typing import Any

import networkx as nx

from .blast import calculate_blast_radius
from .graph import build_environment_graph
from .policy import can_reach


def _edge_permission(attributes: dict[str, Any], expected: str | None) -> str | None:
    available = attributes.get("permission", attributes.get("permissions", attributes.get("actions")))
    if isinstance(available, list):
        if expected and expected in available:
            return expected
        return str(available[0]) if available else None
    return str(available) if available else expected


def _transitions(attack_path: dict[str, Any], environment_before: dict[str, Any], token_id: str | None = None) -> list[dict[str, Any]]:
    """Resolve observed step targets through the actual directed environment graph."""
    graph = build_environment_graph(environment_before)
    if not graph:
        return []
    steps = attack_path.get("steps", [])
    current = token_id or next((str(step.get("token_id")) for step in steps if step.get("token_id")), None)
    if current is None or current not in graph:
        current = next((str(step.get("identity")) for step in steps if step.get("identity") and str(step.get("identity")) in graph), None)
    if current is None:
        return []

    result: list[dict[str, Any]] = []
    for step in steps:
        # The initial compromise describes evidence of acquisition. Replay begins
        # at the credential's first observed use in the environment model.
        if step.get("stage") == "initial_compromise":
            continue
        if step.get("stage") == "token_created":
            targets = [step.get("token_id"), step.get("resource"), step.get("application")]
        else:
            targets = [step.get("resource"), step.get("application"), step.get("token_id")]
        destination = None
        node_path = None
        starts = [current, step.get("token_id"), step.get("application"), step.get("identity")]
        for value in targets:
            if value is None or str(value) not in graph:
                continue
            for start in starts:
                if start is None or str(start) == str(value) or str(start) not in graph:
                    continue
                try:
                    candidate_path = nx.shortest_path(graph, str(start), str(value))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                if len(candidate_path) > 1:
                    destination, node_path = str(value), candidate_path
                    break
            if node_path:
                break
        if not node_path or destination is None:
            continue
        expected_permission = step.get("permission")
        for source, target in zip(node_path, node_path[1:]):
            attributes = graph[source][target]
            result.append({
                "from": source,
                "to": target,
                "permission": _edge_permission(attributes, expected_permission),
                "attack_step": int(step.get("step_number", len(result) + 1)),
            })
        current = destination
    return result


def _replay(transitions: list[dict[str, Any]], environment: dict[str, Any], token: str) -> list[dict[str, Any]]:
    steps = []
    for edge in transitions:
        decision = can_reach(environment, edge["from"], edge["to"], edge.get("permission"), token)
        steps.append({**edge, "step_number": edge["attack_step"], **decision})
        if not decision["allowed"]:
            break
    return steps


def _normal_access_preserved(transitions: list[dict[str, Any]], before: dict[str, Any], after: dict[str, Any]) -> bool:
    attack_edges = {(item["from"], item["to"], item.get("permission")) for item in transitions}
    for edge in before.get("edges", []):
        source = str(edge.get("from", edge.get("source", "")))
        target = str(edge.get("to", edge.get("target", "")))
        permissions = edge.get("permission", edge.get("permissions", edge.get("actions")))
        permissions = permissions if isinstance(permissions, list) else [permissions]
        for permission in permissions:
            if not permission or (source, target, str(permission)) in attack_edges:
                continue
            was_allowed = can_reach(before, source, target, str(permission)).get("allowed", False)
            remains_allowed = can_reach(after, source, target, str(permission)).get("allowed", False)
            if was_allowed and not remains_allowed:
                return False
    return True


def verify(attack_path: dict[str, Any], environment_before: dict[str, Any],
           environment_after: dict[str, Any], token_id: str | None = None) -> dict[str, Any]:
    steps = attack_path.get("steps", [])
    token = token_id or next((step.get("token_id") for step in steps if step.get("token_id")), None)
    transitions = _transitions(attack_path, environment_before, token)
    before_steps = _replay(transitions, environment_before, token or "")
    after_steps = _replay(transitions, environment_after, token or "")
    denied = next((step for step in after_steps if not step["allowed"]), None)
    status = "PATH_UNVERIFIABLE" if not transitions else "PATH_BROKEN" if denied else "PATH_STILL_OPEN"
    return {
        "result": status,
        "first_denied_step": denied["step_number"] if denied else None,
        "denial_reason": denied["reason"] if denied else None,
        "steps_before": before_steps,
        "steps_after": after_steps,
        "transition_count": len(transitions),
        "normal_access_preserved": _normal_access_preserved(transitions, environment_before, environment_after) if transitions else None,
        "blast_radius_before": calculate_blast_radius(environment_before, token),
        "blast_radius_after": calculate_blast_radius(environment_after, token),
        "transition_count": len(transitions),
    }
