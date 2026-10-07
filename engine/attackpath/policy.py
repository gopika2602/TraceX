"""Permission checks for a single environment edge."""

from __future__ import annotations

from typing import Any

from .graph import build_environment_graph


def _token_revoked(environment: dict[str, Any], token_id: str | None) -> bool:
    if token_id is None:
        return False
    for node in environment.get("nodes", []):
        if isinstance(node, dict) and node.get("id", node.get("node_id")) == token_id:
            return bool(node.get("revoked", False))
    for token in environment.get("tokens", []):
        if isinstance(token, dict) and token.get("id", token.get("token_id")) == token_id:
            return bool(token.get("revoked", False))
    revoked = environment.get("revoked_tokens", [])
    return token_id in revoked


def can_reach(environment: dict[str, Any], source: str, target: str,
              permission: str | None = None, token_id: str | None = None) -> dict[str, Any]:
    """Return whether an exact directed edge authorizes the requested permission."""
    if _token_revoked(environment, token_id):
        return {"allowed": False, "reason": "TOKEN_REVOKED"}
    graph = build_environment_graph(environment)
    if not graph.has_edge(str(source), str(target)):
        return {"allowed": False, "reason": "NO_EDGE"}
    edge = graph[str(source)][str(target)]
    available = edge.get("permission", edge.get("permissions", edge.get("actions", [])))
    if isinstance(available, str):
        available = [available]
    if permission and permission not in (available or []):
        return {"allowed": False, "reason": "SCOPE_INSUFFICIENT"}
    return {"allowed": True, "reason": None}
