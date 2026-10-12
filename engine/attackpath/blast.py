"""Reachability and sensitivity summary for an environment graph."""

from __future__ import annotations

from collections import deque
from typing import Any

from .graph import build_environment_graph, node_map
from .policy import can_reach


def calculate_blast_radius(environment: dict[str, Any], compromised: str | None,
                           events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    graph = build_environment_graph(environment)
    metadata = node_map(environment)
    starts = [compromised] if compromised in graph else []
    owner = metadata.get(str(compromised), {}).get("owner") if compromised else None
    if owner in graph: starts.append(owner)
    distance: dict[str, int] = {}
    queue = deque((node, 0) for node in starts)
    while queue:
        node, hops = queue.popleft()
        if node in distance and distance[node] <= hops: continue
        distance[node] = hops
        for child in graph.successors(node):
            edge = graph[node][child]
            permission = edge.get("permission", edge.get("permissions", edge.get("actions")))
            if isinstance(permission, list):
                permission = permission[0] if permission else None
            if not can_reach(environment, node, child, permission, compromised).get("allowed", False):
                continue
            if child not in distance: queue.append((child, hops + 1))
    resources = []
    for node_id, hops in distance.items():
        if node_id in starts: continue
        attrs = metadata.get(node_id, {})
        resources.append({"node_id": node_id, "hops": hops,
                          "sensitivity": attrs.get("sensitivity", "unknown"),
                          "tags": attrs.get("tags", []),
                          "reached_via": next((dict(graph[parent][node_id]) for parent in graph.predecessors(node_id)
                                               if parent in distance and distance[parent] < hops), {})})
    tags = {str(tag).lower() for node in resources for tag in (node["tags"] if isinstance(node["tags"], list) else [node["tags"]])}
    sensitive = [item for item in resources if item["sensitivity"] == "high"]
    # Telemetry destinations are reported separately from policy reachability.
    # A destination in a record does not prove a successful access or an allowed
    # trust relationship; those conclusions require explicit result/policy data.
    observed: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(events or []):
        destination = event.get("destination") if isinstance(event.get("destination"), dict) else {}
        for key in ("resource", "application"):
            value = destination.get(key)
            if value and str(value).lower() not in {"unknown", "none", ""}:
                item = observed.setdefault(str(value), {"node_id": str(value), "event_ids": []})
                event_id = str(event.get("event_id", event.get("id", f"event-{index}")))
                if event_id not in item["event_ids"]:
                    item["event_ids"].append(event_id)
    return {"summary": {"reachable_resources": len(resources), "sensitive_assets": len(sensitive),
                        "critical_systems": sum("critical" in t for t in tags),
                        "financial_apis": sum(any("financial" in str(tag).lower() for tag in (item["tags"] if isinstance(item["tags"], list) else [item["tags"]])) for item in resources),
                        "customer_data_systems": sum(any(tag in {"customer-data", "customer_data", "pii"} for tag in (str(value).lower() for value in (item["tags"] if isinstance(item["tags"], list) else [item["tags"]]))) for item in resources),
                        "other_identities": sum(metadata.get(item["node_id"], {}).get("type") == "identity" for item in resources)},
            "reachable_nodes": resources,
            "observed_targets": list(observed.values())}
