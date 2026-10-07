"""Reachability and sensitivity summary for an environment graph."""

from __future__ import annotations

from collections import deque
from typing import Any

from .graph import build_environment_graph, node_map


def calculate_blast_radius(environment: dict[str, Any], compromised: str | None) -> dict[str, Any]:
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
            if child not in distance: queue.append((child, hops + 1))
    resources = []
    for node_id, hops in distance.items():
        if node_id in starts: continue
        attrs = metadata.get(node_id, {})
        resources.append({"node_id": node_id, "hops": hops,
                          "sensitivity": attrs.get("sensitivity", "low"),
                          "tags": attrs.get("tags", []),
                          "reached_via": next((dict(graph[parent][node_id]) for parent in graph.predecessors(node_id)
                                               if parent in distance and distance[parent] < hops), {})})
    tags = {str(tag).lower() for node in resources for tag in (node["tags"] if isinstance(node["tags"], list) else [node["tags"]])}
    sensitive = [item for item in resources if item["sensitivity"] == "high"]
    return {"summary": {"reachable_resources": len(resources), "sensitive_assets": len(sensitive),
                        "critical_systems": sum("critical" in t for t in tags),
                        "financial_apis": sum("financial" in str(item["tags"]).lower() or "payment" in item["node_id"].lower() for item in resources),
                        "customer_data_systems": sum("customer" in item["node_id"].lower() or "pii" in str(item["tags"]).lower() for item in resources),
                        "other_identities": sum(metadata.get(item["node_id"], {}).get("type") == "identity" for item in resources)},
            "reachable_nodes": resources, "synthetic": True}
