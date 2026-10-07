"""Environment graph construction and metadata access."""

from __future__ import annotations

from typing import Any

import networkx as nx


def build_environment_graph(environment: dict[str, Any]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for node in environment.get("nodes", []):
        if isinstance(node, str):
            graph.add_node(node, id=node)
        else:
            node_id = node.get("id", node.get("node_id"))
            if node_id is not None:
                graph.add_node(str(node_id), **node)
    for edge in environment.get("edges", []):
        source = edge.get("from", edge.get("source"))
        target = edge.get("to", edge.get("target"))
        if source is not None and target is not None:
            graph.add_edge(str(source), str(target), **edge)
    return graph


def node_map(environment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for node in environment.get("nodes", []):
        if isinstance(node, dict):
            node_id = node.get("id", node.get("node_id"))
            if node_id is not None:
                result[str(node_id)] = node
        elif isinstance(node, str):
            result[node] = {"id": node}
    return result
