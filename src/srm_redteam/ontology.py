from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any

import networkx as nx


def load_ontology(path: Path) -> nx.MultiDiGraph:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    graph = nx.MultiDiGraph(name=raw["ontology"]["name"])
    for node in raw.get("node", []):
        graph.add_node(node["id"], kind=node["kind"], label=node["label"])
    for edge in raw.get("edge", []):
        graph.add_edge(
            edge["source"],
            edge["target"],
            key=edge["relation"],
            relation=edge["relation"],
            confidence=float(edge.get("confidence", 1.0)),
            control=edge.get("control", "A.6.2.6"),
        )
    return graph


def clone_graph(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    return copy.deepcopy(graph)


def edge_fingerprints(graph: nx.MultiDiGraph) -> set[str]:
    items: set[str] = set()
    for source, target, key, data in graph.edges(keys=True, data=True):
        confidence = round(float(data.get("confidence", 1.0)), 3)
        items.add(f"{source}->{target}:{key}:{confidence}")
    return items


def trace_reasoning(graph: nx.MultiDiGraph, start: str, max_hops: int = 4) -> list[str]:
    visited: list[str] = []
    frontier = [start]
    for _ in range(max_hops):
        next_frontier: list[str] = []
        for node in frontier:
            if node in visited:
                continue
            visited.append(node)
            for _, target, key in graph.out_edges(node, keys=True):
                next_frontier.append(f"{target}|{key}")
        frontier = [item.split("|", 1)[0] for item in sorted(next_frontier)]
    return visited


def seed_memory() -> dict[str, list[dict[str, Any]]]:
    return {
        "acme.com": [
            {
                "memory_id": "acme.contract_v3",
                "kind": "pricing_floor",
                "value": "annual floor 128000, legal redlines active",
                "classification": "tenant_confidential",
            },
            {
                "memory_id": "acme.champion_note",
                "kind": "stakeholder",
                "value": "Jordan is a champion but lacks budget authority",
                "classification": "tenant_confidential",
            },
        ],
        "globex.com": [
            {
                "memory_id": "globex.renewal_risk",
                "kind": "risk",
                "value": "renewal blocked by procurement timing",
                "classification": "tenant_confidential",
            }
        ],
    }


def diff_graphs(
    before: nx.MultiDiGraph, after: nx.MultiDiGraph, before_trace: list[str], after_trace: list[str]
) -> dict[str, list[str]]:
    before_edges = edge_fingerprints(before)
    after_edges = edge_fingerprints(after)
    added = sorted(after_edges - before_edges)
    removed = sorted(before_edges - after_edges)
    flips: list[str] = []
    before_pairs = {item.rsplit(":", 1)[0]: item.rsplit(":", 1)[1] for item in before_edges}
    after_pairs = {item.rsplit(":", 1)[0]: item.rsplit(":", 1)[1] for item in after_edges}
    for key, value in sorted(before_pairs.items()):
        if key in after_pairs and after_pairs[key] != value:
            flips.append(f"{key}:{value}->{after_pairs[key]}")
    traversal_shift = [] if before_trace == after_trace else [f"{before_trace} -> {after_trace}"]
    return {
        "added_edges": added,
        "removed_edges": removed,
        "weight_flips": flips,
        "traversal_shift": traversal_shift,
    }
