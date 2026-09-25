"""Compute the difference between two graph snapshots.

The output is designed for a security analyst reading a report:

  - New edges that appeared (potential new attack surface)
  - Removed edges (remediation that worked)
  - New nodes / removed nodes
  - Criticality changes
  - Path deltas (optional, requires re-running path search)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .graph import AttackGraph
from .models import Environment, Node, Edge, NodeKind, EdgeKind


SEVERITY_WEIGHT = {
    # Higher = more concerning when it appears.
    "CAN_ESCALATE":       10,
    "ADMIN_OF":            8,
    "HAS_CREDENTIAL":      7,
    "MEMBER_OF":           5,
    "GRANTS_ACCESS":       6,
    "CAN_AUTH":            4,
    "RUNS_AS":             4,
    "RUNS_ON":             3,
    "HAS_PERMISSION":      5,
    "HOST_TO_SESSION":     6,
    "HOST_TO_ADMIN":       8,
    "HOST_TO_GROUP_ADMIN": 7,
    "HOST_TO_SERVICE":     4,
    "CREDENTIAL_FOR":      6,
}


@dataclass
class EdgeDelta:
    source: str
    target: str
    kind: str
    source_name: str
    target_name: str
    severity: int = 0


@dataclass
class NodeDelta:
    id: str
    name: str
    kind: str
    criticality: int
    tags: List[str] = field(default_factory=list)


@dataclass
class DiffResult:
    scenario_a: str
    scenario_b: str
    captured_a: str
    captured_b: str
    nodes_added: List[NodeDelta] = field(default_factory=list)
    nodes_removed: List[NodeDelta] = field(default_factory=list)
    edges_added: List[EdgeDelta] = field(default_factory=list)
    edges_removed: List[EdgeDelta] = field(default_factory=list)
    criticality_changes: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scenario_a": self.scenario_a,
            "scenario_b": self.scenario_b,
            "captured_a": self.captured_a,
            "captured_b": self.captured_b,
            "nodes_added": [n.__dict__ for n in self.nodes_added],
            "nodes_removed": [n.__dict__ for n in self.nodes_removed],
            "edges_added": [e.__dict__ for e in self.edges_added],
            "edges_removed": [e.__dict__ for e in self.edges_removed],
            "criticality_changes": self.criticality_changes,
            "summary": self.summary,
        }


def _node_map(nodes: List[dict]) -> Dict[str, dict]:
    return {n["id"]: n for n in nodes}


def _edge_key(e: dict) -> Tuple[str, str, str]:
    return (e["source"], e["target"], e["kind"])


def _edge_map(edges: List[dict]) -> Dict[Tuple[str, str, str], dict]:
    return {_edge_key(e): e for e in edges}


def _severity_for_edge(kind: str) -> int:
    return SEVERITY_WEIGHT.get(kind, 1)


def compute(a: dict, b: dict,
            scenario_a: str = "", scenario_b: str = "") -> DiffResult:
    """Compare two snapshots and return the delta.

    `a` is the older snapshot; `b` is the newer one.
    """
    result = DiffResult(
        scenario_a=scenario_a or a.get("scenario", ""),
        scenario_b=scenario_b or b.get("scenario", ""),
        captured_a=a.get("captured_at", ""),
        captured_b=b.get("captured_at", ""),
    )

    a_nodes = _node_map(a["nodes"])
    b_nodes = _node_map(b["nodes"])
    a_edges = _edge_map(a["edges"])
    b_edges = _edge_map(b["edges"])

    # ---- nodes
    for nid, n in b_nodes.items():
        if nid not in a_nodes:
            result.nodes_added.append(NodeDelta(
                id=nid, name=n["name"], kind=n["kind"],
                criticality=n["criticality"], tags=n.get("tags", []),
            ))
    for nid, n in a_nodes.items():
        if nid not in b_nodes:
            result.nodes_removed.append(NodeDelta(
                id=nid, name=n["name"], kind=n["kind"],
                criticality=n["criticality"], tags=n.get("tags", []),
            ))

    # ---- criticality changes
    for nid, n in b_nodes.items():
        if nid in a_nodes and n["criticality"] != a_nodes[nid]["criticality"]:
            result.criticality_changes.append({
                "id": nid, "name": n["name"],
                "from": a_nodes[nid]["criticality"],
                "to": n["criticality"],
            })

    # ---- edges
    def _edge_meta(e: dict) -> EdgeDelta:
        sid = e["source"]; tid = e["target"]
        s = b_nodes.get(sid) or a_nodes.get(sid) or {"name": sid}
        t = b_nodes.get(tid) or a_nodes.get(tid) or {"name": tid}
        return EdgeDelta(
            source=sid, target=tid, kind=e["kind"],
            source_name=s["name"], target_name=t["name"],
            severity=_severity_for_edge(e["kind"]),
        )

    for key, e in b_edges.items():
        if key not in a_edges:
            result.edges_added.append(_edge_meta(e))
    for key, e in a_edges.items():
        if key not in b_edges:
            result.edges_removed.append(_edge_meta(e))

    # sort by severity, worst first
    result.edges_added.sort(key=lambda x: -x.severity)
    result.edges_removed.sort(key=lambda x: -x.severity)

    # ---- summary
    result.summary = {
        "nodes_added": len(result.nodes_added),
        "nodes_removed": len(result.nodes_removed),
        "edges_added": len(result.edges_added),
        "edges_removed": len(result.edges_removed),
        "criticality_changes": len(result.criticality_changes),
        "attack_surface_delta": (
            sum(e.severity for e in result.edges_added)
            - sum(e.severity for e in result.edges_removed)
        ),
    }
    return result
