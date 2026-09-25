"""Minimum-cost mitigation solver.

Finds the cheapest set of edges + nodes whose removal severs every path
from a source to a target set.  Modelled as a min-cut over a flow network:
each node is split into in/out, each attacker edge becomes an arc, and all
targets drain into a super-sink.

Designed to prefer *actionable* cuts.  Edges that terminate at ASSET nodes
are protected — the algorithm can't just "cut DC01 → NTDS.dit" because that
isn't a real change an admin can make.
"""
from __future__ import annotations

from collections import deque
from typing import Dict, List, Tuple

from .graph import AttackGraph
from .models import NodeKind


INF = 1e12


class Dinic:
    def __init__(self, n: int):
        self.n = n
        self.graph: List[List[int]] = [[] for _ in range(n)]
        self.edges: List[List] = []
        self.original_edges: List[Tuple[int, int, int]] = []

    def add_edge(self, u: int, v: int, cap: float, orig_id: int = -1) -> int:
        eid = len(self.edges)
        self.edges.append([v, float(cap), 0.0, eid + 1, orig_id])
        self.edges.append([u, 0.0, 0.0, eid, -1])
        self.graph[u].append(eid)
        self.graph[v].append(eid + 1)
        self.original_edges.append((u, v, eid))
        return eid

    def _bfs(self, s: int, t: int) -> bool:
        self.level = [-1] * self.n
        self.level[s] = 0
        q = deque([s])
        while q:
            u = q.popleft()
            for eid in self.graph[u]:
                e = self.edges[eid]
                if e[1] - e[2] > 1e-9 and self.level[e[0]] < 0:
                    self.level[e[0]] = self.level[u] + 1
                    q.append(e[0])
        return self.level[t] >= 0

    def _dfs(self, u: int, t: int, f: float) -> float:
        if u == t:
            return f
        while self.it[u] < len(self.graph[u]):
            eid = self.graph[u][self.it[u]]
            e = self.edges[eid]
            if e[1] - e[2] > 1e-9 and self.level[e[0]] == self.level[u] + 1:
                d = self._dfs(e[0], t, min(f, e[1] - e[2]))
                if d > 1e-12:
                    e[2] += d
                    self.edges[e[3]][2] -= d
                    return d
            self.it[u] += 1
        return 0.0

    def max_flow(self, s: int, t: int) -> float:
        flow = 0.0
        while self._bfs(s, t):
            self.it = [0] * self.n
            while True:
                f = self._dfs(s, t, INF)
                if f < 1e-12:
                    break
                flow += f
        return flow

    def residual_reachable(self, s: int) -> List[bool]:
        visited = [False] * self.n
        visited[s] = True
        q = deque([s])
        while q:
            u = q.popleft()
            for eid in self.graph[u]:
                e = self.edges[eid]
                if e[1] - e[2] > 1e-9 and not visited[e[0]]:
                    visited[e[0]] = True
                    q.append(e[0])
        return visited

    def min_cut_original_edges(self, s: int) -> List[int]:
        reach = self.residual_reachable(s)
        cut = []
        for u, v, eid in self.original_edges:
            if reach[u] and not reach[v]:
                orig = self.edges[eid][4]
                if orig >= 0:
                    cut.append(orig)
        return cut


class MitigationSolver:
    """Minimum-cost cut that severs every source → target path.

    Edges that terminate at an ASSET are given effectively-infinite capacity
    so the algorithm is forced to propose a real change (revoke a group
    membership, remove an ACE, disable a workstation) rather than
    disconnecting the crown jewel from its own host.
    """

    NODE_FIX_COST = {1: 3.0, 2: 4.0, 3: 5.0, 4: 10.0, 5: INF}

    EDGE_FIX_COST = {
        "MEMBER_OF":        2.0,
        "HAS_CREDENTIAL":   3.0,
        "CREDENTIAL_FOR":   3.0,
        "CAN_AUTH":         1.5,
        "ADMIN_OF":         2.0,
        "RUNS_ON":          5.0,
        "RUNS_AS":          3.0,
        "HAS_PERMISSION":   1.5,
        "GRANTS_ACCESS":    1.5,
        "CAN_ESCALATE":     1.5,
        "HOST_TO_SERVICE":  4.0,
        "HOST_TO_SESSION":  2.5,
        "HOST_TO_ADMIN":    3.0,
        "HOST_TO_GROUP_ADMIN": 2.5,
    }

    def __init__(self, graph: AttackGraph, protect_asset_endpoints: bool = True):
        self.graph = graph
        self.protect_asset_endpoints = protect_asset_endpoints

    def _node_cost(self, nid: str) -> float:
        n = self.graph.nodes[nid]
        base = self.NODE_FIX_COST.get(n.criticality, 5.0)
        if n.kind == NodeKind.MACHINE:
            base *= 1.4
        elif n.kind == NodeKind.SERVICE:
            base *= 1.2
        return base

    def _edge_cost(self, ae) -> float:
        return self.EDGE_FIX_COST.get(ae.kind, 2.0)

    def _is_protected_edge(self, ae) -> bool:
        """True if cutting this edge would be operationally meaningless."""
        if not self.protect_asset_endpoints:
            return False
        tgt = self.graph.nodes.get(ae.target)
        if tgt is not None and tgt.kind == NodeKind.ASSET:
            return True
        # Also protect edges whose source is an ASSET (assets don't act).
        src = self.graph.nodes.get(ae.source)
        if src is not None and src.kind == NodeKind.ASSET:
            return True
        return False

    def solve(self, source: str, targets: List[str]) -> Dict:
        flow_nodes: List[Tuple[str, str]] = []
        for nid in self.graph.nodes:
            flow_nodes.append((nid, "in"))
            flow_nodes.append((nid, "out"))
        sink_idx = len(flow_nodes)
        flow_nodes.append(("__super_sink__", "sink"))

        idx = {fn: i for i, fn in enumerate(flow_nodes)}
        dinic = Dinic(len(flow_nodes))
        meta: Dict[int, Dict] = {}

        # ---- node-internal edges
        for nid in self.graph.nodes:
            u = idx[(nid, "in")]
            v = idx[(nid, "out")]
            # Source and targets are never node-cut.
            cap = INF if (nid == source or nid in targets) else self._node_cost(nid)
            orig = len(meta)
            meta[orig] = {
                "type": "node",
                "id": nid,
                "name": self.graph.nodes[nid].name,
                "kind": self.graph.nodes[nid].kind.value,
                "criticality": self.graph.nodes[nid].criticality,
                "cost": None if cap >= INF else round(cap, 3),
            }
            dinic.add_edge(u, v, cap, orig)

        # ---- attacker edges
        protected = 0
        for ae in self.graph.attacker_edges:
            u = idx[(ae.source, "out")]
            v = idx[(ae.target, "in")]
            if self._is_protected_edge(ae):
                cap = INF
                protected += 1
            else:
                cap = self._edge_cost(ae)
            orig = len(meta)
            meta[orig] = {
                "type": "edge",
                "source": ae.source,
                "target": ae.target,
                "source_name": self.graph.nodes[ae.source].name,
                "target_name": self.graph.nodes[ae.target].name,
                "edge_kind": ae.kind,
                "technique": ae.technique,
                "cost": None if cap >= INF else round(cap, 3),
                "description": ae.description,
                "protected": cap >= INF,
            }
            dinic.add_edge(u, v, cap, orig)

        # ---- super-sink
        for t in targets:
            u = idx[(t, "out")]
            dinic.add_edge(u, sink_idx, INF, -1)

        source_flow = idx[(source, "out")]
        flow_value = dinic.max_flow(source_flow, sink_idx)
        cut_ids = dinic.min_cut_original_edges(source_flow)
        mitigations = [meta[i] for i in cut_ids
                       if meta[i].get("cost") is not None]

        # ---- verify the cut
        excluded = set()
        for m in mitigations:
            if m["type"] == "edge":
                excluded.add(f"{m['source']}->{m['target']}")
            elif m["type"] == "node":
                for ae in self.graph.attacker_edges:
                    if ae.source == m["id"] or ae.target == m["id"]:
                        excluded.add(f"{ae.source}->{ae.target}")

        before = self.graph.find_paths(source, targets, max_paths=50)
        with self.graph.with_exclusions(excluded):
            after = self.graph.find_paths(source, targets, max_paths=50)

        nodes_cut = [m for m in mitigations if m["type"] == "node"]
        edges_cut = [m for m in mitigations if m["type"] == "edge"]

        return {
            "source": source,
            "targets": targets,
            "max_flow": round(flow_value, 3) if flow_value < INF / 2 else None,
            "total_cost": round(sum(m["cost"] for m in mitigations), 3),
            "mitigations": mitigations,
            "nodes_cut": nodes_cut,
            "edges_cut": edges_cut,
            "excluded_edges": sorted(excluded),
            "before": {"count": len(before)},
            "after": {"count": len(after)},
            "severed": len(after) == 0,
            "protected_edges": protected,
            "protected_note": (
                "Edges terminating at ASSET nodes are treated as uncuttable "
                "— the solver will propose an actionable change instead of "
                "disconnecting a crown jewel from its own host."
                if protected else None
            ),
        }
