from __future__ import annotations
import heapq
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .models import (
    Node, Edge, NodeKind, EdgeKind,
    AttackEdge, AttackPath, PathStep, Environment,
)


FORWARD_RULES: Dict[EdgeKind, Tuple[float, str, str]] = {
    EdgeKind.MEMBER_OF: (0.3, "T1069", "Identity inherits group memberships"),
    EdgeKind.HAS_CREDENTIAL: (0.4, "T1552", "Attacker reads stored credential material"),
    EdgeKind.CREDENTIAL_FOR: (0.5, "T1078", "Credential authenticates as this identity"),
    EdgeKind.CAN_AUTH: (1.0, "T1078", "Interactive/remote logon permitted"),
    EdgeKind.ADMIN_OF: (0.9, "T1078", "Identity administers the target"),
    EdgeKind.RUNS_ON: (0.8, "T1569", "Service executes on host"),
    EdgeKind.RUNS_AS: (0.7, "T1003", "Service runs under this identity"),
    EdgeKind.HAS_PERMISSION: (0.6, "T1069", "Identity holds permission"),
    EdgeKind.GRANTS_ACCESS: (0.6, "T1222", "Permission grants access to target"),
    EdgeKind.CAN_ESCALATE: (0.5, "T1078", "Direct privilege escalation path"),
}


class _EdgeFilter:
    """Context manager that temporarily removes edges from a graph.

    Usage:
        with graph.with_exclusions({"a->b", "c->d"}):
            graph.find_paths(...)
    """

    def __init__(self, graph: "AttackGraph", excluded: set):
        self.graph = graph
        self.excluded = set(excluded)
        self._backup = None

    def __enter__(self):
        self._backup = self.graph.adj
        self.graph.adj = {
            k: [e for e in v if f"{e.source}->{e.target}" not in self.excluded]
            for k, v in self._backup.items()
        }
        return self.graph

    def __exit__(self, *exc):
        self.graph.adj = self._backup
        return False


class AttackGraph:
    def __init__(self, env: Environment):
        self.env = env
        self.nodes: Dict[str, Node] = {n.id: n for n in env.nodes}
        self.declared: List[Edge] = list(env.edges)
        self.attacker_edges: List[AttackEdge] = []
        self.adj: Dict[str, List[AttackEdge]] = defaultdict(list)
        self._validate()
        self._materialise()

    # -------------------------------------------------------------- mitigation
    def with_exclusions(self, excluded_edges: set) -> _EdgeFilter:
        return _EdgeFilter(self, excluded_edges)

    # ------------------------------------------------------------- validation
    def _validate(self) -> None:
        ids = set(self.nodes)
        for e in self.declared:
            if e.source not in ids or e.target not in ids:
                raise ValueError(
                    f"Edge {e.source} -> {e.target} references unknown node"
                )

    # ----------------------------------------------------- materialisation
    def _materialise(self) -> None:
        by_kind: Dict[EdgeKind, List[Edge]] = defaultdict(list)
        for e in self.declared:
            by_kind[e.kind].append(e)
            if e.kind in FORWARD_RULES:
                w, tech, desc = FORWARD_RULES[e.kind]
                self._add(AttackEdge(
                    source=e.source, target=e.target,
                    kind=e.kind.value,
                    technique=e.technique or tech,
                    weight=e.weight or w,
                    description=desc,
                ))

        for e in by_kind[EdgeKind.RUNS_ON]:
            self._add(AttackEdge(
                source=e.target, target=e.source, kind="HOST_TO_SERVICE",
                technique="T1569", weight=0.8,
                description="Attacker on host interacts with hosted service",
            ))

        for e in by_kind[EdgeKind.CAN_AUTH]:
            if self.nodes[e.target].kind == NodeKind.MACHINE:
                self._add(AttackEdge(
                    source=e.target, target=e.source, kind="HOST_TO_SESSION",
                    technique="T1003.001", weight=1.2,
                    description="Credential material recoverable from live session",
                ))

        for e in by_kind[EdgeKind.ADMIN_OF]:
            if self.nodes[e.target].kind == NodeKind.MACHINE:
                self._add(AttackEdge(
                    source=e.target, target=e.source, kind="HOST_TO_ADMIN",
                    technique="T1003.002", weight=1.0,
                    description="Administrator credential material cached on host",
                ))

        # A principal with DCSync rights over a domain can pull ANY credential
        # in that domain.  So once an attacker has "reached" a domain node
        # (via trust traversal or by compromising its DC), they can pivot to
        # any principal that has DCSync on it.
        domain_ids = {nid for nid, n in self.nodes.items()
                      if "domain" in (n.tags or [])}

        if domain_ids:
            # Find every *non-domain* principal with a CAN_ESCALATE edge into
            # a domain node. Domain-to-domain trust edges are excluded — those
            # are already emitted in both directions by the trust parser.
            dcsync_principals: dict = defaultdict(set)
            for e in self.attacker_edges:
                if (e.kind == "CAN_ESCALATE"
                        and e.target in domain_ids
                        and e.source not in domain_ids):
                    dcsync_principals[e.target].add(e.source)

            # Reverse direction: domain -> principal.
            for domain_id, principals in dcsync_principals.items():
                for principal_id in principals:
                    self._add(AttackEdge(
                        source=domain_id,
                        target=principal_id,
                        kind="DOMAIN_TO_DCSYNC",
                        technique="T1003.006",
                        weight=0.4,
                        description=("Attacker with domain access dumps the "
                                     "DCSync principal's credential hash"),
                    ))

        # If a *group* is admin of a machine, an attacker on that machine
        # can dump the credentials of every user in that group.
        group_admin_of: dict = defaultdict(set)
        for e in by_kind[EdgeKind.ADMIN_OF]:
            src_node = self.nodes.get(e.source)
            tgt_node = self.nodes.get(e.target)
            if (src_node is not None
                    and tgt_node is not None
                    and src_node.kind == NodeKind.IDENTITY
                    and "group" in src_node.tags
                    and tgt_node.kind == NodeKind.MACHINE):
                group_admin_of[e.source].add(e.target)

        for e in by_kind[EdgeKind.MEMBER_OF]:
            if e.target in group_admin_of:
                user_node = self.nodes.get(e.source)
                if user_node is not None and user_node.kind == NodeKind.IDENTITY:
                    for machine_id in group_admin_of[e.target]:
                        self._add(AttackEdge(
                            source=machine_id,
                            target=e.source,
                            kind="HOST_TO_GROUP_ADMIN",
                            technique="T1003",
                            weight=1.5,
                            description=("Attacker on host dumps credentials "
                                         "of a group-privileged user"),
                        ))

    def _add(self, ae: AttackEdge) -> None:
        if ae.source not in self.nodes or ae.target not in self.nodes:
            return
        self.attacker_edges.append(ae)
        self.adj[ae.source].append(ae)

    def get_node(self, nid: str) -> Node:
        return self.nodes[nid]

    def crown_jewels(self) -> List[Node]:
        return [n for n in self.nodes.values()
                if n.kind == NodeKind.ASSET and n.criticality >= 4]

    # ---------------------------------------------------------------- dijkstra
    def _dijkstra(self, source: str):
        dist: Dict[str, float] = {source: 0.0}
        prev: Dict[str, Tuple[str, AttackEdge]] = {}
        pq: List[Tuple[float, str]] = [(0.0, source)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            for e in self.adj.get(u, []):
                nd = d + e.weight
                if nd < dist.get(e.target, float("inf")):
                    dist[e.target] = nd
                    prev[e.target] = (u, e)
                    heapq.heappush(pq, (nd, e.target))
        return dist, prev

    def shortest_path(self, source: str, target: str) -> Optional[AttackPath]:
        dist, prev = self._dijkstra(source)
        if target not in dist:
            return None
        return self._reconstruct(source, target, dist[target], prev)

    def _reconstruct(self, source: str, target: str, cost: float,
                     prev: Dict[str, Tuple[str, AttackEdge]]) -> AttackPath:
        steps_rev: List[PathStep] = []
        node = target
        while node != source:
            parent, edge = prev[node]
            steps_rev.append(PathStep(
                source=parent, target=node, kind=edge.kind,
                technique=edge.technique, weight=edge.weight,
                description=edge.description,
            ))
            node = parent
        steps = list(reversed(steps_rev))
        nodes = [source] + [s.target for s in steps]
        risk = self._risk(target, cost)
        return AttackPath(source=source, target=target, nodes=nodes,
                          steps=steps, cost=round(cost, 3),
                          hops=len(steps), risk=round(risk, 3))

    def _risk(self, target: str, cost: float) -> float:
        crit = self.nodes[target].criticality
        return round(crit * 10.0 / (1.0 + cost), 3)

    # ------------------------------------------------------------- path search
    def find_paths(self, source: str, targets: List[str],
                   max_paths: int = 5, max_depth: int = 14,
                   cost_ratio: float = 2.5) -> List[AttackPath]:
        results: List[AttackPath] = []
        for t in targets:
            best = self.shortest_path(source, t)
            if best is None:
                continue
            cutoff = best.cost * cost_ratio
            for cost, node_path, edge_path in self._enumerate(
                source, t, cutoff, max_depth, max_paths
            ):
                steps = [
                    PathStep(source=a, target=b, kind=e.kind,
                             technique=e.technique, weight=e.weight,
                             description=e.description)
                    for (a, b, e) in edge_path
                ]
                results.append(AttackPath(
                    source=source, target=t, nodes=node_path, steps=steps,
                    cost=round(cost, 3), hops=len(steps),
                    risk=round(self._risk(t, cost), 3),
                ))
        seen, unique = set(), []
        for p in sorted(results, key=lambda x: -x.risk):
            key = tuple(p.nodes)
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        return unique[: max_paths * max(1, len(targets))]

    def _enumerate(self, source, target, cutoff, max_depth, max_results):
        results = []

        def dfs(node, path, edges, cost, visited):
            if len(results) >= max_results or cost > cutoff or len(path) > max_depth:
                return
            if node == target:
                results.append((cost, list(path), list(edges)))
                return
            for e in self.adj.get(node, []):
                if e.target in visited:
                    continue
                visited.add(e.target)
                path.append(e.target)
                edges.append((node, e.target, e))
                dfs(e.target, path, edges, cost + e.weight, visited)
                edges.pop()
                path.pop()
                visited.discard(e.target)

        dfs(source, [source], [], 0.0, {source})
        results.sort(key=lambda x: x[0])
        return results

    def blast_radius(self, source: str) -> Dict[str, List[str]]:
        dist, prev = self._dijkstra(source)
        reachable: Dict[str, List[str]] = {}
        for nid in dist:
            if nid == source:
                continue
            p = self._reconstruct(source, nid, dist[nid], prev)
            reachable[nid] = p.nodes
        return reachable

    def choke_points(self, source: str, targets: List[str]) -> List[Dict]:
        candidates: Dict[str, set] = defaultdict(set)
        for t in targets:
            p = self.shortest_path(source, t)
            if p is None:
                continue
            for n in p.nodes:
                if n not in (source, t):
                    candidates[n].add(t)
        results = []
        for cand, covered in candidates.items():
            still_reachable = []
            for t in covered:
                dist, _ = self._dijkstra_excluding(source, cand)
                if t in dist:
                    still_reachable.append(t)
            broken = covered - set(still_reachable)
            if broken:
                node = self.nodes[cand]
                results.append({
                    "id": cand, "name": node.name, "kind": node.kind.value,
                    "criticality": node.criticality,
                    "breaks_targets": sorted(broken),
                    "coverage": round(len(broken) / max(1, len(targets)), 3),
                })
        results.sort(key=lambda r: (-r["coverage"], -r["criticality"]))
        return results

    def _dijkstra_excluding(self, source: str, exclude: str):
        dist: Dict[str, float] = {source: 0.0}
        prev: Dict[str, Tuple[str, AttackEdge]] = {}
        pq: List[Tuple[float, str]] = [(0.0, source)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            for e in self.adj.get(u, []):
                if e.target == exclude or e.source == exclude:
                    continue
                nd = d + e.weight
                if nd < dist.get(e.target, float("inf")):
                    dist[e.target] = nd
                    prev[e.target] = (u, e)
                    heapq.heappush(pq, (nd, e.target))
        return dist, prev

    def to_payload(self) -> Dict:
        return {
            "name": self.env.name,
            "description": self.env.description,
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.declared],
            "attacker_edges": [a.model_dump() for a in self.attacker_edges],
            "stats": {
                "nodes": len(self.nodes),
                "declared_edges": len(self.declared),
                "attacker_edges": len(self.attacker_edges),
                "crown_jewels": len(self.crown_jewels()),
            },
        }


# ---------------------------------------------------------- strategy grouping

def group_paths_by_strategy(paths, graph: "AttackGraph") -> list:
    """Cluster paths that represent the same strategic attack.

    Two paths share a strategy when they have the same source, the same
    target, and cross the same sequence of high-criticality "landmark"
    nodes.  Permuting through different workstations or session chains
    does not change the strategy.

    Returns a list of dicts, one per strategy, sorted by best cost.
    """
    groups: dict = {}
    for p in paths:
        landmarks = tuple(
            nid for nid in p.nodes
            if nid in graph.nodes and graph.nodes[nid].criticality >= 4
        )
        key = (p.source, p.target, landmarks)
        groups.setdefault(key, []).append(p)

    result = []
    for (src, tgt, landmarks), ps in groups.items():
        ps.sort(key=lambda x: x.cost)
        result.append({
            "source": src,
            "target": tgt,
            "landmarks": list(landmarks),
            "landmark_names": [
                graph.nodes[n].name if n in graph.nodes else n
                for n in landmarks
            ],
            "representative": ps[0],
            "variants": ps,
            "variant_count": len(ps),
            "best_cost": ps[0].cost,
            "worst_cost": ps[-1].cost,
        })
    result.sort(key=lambda g: (g["target"], g["best_cost"]))
    return result
