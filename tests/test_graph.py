"""Verify the graph engine derives everything from the passed Environment."""
from backend.app.graph import AttackGraph
from backend.app.models import Environment, Node, Edge, NodeKind, EdgeKind


def _small_env():
    """alice -> developers -> server -> db  (a 3-hop chain)."""
    return Environment(
        name="t",
        nodes=[
            Node(id="alice", kind=NodeKind.IDENTITY, name="Alice", criticality=2),
            Node(id="devs", kind=NodeKind.IDENTITY, name="Developers",
                 criticality=2, tags=["group"]),
            Node(id="srv", kind=NodeKind.MACHINE, name="SRV-01", criticality=3),
            Node(id="db", kind=NodeKind.ASSET, name="DB", criticality=5),
        ],
        edges=[
            Edge(source="alice", target="devs", kind=EdgeKind.MEMBER_OF, weight=0.3),
            Edge(source="devs", target="srv", kind=EdgeKind.CAN_AUTH, weight=1.0),
            Edge(source="srv", target="db", kind=EdgeKind.GRANTS_ACCESS, weight=0.5),
        ],
    )


def test_shortest_path_exists():
    g = AttackGraph(_small_env())
    p = g.shortest_path("alice", "db")
    assert p is not None
    assert p.nodes == ["alice", "devs", "srv", "db"]
    assert p.hops == 3


def test_path_disappears_when_edge_removed():
    g = AttackGraph(_small_env())
    with g.with_exclusions({"devs->srv"}):
        assert g.shortest_path("alice", "db") is None


def test_blast_radius_grows_with_edges():
    g = AttackGraph(_small_env())
    reach = g.blast_radius("alice")
    assert set(reach.keys()) == {"devs", "srv", "db"}


def test_min_cut_severs_path():
    from backend.app.mincut import MitigationSolver
    g = AttackGraph(_small_env())
    result = MitigationSolver(g).solve("alice", ["db"])
    assert result["severed"] is True
    assert result["after"]["count"] == 0
    # The cheapest cut is one of the three edges on the path.
    assert result["total_cost"] > 0


def test_different_source_different_paths():
    """Dataset-independence: change the source, paths must change."""
    g = AttackGraph(_small_env())
    assert g.shortest_path("alice", "db") is not None
    # 'devs' isn't a real source here, but 'db' has no outgoing edges:
    assert g.shortest_path("db", "alice") is None
