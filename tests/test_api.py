"""End-to-end tests through the FastAPI TestClient."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(temp_db, monkeypatch):
    """Fresh app with a temp DB."""
    import backend.app.api as api
    monkeypatch.setattr(api, "_loaded_envs", {})
    monkeypatch.setattr(api, "_graph_cache", {})
    monkeypatch.setattr(api, "_env_labels", {})
    monkeypatch.setattr(api, "_active_source", None)
    from backend.app.main import app
    return TestClient(app)


def test_health_lists_no_default(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_demo_load_and_active(client):
    r = client.post("/api/demo/load")
    assert r.status_code == 200
    assert r.json()["ok"] is True

    r2 = client.get("/api/active")
    assert r2.json()["active"] is not None


def test_ingest_preview_does_not_commit(client, pattern_a_zip):
    client.post("/api/demo/load")
    before = client.get("/api/active").json()["active"]

    r = client.post(
        "/api/ingest/preview",
        files={"file": ("pattern_a.zip", pattern_a_zip, "application/zip")},
    )
    body = r.json()
    assert body["ok"] is True
    assert body["stats"]["edges"] == 3

    # Active source must be unchanged.
    after = client.get("/api/active").json()["active"]
    assert after == before


def test_ingest_commit_switches_active(client, pattern_b_zip):
    client.post("/api/demo/load")
    r = client.post(
        "/api/ingest/commit",
        files={"file": ("pattern_b.zip", pattern_b_zip, "application/zip")},
    )
    body = r.json()
    assert body["ok"] is True

    active = client.get("/api/active").json()["active"]
    assert active == body["active"]

    # Fetch the active graph and confirm it contains dave/erin.
    g = client.get("/api/graph").json()
    names = {n["name"] for n in g["nodes"]}
    assert "dave" in names and "erin" in names


def test_ingest_commit_persists(client, temp_db, pattern_a_zip):
    client.post(
        "/api/ingest/commit",
        files={"file": ("pattern_a.zip", pattern_a_zip, "application/zip")},
    )
    # Check the SQLite store directly.
    from backend.app import store
    saved = store.list_saved()
    assert any("pattern_a" in s["name"] for s in saved)


def test_persistence_roundtrip(temp_db):
    from backend.app import store
    from backend.app.models import Environment, Node, Edge, NodeKind, EdgeKind
    env = Environment(
        name="roundtrip",
        description="test",
        nodes=[Node(id="a", kind=NodeKind.IDENTITY, name="A")],
        edges=[Edge(source="a", target="a", kind=EdgeKind.MEMBER_OF)],
    )
    store.save_environment(env)
    loaded = store.load_environment("roundtrip")
    assert loaded is not None
    assert loaded.nodes[0].name == "A"
    assert len(loaded.edges) == 1
