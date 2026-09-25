"""Verify the ingestion pipeline classifies schemas correctly."""
import pytest
from backend.app.ingest.pipeline import ingest_bytes


def test_pattern_a_classification(pattern_a_zip):
    r = ingest_bytes(pattern_a_zip, "pattern_a.zip")
    assert r.ok is True, r.errors

    by_src = {m.source_name: m for m in r.mappings}
    assert by_src["users.csv"].kind == "entity"
    assert by_src["users.csv"].entity_type == "IDENTITY"
    assert by_src["groups.csv"].kind == "entity"
    assert by_src["groups.csv"].entity_type == "GROUP"
    assert by_src["memberships.csv"].kind == "relationship"
    assert by_src["memberships.csv"].relationship_type == "MEMBER_OF"

    # 3 users, 2 groups, 3 membership edges
    assert r.stats["identity"] == 3
    assert r.stats["group"] == 2
    assert r.stats["edges"] == 3
    assert r.stats["unresolved"] == 0


def test_pattern_b_classification(pattern_b_zip):
    r = ingest_bytes(pattern_b_zip, "pattern_b.zip")
    assert r.ok is True, r.errors
    by_src = {m.source_name: m for m in r.mappings}
    assert by_src["accounts.csv"].entity_type == "IDENTITY"
    assert by_src["roles.csv"].entity_type in ("GROUP", "IDENTITY")
    assert by_src["role_bindings.csv"].kind == "relationship"
    assert r.stats["edges"] == 2
    assert r.stats["unresolved"] == 0


def test_pattern_c_refuses_to_fabricate(pattern_c_csv):
    """A flat file with no entity definitions must not create fake nodes."""
    r = ingest_bytes(pattern_c_csv, "access.csv")
    assert r.ok is False
    assert r.stats["unresolved"] >= 1
    # The mapper should still have recognised it as a relationship table.
    assert any(m.kind == "relationship" for m in r.mappings)


def test_per_row_relationship_type(pattern_enterprise_zip):
    """A relationship_type column overrides the table-level guess."""
    r = ingest_bytes(pattern_enterprise_zip, "enterprise.zip")
    assert r.ok is True, r.errors
    rel = next(m for m in r.mappings if m.source_name == "relations.csv")
    assert "rel_type" in rel.column_map.values()

    from collections import Counter
    kinds = Counter(e.kind.value for e in r.environment.edges)
    assert kinds.get("MEMBER_OF", 0) == 2
    assert kinds.get("ADMIN_OF", 0) == 1


def test_no_dataset_specific_code():
    """The ingest package must not contain any hard-coded ACME names."""
    from pathlib import Path
    ingest = Path(__file__).resolve().parents[1] / "backend" / "app" / "ingest"
    forbidden = ["acme", "frank", "dave", "carol", "srv-jump", "customer-pii"]
    for py in ingest.rglob("*.py"):
        text = py.read_text().lower()
        for word in forbidden:
            assert word not in text, f"{py.name} contains '{word}'"
