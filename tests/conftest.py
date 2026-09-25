"""Shared pytest fixtures."""
import io
import sys
import zipfile
from pathlib import Path

import pytest

# Make `backend.app` importable when pytest runs from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _csv_bytes(rows, cols):
    lines = [",".join(cols)]
    for r in rows:
        lines.append(",".join(str(r.get(c, "")) for c in cols))
    return ("\n".join(lines) + "\n").encode()


def _zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def pattern_a_zip():
    """users / groups / memberships — the classic pattern."""
    users = [
        {"user_id": "u1", "username": "alice", "department": "Engineering"},
        {"user_id": "u2", "username": "bob", "department": "Finance"},
        {"user_id": "u3", "username": "carol", "department": "IT"},
    ]
    groups = [
        {"group_id": "g1", "group_name": "Engineering"},
        {"group_id": "g2", "group_name": "Domain Admins"},
    ]
    memberships = [
        {"user_id": "u1", "group_id": "g1"},
        {"user_id": "u2", "group_id": "g1"},
        {"user_id": "u3", "group_id": "g2"},
    ]
    return _zip_bytes({
        "users.csv": _csv_bytes(users, ["user_id", "username", "department"]),
        "groups.csv": _csv_bytes(groups, ["group_id", "group_name"]),
        "memberships.csv": _csv_bytes(memberships, ["user_id", "group_id"]),
    })


@pytest.fixture
def pattern_b_zip():
    """accounts / roles / role_bindings — role-based variant."""
    accounts = [
        {"account_id": "a1", "name": "dave"},
        {"account_id": "a2", "name": "erin"},
    ]
    roles = [
        {"role_id": "r1", "role_name": "reader"},
        {"role_id": "r2", "role_name": "admin"},
    ]
    bindings = [
        {"account_id": "a1", "role_id": "r1"},
        {"account_id": "a2", "role_id": "r2"},
    ]
    return _zip_bytes({
        "accounts.csv": _csv_bytes(accounts, ["account_id", "name"]),
        "roles.csv": _csv_bytes(roles, ["role_id", "role_name"]),
        "role_bindings.csv": _csv_bytes(bindings, ["account_id", "role_id"]),
    })


@pytest.fixture
def pattern_c_csv():
    """Flat file: only relationships, no entity definitions."""
    return _csv_bytes(
        [
            {"principal": "alice", "resource": "dev-db", "permission": "READ"},
            {"principal": "bob", "resource": "customer-db", "permission": "ADMIN"},
        ],
        ["principal", "resource", "permission"],
    )


@pytest.fixture
def pattern_enterprise_zip():
    """Entities + relationships with per-row relationship_type."""
    nodes = [
        {"id": "n1", "name": "Alice", "type": "IDENTITY", "criticality": 2},
        {"id": "n2", "name": "Bob", "type": "IDENTITY", "criticality": 2},
        {"id": "g1", "group_name": "Admins", "type": "GROUP", "criticality": 5},
        {"id": "m1", "hostname": "SRV-01", "type": "MACHINE", "criticality": 3},
    ]
    rels = [
        {"source_id": "n1", "target_id": "g1", "relationship_type": "MEMBER_OF"},
        {"source_id": "n2", "target_id": "g1", "relationship_type": "MEMBER_OF"},
        {"source_id": "g1", "target_id": "m1", "relationship_type": "ADMIN_OF"},
    ]
    return _zip_bytes({
        "entities.csv": _csv_bytes(nodes, ["id", "name", "type", "criticality"]),
        "groups.csv": _csv_bytes(
            [n for n in nodes if n["type"] == "GROUP"],
            ["id", "group_name", "type", "criticality"],
        ),
        "relations.csv": _csv_bytes(
            rels, ["source_id", "target_id", "relationship_type"]),
    })


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Point store.DB_PATH at a temp file so tests don't touch data.db."""
    from backend.app import store
    db = tmp_path / "test.db"
    monkeypatch.setattr(store, "DB_PATH", db)
    store.init_db()
    yield db
