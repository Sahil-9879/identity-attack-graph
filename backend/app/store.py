"""SQLite persistence for imported scenarios and mitigation plans."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .models import Environment, Node, Edge

# Data directory is configurable so Docker and local dev can share the file.
_data_dir = Path(os.environ.get(
    "IAG_DATA_DIR",
    Path.home() / "identity-attack-graph",
))
DB_PATH = _data_dir / "data.db"
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scenarios (
            name TEXT PRIMARY KEY,
            description TEXT,
            source_type TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS nodes (
            scenario TEXT NOT NULL,
            id TEXT NOT NULL,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            criticality INTEGER,
            tags TEXT,
            attributes TEXT,
            PRIMARY KEY (scenario, id),
            FOREIGN KEY (scenario) REFERENCES scenarios(name) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS edges (
            scenario TEXT NOT NULL,
            idx INTEGER NOT NULL,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            kind TEXT NOT NULL,
            weight REAL,
            technique TEXT,
            PRIMARY KEY (scenario, idx),
            FOREIGN KEY (scenario) REFERENCES scenarios(name) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            node_count INTEGER,
            edge_count INTEGER,
            nodes_json TEXT,
            edges_json TEXT,
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_scenario
            ON snapshots(scenario, captured_at DESC);
        CREATE TABLE IF NOT EXISTS mitigation_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT NOT NULL,
            source TEXT NOT NULL,
            targets TEXT NOT NULL,
            excluded_edges TEXT NOT NULL,
            total_cost REAL,
            notes TEXT,
            created_at TEXT
        );
        """)


def save_environment(env: Environment, source_type: str = "import") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scenarios(name, description, source_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (env.name, env.description, source_type, now))
        conn.execute("DELETE FROM nodes WHERE scenario = ?", (env.name,))
        conn.execute("DELETE FROM edges WHERE scenario = ?", (env.name,))
        conn.executemany(
            "INSERT INTO nodes(scenario, id, kind, name, criticality, tags, attributes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(env.name, n.id, n.kind.value, n.name, n.criticality,
              json.dumps(n.tags), json.dumps(n.attributes)) for n in env.nodes])
        conn.executemany(
            "INSERT INTO edges(scenario, idx, source, target, kind, weight, technique) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(env.name, i, e.source, e.target, e.kind.value, e.weight, e.technique)
             for i, e in enumerate(env.edges)])


def load_environment(name: str) -> Optional[Environment]:
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT name, description FROM scenarios WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        node_rows = conn.execute(
            "SELECT id, kind, name, criticality, tags, attributes "
            "FROM nodes WHERE scenario = ?", (name,)).fetchall()
        edge_rows = conn.execute(
            "SELECT source, target, kind, weight, technique "
            "FROM edges WHERE scenario = ? ORDER BY idx", (name,)).fetchall()
    nodes = [Node(id=r["id"], kind=r["kind"], name=r["name"],
                  criticality=r["criticality"] or 1,
                  tags=json.loads(r["tags"] or "[]"),
                  attributes=json.loads(r["attributes"] or "{}"))
             for r in node_rows]
    edges = [Edge(source=r["source"], target=r["target"], kind=r["kind"],
                  weight=r["weight"] or 1.0, technique=r["technique"])
             for r in edge_rows]
    return Environment(name=row["name"], description=row["description"] or "",
                       nodes=nodes, edges=edges)


def list_saved() -> List[Dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT name, description, source_type, created_at FROM scenarios "
            "ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def delete_environment(name: str) -> bool:
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM scenarios WHERE name = ?", (name,))
        return cur.rowcount > 0


def save_plan(scenario, source, targets, excluded, total_cost, notes="") -> int:
    now = datetime.now(timezone.utc).isoformat()
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO mitigation_plans(scenario, source, targets, excluded_edges, "
            "total_cost, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scenario, source, json.dumps(list(targets)),
             json.dumps(sorted(excluded)), total_cost, notes, now))
        return cur.lastrowid


def list_plans(scenario: Optional[str] = None) -> List[Dict]:
    with _lock, _connect() as conn:
        if scenario:
            rows = conn.execute(
                "SELECT * FROM mitigation_plans WHERE scenario = ? ORDER BY created_at DESC",
                (scenario,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM mitigation_plans ORDER BY created_at DESC").fetchall()
    return [{"id": r["id"], "scenario": r["scenario"], "source": r["source"],
             "targets": json.loads(r["targets"]),
             "excluded_edges": json.loads(r["excluded_edges"]),
             "total_cost": r["total_cost"], "notes": r["notes"],
             "created_at": r["created_at"]} for r in rows]


def delete_plan(plan_id: int) -> bool:
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM mitigation_plans WHERE id = ?", (plan_id,))
        return cur.rowcount > 0


# ------------------------------------------------------------- snapshots

def save_snapshot(scenario: str, env: Environment,
                  metadata: dict | None = None) -> int:
    """Save a compact snapshot of the current graph state."""
    import json as _json
    now = datetime.now(timezone.utc).isoformat()

    nodes = [
        {"id": n.id, "name": n.name, "kind": n.kind.value,
         "criticality": n.criticality, "tags": list(n.tags)}
        for n in env.nodes
    ]
    edges = [
        {"source": e.source, "target": e.target, "kind": e.kind.value}
        for e in env.edges
    ]
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO snapshots(scenario, captured_at, node_count, "
            "edge_count, nodes_json, edges_json, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scenario, now, len(nodes), len(edges),
             _json.dumps(nodes), _json.dumps(edges),
             _json.dumps(metadata or {})),
        )
        return cur.lastrowid


def list_snapshots(scenario: str | None = None) -> list[dict]:
    with _lock, _connect() as conn:
        if scenario:
            rows = conn.execute(
                "SELECT id, scenario, captured_at, node_count, edge_count "
                "FROM snapshots WHERE scenario = ? ORDER BY captured_at DESC",
                (scenario,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, scenario, captured_at, node_count, edge_count "
                "FROM snapshots ORDER BY captured_at DESC").fetchall()
    return [dict(r) for r in rows]


def load_snapshot(snapshot_id: int) -> dict | None:
    import json as _json
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "scenario": row["scenario"],
        "captured_at": row["captured_at"],
        "nodes": _json.loads(row["nodes_json"]),
        "edges": _json.loads(row["edges_json"]),
        "metadata": _json.loads(row["metadata_json"] or "{}"),
    }


def delete_snapshot(snapshot_id: int) -> bool:
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
        return cur.rowcount > 0
