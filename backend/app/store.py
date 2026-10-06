"""SQLite / Turso persistence for scenarios, snapshots, and mitigation plans.

Runs locally on `sqlite3` (stdlib) or in production on Turso, depending on
whether TURSO_DATABASE_URL + TURSO_AUTH_TOKEN are set.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Environment, Node, Edge


# ---------------------------------------------------------------- config

_data_dir = Path(os.environ.get(
    "IAG_DATA_DIR",
    Path.home() / "identity-attack-graph",
))
DB_PATH = _data_dir / "data.db"
_lock = threading.Lock()

TURSO_URL = os.environ.get("TURSO_DATABASE_URL", "").strip()
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "").strip()
USE_TURSO = bool(TURSO_URL and TURSO_TOKEN)


# ---------------------------------------------------------------- connection

def _connect():
    """Return a DB-API 2.0 connection — Turso if configured, else local SQLite."""
    if USE_TURSO:
        import turso_serverless
        # NOTE: turso_serverless.connect() takes the URL as a POSITIONAL arg.
        return turso_serverless.connect(
            TURSO_URL,
            auth_token=TURSO_TOKEN,
        )
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _rows_as_dicts(cursor, rows) -> List[Dict[str, Any]]:
    if not rows:
        return []
    try:
        keys = list(rows[0].keys())
        return [dict(zip(keys, r)) for r in rows]
    except AttributeError:
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, r)) for r in rows]


def _row_as_dict(cursor, row) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    try:
        return dict(row)
    except (TypeError, ValueError):
        cols = [d[0] for d in cursor.description]
        return dict(zip(cols, row))


def _execute(stmt: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(stmt, params)
            rows = cur.fetchall() if cur.description else []
            return _rows_as_dicts(cur, rows)
        finally:
            try: conn.close()
            except Exception: pass


def _execute_write(stmt: str, params: tuple = ()) -> int:
    """Run an INSERT/UPDATE/DELETE.  Returns rowcount."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(stmt, params)
            conn.commit()
            return cur.rowcount or 0
        finally:
            try: conn.close()
            except Exception: pass


def _execute_insert_returning_id(stmt: str, params: tuple = ()) -> int:
    """Run an INSERT that ends with RETURNING id, return the new id."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(stmt, params)
            row = cur.fetchone()
            conn.commit()
            if row is None:
                return 0
            try:
                return int(row[0])
            except (TypeError, IndexError):
                return 0
        finally:
            try: conn.close()
            except Exception: pass


def _execute_many(stmt: str, seq) -> None:
    with _lock:
        conn = _connect()
        try:
            try:
                conn.executemany(stmt, seq)
            except (AttributeError, NotImplementedError):
                # Fallback for drivers without executemany
                for params in seq:
                    conn.execute(stmt, params)
            conn.commit()
        finally:
            try: conn.close()
            except Exception: pass


def _execute_batch(prefix: str, seq, batch_size: int = 100) -> None:
    """Insert many rows using multi-value VALUES lists.

    Turso (and any HTTP-based driver) is dominated by round-trip latency.
    Sending one INSERT with 100 rows is ~100x faster than 100 separate
    INSERTs. Falls back to executemany on drivers that can't handle the
    multi-value syntax.
    """
    if not seq:
        return
    seq = list(seq)
    for start in range(0, len(seq), batch_size):
        chunk = seq[start:start + batch_size]
        placeholders = ",".join(["(" + ",".join(["?"] * len(row)) + ")" for row in chunk])
        stmt = f"{prefix} VALUES {placeholders}"
        flat = tuple(v for row in chunk for v in row)
        with _lock:
            conn = _connect()
            try:
                conn.execute(stmt, flat)
                conn.commit()
            finally:
                try: conn.close()
                except Exception: pass


# ---------------------------------------------------------------- schema

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS scenarios (
        name TEXT PRIMARY KEY,
        description TEXT,
        source_type TEXT,
        created_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS nodes (
        scenario TEXT NOT NULL,
        id TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        criticality INTEGER,
        tags TEXT,
        attributes TEXT,
        PRIMARY KEY (scenario, id)
    )""",
    """CREATE TABLE IF NOT EXISTS edges (
        scenario TEXT NOT NULL,
        idx INTEGER NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        kind TEXT NOT NULL,
        weight REAL,
        technique TEXT,
        PRIMARY KEY (scenario, idx)
    )""",
    """CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scenario TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        node_count INTEGER,
        edge_count INTEGER,
        nodes_json TEXT,
        edges_json TEXT,
        metadata_json TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_login_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS mitigation_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scenario TEXT NOT NULL,
        source TEXT NOT NULL,
        targets TEXT NOT NULL,
        excluded_edges TEXT NOT NULL,
        total_cost REAL,
        notes TEXT,
        created_at TEXT
    )""",
]


def init_db() -> None:
    for stmt in SCHEMA:
        _execute_write(stmt)
    # Migrations — add user_id to tables that predate user accounts.
    # ALTER TABLE ADD COLUMN is idempotent-safe here because we swallow
    # the "duplicate column" error that SQLite/Turso raise.
    for tbl in ("scenarios", "snapshots", "mitigation_plans"):
        try:
            _execute_write(f"ALTER TABLE {tbl} ADD COLUMN user_id INTEGER")
        except Exception:
            pass


# ---------------------------------------------------------------- scenarios

def save_environment(env: Environment, source_type: str = "import",
                     user_id: Optional[int] = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    _execute_write(
        "INSERT OR REPLACE INTO scenarios(name, description, source_type, created_at, user_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (env.name, env.description or "", source_type, now, user_id),
    )
    _execute_write("DELETE FROM nodes WHERE scenario = ?", (env.name,))
    _execute_write("DELETE FROM edges WHERE scenario = ?", (env.name,))

    if env.nodes:
        _execute_batch(
            "INSERT INTO nodes(scenario, id, kind, name, criticality, tags, attributes)",
            [(env.name, n.id, n.kind.value, n.name, n.criticality,
              json.dumps(n.tags), json.dumps(n.attributes))
             for n in env.nodes],
            batch_size=100,
        )
    if env.edges:
        _execute_batch(
            "INSERT INTO edges(scenario, idx, source, target, kind, weight, technique)",
            [(env.name, i, e.source, e.target, e.kind.value, e.weight, e.technique)
             for i, e in enumerate(env.edges)],
            batch_size=200,
        )


def load_environment(name: str) -> Optional[Environment]:
    srows = _execute(
        "SELECT name, description FROM scenarios WHERE name = ?", (name,))
    if not srows:
        return None
    scenario = srows[0]

    node_rows = _execute(
        "SELECT id, kind, name, criticality, tags, attributes "
        "FROM nodes WHERE scenario = ?", (name,))
    edge_rows = _execute(
        "SELECT source, target, kind, weight, technique "
        "FROM edges WHERE scenario = ? ORDER BY idx", (name,))

    nodes = [
        Node(id=r["id"], kind=r["kind"], name=r["name"],
             criticality=r["criticality"] or 1,
             tags=json.loads(r["tags"] or "[]"),
             attributes=json.loads(r["attributes"] or "{}"))
        for r in node_rows
    ]
    edges = [
        Edge(source=r["source"], target=r["target"], kind=r["kind"],
             weight=r["weight"] or 1.0, technique=r["technique"])
        for r in edge_rows
    ]
    return Environment(name=scenario["name"],
                       description=scenario["description"] or "",
                       nodes=nodes, edges=edges)


def list_saved() -> List[Dict]:
    return _execute(
        "SELECT name, description, source_type, created_at FROM scenarios "
        "ORDER BY created_at DESC")


def delete_environment(name: str) -> bool:
    _execute_write("DELETE FROM nodes WHERE scenario = ?", (name,))
    _execute_write("DELETE FROM edges WHERE scenario = ?", (name,))
    _execute_write("DELETE FROM scenarios WHERE name = ?", (name,))
    return True


# ---------------------------------------------------------------- plans

def save_plan(scenario, source, targets, excluded, total_cost, notes="") -> int:
    now = datetime.now(timezone.utc).isoformat()
    return _execute_insert_returning_id(
        "INSERT INTO mitigation_plans(scenario, source, targets, excluded_edges, "
        "total_cost, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (scenario, source, json.dumps(list(targets)),
         json.dumps(sorted(excluded)), total_cost, notes, now))


def list_plans(scenario: Optional[str] = None) -> List[Dict]:
    if scenario:
        rows = _execute(
            "SELECT * FROM mitigation_plans WHERE scenario = ? ORDER BY created_at DESC",
            (scenario,))
    else:
        rows = _execute(
            "SELECT * FROM mitigation_plans ORDER BY created_at DESC")
    return [{
        "id": r["id"], "scenario": r["scenario"], "source": r["source"],
        "targets": json.loads(r["targets"]),
        "excluded_edges": json.loads(r["excluded_edges"]),
        "total_cost": r["total_cost"], "notes": r["notes"],
        "created_at": r["created_at"],
    } for r in rows]


def delete_plan(plan_id: int) -> bool:
    _execute_write("DELETE FROM mitigation_plans WHERE id = ?", (plan_id,))
    return True


# ---------------------------------------------------------------- snapshots

def save_snapshot(scenario: str, env: Environment,
                  metadata: dict | None = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    nodes = [{"id": n.id, "name": n.name, "kind": n.kind.value,
              "criticality": n.criticality, "tags": list(n.tags)}
             for n in env.nodes]
    edges = [{"source": e.source, "target": e.target, "kind": e.kind.value}
             for e in env.edges]
    return _execute_insert_returning_id(
        "INSERT INTO snapshots(scenario, captured_at, node_count, edge_count, "
        "nodes_json, edges_json, metadata_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        (scenario, now, len(nodes), len(edges),
         json.dumps(nodes), json.dumps(edges), json.dumps(metadata or {})))


def list_snapshots(scenario: Optional[str] = None) -> List[Dict]:
    if scenario:
        return _execute(
            "SELECT id, scenario, captured_at, node_count, edge_count "
            "FROM snapshots WHERE scenario = ? ORDER BY captured_at DESC",
            (scenario,))
    return _execute(
        "SELECT id, scenario, captured_at, node_count, edge_count "
        "FROM snapshots ORDER BY captured_at DESC")


def load_snapshot(snapshot_id: int) -> Optional[Dict]:
    rows = _execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,))
    if not rows:
        return None
    r = rows[0]
    return {
        "id": r["id"], "scenario": r["scenario"],
        "captured_at": r["captured_at"],
        "nodes": json.loads(r["nodes_json"]),
        "edges": json.loads(r["edges_json"]),
        "metadata": json.loads(r["metadata_json"] or "{}"),
    }


def delete_snapshot(snapshot_id: int) -> bool:
    _execute_write("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
    return True


# ---------------------------------------------------------------- users

def create_user(email: str, username: str, password_hash: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    return _execute_insert_returning_id(
        "INSERT INTO users(email, username, password_hash, created_at) "
        "VALUES (?, ?, ?, ?) RETURNING id",
        (email.lower().strip(), username.strip(), password_hash, now),
    )


def get_user_by_email(email: str) -> Optional[Dict]:
    rows = _execute("SELECT * FROM users WHERE email = ?",
                    (email.lower().strip(),))
    return rows[0] if rows else None


def get_user_by_username(username: str) -> Optional[Dict]:
    rows = _execute("SELECT * FROM users WHERE username = ?",
                    (username.strip(),))
    return rows[0] if rows else None


def get_user_by_id(user_id: int) -> Optional[Dict]:
    rows = _execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return rows[0] if rows else None


def update_last_login(user_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    _execute_write("UPDATE users SET last_login_at = ? WHERE id = ?",
                   (now, user_id))


def count_users() -> int:
    rows = _execute("SELECT COUNT(*) AS n FROM users")
    return int(rows[0]["n"]) if rows else 0


def list_user_scenarios(user_id: int) -> List[Dict]:
    """Every scenario imported by this user (not the built-in demo)."""
    return _execute(
        "SELECT name, description, source_type, created_at, "
        "       (SELECT COUNT(*) FROM nodes WHERE nodes.scenario = scenarios.name) AS node_count, "
        "       (SELECT COUNT(*) FROM edges WHERE edges.scenario = scenarios.name) AS edge_count "
        "FROM scenarios WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,))


def assign_scenario_owner(scenario_name: str, user_id: int) -> None:
    _execute_write("UPDATE scenarios SET user_id = ? WHERE name = ?",
                   (user_id, scenario_name))
