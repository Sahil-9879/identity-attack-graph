"""Schema profiler: inspect a table and describe its columns + overall shape.

Two passes:
  Pass 1 — per column: assign a STRUCTURAL role.
  Pass 2 — per table: decide ENTITY vs RELATIONSHIP, and pick id/src/tgt cols.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


PRIMARY_ID_NAMES = {"id", "sid", "guid", "uuid", "pk", "key", "oid"}
REF_SUFFIXES = ("_id", "_sid", "_guid", "_uuid", "_key", "_ref", "_fk", "_oid")
NAME_HINTS = {"name", "username", "sam", "samaccountname", "display",
              "displayname", "label", "title", "cn"}
PRIV_HINTS = {"privilege", "permission", "access", "right", "rights",
              "effective_permission", "access_level"}
CRIT_HINTS = {"criticality", "severity", "impact", "priority",
              "sensitivity", "classification", "importance", "risk",
              "business_impact"}
TYPE_HINTS = {"type", "kind", "class", "category", "entity", "entity_type"}

SOURCE_WORDS = {"source", "from", "src", "member", "user", "username",
                "account", "principal", "subject", "identity", "parent",
                "owner", "assignee", "origin"}
TARGET_WORDS = {"target", "to", "dst", "destination", "resource",
                "object", "group", "groupname", "role", "asset",
                "machine", "host", "server", "share", "database",
                "bucket", "container", "child"}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
SID_RE = re.compile(r"^S-1-\d", re.I)


def _looks_like_id(value: str) -> bool:
    if not value:
        return False
    if UUID_RE.match(value) or SID_RE.match(value):
        return True
    if value.isdigit():
        return True
    if re.match(r"^[a-zA-Z_]{1,6}[-_]?\d{1,}$", value):
        return True
    return False


def _is_float(s: str) -> bool:
    try:
        float(s)
        return "." in s
    except ValueError:
        return False


def _tokens(name: str) -> List[str]:
    return [t for t in re.split(r"[_\-\.\s]+", name.lower()) if t]


def _matches_synonym(tok: str, syns) -> bool:
    """Match a token against a list of synonyms, tolerating simple plurals."""
    t = tok.lower().rstrip("s")
    for s in syns:
        if t == s.lower().rstrip("s"):
            return True
    return False


# ---------------------------------------------------------------- ColumnProfile

@dataclass
class ColumnProfile:
    name: str
    dtype: str = "string"
    total: int = 0
    non_null: int = 0
    unique_values: int = 0
    examples: List[str] = field(default_factory=list)
    likely_role: str = "metadata"
    confidence: float = 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "dtype": self.dtype,
            "null_pct": round(1 - self.non_null / max(1, self.total), 3),
            "unique_pct": round(self.unique_values / max(1, self.total), 3),
            "examples": self.examples[:5],
            "likely_role": self.likely_role,
            "confidence": self.confidence,
        }


@dataclass
class TableProfile:
    source_name: str
    rows: int
    columns: List[ColumnProfile]
    id_column: Optional[str] = None
    name_column: Optional[str] = None
    source_column: Optional[str] = None
    target_column: Optional[str] = None
    privilege_column: Optional[str] = None
    criticality_column: Optional[str] = None
    type_column: Optional[str] = None
    shape: str = "unknown"
    shape_confidence: float = 0.0

    def as_dict(self) -> dict:
        return {
            "source": self.source_name,
            "rows": self.rows,
            "shape": self.shape,
            "shape_confidence": self.shape_confidence,
            "columns": [c.as_dict() for c in self.columns],
            "id_column": self.id_column,
            "name_column": self.name_column,
            "source_column": self.source_column,
            "target_column": self.target_column,
            "privilege_column": self.privilege_column,
            "criticality_column": self.criticality_column,
            "type_column": self.type_column,
        }


# ---------------------------------------------------------------- pass 1

def _infer_column_role(col: ColumnProfile) -> tuple[str, float]:
    name = col.name.lower().strip()
    toks = _tokens(name)

    # 1) exact primary key
    if name in PRIMARY_ID_NAMES:
        return "id_primary", 0.95

    # 2) foreign-key suffix → reference with optional direction
    for suf in REF_SUFFIXES:
        if name.endswith(suf):
            prefix = name[: -len(suf)]
            if prefix in SOURCE_WORDS:
                return "source_hint", 0.9
            if prefix in TARGET_WORDS:
                return "target_hint", 0.9
            return "reference", 0.8

    # 3) canonical source/target names
    if name in ("source", "from", "src"):
        return "source_hint", 0.9
    if name in ("target", "to", "dst", "destination"):
        return "target_hint", 0.9
    if name in ("resource", "object"):
        return "target_hint", 0.85

    # 4) name-like hints (must come BEFORE generic source/target words,
    #    otherwise "group_name" would be misread as a target hint).
    if any(t in NAME_HINTS for t in toks) and "id" not in toks:
        return "name", 0.85

    # 5) plain source/target words as whole tokens, as a *fallback*.
    #    e.g. "principal" (source) / "resource" (target).
    for tok in toks:
        if tok in SOURCE_WORDS:
            return "source_hint", 0.7
        if tok in TARGET_WORDS:
            return "target_hint", 0.7

    # 5) value-driven reference
    examples = [str(e) for e in col.examples if e not in (None, "")]
    if examples:
        id_like = sum(1 for e in examples if _looks_like_id(e)) / len(examples)
        distinct_ratio = col.unique_values / max(1, col.non_null)
        if id_like >= 0.9 and distinct_ratio >= 0.8:
            return "reference", 0.6

    # 6) value semantics
    #    NOTE: check rel_type BEFORE generic type/privilege/name checks.
    if name in ("relationship_type", "relation_type", "rel_type",
                "edge_type", "link_type"):
        return "rel_type", 0.95
    if any(t in PRIV_HINTS for t in toks):
        return "privilege", 0.85
    if any(t in CRIT_HINTS for t in toks):
        return "criticality", 0.85
    if any(t in TYPE_HINTS for t in toks):
        # "type" is an entity attribute — but "relationship_type" was
        # already caught above.
        return "type", 0.8

    return "metadata", 0.0


# ---------------------------------------------------------------- pass 2

def _classify_shape(cols: List[ColumnProfile], source_name: str) -> tuple[str, float]:
    roles = [c.likely_role for c in cols]
    has_primary = "id_primary" in roles
    has_name = "name" in roles
    ref_count = sum(1 for r in roles if r in ("reference", "source_hint", "target_hint"))

    file_toks = _tokens(source_name.rsplit(".", 1)[0])
    file_is_rel = any(
        _matches_synonym(t, ("membership", "relation", "link", "binding",
                             "assignment", "grant", "permission", "access"))
        for t in file_toks
    )

    if ref_count >= 2 and not has_name:
        return "relationship", 0.9 if file_is_rel else 0.8
    if ref_count >= 2 and has_primary and not has_name:
        return "relationship", 0.75
    if has_name:
        return "entity", 0.9
    if has_primary:
        return "entity", 0.7
    if ref_count == 1 and not has_name:
        # one column that points somewhere, no name → could be an entity keyed
        # by an external id, or a 1-relationship table. Treat as entity; the
        # caller can override.
        return "entity", 0.5
    return "unknown", 0.0


# ---------------------------------------------------------------- public API

def profile_table(source_name: str, rows: List[Dict[str, Any]]) -> TableProfile:
    if not rows:
        return TableProfile(source_name=source_name, rows=0, columns=[])

    col_names = list(rows[0].keys())
    cols: List[ColumnProfile] = []

    for cname in col_names:
        c = ColumnProfile(name=cname, total=len(rows))
        vals = []
        for r in rows:
            v = r.get(cname)
            if v is None or v == "":
                continue
            c.non_null += 1
            vals.append(str(v))
        c.unique_values = len(set(vals))
        c.examples = vals[:5]
        if vals:
            if all(v.isdigit() for v in vals):
                c.dtype = "int"
            elif all(_is_float(v) or v.isdigit() for v in vals):
                c.dtype = "float"
        c.likely_role, c.confidence = _infer_column_role(c)
        cols.append(c)

    shape, shape_conf = _classify_shape(cols, source_name)

    def best(role_names) -> Optional[str]:
        cands = [c for c in cols if c.likely_role in role_names and c.confidence >= 0.5]
        if not cands:
            return None
        return max(cands, key=lambda x: x.confidence).name

    prof = TableProfile(
        source_name=source_name,
        rows=len(rows),
        columns=cols,
        shape=shape,
        shape_confidence=shape_conf,
        id_column=best({"id_primary"}),
        name_column=best({"name"}),
        privilege_column=best({"privilege"}),
        criticality_column=best({"criticality"}),
        type_column=best({"type"}),
    )

    # ---- relationship tables: source + target
    if shape == "relationship":
        src = best({"source_hint"})
        tgt = best({"target_hint"})

        # Ensure src != tgt; then fill any remaining side positionally.
        if src == tgt:
            tgt = None

        refs = [c.name for c in cols
                if c.likely_role in ("source_hint", "target_hint", "reference")]

        if not src:
            src = next((r for r in refs if r != tgt), None)
        if not tgt:
            tgt = next((r for r in refs if r != src), None)

        prof.source_column = src
        prof.target_column = tgt

    # ---- entity tables: pick an id column
    if shape == "entity" and not prof.id_column:
        # candidates: any column that points somewhere (ref/source_hint/target_hint)
        cands = [c for c in cols
                 if c.likely_role in ("id_primary", "reference",
                                      "source_hint", "target_hint")]
        if cands:
            # highest uniqueness wins
            prof.id_column = max(
                cands, key=lambda c: c.unique_values / max(1, c.non_null)
            ).name
        elif cols:
            # last resort: first column
            prof.id_column = cols[0].name

    return prof
