"""Turn a TableProfile into a Mapping: what does this table MEAN?"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .ontology import NODE_SYNONYMS, RELATIONSHIP_SYNONYMS
from .profiler import TableProfile


@dataclass
class Mapping:
    source_name: str
    kind: str                          # entity | relationship | unknown
    entity_type: Optional[str] = None
    relationship_type: Optional[str] = None
    column_map: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0
    warnings: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "source": self.source_name,
            "kind": self.kind,
            "entity_type": self.entity_type,
            "relationship_type": self.relationship_type,
            "column_map": self.column_map,
            "confidence": self.confidence,
            "warnings": self.warnings,
        }


def _tokens(name: str) -> List[str]:
    return [t for t in re.split(r"[_\-\.\s]+", name.lower()) if t]


def _matches(tok: str, syns) -> bool:
    t = tok.rstrip("s")
    return any(t == s.rstrip("s") for s in syns)


# --------------------------------------------------------- what does X point at?

_OBJECT_GROUP    = {"group", "groups", "role", "roles", "team", "teams", "ou"}
_OBJECT_RESOURCE = {"resource", "resources", "asset", "assets", "database",
                    "databases", "db", "share", "shares", "bucket", "buckets",
                    "file", "files", "folder", "folders"}
_OBJECT_IDENTITY = {"user", "users", "account", "accounts", "principal",
                    "principals", "identity", "identities", "member", "members"}
_OBJECT_MACHINE  = {"machine", "machines", "host", "hosts", "server", "servers",
                    "computer", "computers", "workstation", "workstations",
                    "vm", "vms", "node", "nodes"}
_OBJECT_SERVICE  = {"service", "services", "daemon", "process", "processes"}


def _object_side(col_name: str) -> str:
    """What kind of object does this column name point at?"""
    for tok in _tokens(col_name):
        t = tok.rstrip("s")
        if t in _OBJECT_GROUP:    return "group"
        if t in _OBJECT_RESOURCE: return "resource"
        if t in _OBJECT_IDENTITY: return "identity"
        if t in _OBJECT_MACHINE:  return "machine"
        if t in _OBJECT_SERVICE:  return "service"
    return "unknown"


# ------------------------------------------------------------------ entity

import re as _re

_GROUP_PATTERNS = _re.compile(
    r"^(gg[-_]|group[-_]|ad[-_]|dom[a-z]*[-_])"      # prefix forms
    r"|"
    r"(admins?|operators?|users?|groups?|team|teams|"
    r"administrators?|backup|domain admins|service accounts?)$",
    _re.I,
)


def _looks_like_group_name(value: str) -> bool:
    if not value:
        return False
    v = str(value).strip()
    if not v:
        return False
    # both "GG-Developers" (single token) and "Domain Admins" (two tokens)
    if _GROUP_PATTERNS.search(v):
        return True
    # group-like suffix on the last token
    last = v.split()[-1] if v.split() else v
    if _GROUP_PATTERNS.search(last):
        return True
    return False


def _entity_scores(profile: TableProfile) -> Dict[str, float]:
    scores = {t: 0.0 for t in NODE_SYNONYMS}
    toks = _tokens(profile.source_name.rsplit(".", 1)[0])
    for t, syns in NODE_SYNONYMS.items():
        for tok in toks:
            if _matches(tok, syns):
                scores[t] += 0.5
                break
    # column names
    for c in profile.columns:
        toks = _tokens(c.name)
        for t, syns in NODE_SYNONYMS.items():
            for tok in toks:
                if _matches(tok, syns):
                    scores[t] += 0.15
                    break
    # value contribution — inspect name column
    for c in profile.columns:
        if c.likely_role != "name":
            continue
        for ex in c.examples:
            exl = str(ex).lower()
            for t, syns in NODE_SYNONYMS.items():
                if any(s in exl for s in syns):
                    scores[t] += 0.2
                    break
            # NEW: value-based group detection
            if _looks_like_group_name(ex):
                scores["GROUP"] += 0.45
    return scores


# --------------------------------------------------------------- relationship

def _rel_scores(profile: TableProfile) -> Dict[str, float]:
    scores = {t: 0.0 for t in RELATIONSHIP_SYNONYMS}

    # ---- file name (plural-tolerant)
    for tok in _tokens(profile.source_name.rsplit(".", 1)[0]):
        for t, syns in RELATIONSHIP_SYNONYMS.items():
            if _matches(tok, syns):
                scores[t] += 0.45
                break

    # ---- column names (plural-tolerant)
    for c in profile.columns:
        for tok in _tokens(c.name):
            for t, syns in RELATIONSHIP_SYNONYMS.items():
                if _matches(tok, syns):
                    scores[t] += 0.2
                    break

    # ---- semantic direction: what do the source/target columns point at?
    src_side = _object_side(profile.source_column or "")
    tgt_side = _object_side(profile.target_column or "")

    if tgt_side == "group":
        scores["MEMBER_OF"] += 0.6
        scores["HAS_ROLE"] += 0.3
    if tgt_side == "role":
        scores["HAS_ROLE"] += 0.6
    if tgt_side == "resource":
        scores["CAN_ACCESS"] += 0.4
        scores["CAN_EXECUTE"] += 0.15
    if tgt_side == "machine":
        scores["CAN_LOGIN"] += 0.35
        scores["CONNECTS_TO"] += 0.2
        scores["CAN_ADMIN"] += 0.15
    if tgt_side == "identity":
        scores["TRUSTS"] += 0.3
        scores["CAN_ADMIN"] += 0.15
    if tgt_side == "service":
        scores["USES"] += 0.3
        scores["RUNS"] += 0.2
    if src_side == "machine" and tgt_side == "machine":
        scores["CONNECTS_TO"] += 0.3

    # ---- privilege column → CAN_ACCESS / CAN_ADMIN
    if profile.privilege_column:
        scores["CAN_ACCESS"] += 0.2
        scores["CAN_ADMIN"] += 0.15
        col_lower = (profile.source_name + " " + profile.privilege_column).lower()
        if "admin" in col_lower:
            scores["CAN_ADMIN"] += 0.3

    # ---- file-name patterns that unambiguously identify a relationship
    file_low = profile.source_name.lower()
    if "runas" in file_low or "runs_as" in file_low or "run-as" in file_low:
        scores["RUNS"] += 0.8
    if "member" in file_low:
        scores["MEMBER_OF"] += 0.4
    if "admin" in file_low and "access" in file_low:
        scores["CAN_ADMIN"] += 0.5
    if "connect" in file_low:
        scores["CONNECTS_TO"] += 0.5
    if "credential" in file_low and "holder" in file_low:
        scores["HAS_CREDENTIAL"] += 0.6

    # ---- fallback
    if all(v == 0 for v in scores.values()):
        scores["CAN_ACCESS"] = 0.4

    return scores


# --------------------------------------------------------------- main

def map_table(profile: TableProfile) -> Mapping:
    m = Mapping(source_name=profile.source_name, kind="unknown")

    # ---------------- relationship ----------------
    if profile.shape == "relationship":
        m.kind = "relationship"
        rel_scores = _rel_scores(profile)
        best_rel, best_score = max(rel_scores.items(), key=lambda kv: kv[1])
        m.relationship_type = best_rel
        m.confidence = round(min(1.0, profile.shape_confidence * 0.5 + best_score), 3)

        if profile.source_column:
            m.column_map[profile.source_column] = "source"
        if profile.target_column:
            m.column_map[profile.target_column] = "target"
        if profile.privilege_column:
            m.column_map[profile.privilege_column] = "privilege"

        # per-row relationship type (source of truth when present)
        for c in profile.columns:
            if c.likely_role == "rel_type":
                m.column_map[c.name] = "rel_type"

        for c in profile.columns:
            if c.name in m.column_map:
                continue
            m.column_map[c.name] = f"metadata:{c.name}"

        if not (profile.source_column and profile.target_column):
            m.confidence = 0.0
            m.warnings.append("Relationship table without source/target columns.")

        if m.confidence < 0.4:
            m.warnings.append(
                f"Low confidence ({m.confidence:.2f}) — confirm relationship "
                "type and source/target columns.")

        return m

    # ---------------- entity ----------------
    if profile.shape == "entity":
        m.kind = "entity"
        escores = _entity_scores(profile)
        best_ent, best_score = max(escores.items(), key=lambda kv: kv[1])
        m.entity_type = best_ent
        m.confidence = round(min(1.0, profile.shape_confidence * 0.5 + best_score), 3)

        if profile.id_column:
            m.column_map[profile.id_column] = "id"
        else:
            m.warnings.append("No id column found — will use row index.")

        if profile.name_column:
            m.column_map[profile.name_column] = "name"
        if profile.type_column:
            m.column_map[profile.type_column] = "type"
        if profile.criticality_column:
            m.column_map[profile.criticality_column] = "criticality"

        for c in profile.columns:
            if c.name in m.column_map:
                continue
            m.column_map[c.name] = f"metadata:{c.name}"

        return m

    # ---------------- unknown ----------------
    m.confidence = 0.0
    m.warnings.append(
        "Could not classify this table as entity or relationship. "
        "Manual mapping required.")
    return m
