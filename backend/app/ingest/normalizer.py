"""Convert mapped tables into canonical Node / Edge lists."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Node, Edge, NodeKind, EdgeKind
from .mapper import Mapping
from .ontology import normalise_criticality, normalise_privilege


NODE_KIND = {
    "IDENTITY":    NodeKind.IDENTITY,
    "GROUP":       NodeKind.IDENTITY,
    "CREDENTIAL":  NodeKind.CREDENTIAL,
    "MACHINE":     NodeKind.MACHINE,
    "SERVICE":     NodeKind.SERVICE,
    "ROLE":        NodeKind.IDENTITY,
    "ASSET":       NodeKind.ASSET,
    "APPLICATION": NodeKind.SERVICE,
    "NETWORK":     NodeKind.MACHINE,
}

EDGE_KIND = {
    "MEMBER_OF":       EdgeKind.MEMBER_OF,
    "HAS_CREDENTIAL":  EdgeKind.HAS_CREDENTIAL,
    "USES":            EdgeKind.RUNS_AS,
    "CAN_ACCESS":      EdgeKind.GRANTS_ACCESS,
    "CAN_LOGIN":       EdgeKind.CAN_AUTH,
    "RUNS":            EdgeKind.RUNS_AS,
    "HOSTS":           EdgeKind.RUNS_ON,
    "HAS_ROLE":        EdgeKind.HAS_PERMISSION,
    "CAN_ADMIN":       EdgeKind.ADMIN_OF,
    "CAN_EXECUTE":     EdgeKind.GRANTS_ACCESS,
    "TRUSTS":          EdgeKind.CAN_ESCALATE,
    "CONNECTS_TO":     EdgeKind.CAN_AUTH,
    "OWNS":            EdgeKind.ADMIN_OF,
    "CONTAINS":        EdgeKind.GRANTS_ACCESS,
    "DEPENDS_ON":      EdgeKind.GRANTS_ACCESS,
}


# Generic domain-prefix matcher: any short alphabetic token followed by
# MYDOMAIN\\alice, etc. without naming any specific domain.
_DOMAIN_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,31}[\\/]")


def _strip_domain(value: str) -> str:
    return _DOMAIN_PREFIX.sub("", value)


@dataclass
class Normalised:
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    unresolved: List[Dict] = field(default_factory=list)
    id_index: Dict[str, Node] = field(default_factory=dict)


def _make_node_id(mapping: Mapping, raw_id: str, row_idx: int) -> str:
    if raw_id and str(raw_id).strip():
        return str(raw_id).strip()
    return f"{mapping.entity_type.lower() or 'node'}_{row_idx}"


def add_entities(mapping: Mapping, rows: List[Dict[str, Any]],
                 out: Normalised) -> None:
    if mapping.kind != "entity":
        return
    entity_type = mapping.entity_type or "IDENTITY"
    kind = NODE_KIND.get(entity_type, NodeKind.IDENTITY)

    id_col = name_col = crit_col = type_col = None
    for src_col, role in mapping.column_map.items():
        if role == "id": id_col = src_col
        elif role == "name": name_col = src_col
        elif role == "criticality": crit_col = src_col
        elif role == "type": type_col = src_col

    for i, row in enumerate(rows):
        raw_id = str(row.get(id_col, "")).strip() if id_col else ""
        node_id = _make_node_id(mapping, raw_id, i)
        if node_id in out.id_index:
            out.warnings.append(
                f"Duplicate node id '{node_id}' in {mapping.source_name}; skipped.")
            continue

        name = str(row.get(name_col, "")).strip() if name_col else node_id
        if not name:
            name = node_id

        crit = normalise_criticality(row.get(crit_col) if crit_col else None)

        actual_type = entity_type
        if type_col and row.get(type_col):
            from .ontology import canon_node_type
            override = canon_node_type(str(row[type_col]))
            if override:
                actual_type = override

        tags = []
        if entity_type == "GROUP" or actual_type == "GROUP":
            tags.append("group")

        attrs = {}
        for src_col, role in mapping.column_map.items():
            if role.startswith("metadata:"):
                attrs[role.split(":", 1)[1]] = row.get(src_col)

        node = Node(
            id=node_id,
            kind=NODE_KIND.get(actual_type, kind),
            name=name,
            criticality=crit,
            tags=tags,
            attributes={"source": mapping.source_name, "row": i, **attrs},
        )
        out.nodes.append(node)
        out.id_index[node_id] = node


def add_relationships(mapping: Mapping, rows: List[Dict[str, Any]],
                      out: Normalised) -> None:
    if mapping.kind != "relationship":
        return
    rel_type = mapping.relationship_type
    if not rel_type:
        out.errors.append(f"{mapping.source_name}: no relationship type.")
        return
    edge_kind = EDGE_KIND.get(rel_type, EdgeKind.GRANTS_ACCESS)

    src_col = tgt_col = priv_col = rel_type_col = None
    for col, role in mapping.column_map.items():
        if role == "source": src_col = col
        elif role == "target": tgt_col = col
        elif role == "privilege": priv_col = col
        elif role == "rel_type": rel_type_col = col
    if not (src_col and tgt_col):
        out.errors.append(f"{mapping.source_name}: missing source/target column.")
        return

    # ---- secondary indexes for reference resolution
    name_index: Dict[str, Node] = {}
    short_index: Dict[str, Node] = {}
    for node in out.nodes:
        nm = (node.name or "").strip().lower()
        if nm and nm not in name_index:
            name_index[nm] = node
        if nm:
            first = nm.split()[0]
            if first not in short_index:
                short_index[first] = node
            clean = _strip_domain(nm)
            if clean and clean != nm:
                short_index.setdefault(clean, node)
                if clean.split():
                    short_index.setdefault(clean.split()[0], node)

    def resolve(value: str) -> Optional[Node]:
        if not value:
            return None
        v = value.strip()
        # 1) exact id
        n = out.id_index.get(v)
        if n: return n
        # 2) case-insensitive id
        for k, node in out.id_index.items():
            if k.lower() == v.lower():
                return node
        # 3) exact name
        n = name_index.get(v.lower())
        if n: return n
        # 4) first-token of name
        n = short_index.get(v.lower())
        if n: return n
        # 5) generic domain-prefix strip and retry
        clean = _strip_domain(v.lower())
        if clean != v.lower():
            n = name_index.get(clean)
            if n: return n
            n = short_index.get(clean.split()[0] if clean.split() else clean)
            if n: return n
        return None

    for i, row in enumerate(rows):
        s_raw = str(row.get(src_col, "")).strip()
        t_raw = str(row.get(tgt_col, "")).strip()
        if not s_raw or not t_raw:
            continue
        s_node = resolve(s_raw)
        t_node = resolve(t_raw)
        if not s_node or not t_node:
            out.unresolved.append({
                "file": mapping.source_name, "row": i,
                "source": s_raw, "target": t_raw,
                "reason": "source and/or target not found in any entity table",
            })
            continue

        priv = normalise_privilege(row.get(priv_col) if priv_col else None)

        # per-row relationship_type overrides the table-level guess
        row_rel_type = rel_type
        if rel_type_col:
            raw = str(row.get(rel_type_col, "")).strip()
            if raw:
                from .ontology import canon_relationship_type
                canon = canon_relationship_type(raw)
                if canon:
                    row_rel_type = canon
                else:
                    out.warnings.append(
                        f"{mapping.source_name} row {i}: unknown relationship_type "
                        f"'{raw}' — falling back to {rel_type}.")

        row_edge_kind = EDGE_KIND.get(row_rel_type, edge_kind)
        weight = _weight_for(row_rel_type, priv)

        out.edges.append(Edge(
            source=s_node.id, target=t_node.id, kind=row_edge_kind,
            weight=weight, technique=None,
        ))


def _weight_for(rel_type: str, privilege: str) -> float:
    base = {
        "MEMBER_OF": 0.3, "HAS_CREDENTIAL": 0.4, "CAN_LOGIN": 1.0,
        "CAN_ACCESS": 0.6, "CAN_ADMIN": 0.5, "RUNS": 0.5, "HOSTS": 0.7,
        "HAS_ROLE": 0.6, "CAN_EXECUTE": 0.6, "TRUSTS": 0.4,
        "CONNECTS_TO": 0.8, "OWNS": 0.6, "CONTAINS": 0.6, "DEPENDS_ON": 0.7,
        "USES": 0.6,
    }.get(rel_type, 0.6)
    if privilege == "OWNER":   base *= 0.5
    elif privilege == "ADMIN": base *= 0.6
    elif privilege == "EXECUTE": base *= 0.8
    return round(base, 3)
