"""JSON importer with schema validation and normalisation.

Produces an ImportResult whose Environment is consumable by the graph
engine. Never raises on malformed input — reports errors instead.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..models import Node, Edge, NodeKind, EdgeKind
from .base import DataSource, ImportError, ImportResult, ImportStats, ImportWarning


# ---------------------------------------------------------------- schema maps

NODE_TYPE_MAP: Dict[str, NodeKind] = {
    "IDENTITY":   NodeKind.IDENTITY,
    "GROUP":      NodeKind.IDENTITY,      # groups are a kind of identity
    "USER":       NodeKind.IDENTITY,
    "CREDENTIAL": NodeKind.CREDENTIAL,
    "MACHINE":    NodeKind.MACHINE,
    "HOST":       NodeKind.MACHINE,
    "SERVICE":    NodeKind.SERVICE,
    "PERMISSION": NodeKind.PERMISSION,
    "ASSET":      NodeKind.ASSET,
}

RELATIONSHIP_MAP: Dict[str, EdgeKind] = {
    "MEMBER_OF":       EdgeKind.MEMBER_OF,
    "HAS_CREDENTIAL":  EdgeKind.HAS_CREDENTIAL,
    "CREDENTIAL_FOR":  EdgeKind.CREDENTIAL_FOR,
    "CAN_AUTH":        EdgeKind.CAN_AUTH,
    "CAN_ACCESS":      EdgeKind.CAN_AUTH,       # alias
    "ADMIN_OF":        EdgeKind.ADMIN_OF,
    "CAN_ADMIN":       EdgeKind.ADMIN_OF,       # alias
    "RUNS_ON":         EdgeKind.RUNS_ON,
    "RUNS_AS":         EdgeKind.RUNS_AS,
    "HAS_PERMISSION":  EdgeKind.HAS_PERMISSION,
    "GRANTS_ACCESS":   EdgeKind.GRANTS_ACCESS,
    "CAN_ESCALATE":    EdgeKind.CAN_ESCALATE,
}

PRIVILEGE_LEVELS = {"NONE", "READ", "WRITE", "EXECUTE", "ADMIN", "SYSTEM", None}


class _Normalised:
    def __init__(self):
        self.nodes: List[Node] = []
        self.edges: List[Edge] = []
        self.stats = ImportStats()
        self.warnings: List[ImportWarning] = []
        self.errors: List[ImportError] = []


def normalise_document(doc: Dict[str, Any]) -> _Normalised:
    """Validate and normalise a JSON environment document.

    Expected shape:
        {
          "metadata": { "name": ..., "version": ..., "source": ... },
          "nodes":    [ { id, name, type, criticality?, tags?, attributes? }, ... ],
          "edges":    [ { source, target, relationship_type,
                          weight?, technique?, origin? }, ... ]
        }
    """
    n = _Normalised()

    # ---------------------------------------------------------- top level
    if not isinstance(doc, dict):
        n.errors.append(ImportError("not_object", "Top-level value must be a JSON object"))
        return n

    meta = doc.get("metadata") or {}
    if not isinstance(meta, dict) or not meta.get("name"):
        n.errors.append(ImportError("metadata_missing", "metadata.name is required"))

    nodes_raw = doc.get("nodes")
    edges_raw = doc.get("edges")
    if not isinstance(nodes_raw, list):
        n.errors.append(ImportError("nodes_missing", "nodes[] is required and must be an array"))
        return n
    if not isinstance(edges_raw, list):
        n.errors.append(ImportError("edges_missing", "edges[] is required and must be an array"))
        return n

    # ---------------------------------------------------------- nodes
    seen_ids: set = set()
    for i, raw in enumerate(nodes_raw):
        loc = f"nodes[{i}]"
        if not isinstance(raw, dict):
            n.errors.append(ImportError("node_bad_shape", f"{loc} must be an object"))
            continue
        nid = raw.get("id")
        if not nid or not isinstance(nid, str):
            n.errors.append(ImportError("node_id_missing", f"{loc}.id is required"))
            continue
        if nid in seen_ids:
            n.errors.append(ImportError("node_id_duplicate",
                                        f"duplicate node id '{nid}'", detail=loc))
            continue
        seen_ids.add(nid)

        raw_type = (raw.get("type") or "").upper()
        kind = NODE_TYPE_MAP.get(raw_type)
        if kind is None:
            n.errors.append(ImportError("node_type_unknown",
                                        f"unsupported node type '{raw.get('type')}'",
                                        detail=loc))
            continue

        crit = raw.get("criticality")
        if crit is None:
            crit = 3
            n.warnings.append(ImportWarning(
                "criticality_default",
                f"{loc} has no criticality; defaulting to 3",
                detail=nid,
            ))
        if not isinstance(crit, int) or not 1 <= crit <= 5:
            n.errors.append(ImportError("criticality_invalid",
                                        f"{loc}.criticality must be 1..5",
                                        detail=str(crit)))
            continue

        n.nodes.append(Node(
            id=nid,
            kind=kind,
            name=str(raw.get("name") or nid),
            criticality=crit,
            tags=list(raw.get("tags") or []),
            attributes=dict(raw.get("attributes") or {}),
        ))
        # stats
        if raw_type == "GROUP":
            n.stats.groups += 1
        elif kind == NodeKind.IDENTITY:
            n.stats.identities += 1
        elif kind == NodeKind.CREDENTIAL:
            n.stats.credentials += 1
        elif kind == NodeKind.MACHINE:
            n.stats.machines += 1
        elif kind == NodeKind.SERVICE:
            n.stats.services += 1
        elif kind == NodeKind.PERMISSION:
            n.stats.permissions += 1
        elif kind == NodeKind.ASSET:
            n.stats.assets += 1

    valid_ids = {node.id for node in n.nodes}

    # ---------------------------------------------------------- edges
    for i, raw in enumerate(edges_raw):
        loc = f"edges[{i}]"
        if not isinstance(raw, dict):
            n.errors.append(ImportError("edge_bad_shape", f"{loc} must be an object"))
            continue
        src = raw.get("source")
        tgt = raw.get("target")
        rel = (raw.get("relationship_type") or "").upper()

        if not src or not isinstance(src, str):
            n.errors.append(ImportError("edge_source_missing", f"{loc}.source required"))
            continue
        if not tgt or not isinstance(tgt, str):
            n.errors.append(ImportError("edge_target_missing", f"{loc}.target required"))
            continue
        if src not in valid_ids:
            n.errors.append(ImportError("edge_dangling",
                                        f"{loc}.source '{src}' not in nodes[]"))
            continue
        if tgt not in valid_ids:
            n.errors.append(ImportError("edge_dangling",
                                        f"{loc}.target '{tgt}' not in nodes[]"))
            continue

        kind = RELATIONSHIP_MAP.get(rel)
        if kind is None:
            n.errors.append(ImportError("edge_kind_unknown",
                                        f"unsupported relationship_type '{raw.get('relationship_type')}'",
                                        detail=loc))
            continue

        priv = raw.get("privilege_level")
        if priv is not None:
            priv = str(priv).upper()
            if priv not in PRIVILEGE_LEVELS:
                n.errors.append(ImportError("privilege_invalid",
                                            f"{loc}.privilege_level '{priv}' unsupported"))
                continue

        weight = raw.get("weight", 1.0)
        try:
            weight = float(weight)
            if weight <= 0:
                raise ValueError
        except (TypeError, ValueError):
            n.errors.append(ImportError("edge_weight_invalid",
                                        f"{loc}.weight must be a positive number"))
            continue

        origin = (raw.get("origin") or "OBSERVED").upper()
        if origin not in {"OBSERVED", "DERIVED", "SIMULATED"}:
            n.warnings.append(ImportWarning("origin_unknown",
                                            f"{loc}.origin '{origin}' not recognised",
                                            detail="defaulting to OBSERVED"))
            origin = "OBSERVED"

        n.edges.append(Edge(
            source=src,
            target=tgt,
            kind=kind,
            weight=weight,
            technique=raw.get("technique"),
        ))
        n.stats.relationships += 1

    # ---------------------------------------------------------- warnings
    referenced = {e.source for e in n.edges} | {e.target for e in n.edges}
    isolated = [node.id for node in n.nodes if node.id not in referenced]
    if isolated:
        n.warnings.append(ImportWarning(
            "isolated_nodes",
            f"{len(isolated)} node(s) have no relationships",
            detail=", ".join(isolated[:8]) + ("…" if len(isolated) > 8 else ""),
        ))

    if not any(node.kind == NodeKind.ASSET for node in n.nodes):
        n.warnings.append(ImportWarning(
            "no_assets",
            "dataset contains no ASSET nodes — crown jewels cannot be auto-detected",
        ))

    return n


class JsonDataSource(DataSource):
    name = "json"
    label = "JSON Environment"

    def load(self, text: str, source_label: str = "Imported: JSON", **_) -> ImportResult:
        import json as _json
        result = ImportResult(source_label=source_label)
        try:
            doc = _json.loads(text)
        except Exception as e:
            result.errors.append(ImportError("json_parse", "Not valid JSON",
                                             detail=str(e)))
            return result

        n = normalise_document(doc)
        result.errors.extend(n.errors)
        result.warnings.extend(n.warnings)
        result.stats = n.stats
        if n.errors:
            return result

        from ..models import Environment
        meta = doc.get("metadata") or {}
        result.environment = Environment(
            name=meta.get("name") or "imported",
            description=meta.get("description", ""),
            nodes=n.nodes,
            edges=n.edges,
        )
        return result
