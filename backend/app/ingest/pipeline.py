"""Upload → detect → parse → profile → map → normalise → resolve.

The caller gets one ImportResult containing:
  * the canonical Environment (if successful)
  * the mapping decisions (with confidence)
  * validation results
  * warnings / errors
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Environment
from .mapper import Mapping, map_table
from .normalizer import Normalised, add_entities, add_relationships
from .profiler import TableProfile, profile_table


MAX_UPLOAD = 20 * 1024 * 1024        # 20 MB
MAX_UNCOMPRESSED = 200 * 1024 * 1024


@dataclass
class IngestResult:
    ok: bool = False
    environment: Optional[Environment] = None
    profiles: List[TableProfile] = field(default_factory=list)
    mappings: List[Mapping] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    unresolved: List[Dict] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    source_label: str = "import"

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "source_label": self.source_label,
            "stats": self.stats,
            "warnings": self.warnings,
            "errors": self.errors,
            "unresolved": self.unresolved[:50],
            "profiles": [p.as_dict() for p in self.profiles],
            "mappings": [m.as_dict() for m in self.mappings],
            "environment": self.environment.model_dump() if self.environment else None,
        }


# --------------------------------------------------------------- format detection

def _detect_format(filename: str, data: bytes) -> str:
    lower = filename.lower()
    if lower.endswith(".zip") or data[:2] == b"PK":
        return "zip"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith((".csv", ".tsv")):
        return "csv"
    # content sniff
    head = data[:512].lstrip()
    if head[:1] in (b"{", b"["):
        return "json"
    return "csv"


# --------------------------------------------------------------- csv / tsv

def _parse_csv_bytes(data: bytes) -> List[Dict[str, Any]]:
    text = data.decode("utf-8-sig")
    # sniff delimiter
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except Exception:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    return [dict(r) for r in reader]


# --------------------------------------------------------------- json

def _tables_from_json(doc: Any) -> List[tuple[str, List[Dict[str, Any]]]]:
    """Return [(table_name, rows)]."""
    out = []
    if isinstance(doc, list):
        rows = [r for r in doc if isinstance(r, dict)]
        out.append(("root", rows))
    elif isinstance(doc, dict):
        for key, val in doc.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                out.append((key, val))
        # If no arrays found, treat the dict itself as one row
        if not out:
            out.append(("root", [doc]))
    return out


# --------------------------------------------------------------- pipeline

def ingest_bytes(data: bytes, filename: str) -> IngestResult:
    result = IngestResult(source_label=f"Imported: {filename}")
    if len(data) > MAX_UPLOAD:
        result.errors.append(f"Upload exceeds {MAX_UPLOAD // 1024 // 1024} MB")
        return result

    fmt = _detect_format(filename, data)

    # ---- collect (source_name, rows) pairs
    tables: List[tuple[str, List[Dict[str, Any]]]] = []

    if fmt == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception as e:
            result.errors.append(f"Invalid ZIP: {e}")
            return result
        total = 0
        for info in zf.infolist():
            if ".." in info.filename or info.filename.startswith("/"):
                result.errors.append(f"Refusing suspicious ZIP entry: {info.filename}")
                return result
            total += info.file_size
            if total > MAX_UNCOMPRESSED:
                result.errors.append("ZIP uncompressed size too large")
                return result
            base = info.filename.split("/")[-1]
            low = base.lower()
            try:
                if low.endswith(".csv") or low.endswith(".tsv"):
                    rows = _parse_csv_bytes(zf.read(info))
                    tables.append((base, rows))
                elif low.endswith(".json"):
                    doc = json.loads(zf.read(info).decode("utf-8"))
                    for key, rows in _tables_from_json(doc):
                        tables.append((f"{base}:{key}", rows))
                else:
                    result.warnings.append(f"Skipped unsupported file: {base}")
            except Exception as e:
                result.warnings.append(f"Failed to parse {base}: {e}")
        if not tables:
            result.errors.append("ZIP contained no supported data files.")
            return result

    elif fmt == "json":
        try:
            doc = json.loads(data.decode("utf-8"))
        except Exception as e:
            result.errors.append(f"Invalid JSON: {e}")
            return result
        for key, rows in _tables_from_json(doc):
            tables.append((key, rows))

    else:  # csv
        try:
            rows = _parse_csv_bytes(data)
        except Exception as e:
            result.errors.append(f"Invalid CSV: {e}")
            return result
        tables.append((filename, rows))

    # ---- auto-detect BloodHound / SharpHound export
    from .bloodhound import looks_like_bloodhound, normalise as bh_normalise
    table_dict = {name: rows for name, rows in tables if rows}
    if looks_like_bloodhound(table_dict):
        norm = bh_normalise(table_dict, source_label=filename)
        result.warnings.extend(norm.warnings)
        result.errors.extend(norm.errors)
        result.unresolved = norm.unresolved
        kinds = {"identity": 0, "group": 0, "credential": 0,
                 "machine": 0, "service": 0, "permission": 0, "asset": 0}
        for n in norm.nodes:
            if "group" in n.tags:
                kinds["group"] += 1
            elif n.kind.value in kinds:
                kinds[n.kind.value] += 1
        result.stats = {**kinds, "nodes": len(norm.nodes),
                        "edges": len(norm.edges),
                        "unresolved": len(norm.unresolved)}
        if norm.nodes:
            from pathlib import Path as _P
            base_name = _P(filename).stem[:40] or "bloodhound"
            result.environment = Environment(
                name=f"{base_name} (BH {len(norm.nodes)}n/{len(norm.edges)}e)",
                description=f"BloodHound import: {filename}",
                nodes=norm.nodes, edges=norm.edges,
            )
            result.ok = True
        else:
            result.errors.append("BloodHound export contained no objects.")
            result.ok = False
        result.source_label = f"BloodHound: {filename}"
        return result

    # ---- profile + map each table
    for name, rows in tables:
        if not rows:
            result.warnings.append(f"{name}: empty table, skipped.")
            continue
        prof = profile_table(name, rows)
        result.profiles.append(prof)
        mapping = map_table(prof)
        result.mappings.append(mapping)
        result.warnings.extend(f"{name}: {w}" for w in mapping.warnings)

    # ---- normalise
    norm = Normalised()
    # Two passes: all entities first, then relationships (so refs resolve)
    for mapping, (_, rows) in zip(result.mappings, [t for t in tables if t[1]]):
        if mapping.kind == "entity":
            add_entities(mapping, rows, norm)
    for mapping, (_, rows) in zip(result.mappings, [t for t in tables if t[1]]):
        if mapping.kind == "relationship":
            add_relationships(mapping, rows, norm)

    result.warnings.extend(norm.warnings)
    result.errors.extend(norm.errors)
    result.unresolved = norm.unresolved

    # ---- stats
    kinds: Dict[str, int] = {
        "identity": 0, "group": 0, "credential": 0, "machine": 0,
        "service": 0, "permission": 0, "asset": 0,
    }
    for n in norm.nodes:
        if "group" in n.tags:
            kinds["group"] += 1
        elif n.kind.value in kinds:
            kinds[n.kind.value] += 1

    result.stats = {
        **kinds,
        "nodes": len(norm.nodes),
        "edges": len(norm.edges),
        "unresolved": len(norm.unresolved),
    }

    if not norm.nodes:
        result.errors.append("No entities were recognised in this dataset.")
        return result

    # ---- build environment
    base_name = Path(filename).stem[:40] or "import"
    result.environment = Environment(
        name=f"{base_name} ({len(norm.nodes)}n/{len(norm.edges)}e)",
        description=f"Imported from {filename}",
        nodes=norm.nodes,
        edges=norm.edges,
    )
    result.ok = True
    return result


# ---------------------------------------------------------------- overrides

def apply_overrides(mappings: List[Mapping],
                    profiles: List[TableProfile],
                    overrides: Dict[str, Dict]) -> None:
    """Mutate mappings in place with user-supplied overrides.

    `overrides` is keyed by source_name (file).  Each value may contain:
        kind: "entity" | "relationship" | "unknown"
        entity_type: canonical NODE_TYPE
        relationship_type: canonical REL_TYPE
        column_map: { source_column: canonical_role }
    """
    by_name = {m.source_name: m for m in mappings}
    for source, ov in (overrides or {}).items():
        m = by_name.get(source)
        if m is None:
            continue
        if "kind" in ov and ov["kind"]:
            m.kind = ov["kind"]
        if "entity_type" in ov and ov["entity_type"] is not None:
            m.entity_type = ov["entity_type"] or None
        if "relationship_type" in ov and ov["relationship_type"] is not None:
            m.relationship_type = ov["relationship_type"] or None
        if "column_map" in ov and isinstance(ov["column_map"], dict):
            # Replace the whole column map so the user's intent is exact.
            m.column_map = dict(ov["column_map"])
        m.confidence = 1.0
        m.warnings = [w for w in m.warnings
                      if not w.startswith("Low confidence")]


def ingest_bytes_with_overrides(data: bytes,
                                filename: str,
                                overrides: Dict[str, Dict]) -> IngestResult:
    """Same as ingest_bytes but applies user overrides before normalisation."""
    result = ingest_bytes(data, filename)

    # If errors only come from ambiguity (not from malformed data), retry
    # with overrides applied.
    if overrides and (result.mappings):
        apply_overrides(result.mappings, result.profiles, overrides)

        # Rebuild from the mappings
        norm = Normalised()
        from .normalizer import add_entities, add_relationships
        # Need the raw rows again — re-parse from the upload.
        rows_by_source: Dict[str, List[Dict]] = _extract_rows(data, filename)

        for mapping in result.mappings:
            if mapping.source_name not in rows_by_source:
                continue
            if mapping.kind == "entity":
                add_entities(mapping, rows_by_source[mapping.source_name], norm)
        for mapping in result.mappings:
            if mapping.source_name not in rows_by_source:
                continue
            if mapping.kind == "relationship":
                add_relationships(mapping, rows_by_source[mapping.source_name], norm)

        # Rebuild stats + environment
        kinds = {"identity": 0, "group": 0, "credential": 0,
                 "machine": 0, "service": 0, "permission": 0, "asset": 0}
        for n in norm.nodes:
            if "group" in n.tags:
                kinds["group"] += 1
            elif n.kind.value in kinds:
                kinds[n.kind.value] += 1

        from pathlib import Path as _P
        base_name = _P(filename).stem[:40] or "import"
        result.stats = {**kinds, "nodes": len(norm.nodes), "edges": len(norm.edges),
                        "unresolved": len(norm.unresolved)}
        result.warnings = list(norm.warnings)
        result.errors = list(norm.errors)
        result.unresolved = norm.unresolved

        if norm.nodes:
            result.environment = Environment(
                name=f"{base_name} ({len(norm.nodes)}n/{len(norm.edges)}e)",
                description=f"Imported from {filename}",
                nodes=norm.nodes, edges=norm.edges,
            )
            result.ok = True
        else:
            result.environment = None
            result.ok = False
            if not result.errors:
                result.errors = ["No entities were recognised after overrides."]
    return result


def _extract_rows(data: bytes, filename: str) -> Dict[str, List[Dict]]:
    """Re-parse a dataset to recover the raw rows by source name."""
    import csv as _csv
    import io as _io
    import json as _json
    import zipfile as _zip
    from pathlib import Path as _P

    fmt = _detect_format(filename, data)
    out: Dict[str, List[Dict]] = {}

    def _csv_rows(b: bytes) -> List[Dict]:
        text = b.decode("utf-8-sig")
        try:
            dialect = _csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        except Exception:
            dialect = _csv.excel
        return [dict(r) for r in _csv.DictReader(_io.StringIO(text), dialect=dialect)]

    def _json_tables(doc):
        if isinstance(doc, list):
            yield "root", [r for r in doc if isinstance(r, dict)]
        elif isinstance(doc, dict):
            for k, v in doc.items():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    yield k, v
            if not any(isinstance(v, list) for v in doc.values()):
                yield "root", [doc]

    if fmt == "zip":
        zf = _zip.ZipFile(_io.BytesIO(data))
        for info in zf.infolist():
            base = info.filename.split("/")[-1]
            low = base.lower()
            if low.endswith((".csv", ".tsv")):
                try:
                    out[base] = _csv_rows(zf.read(info))
                except Exception:
                    pass
            elif low.endswith(".json"):
                try:
                    doc = _json.loads(zf.read(info).decode("utf-8"))
                    for k, rows in _json_tables(doc):
                        out[f"{base}:{k}"] = rows
                except Exception:
                    pass
    elif fmt == "json":
        try:
            doc = _json.loads(data.decode("utf-8"))
            for k, rows in _json_tables(doc):
                out[k] = rows
        except Exception:
            pass
    else:
        try:
            out[filename] = _csv_rows(data)
        except Exception:
            pass
    return out
