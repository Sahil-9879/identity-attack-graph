"""ZIP-of-CSVs importer.

Expected ZIP layout (flat or one directory deep):

    environment.zip
    ├── identities.csv    id,name,type,criticality
    ├── groups.csv        id,name,type,criticality
    ├── memberships.csv   identity_id,group_id
    ├── machines.csv      id,name,type,criticality
    ├── services.csv      id,name,criticality,runs_on_id,runs_as_id
    ├── credentials.csv   id,name,criticality,owner_id
    ├── permissions.csv   source_id,target_id,relationship_type,privilege_level
    └── assets.csv        id,name,type,criticality

Required: identities.csv, machines.csv, assets.csv.
All others are optional.

Guards:
  * max compressed upload      20 MB
  * max total uncompressed     200 MB  (zip bomb guard)
  * rejects entries whose path contains ".." or starts with "/"
  * decodes as UTF-8 with optional BOM
  * does not execute anything — CSV is parsed as data only
"""
from __future__ import annotations

import csv
import io
import zipfile
from typing import Any, Dict, List

from .base import DataSource, ImportError, ImportResult

MAX_UPLOAD = 20 * 1024 * 1024
MAX_UNCOMPRESSED = 200 * 1024 * 1024

REQUIRED = {"identities.csv", "machines.csv", "assets.csv"}


def _read_csv(data: bytes) -> List[Dict[str, str]]:
    text = data.decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(text)))


class ZipCsvDataSource(DataSource):
    name = "zip_csv"
    label = "CSV bundle (ZIP)"

    def load(self, data: bytes, filename: str = "environment.zip", **_) -> ImportResult:
        result = ImportResult(source_label=f"Imported: {filename}")

        if len(data) > MAX_UPLOAD:
            result.errors.append(ImportError(
                "upload_too_large",
                f"ZIP exceeds {MAX_UPLOAD // 1024 // 1024} MB"))
            return result

        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception as e:
            result.errors.append(ImportError("zip_invalid", "Not a valid ZIP",
                                             detail=str(e)))
            return result

        # Safety: path traversal + zip bomb
        total = 0
        names: set = set()
        for info in zf.infolist():
            if ".." in info.filename or info.filename.startswith("/"):
                result.errors.append(ImportError(
                    "zip_path_traversal",
                    f"Refusing entry with suspicious path: {info.filename}"))
                return result
            total += info.file_size
            if total > MAX_UNCOMPRESSED:
                result.errors.append(ImportError(
                    "zip_too_large",
                    f"Uncompressed size exceeds {MAX_UNCOMPRESSED // 1024 // 1024} MB"))
                return result
            names.add(info.filename.split("/")[-1].lower())

        missing = REQUIRED - names
        if missing:
            result.errors.append(ImportError(
                "zip_missing_files",
                f"ZIP missing required file(s): {', '.join(sorted(missing))}"))
            return result

        # Parse every CSV we care about
        tables: Dict[str, List[Dict[str, str]]] = {}
        for info in zf.infolist():
            base = info.filename.split("/")[-1].lower()
            if base.endswith(".csv"):
                try:
                    tables[base] = _read_csv(zf.read(info))
                except Exception as e:
                    result.errors.append(ImportError(
                        "csv_parse_failed",
                        f"Failed to parse {base}", detail=str(e)))
                    return result

        doc = self._to_document(tables, filename)
        from .json_import import normalise_document
        normalised = normalise_document(doc)
        result.errors.extend(normalised.errors)
        result.warnings.extend(normalised.warnings)
        result.stats = normalised.stats
        if normalised.errors:
            return result

        from ..models import Environment
        result.environment = Environment(
            name=doc["metadata"]["name"],
            description=doc["metadata"].get("description", ""),
            nodes=normalised.nodes,
            edges=normalised.edges,
        )
        return result

    # ------------------------------------------------------------------
    def _to_document(self, tables: Dict[str, List[Dict[str, str]]],
                     filename: str) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        def add(nid: str, name: str, type_: str, crit) -> None:
            try:
                c = int(crit) if crit not in (None, "") else 3
            except (TypeError, ValueError):
                c = 3
            nodes.append({"id": nid, "name": name or nid,
                          "type": type_, "criticality": c})

        def row_type(row: Dict[str, str], default: str) -> str:
            return (row.get("type") or default).upper()

        for row in tables.get("identities.csv", []):
            if row.get("id"):
                add(row["id"], row.get("name") or row["id"],
                    row_type(row, "IDENTITY"), row.get("criticality"))

        for row in tables.get("groups.csv", []):
            if row.get("id"):
                add(row["id"], row.get("name") or row["id"],
                    row_type(row, "GROUP"), row.get("criticality"))

        for row in tables.get("machines.csv", []):
            if row.get("id"):
                add(row["id"], row.get("name") or row["id"],
                    row_type(row, "MACHINE"), row.get("criticality"))

        for row in tables.get("services.csv", []):
            if row.get("id"):
                add(row["id"], row.get("name") or row["id"],
                    row_type(row, "SERVICE"), row.get("criticality"))
                if row.get("runs_on_id"):
                    edges.append({"source": row["id"],
                                  "target": row["runs_on_id"],
                                  "relationship_type": "RUNS_ON"})
                if row.get("runs_as_id"):
                    edges.append({"source": row["id"],
                                  "target": row["runs_as_id"],
                                  "relationship_type": "RUNS_AS"})

        for row in tables.get("credentials.csv", []):
            if row.get("id"):
                add(row["id"], row.get("name") or row["id"],
                    row_type(row, "CREDENTIAL"), row.get("criticality"))
                if row.get("owner_id"):
                    edges.append({"source": row["owner_id"],
                                  "target": row["id"],
                                  "relationship_type": "HAS_CREDENTIAL"})

        for row in tables.get("assets.csv", []):
            if row.get("id"):
                add(row["id"], row.get("name") or row["id"],
                    row_type(row, "ASSET"), row.get("criticality"))

        for row in tables.get("memberships.csv", []):
            if row.get("identity_id") and row.get("group_id"):
                edges.append({"source": row["identity_id"],
                              "target": row["group_id"],
                              "relationship_type": "MEMBER_OF"})

        for row in tables.get("permissions.csv", []):
            if (row.get("source_id") and row.get("target_id")
                    and row.get("relationship_type")):
                edges.append({
                    "source": row["source_id"],
                    "target": row["target_id"],
                    "relationship_type": row["relationship_type"],
                    "privilege_level": row.get("privilege_level") or None,
                })

        return {
            "metadata": {
                "name": filename.rsplit(".", 1)[0],
                "version": "1.0",
                "source": "csv_zip_import",
            },
            "nodes": nodes,
            "edges": edges,
        }
