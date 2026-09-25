"""Loads the bundled ACME Synthetic Enterprise.

The dataset is a JSON file, not Python code. It is explicitly labelled
as demo data and is only loaded when the caller asks for it.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import Environment
from .base import DataSource, ImportError, ImportResult, ImportStats

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"
DEMO_FILE = DEMO_DIR / "acme_enterprise.json"


class DemoDataSource(DataSource):
    name = "demo"
    label = "ACME Synthetic Enterprise (Demo)"

    def load(self, **kwargs) -> ImportResult:
        result = ImportResult(source_label="Demo Environment")
        if not DEMO_FILE.exists():
            result.errors.append(ImportError(
                code="demo_missing",
                message="Demo dataset file is missing",
                detail=str(DEMO_FILE),
            ))
            return result

        raw = json.loads(DEMO_FILE.read_text())

        # Reuse the JSON importer's normalisation logic
        from .json_import import normalise_document
        normalised = normalise_document(raw)
        result.errors.extend(normalised.errors)
        result.warnings.extend(normalised.warnings)
        if normalised.errors:
            return result

        env = Environment(
            name=raw["metadata"]["name"],
            description=raw["metadata"].get("description", ""),
            nodes=normalised.nodes,
            edges=normalised.edges,
        )
        result.environment = env
        result.stats = normalised.stats
        return result
