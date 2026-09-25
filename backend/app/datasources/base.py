"""The contract every data source implements.

An importer's job is simple:
  raw bytes  ->  ImportResult { Environment, warnings, errors, stats }

The graph engine only ever sees the Environment. It has no idea whether
the data came from JSON, a ZIP, BloodHound, or a future AD connector.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..models import Environment


@dataclass
class ImportWarning:
    code: str
    message: str
    detail: str = ""


@dataclass
class ImportError:
    code: str
    message: str
    detail: str = ""


@dataclass
class ImportStats:
    identities: int = 0
    groups: int = 0
    credentials: int = 0
    machines: int = 0
    services: int = 0
    permissions: int = 0
    assets: int = 0
    relationships: int = 0

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ImportResult:
    """Everything an importer produces. The API returns this verbatim."""

    environment: Environment | None = None
    stats: ImportStats = field(default_factory=ImportStats)
    warnings: List[ImportWarning] = field(default_factory=list)
    errors: List[ImportError] = field(default_factory=list)
    source_label: str = "unknown"

    @property
    def ok(self) -> bool:
        return self.environment is not None and not self.errors

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "source_label": self.source_label,
            "stats": self.stats.as_dict(),
            "warnings": [w.__dict__ for w in self.warnings],
            "errors": [e.__dict__ for e in self.errors],
            "environment": (
                self.environment.model_dump() if self.environment else None
            ),
        }


class DataSource:
    """Base class. Subclasses implement `load()`."""

    name: str = "base"
    label: str = "Base"

    def load(self, **kwargs) -> ImportResult:
        raise NotImplementedError
