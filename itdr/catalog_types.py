"""
itdr.catalog_types
==================
The shared DetectionDoc record.

It lives apart from `itdr.catalog` so that catalog modules can import
the type without importing each other. `python -m itdr.catalog` runs
catalog.py as __main__, so any module it imports that imports catalog
back gets a SECOND copy of the module and a circular import — splitting
the type out removes the cycle entirely rather than papering over it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionDoc:
    checker_cls: type
    name: str
    mitre_id: str
    mitre_name: str
    tactic: str
    severity: str
    hypothesis: str
    telemetry: list[str]
    logic: str
    false_positives: list[str]
    tuning: list[str]
    references: list[str] = field(default_factory=list)
