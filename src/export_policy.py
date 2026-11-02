"""Export policy for the lab.

This module does NOT use DataFog. It only receives the entity types that
DataFog detected and decides whether an export is allowed or blocked.

Keeping detection (DataFog) separate from the decision (the application) lets
the organization change its policy without touching the detection engine.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

# DataFog entity types that this fictional organization treats as protected
# personal data. Any of them blocks an unprotected export.
PROTECTED_ENTITIES: tuple[str, ...] = ("EMAIL", "PHONE")

ENTITY_LABELS = {
    "EMAIL": "email addresses",
    "PHONE": "phone numbers",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    counts: dict[str, int] = field(default_factory=dict)


def evaluate_export(detected_types: Iterable[str]) -> Decision:
    """Decide whether an export is allowed based on the detected entity types."""
    counts = Counter(t for t in detected_types if t in PROTECTED_ENTITIES)
    if not counts:
        return Decision(True, "No protected personal data was detected.")

    summary = ", ".join(f"{n} {ENTITY_LABELS.get(t, t)}" for t, n in sorted(counts.items()))
    return Decision(False, f"The file contains protected personal data ({summary}).", dict(counts))
