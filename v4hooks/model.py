"""Finding record shared by detectors, scanner, benchmark and report writer."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class HookFinding:
    detector: str  # e.g. "V4H-01"
    title: str
    severity: str
    contract: str  # the hook contract analysed (most-derived)
    function: str  # callback / function the evidence is anchored on
    file: str
    line_start: int
    line_end: int
    message: str  # deterministic, detector-written explanation
    evidence: dict[str, Any] = field(default_factory=dict)
    snippet: str = ""
    # "confirmed": the flagged code has a consequence the detector can see (moves value,
    # calls out, writes state another check reads, bricks a pool). "pattern": the shape
    # is present but the consequence isn't visible statically.
    confidence: str = "pattern"

    @property
    def fingerprint(self) -> str:
        key = f"{self.detector}|{self.contract}|{self.function}|{self.file}|{self.line_start}"
        if self.evidence.get("callback"):  # several findings can share one anchor (V4H-03)
            key += f"|{self.evidence['callback']}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def sort_key(self) -> tuple:
        return (self.file, self.line_start, self.detector, self.contract, self.function)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HookFinding:
        d = {k: v for k, v in d.items() if k != "fingerprint"}
        return cls(**d)
