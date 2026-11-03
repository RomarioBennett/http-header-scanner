"""Data models: findings, severities, and the overall scan result."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(str, Enum):
    PASS = "pass"  # correctly configured
    WARN = "warn"  # present but weak / partially configured
    FAIL = "fail"  # missing or actively broken
    INFO = "info"  # informational, not scored


# How many points each severity is worth. PASS earns all of them,
# WARN earns half, FAIL earns none, INFO is excluded from the total.
POINTS: dict[Severity, int] = {
    Severity.HIGH: 30,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
}

GRADES = "ABCDF"


@dataclass(frozen=True)
class Finding:
    """The outcome of a single check."""

    id: str
    title: str
    severity: Severity
    status: Status
    detail: str
    value: str | None = None
    recommendation: str | None = None

    @property
    def possible(self) -> float:
        return 0 if self.status is Status.INFO else POINTS[self.severity]

    @property
    def earned(self) -> float:
        if self.status is Status.PASS:
            return self.possible
        if self.status is Status.WARN:
            return self.possible / 2
        return 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "detail": self.detail,
            "value": self.value,
            "recommendation": self.recommendation,
        }


def grade_for(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return letter
    return "F"


@dataclass(frozen=True)
class ScanResult:
    """Everything we learned from scanning one URL."""

    url: str
    final_url: str
    status_code: int
    redirects: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def score(self) -> int:
        possible = sum(f.possible for f in self.findings)
        if possible == 0:
            return 0
        earned = sum(f.earned for f in self.findings)
        # Round half up (Python's round() uses banker's rounding).
        return int(earned / possible * 100 + 0.5)

    @property
    def grade(self) -> str:
        return grade_for(self.score)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "redirects": self.redirects,
            "score": self.score,
            "grade": self.grade,
            "elapsed_ms": self.elapsed_ms,
            "findings": [f.to_dict() for f in self.findings],
        }
