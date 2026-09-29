"""Data model shared by all analyzers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name


VERDICTS = {
    Severity.INFO: "CLEAN",
    Severity.LOW: "LOW RISK",
    Severity.MEDIUM: "SUSPICIOUS",
    Severity.HIGH: "HIGH RISK",
}


@dataclass
class Finding:
    """A single observation about the file, ranked by severity."""

    severity: Severity
    category: str
    title: str
    detail: str = ""
    attack: str = ""  # optional MITRE ATT&CK technique ID

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class Artifact:
    """Something extracted from the file: macro source, a script, an embedded file."""

    kind: str  # vba_macro | xlm_macro | javascript | embedded_file | ole_object
    name: str
    size: int
    sha256: str
    content: str | None = None  # text content for code artifacts (macros, scripts)
    saved_to: str | None = None
    notes: str = ""

    def to_dict(self, include_content: bool = True) -> dict:
        d = asdict(self)
        if not include_content:
            d.pop("content")
        return d


@dataclass
class Report:
    path: str
    file_type: str
    size: int
    hashes: dict[str, str]
    entropy: float
    metadata: dict[str, str] = field(default_factory=dict)
    keywords: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(
        self,
        severity: Severity,
        category: str,
        title: str,
        detail: str = "",
        attack: str = "",
    ) -> None:
        self.findings.append(Finding(severity, category, title, detail, attack))

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def verdict(self) -> str:
        return VERDICTS[self.max_severity]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "file_type": self.file_type,
            "size": self.size,
            "hashes": self.hashes,
            "entropy": round(self.entropy, 3),
            "verdict": self.verdict,
            "max_severity": self.max_severity.name,
            "metadata": self.metadata,
            "keywords": self.keywords,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "errors": self.errors,
        }
