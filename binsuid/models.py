from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VectorType(str, Enum):
    SUID = "suid"
    SGID = "sgid"
    CAPABILITIES = "capabilities"
    PROCESS_CAPABILITIES = "process-capabilities"
    SUDO = "sudo"
    PATH_HIJACK = "path-hijack"
    PERSISTENCE = "persistence"
    GROUP = "group"


# Functions most relevant for privilege escalation (ordered by priority).
PRIVESC_FUNCTIONS = (
    "privilege-escalation",
    "shell",
    "command",
    "inherit",
    "library-load",
    "file-write",
    "file-read",
    "sudo",
)


@dataclass
class Technique:
    executable: str
    function: str
    code: str
    context: str
    description: str = ""
    capability_requirements: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    gtfobins_url: str = ""

    @property
    def label(self) -> str:
        source = self.metadata.get("source", "gtfobins")
        if source == "gtfobins":
            return f"{self.function} ({self.context})"
        return f"{self.function} ({self.context}/{source})"


@dataclass
class Finding:
    vector: VectorType
    path: str
    executable: str
    details: str = ""
    capabilities: list[str] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    severity: str = "high"
    notes: list[str] = field(default_factory=list)
    best_technique: Technique | None = None
    priority_score: int = 0

    @property
    def is_exploitable(self) -> bool:
        return self.best_technique is not None

    @property
    def has_techniques(self) -> bool:
        return bool(self.techniques)

    @property
    def summary(self) -> str:
        if self.vector == VectorType.CAPABILITIES:
            caps = ", ".join(self.capabilities) if self.capabilities else self.details
            return f"{self.path} [{caps}]"
        if self.vector == VectorType.PROCESS_CAPABILITIES:
            return self.path
        if self.vector == VectorType.SUDO:
            return f"{self.path} ({self.details})"
        if self.vector == VectorType.PATH_HIJACK:
            return f"{self.path} ({self.details})"
        if self.vector == VectorType.PERSISTENCE:
            return f"{self.path} ({self.details})"
        if self.vector == VectorType.GROUP:
            return f"{self.executable} ({self.details})"
        return self.path


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_paths: list[str] = field(default_factory=list)

    @property
    def exploitable(self) -> list[Finding]:
        return [f for f in self.findings if f.is_exploitable]

    @property
    def informational(self) -> list[Finding]:
        return [f for f in self.findings if not f.is_exploitable]
