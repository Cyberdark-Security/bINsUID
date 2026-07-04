from __future__ import annotations

import os

from binsuid.models import Finding, VectorType
from binsuid.utils import is_writable_by_unprivileged


def _path_entries() -> list[str]:
    raw = os.environ.get("PATH", "")
    entries: list[str] = []
    seen: set[str] = set()
    for part in raw.split(os.pathsep):
        part = part.strip()
        if not part or part in seen:
            continue
        seen.add(part)
        entries.append(part)
    return entries


def scan_writable_path(*, extra_paths: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    checked: set[str] = set()

    for directory in _path_entries() + (extra_paths or []):
        if directory in checked:
            continue
        checked.add(directory)

        if not os.path.isdir(directory):
            continue

        if not is_writable_by_unprivileged(directory):
            continue

        reason = "user-writable" if os.access(directory, os.W_OK) else "group/other-writable"
        findings.append(
            Finding(
                vector=VectorType.PATH_HIJACK,
                path=directory,
                executable=os.path.basename(directory.rstrip("/\\")) or directory,
                details=reason,
                severity="high" if reason == "user-writable" else "medium",
                notes=[
                    "Writable PATH entry — place a trojan before legitimate binaries "
                    "when a SUID/SGID binary invokes relative commands",
                ],
            )
        )
    return findings
