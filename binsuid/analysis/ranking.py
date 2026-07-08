"""Rank and filter findings so priority targets stand out from system noise."""

from __future__ import annotations

from binsuid.models import Finding, VectorType
from binsuid.utils import is_abs_path

KNOWN_SYSTEM_SUID = frozenset({
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec", "/bin/mount", "/bin/umount", "/bin/su", "/bin/passwd",
    "/bin/chfn", "/bin/chsh", "/bin/gpasswd", "/bin/newgrp", "/bin/sudo",
})

SUSPICIOUS_PREFIXES = ("/usr/local/", "/opt/", "/tmp/", "/home/", "/srv/", "/dev/shm/")


def is_known_system_suid(path: str) -> bool:
    return path in KNOWN_SYSTEM_SUID or path.endswith("/sudo") and "/bin/sudo" in path


def is_custom_suid(path: str) -> bool:
    return is_abs_path(path) and not is_known_system_suid(path)


def score_finding(finding: Finding) -> int:
    score = 0

    if finding.is_exploitable:
        score += 1000

    if finding.vector == VectorType.SUID:
        if is_custom_suid(finding.path):
            score += 500
        elif is_known_system_suid(finding.path) or finding.details == "known-suid":
            score -= 800
        if any(finding.path.startswith(prefix) for prefix in SUSPICIOUS_PREFIXES):
            score += 250

    if finding.vector == VectorType.SGID:
        score += 450
        if any(finding.path.startswith(prefix) for prefix in SUSPICIOUS_PREFIXES):
            score += 200
        if finding.details == "known-sgid":
            score -= 300

    if finding.vector == VectorType.PATH_HIJACK:
        score += 350
        if finding.details == "user-writable":
            score += 150

    if finding.vector == VectorType.PERSISTENCE:
        score += 400
        if finding.severity == "high":
            score += 100

    if finding.vector == VectorType.GROUP:
        score += 300
        if finding.executable in {"docker", "lxd", "disk"}:
            score += 200

    if finding.vector == VectorType.CAPABILITIES:
        score += 600
        if any("writable" in note.lower() for note in finding.notes):
            score += 200

    if finding.vector == VectorType.PROCESS_CAPABILITIES:
        score += 300
        if any(c in finding.capabilities for c in ("CAP_SETUID", "CAP_SETFCAP", "CAP_SYS_ADMIN")):
            score += 250

    if finding.vector == VectorType.SUDO and finding.is_exploitable:
        score += 900

    if finding.vector == VectorType.SUDO and "setenv=True" in finding.details:
        score += 350
        if "SETENV" not in " ".join(finding.notes):
            finding.notes.append(
                "SETENV sudo rule — LD_PRELOAD / PYTHONSTARTUP / PERL5OPT abuse likely"
            )

    if finding.severity == "critical":
        score += 200
    elif finding.severity == "high":
        score += 100

    if any("PATH hijack" in (tech.description or "") for tech in finding.techniques):
        score += 400
        if not any("PATH hijack candidate" in note for note in finding.notes):
            for tech in finding.techniques:
                if "PATH hijack" in (tech.description or ""):
                    cmd = tech.description.split("(")[-1].rstrip(")")
                    finding.notes.append(f"PATH hijack candidate ({cmd})")
                    break

    return score


def partition_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    for finding in findings:
        finding.priority_score = score_finding(finding)

    priority = [f for f in findings if f.priority_score > 0]
    noise = [f for f in findings if f.priority_score <= 0]

    priority.sort(key=lambda f: (-f.priority_score, f.path))
    noise.sort(key=lambda f: f.path)
    return priority, noise


def best_candidate(findings: list[Finding]) -> Finding | None:
    priority, _ = partition_findings(findings)
    if not priority:
        return None
    auto = [f for f in priority if f.is_exploitable]
    if auto:
        return auto[0]
    return priority[0]


def ranked_exploitable(findings: list[Finding]) -> list[Finding]:
    """Exploitable findings ordered by priority (highest first)."""
    priority, _ = partition_findings(findings)
    return [f for f in priority if f.is_exploitable]
