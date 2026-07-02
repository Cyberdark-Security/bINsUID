from __future__ import annotations

import os
import re

from binsuid.capabilities import INTERESTING_CAPS, severity_for_caps
from binsuid.models import Finding, VectorType
from binsuid.utils import (
    bump_severity,
    explain_capability_flags,
    is_suspicious_capability_path,
    is_writable_by_unprivileged,
    parse_capability_flags,
    parse_capability_string,
    run_command,
    which,
)

# Extra paths from CyberSecPlayground Day 21 hands-on (writable / non-standard).
SUSPICIOUS_SCAN_PATHS = ("/opt", "/tmp", "/home", "/var/tmp", "/dev/shm")


def scan_capabilities(
    *,
    quick: bool = False,
    audit_suspicious_paths: bool = True,
) -> tuple[list[Finding], list[str]]:
    errors: list[str] = []
    if not which("getcap"):
        return [], ["getcap not found (install libcap2-bin)"]

    if quick:
        roots = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
        if audit_suspicious_paths:
            roots.extend(SUSPICIOUS_SCAN_PATHS)
    else:
        roots = ["/"]

    findings: list[Finding] = []
    seen_paths: set[str] = set()
    cap_re = re.compile(r"^(.+?)\s+(.+)$")

    for root in roots:
        if not os.path.exists(root):
            continue
        code, stdout, stderr = run_command(["getcap", "-r", root], timeout=300 if root == "/" else 60)
        if code not in (0, 1):
            errors.append(stderr.strip() or f"getcap failed on {root}")
            continue

        for line in stdout.splitlines():
            finding = _parse_getcap_line(line, cap_re, quick=quick)
            if finding is None or finding.path in seen_paths:
                continue
            seen_paths.add(finding.path)
            findings.append(finding)

    return findings, errors


def _parse_getcap_line(line: str, cap_re: re.Pattern[str], *, quick: bool) -> Finding | None:
    line = line.strip()
    if not line:
        return None
    match = cap_re.match(line)
    if not match:
        return None

    path, cap_value = match.groups()
    caps = parse_capability_string(cap_value)
    flags = parse_capability_flags(cap_value)
    interesting = [c for c in caps if c in INTERESTING_CAPS]
    if not interesting and not quick:
        interesting = [c for c in caps if c.startswith("CAP_")]
    if not interesting:
        return None

    flag_help = explain_capability_flags(flags)
    details = cap_value
    if flag_help:
        details = f"{cap_value} — {flag_help}"

    notes: list[str] = []
    severity = severity_for_caps(interesting)

    if is_suspicious_capability_path(path):
        notes.append(
            "Located under a non-standard path (/opt, /tmp, /home…) — "
            "common misconfiguration (CyberSecPlayground Day 21)"
        )
        severity = bump_severity(severity)

    if is_writable_by_unprivileged(path):
        notes.append(
            "Binary is writable by current user, group, or others — "
            "replaceable capable binary risk"
        )
        severity = bump_severity(severity)

    if len(interesting) > 1:
        notes.append(
            "Multiple capabilities on one binary — versatile foothold "
            "(see combined-cap abuse patterns)"
        )

    return Finding(
        vector=VectorType.CAPABILITIES,
        path=path,
        executable=os.path.basename(path),
        details=details,
        capabilities=interesting,
        severity=severity,
        notes=notes,
    )
