from __future__ import annotations

import os
import stat
from typing import Iterable

from binsuid.models import Finding, VectorType
from binsuid.utils import run_command

# Paths scanned in quick mode (covers typical lab/CTF targets).
QUICK_SEARCH_PATHS = (
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/opt",
    "/snap/bin",
)

# Well-known SUID binaries that are rarely exploitable via GTFOBins.
SUID_IGNORE = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/bin/mount",
    "/bin/umount",
    "/bin/su",
}


def _is_suid(path: str) -> bool:
    try:
        mode = os.stat(path, follow_symlinks=False).st_mode
        return bool(mode & stat.S_ISUID)
    except OSError:
        return False


def _walk_suid(root: str) -> list[str]:
    found: list[str] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in {".git", "proc", "sys"}]
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if _is_suid(path):
                    found.append(path)
    except OSError:
        pass
    return found


def scan_suid(*, quick: bool = False, extra_paths: Iterable[str] | None = None) -> list[Finding]:
    paths: list[str] = []
    errors: list[str] = []

    if quick:
        for root in QUICK_SEARCH_PATHS:
            if os.path.isdir(root):
                paths.extend(_walk_suid(root))
    else:
        code, stdout, stderr = run_command(
            ["find", "/", "-path", "/proc", "-prune", "-o", "-path", "/sys", "-prune", "-o",
             "-path", "/dev", "-prune", "-o", "-perm", "-4000", "-type", "f", "-print"],
            timeout=300,
        )
        if code == 0 and stdout.strip():
            paths = [line.strip() for line in stdout.splitlines() if line.strip()]
        else:
            errors.append(stderr.strip() or "find unavailable; falling back to common paths")
            for root in QUICK_SEARCH_PATHS:
                if os.path.isdir(root):
                    paths.extend(_walk_suid(root))

    if extra_paths:
        for path in extra_paths:
            if os.path.isfile(path) and _is_suid(path):
                paths.append(path)

    findings: list[Finding] = []
    seen: set[str] = set()
    for path in sorted(set(paths)):
        if path in seen:
            continue
        seen.add(path)
        findings.append(
            Finding(
                vector=VectorType.SUID,
                path=path,
                executable=os.path.basename(path),
                details="setuid" if path not in SUID_IGNORE else "known-suid",
                severity="medium" if path in SUID_IGNORE else "high",
            )
        )
    return findings
