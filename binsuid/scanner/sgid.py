from __future__ import annotations

import os
import stat
from typing import Iterable

from binsuid.models import Finding, VectorType
from binsuid.scanner.suid import QUICK_SEARCH_PATHS
from binsuid.utils import run_command

# Well-known SGID binaries rarely useful for direct privesc.
SGID_IGNORE = {
    "/usr/bin/ssh-agent",
    "/usr/bin/crontab",
    "/usr/bin/dotlockfile",
    "/usr/bin/mail",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/locate",
    "/usr/bin/expiry",
    "/usr/bin/chage",
    "/usr/bin/utmpdump",
    "/usr/bin/screen",
    "/usr/bin/wall",
}


def _is_sgid(path: str) -> bool:
    try:
        mode = os.stat(path, follow_symlinks=False).st_mode
        return bool(mode & stat.S_ISGID)
    except OSError:
        return False


def _walk_sgid(root: str) -> list[str]:
    found: list[str] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in {".git", "proc", "sys"}]
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if _is_sgid(path):
                    found.append(path)
    except OSError:
        pass
    return found


def scan_sgid(*, quick: bool = False, extra_paths: Iterable[str] | None = None) -> list[Finding]:
    paths: list[str] = []

    if quick:
        for root in QUICK_SEARCH_PATHS:
            if os.path.isdir(root):
                paths.extend(_walk_sgid(root))
    else:
        code, stdout, stderr = run_command(
            ["find", "/", "-path", "/proc", "-prune", "-o", "-path", "/sys", "-prune", "-o",
             "-path", "/dev", "-prune", "-o", "-perm", "-2000", "-type", "f", "-print"],
            timeout=300,
        )
        if code == 0 and stdout.strip():
            paths = [line.strip() for line in stdout.splitlines() if line.strip()]
        else:
            for root in QUICK_SEARCH_PATHS:
                if os.path.isdir(root):
                    paths.extend(_walk_sgid(root))

    if extra_paths:
        for path in extra_paths:
            if os.path.isfile(path) and _is_sgid(path):
                paths.append(path)

    findings: list[Finding] = []
    seen: set[str] = set()
    for path in sorted(set(paths)):
        if path in seen:
            continue
        seen.add(path)
        findings.append(
            Finding(
                vector=VectorType.SGID,
                path=path,
                executable=os.path.basename(path),
                details="setgid" if path not in SGID_IGNORE else "known-sgid",
                severity="medium" if path in SGID_IGNORE else "high",
            )
        )
    return findings
