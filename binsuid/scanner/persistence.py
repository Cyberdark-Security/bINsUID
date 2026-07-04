from __future__ import annotations

import os
import re
from typing import Iterable

from binsuid.models import Finding, VectorType
from binsuid.utils import current_ids, is_writable_by_current_user, is_writable_by_unprivileged, run_command

CRON_DIRS = (
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)
CRON_FILES = ("/etc/crontab",)
SPOOL_DIRS = ("/var/spool/cron/crontabs", "/var/spool/cron")

# Absolute paths referenced in cron lines (skip @keywords and env vars).
_SCRIPT_RE = re.compile(r"(?<![\w./])(/(?:[\w.-]+/)+[\w.-]+)")


def _readable(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.access(path, os.R_OK)
    except OSError:
        return False


def _collect_cron_sources() -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []

    for cron_file in CRON_FILES:
        if _readable(cron_file):
            try:
                with open(cron_file, encoding="utf-8", errors="replace") as handle:
                    sources.append((cron_file, handle.read()))
            except OSError:
                pass

    for cron_dir in CRON_DIRS:
        if not os.path.isdir(cron_dir):
            continue
        try:
            for name in sorted(os.listdir(cron_dir)):
                path = os.path.join(cron_dir, name)
                if not _readable(path):
                    continue
                with open(path, encoding="utf-8", errors="replace") as handle:
                    sources.append((path, handle.read()))
        except OSError:
            continue

    for spool in SPOOL_DIRS:
        if not os.path.isdir(spool):
            continue
        try:
            for name in sorted(os.listdir(spool)):
                path = os.path.join(spool, name)
                if not _readable(path):
                    continue
                with open(path, encoding="utf-8", errors="replace") as handle:
                    sources.append((path, handle.read()))
        except OSError:
            continue

    code, stdout, _ = run_command(["crontab", "-l"], timeout=10)
    if code == 0 and stdout.strip():
        sources.append(("crontab -l", stdout))

    return sources


def _extract_script_paths(content: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@"):
            continue
        for match in _SCRIPT_RE.finditer(stripped):
            path = match.group(1)
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _script_finding(
    script_path: str,
    *,
    source: str,
    uid: int,
) -> Finding | None:
    if not os.path.exists(script_path):
        return None

    try:
        st = os.stat(script_path, follow_symlinks=False)
    except OSError:
        return None

    owned_by_user = st.st_uid == uid if uid is not None else is_writable_by_current_user(script_path)
    writable = is_writable_by_unprivileged(script_path)
    if not owned_by_user and not writable:
        return None

    if owned_by_user and writable:
        details = "owned+writable"
        severity = "high"
    elif owned_by_user:
        details = "owned-by-user"
        severity = "medium"
    else:
        details = "world/group-writable"
        severity = "high"

    notes = [
        f"Referenced from {source} — edit or replace to run code as cron job owner",
    ]
    if owned_by_user:
        notes.append("Script owned by current user — direct modification possible")
    if writable:
        notes.append("Script is writable — inject commands before next cron run")

    return Finding(
        vector=VectorType.PERSISTENCE,
        path=script_path,
        executable=os.path.basename(script_path),
        details=f"{details}; source={source}",
        severity=severity,
        notes=notes,
    )


def scan_persistence(*, extra_scripts: Iterable[str] | None = None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    uid, _, _, _ = current_ids()
    seen: set[str] = set()

    for source, content in _collect_cron_sources():
        for script_path in _extract_script_paths(content):
            if script_path in seen:
                continue
            finding = _script_finding(script_path, source=source, uid=uid)
            if finding:
                seen.add(script_path)
                findings.append(finding)

    if extra_scripts:
        for script_path in extra_scripts:
            if script_path in seen:
                continue
            finding = _script_finding(script_path, source="manual", uid=uid)
            if finding:
                seen.add(script_path)
                findings.append(finding)

    if not _collect_cron_sources() and not extra_scripts:
        errors.append("no cron sources readable")

    return findings, errors
