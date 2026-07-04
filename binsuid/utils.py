from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from typing import Iterable


ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_MAGENTA = "\033[35m"
ANSI_CYAN = "\033[36m"


def color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def disable_color() -> None:
    os.environ["NO_COLOR"] = "1"


def paint(text: str, *codes: str) -> str:
    if not color_enabled() or not codes:
        return text
    return "".join(codes) + text + ANSI_RESET


def which(binary: str) -> str | None:
    return shutil.which(binary)


def is_abs_path(path: str) -> bool:
    """True for Linux absolute paths and native absolute paths (tests on Windows)."""
    return path.startswith("/") or os.path.isabs(path)


def run_command(
    cmd: list[str] | str,
    *,
    shell: bool = False,
    timeout: int | None = 120,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    except FileNotFoundError:
        return 127, "", "command not found"
    except OSError as exc:
        return 1, "", str(exc)


def normalize_executable_name(path: str) -> str:
    name = os.path.basename(path)
    if "." in name and not name.startswith("."):
        base, ext = name.rsplit(".", 1)
        if ext.isdigit() or ext in {"so", "bin"}:
            name = base
    return name


def executable_aliases(path: str) -> list[str]:
    """Generate candidate GTFOBins keys for a filesystem path."""
    name = os.path.basename(path)
    candidates: list[str] = [name]

    normalized = normalize_executable_name(path)
    if normalized not in candidates:
        candidates.append(normalized)

    # python3.11 -> python3, python
    match = re.match(r"^([a-zA-Z][\w-]*?)(\d+(?:\.\d+)*)$", normalized)
    if match:
        base, version = match.groups()
        for variant in (f"{base}{version.split('.')[0]}", base):
            if variant not in candidates:
                candidates.append(variant)

    # vim.basic -> vim
    if "." in normalized:
        stem = normalized.split(".", 1)[0]
        if stem not in candidates:
            candidates.append(stem)

    # busybox symlinks often appear as /bin/ls etc.
    parent = os.path.basename(os.path.dirname(path))
    if parent == "bin" and normalized not in candidates:
        candidates.append(normalized)

    return candidates


def parse_capability_string(cap_value: str) -> list[str]:
    """Parse getcap output value into normalized CAP_* tokens."""
    caps: list[str] = []
    # Strip file capability flags: cap_setuid,cap_net_raw+ep -> individual caps
    cleaned = re.sub(r"\+[a-z]+$", "", cap_value.strip(), flags=re.IGNORECASE)
    for token in cleaned.replace(",", " ").split():
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            token = token.split("=", 1)[0]
        token = token.upper()
        if token.startswith("CAP_"):
            caps.append(token)
        elif token:
            caps.append(f"CAP_{token}")
    return caps


def parse_capability_flags(cap_value: str) -> str:
    """Return capability set flags from getcap value (e.g. +ep, +eip)."""
    match = re.search(r"(\+[a-z]+)$", cap_value.strip(), re.IGNORECASE)
    return match.group(1) if match else ""


# Paths called out in CyberSecPlayground Day 21 for capability audits.
SUSPICIOUS_PATH_PREFIXES = ("/opt/", "/tmp/", "/home/", "/var/tmp/", "/dev/shm/")


def explain_capability_flags(flags: str) -> str:
    """Human-readable meaning of getcap flag suffix (e.g. +ep)."""
    if not flags:
        return ""
    letters = flags.lstrip("+").lower()
    parts: list[str] = []
    mapping = {
        "e": "effective",
        "p": "permitted",
        "i": "inherited",
    }
    for letter in letters:
        parts.append(mapping.get(letter, letter))
    if parts == ["effective", "permitted"]:
        return "effective and permitted bits set (+ep)"
    return ", ".join(parts) + f" ({flags})"


def is_suspicious_capability_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in SUSPICIOUS_PATH_PREFIXES)


def is_writable_by_current_user(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def is_writable_by_unprivileged(path: str) -> bool:
    """True if group/other writable or current user can write."""
    try:
        mode = os.stat(path).st_mode
        if mode & (stat.S_IWOTH | stat.S_IWGRP):
            return True
        return os.access(path, os.W_OK)
    except OSError:
        return False


def bump_severity(severity: str) -> str:
    order = ("low", "medium", "high", "critical")
    if severity not in order:
        return "high"
    idx = min(len(order) - 1, order.index(severity) + 1)
    return order[idx]


def capability_matches(required: Iterable[str], present: Iterable[str]) -> bool:
    required_set = {c.upper() for c in required}
    present_set = {c.upper() for c in present}
    if not required_set:
        return True
    return required_set.issubset(present_set)


def get_shadow_gid() -> int | None:
    code, stdout, _ = run_command(["getent", "group", "shadow"])
    if code != 0 or not stdout.strip():
        return None
    parts = stdout.strip().split(":")
    if len(parts) >= 3 and parts[2].isdigit():
        return int(parts[2])
    return None


def current_ids() -> tuple[int | None, int | None, int | None, int | None]:
    if hasattr(os, "geteuid"):
        uid = os.geteuid()
        gid = os.getegid()
        return uid, gid, os.getuid(), os.getgid()
    return None, None, None, None
