from __future__ import annotations

import os
import re

from binsuid.models import Finding, VectorType
from binsuid.utils import run_command, which

SUDO_LINE_RE = re.compile(
    r"^\s*\((?P<runas>[^)]+)\)\s+(?P<nopass>NOPASSWD:\s*)?(?P<cmds>.+)$"
)
SUDO_USER_RE = re.compile(r"^User\s+(?P<user>\S+)\s+may run the following commands", re.I)

_SHELL_ESCAPE_BINARIES = frozenset({
    "vi", "vim", "view", "less", "more", "nano", "ed", "awk", "gawk", "mawk",
    "find", "python", "python2", "python3", "perl", "ruby", "lua", "nmap",
    "tar", "rsync", "git", "docker", "mysql", "sqlite3", "gdb", "socat",
})


def scan_sudo(*, non_interactive: bool = True) -> tuple[list[Finding], list[str]]:
    errors: list[str] = []
    if not which("sudo"):
        return [], ["sudo not found"]

    cmd = ["sudo", "-n", "-l"] if non_interactive else ["sudo", "-l"]
    code, stdout, stderr = run_command(cmd, timeout=30)

    if code != 0:
        msg = (stderr or stdout).strip()
        if non_interactive:
            errors.append(
                msg or "passwordless sudo -l failed; rerun with --sudo-interactive"
            )
        else:
            errors.append(msg or "sudo -l failed")
        return [], errors

    findings = _parse_sudo_l(stdout)
    return findings, errors


def _parse_sudo_l(output: str) -> list[Finding]:
    findings: list[Finding] = []
    current_user = ""
    for line in output.splitlines():
        user_match = SUDO_USER_RE.match(line.strip())
        if user_match:
            current_user = user_match.group("user")
            continue

        match = SUDO_LINE_RE.match(line)
        if not match:
            continue

        runas = match.group("runas").strip()
        nopass = bool(match.group("nopass"))
        cmds_raw = match.group("cmds").strip()
        setenv = False
        if cmds_raw.startswith("SETENV:"):
            setenv = True
            cmds_raw = cmds_raw[len("SETENV:") :].strip()
        if "SETENV:" in cmds_raw:
            setenv = True
            cmds_raw = cmds_raw.replace("SETENV:", "").strip()
        if cmds_raw.startswith("PASSWD:"):
            cmds_raw = cmds_raw[len("PASSWD:") :].strip()
            nopass = False
        if cmds_raw.startswith("NOPASSWD:"):
            cmds_raw = cmds_raw[len("NOPASSWD:") :].strip()
            nopass = True
        cmds = [c.strip() for c in cmds_raw.split(",")]

        for cmd in cmds:
            if cmd in {"ALL", "PASSWD: ALL"}:
                findings.append(
                    Finding(
                        vector=VectorType.SUDO,
                        path="ALL",
                        executable="ALL",
                        details=f"runas={runas}; nopasswd={nopass}; setenv={setenv}",
                        severity="critical",
                    )
                )
                continue

            binary = cmd.split()[0] if cmd else cmd
            if binary.startswith("("):
                continue
            if binary.startswith("/"):
                path = binary
            elif binary == "sudoedit":
                path = "/usr/bin/sudoedit"
            else:
                resolved = which(binary) if os.name == "posix" else None
                path = resolved or f"/usr/bin/{binary}"

            severity = "medium"
            if nopass and setenv:
                severity = "critical"
            elif nopass:
                severity = "high"

            finding = Finding(
                vector=VectorType.SUDO,
                path=path,
                executable=path.rsplit("/", 1)[-1],
                details=(
                    f"cmd={cmd}; runas={runas}; nopasswd={nopass}; "
                    f"setenv={setenv}; user={current_user}"
                ),
                severity=severity,
            )
            _annotate_sudo_finding(finding, cmd=cmd, runas=runas, nopass=nopass)
            findings.append(finding)
    return findings


def _annotate_sudo_finding(
    finding: Finding, *, cmd: str, runas: str, nopass: bool
) -> None:
    """Add pentester notes for wildcard, runas, and fixed-arg abuse patterns."""
    runas_upper = runas.strip().upper()
    if runas_upper == "ALL" or runas_upper.startswith("ALL,"):
        finding.notes.append(
            "Runas (ALL) — may execute as any target user (root if combined with user specs)"
        )
        if nopass and finding.severity != "critical":
            finding.severity = "high"

    if "*" in cmd:
        finding.notes.append(
            "Wildcard (*) in sudo command — glob expansion / alternate paths may bypass restrictions"
        )
        if nopass and finding.severity == "medium":
            finding.severity = "high"

    binary = cmd.split()[0] if cmd else ""
    bin_name = binary.rsplit("/", 1)[-1].lower()
    args = cmd[len(binary) :].strip() if binary else ""

    if bin_name == "sudoedit":
        finding.notes.append(
            "sudoedit — editor hijack via SUDO_EDITOR/VISUAL or symlink race"
        )
        if nopass and finding.severity != "critical":
            finding.severity = "high"

    if bin_name in _SHELL_ESCAPE_BINARIES and args and nopass:
        finding.notes.append(
            f"Fixed-args {bin_name} rule — shell escape often works despite argument lock"
        )

    if re.search(r"[;&|`$()]", cmd):
        finding.notes.append(
            "Shell metacharacters in sudo command — verify argument injection / quoting bypass"
        )

    sensitive_targets = ("/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/")
    if any(target in cmd for target in sensitive_targets) and nopass:
        finding.notes.append(
            "NOPASSWD access to sensitive path — read/write as target user without password"
        )
