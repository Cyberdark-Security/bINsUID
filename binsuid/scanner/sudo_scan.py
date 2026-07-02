from __future__ import annotations

import re

from binsuid.models import Finding, VectorType
from binsuid.utils import run_command, which

SUDO_LINE_RE = re.compile(
    r"^\s*\((?P<runas>[^)]+)\)\s+(?P<nopass>NOPASSWD:\s*)?(?P<cmds>.+)$"
)
SUDO_USER_RE = re.compile(r"^User\s+(?P<user>\S+)\s+may run the following commands", re.I)


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
        if cmds_raw.startswith("PASSWD:"):
            cmds_raw = cmds_raw[len("PASSWD:") :].strip()
            nopass = False
        cmds = [c.strip() for c in cmds_raw.split(",")]

        for cmd in cmds:
            if cmd in {"ALL", "PASSWD: ALL"}:
                findings.append(
                    Finding(
                        vector=VectorType.SUDO,
                        path="ALL",
                        executable="ALL",
                        details=f"runas={runas}; nopasswd={nopass}",
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
                path = binary

            findings.append(
                Finding(
                    vector=VectorType.SUDO,
                    path=path,
                    executable=path.rsplit("/", 1)[-1],
                    details=f"cmd={cmd}; runas={runas}; nopasswd={nopass}; user={current_user}",
                    severity="high" if nopass else "medium",
                )
            )
    return findings
