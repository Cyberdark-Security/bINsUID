from __future__ import annotations

from binsuid.models import Finding, VectorType
from binsuid.utils import run_command

# Privileged groups and suggested manual techniques for pentesters.
GROUP_HINTS: dict[str, tuple[str, str]] = {
    "docker": (
        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "Docker group — mount host root via container",
    ),
    "lxd": (
        "lxc init ubuntu:22.04 priv -c security.privileged=true && "
        "lxc config device add priv hostdisk disk source=/ path=/mnt/root recursive=true",
        "LXD group — privileged container with host mount",
    ),
    "disk": (
        "debugfs /dev/sda1",
        "Disk group — direct block device / filesystem access",
    ),
    "adm": (
        "grep -i password /var/log/auth.log /var/log/syslog",
        "Adm group — read authentication and system logs",
    ),
    "sudo": (
        "sudo -l",
        "Sudo/wheel group — enumerate passwordless sudo rules",
    ),
    "wheel": (
        "su -",
        "Wheel group — may switch to root if su is permitted",
    ),
}


def _current_groups() -> list[str]:
    code, stdout, _ = run_command(["id", "-Gn"], timeout=5)
    if code == 0 and stdout.strip():
        return [g.strip().lower() for g in stdout.split() if g.strip()]

    try:
        import os

        names: list[str] = []
        for gid in os.getgroups():
            code, out, _ = run_command(["getent", "group", str(gid)], timeout=5)
            if code == 0 and out.strip():
                name = out.strip().split(":")[0]
                names.append(name.lower())
        return names
    except (AttributeError, OSError):
        return []


def scan_groups(*, extra_groups: list[str] | None = None) -> list[Finding]:
    memberships = {g.lower() for g in _current_groups()}
    if extra_groups:
        memberships.update(g.lower() for g in extra_groups)

    findings: list[Finding] = []
    for group, (technique, summary) in GROUP_HINTS.items():
        if group not in memberships:
            continue
        findings.append(
            Finding(
                vector=VectorType.GROUP,
                path=technique,
                executable=group,
                details=summary,
                severity="high" if group in {"docker", "lxd", "disk"} else "medium",
                notes=[f"Suggested: {technique}"],
            )
        )
    return findings
