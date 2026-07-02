from __future__ import annotations

import os
import re

from binsuid.capabilities import INTERESTING_CAPS, severity_for_caps
from binsuid.models import Finding, Technique, VectorType
from binsuid.utils import parse_capability_string, run_command, which

CSP_LESSON_URL = (
    "https://github.com/cybersecplayground/30-Day-Linux-for-Hackers/blob/main/"
    "21_Linux_Capabilities_and_Exploitation.md"
)

CAP_LINE_RE = re.compile(r"^Cap([A-Za-z]+):\s+([0-9a-f]+)$", re.MULTILINE)


def scan_process_capabilities() -> tuple[list[Finding], list[str]]:
    """Enumerate running processes with non-zero effective capabilities."""
    errors: list[str] = []
    proc_root = "/proc"
    if not os.path.isdir(proc_root):
        return [], ["/proc not available (Linux only)"]

    has_capsh = which("capsh") is not None
    if not has_capsh:
        errors.append("capsh not found — process capability names will be limited")

    findings: list[Finding] = []
    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        pid = entry
        status_path = os.path.join(proc_root, pid, "status")
        if not os.path.isfile(status_path):
            continue

        try:
            with open(status_path, encoding="utf-8", errors="replace") as handle:
                status = handle.read()
        except OSError:
            continue

        name_match = re.search(r"^Name:\s+(\S+)", status, re.MULTILINE)
        cap_eff = None
        for match in CAP_LINE_RE.finditer(status):
            if match.group(1) == "Eff":
                cap_eff = match.group(2)
                break
        if not cap_eff or cap_eff == "0000000000000000":
            continue

        proc_name = name_match.group(1) if name_match else "unknown"
        exe_path = _resolve_proc_exe(pid)
        decoded = _decode_cap_mask(cap_eff) if has_capsh else cap_eff
        caps = [c.upper() for c in parse_capability_string(decoded)]
        interesting = [c for c in caps if c in INTERESTING_CAPS]
        if not interesting:
            continue

        label = f"pid {pid} ({proc_name})"
        if exe_path:
            label = f"pid {pid} ({proc_name}) -> {exe_path}"

        findings.append(
            Finding(
                vector=VectorType.PROCESS_CAPABILITIES,
                path=label,
                executable=proc_name,
                details=f"CapEff={cap_eff}; {decoded}",
                capabilities=interesting,
                severity=severity_for_caps(interesting),
                notes=[
                    "Live process capabilities — inspect with: "
                    f"grep Cap /proc/{pid}/status",
                    "See CyberSecPlayground Day 21 § Viewing Process Capabilities",
                ],
                techniques=[
                    Technique(
                        executable=proc_name,
                        function="manual-review",
                        code=(
                            f"getpcaps {pid}\n"
                            f"grep Cap /proc/{pid}/status\n"
                            f"capsh --decode={cap_eff}"
                        ),
                        context=VectorType.PROCESS_CAPABILITIES.value,
                        description="Audit effective process capabilities before exploitation",
                        capability_requirements=interesting,
                        metadata={"source": "cybersecplayground"},
                        gtfobins_url=CSP_LESSON_URL,
                    )
                ],
            )
        )

    return findings, errors


def _resolve_proc_exe(pid: str) -> str | None:
    exe_link = os.path.join("/proc", pid, "exe")
    try:
        return os.readlink(exe_link)
    except OSError:
        return None


def _decode_cap_mask(mask: str) -> str:
    code, stdout, _ = run_command(["capsh", "--decode", mask], timeout=5)
    if code != 0 or not stdout.strip():
        return mask
    # capsh prints: 0x...=cap_net_raw,cap_net_admin
    if "=" in stdout:
        return stdout.split("=", 1)[1].strip()
    return stdout.strip()
