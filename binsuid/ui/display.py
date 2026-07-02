from __future__ import annotations

from binsuid.exploit.selector import escalation_summary
from binsuid.models import Finding, ScanResult, VectorType
from binsuid.ui.banner import BANNER_ART, banner_footer
from binsuid.utils import paint, ANSI_BOLD, ANSI_BLUE, ANSI_CYAN, ANSI_GREEN, ANSI_MAGENTA, ANSI_RED, ANSI_YELLOW

LINE = "=" * 62

VECTOR_COLORS = {
    VectorType.SUID: ANSI_RED,
    VectorType.CAPABILITIES: ANSI_MAGENTA,
    VectorType.PROCESS_CAPABILITIES: ANSI_BLUE,
    VectorType.SUDO: ANSI_CYAN,
}

VECTOR_LABELS = {
    VectorType.SUID: "SUID",
    VectorType.CAPABILITIES: "CAPABILITIES",
    VectorType.PROCESS_CAPABILITIES: "PROCESS",
    VectorType.SUDO: "SUDO",
}


def print_banner(version: str) -> None:
    print(paint(BANNER_ART, ANSI_BOLD, ANSI_CYAN))
    print(paint(banner_footer(version), ANSI_BOLD, ANSI_CYAN))
    print()


def print_scan_phase(label: str) -> None:
    print(paint(f"{label}...", ANSI_CYAN), end="", flush=True)
    print(paint("OK", ANSI_GREEN))


def print_scan_summary(result: ScanResult) -> None:
    vulnerable = result.exploitable
    print()
    print(paint(LINE, ANSI_GREEN))
    print(paint("  SCAN COMPLETE", ANSI_BOLD, ANSI_GREEN))
    print(paint(LINE, ANSI_GREEN))
    print(f"  Total detected      : {len(result.findings)}")
    print(paint(f"  Auto-escalatable    : {len(vulnerable)}", ANSI_BOLD, ANSI_GREEN))
    print(f"  Manual review only  : {len(result.findings) - len(vulnerable)}")
    if result.errors:
        print(paint("\n  Warnings:", ANSI_YELLOW))
        for err in result.errors:
            print(f"    - {err}")
    print()


def print_silent_summary(result: ScanResult) -> None:
    vuln = result.exploitable
    suid = sum(1 for f in vuln if f.vector == VectorType.SUID)
    caps = sum(1 for f in vuln if f.vector == VectorType.CAPABILITIES)
    sudo = sum(1 for f in vuln if f.vector == VectorType.SUDO)
    print(f"Vulnerable: {len(vuln)} | SUID: {suid} | Capabilities: {caps} | Sudo: {sudo}")


def print_concise_targets(findings: list[Finding]) -> None:
    vulnerable = [f for f in findings if f.is_exploitable]
    if not vulnerable:
        print("No auto-escalatable targets.")
        return
    for idx, finding in enumerate(vulnerable, start=1):
        tag = VECTOR_LABELS.get(finding.vector, finding.vector.value)
        method = escalation_summary(finding)
        print(f"[{idx}] {tag} {finding.path} -> {method}")


def print_vulnerable_targets(findings: list[Finding], *, concise: bool = False) -> None:
    if concise:
        print_concise_targets(findings)
        return
    vulnerable = [f for f in findings if f.is_exploitable]
    if not vulnerable:
        print(paint("[-] No automatically exploitable targets found.", ANSI_RED))
        print(paint("    Try full scan (without --quick) or check sudo -l manually.", ANSI_YELLOW))
        return

    print(paint(LINE, ANSI_MAGENTA))
    print(paint("  VULNERABLE TARGETS - READY TO ESCALATE", ANSI_BOLD, ANSI_MAGENTA))
    print(paint(LINE, ANSI_MAGENTA))
    print()

    for idx, finding in enumerate(vulnerable, start=1):
        color = VECTOR_COLORS.get(finding.vector, ANSI_YELLOW)
        tag = VECTOR_LABELS.get(finding.vector, finding.vector.value.upper())
        method = escalation_summary(finding)
        sev = finding.severity.upper()
        print(
            paint(f"  [{idx}] ", ANSI_BOLD)
            + paint(f"{tag:<12}", color)
            + f" {finding.path if finding.vector != VectorType.CAPABILITIES else finding.summary}"
        )
        print(paint(f"       └─ {method}", ANSI_GREEN))
        print(paint(f"       └─ severity: {sev}", ANSI_YELLOW))
        for note in finding.notes[:2]:
            print(paint(f"       └─ ! {note}", ANSI_YELLOW))
        print()

    print(paint("  Enter target number, 'auto' for best target, or 'q' to quit.", ANSI_CYAN))


def prompt_target_choice(max_value: int) -> int | str | None:
    while True:
        raw = input(paint("\n  Escalate which target? [1-", ANSI_BOLD) + f"{max_value}/auto/q]: ").strip().lower()
        if raw in {"q", "quit", "exit"}:
            return None
        if raw == "auto":
            return "auto"
        if raw.isdigit():
            value = int(raw)
            if 1 <= value <= max_value:
                return value
        print(paint("  Invalid choice. Enter a number, 'auto', or 'q'.", ANSI_RED))
