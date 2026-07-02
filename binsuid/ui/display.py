from __future__ import annotations

from binsuid.analysis.ranking import best_candidate, partition_findings
from binsuid.exploit.executor import adapt_command
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
    priority, noise = partition_findings(result.findings)
    vulnerable = result.exploitable
    print()
    print(paint(LINE, ANSI_GREEN))
    print(paint("  SCAN COMPLETE", ANSI_BOLD, ANSI_GREEN))
    print(paint(LINE, ANSI_GREEN))
    print(f"  Total detected      : {len(result.findings)}")
    print(paint(f"  Priority targets    : {len(priority)}", ANSI_BOLD, ANSI_MAGENTA))
    print(paint(f"  Auto-escalatable    : {len(vulnerable)}", ANSI_BOLD, ANSI_GREEN))
    if noise:
        print(f"  System noise hidden : {len(noise)}  (use --show-all to list)")
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


def _finding_location(finding: Finding) -> str:
    if finding.vector == VectorType.CAPABILITIES:
        return finding.summary or finding.path
    return finding.path or finding.executable or "-"


def _print_finding_line(
    finding: Finding,
    *,
    index: int | None = None,
    top: bool = False,
    concise: bool = False,
) -> None:
    tag = VECTOR_LABELS.get(finding.vector, finding.vector.value)
    prefix = f"[{index}] " if index is not None else ""
    marker = paint(">>> ", ANSI_BOLD, ANSI_MAGENTA) if top else "    "

    if finding.is_exploitable:
        flag = paint("AUTO", ANSI_BOLD, ANSI_GREEN)
        detail = escalation_summary(finding)
    else:
        flag = paint("REVIEW", ANSI_YELLOW)
        detail = finding.notes[0] if finding.notes else (finding.details or "-")

    location = _finding_location(finding)
    head = f"{prefix}{flag} {tag} {location}"

    if concise:
        line = f"{marker}{head} | {detail}"
        print(paint(line, ANSI_BOLD, ANSI_MAGENTA) if top else line)
        return

    color = VECTOR_COLORS.get(finding.vector, ANSI_YELLOW)
    print(marker + paint(prefix, ANSI_BOLD) + flag + " " + paint(f"{tag:<12}", color) + f" {location}")
    print(paint(f"         -> {detail}", ANSI_GREEN if finding.is_exploitable else ANSI_YELLOW))
    for note in finding.notes[1:3]:
        print(paint(f"         ! {note}", ANSI_YELLOW))


def print_guidance(finding: Finding) -> None:
    method = escalation_summary(finding)
    print()
    print(paint(LINE, ANSI_MAGENTA))
    print(paint("  RECOMMENDED TARGET", ANSI_BOLD, ANSI_MAGENTA))
    print(paint(LINE, ANSI_MAGENTA))
    print(paint(f"  {_finding_location(finding)}", ANSI_BOLD, ANSI_CYAN))
    print(paint(f"  Method: {method}", ANSI_GREEN))
    if finding.is_exploitable:
        command = adapt_command(finding.best_technique.code, finding) if finding.best_technique else ""
        print(paint("  Next step:", ANSI_BOLD, ANSI_YELLOW))
        print(paint("    binsuid --auto -y", ANSI_BOLD, ANSI_CYAN))
        print(paint("    binsuid --auto --dry-run -y    # preview only", ANSI_CYAN))
        if command:
            print(paint("  Command preview:", ANSI_YELLOW))
            print(f"    {command}")
    else:
        print(paint("  Next step: inspect this binary manually (custom SUID in lab path).", ANSI_YELLOW))
    print()


def print_scan_findings(findings: list[Finding], *, concise: bool = False, show_all: bool = False) -> None:
    if not findings:
        print("No findings.")
        return

    priority, noise = partition_findings(findings)
    top = best_candidate(findings)

    if priority:
        print(paint(LINE, ANSI_MAGENTA))
        print(paint("  PRIORITY TARGETS", ANSI_BOLD, ANSI_MAGENTA))
        print(paint(LINE, ANSI_MAGENTA))
        print()
        for idx, finding in enumerate(priority, start=1):
            _print_finding_line(finding, index=idx, top=(finding is top), concise=concise)
            if not concise:
                print()
    else:
        print(paint("[-] No priority targets identified.", ANSI_RED))

    if noise:
        if show_all:
            print(paint(LINE, ANSI_YELLOW))
            print(paint("  SYSTEM SUID (LOW INTEREST)", ANSI_BOLD, ANSI_YELLOW))
            print(paint(LINE, ANSI_YELLOW))
            print()
            start = len(priority) + 1
            for offset, finding in enumerate(noise):
                _print_finding_line(finding, index=start + offset, concise=concise)
                if not concise:
                    print()
        else:
            print(paint(f"\n  ({len(noise)} standard system SUID binaries hidden — use --show-all)", ANSI_YELLOW))

    if top:
        print_guidance(top)


def print_concise_targets(findings: list[Finding]) -> None:
    print_scan_findings(findings, concise=True)


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
        _print_finding_line(finding, index=idx, top=(finding is best_candidate(vulnerable)), concise=False)

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
