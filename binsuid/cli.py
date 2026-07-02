from __future__ import annotations

import argparse
import json
import os

from binsuid import __version__
from binsuid.exploit import escalate_privileges
from binsuid.scanner.engine import run_scan
from binsuid.ui import (
    print_banner,
    print_scan_phase,
    print_scan_summary,
    print_silent_summary,
    print_vulnerable_targets,
    prompt_target_choice,
)
from binsuid.utils import disable_color


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binsuid",
        description="Automatic SUID, capabilities and sudo privilege escalation for Linux.",
        epilog="Authorized testing only.  binsuid  |  binsuid --auto -y",
    )
    parser.add_argument("-V", "--version", action="version", version=f"binsuid {__version__}")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan-only", action="store_true", help="Scan only, do not offer escalation")
    mode.add_argument("--json", action="store_true", help="JSON output (scripting)")
    mode.add_argument("--auto", action="store_true", help="Escalate the best target automatically")

    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--quick", action="store_true", help="Faster scan (common paths)")
    parser.add_argument("--dry-run", action="store_true", help="Instructor demo — do not execute")
    parser.add_argument("--no-color", action="store_true", help="Plain output without ANSI colors")
    parser.add_argument("--silent", action="store_true", help="Minimal output (summary line only)")
    parser.add_argument("--concise", action="store_true", help="Compact one-line-per-target listing")
    parser.add_argument("--skip-suid", action="store_true", help="Skip SUID scan")
    parser.add_argument("--skip-capabilities", action="store_true", help="Skip file capabilities scan")
    parser.add_argument("--scan-process-caps", action="store_true", help="Include process capabilities")
    parser.add_argument("--no-suspicious-paths", action="store_true", help="Skip /opt /tmp /home in quick mode")
    parser.add_argument("--skip-sudo", action="store_true", help="Skip sudo -l scan")
    parser.add_argument("--sudo-interactive", action="store_true", help="Use sudo -l with password")
    return parser


def _finding_to_dict(finding) -> dict:
    best = finding.best_technique
    return {
        "vector": finding.vector.value,
        "path": finding.path,
        "executable": finding.executable,
        "details": finding.details,
        "capabilities": finding.capabilities,
        "severity": finding.severity,
        "notes": finding.notes,
        "auto_exploitable": finding.is_exploitable,
        "escalation_method": best.description if best else None,
        "escalation_command": best.code if best else None,
    }


def output_json(result) -> None:
    print(json.dumps({
        "version": __version__,
        "vulnerable": [_finding_to_dict(f) for f in result.exploitable],
        "all_findings": [_finding_to_dict(f) for f in result.findings],
        "errors": result.errors,
    }, indent=2))


def _run_scan(args, *, quiet: bool = False) -> object:
    if not quiet:
        if not args.skip_suid:
            print_scan_phase("Scanning SUID binaries")
        if not args.skip_capabilities:
            print_scan_phase("Scanning file capabilities")
        if not args.skip_sudo:
            print_scan_phase("Scanning sudo rules")
        print(paint("-" * 55, ANSI_CYAN))
    return run_scan(
        quick=args.quick,
        skip_suid=args.skip_suid,
        skip_capabilities=args.skip_capabilities,
        skip_process_capabilities=not args.scan_process_caps,
        skip_sudo=args.skip_sudo,
        sudo_interactive=args.sudo_interactive,
        audit_suspicious_paths=not args.no_suspicious_paths,
    )


def escalation_loop(result, *, dry_run: bool = False, assume_yes: bool = False, concise: bool = False) -> int:
    vulnerable = result.exploitable
    if not vulnerable:
        return 1

    print_vulnerable_targets(vulnerable, concise=concise)
    choice = prompt_target_choice(len(vulnerable))
    if choice is None:
        return 0

    finding = vulnerable[0] if choice == "auto" else vulnerable[choice - 1]
    return escalate_privileges(finding, dry_run=dry_run, assume_yes=assume_yes)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        disable_color()

    quiet = args.silent or args.json

    if not quiet:
        print_banner(__version__)

    result = _run_scan(args, quiet=quiet)

    if args.json:
        output_json(result)
        return 0 if result.exploitable else 1

    if args.silent:
        print_silent_summary(result)
    elif not quiet:
        print_scan_summary(result)

    if not result.exploitable:
        return 1

    if args.scan_only:
        print_vulnerable_targets(result.exploitable, concise=args.concise or args.silent)
        return 0

    if args.auto:
        return escalate_privileges(
            result.exploitable[0],
            dry_run=args.dry_run,
            assume_yes=args.yes or args.silent,
        )

    if args.silent:
        return 0

    return escalation_loop(
        result,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        concise=args.concise,
    )


if __name__ == "__main__":
    raise SystemExit(main())
