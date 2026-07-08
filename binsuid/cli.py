from __future__ import annotations

import argparse
import json
import os
import sys

from binsuid import __version__
from binsuid.analysis.ranking import best_candidate
from binsuid.exploit import escalate_privileges
from binsuid.scanner.engine import run_scan
from binsuid.ui import (
    print_banner,
    print_guidance,
    print_scan_findings,
    print_scan_phase,
    print_scan_summary,
    print_silent_summary,
    print_vulnerable_targets,
    prompt_target_choice,
)
from binsuid.utils import ANSI_CYAN, disable_color, paint, run_command

UPGRADE_SCRIPT_URL = (
    "https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/upgrade-binsuid.sh"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binsuid",
        description="Automatic SUID, capabilities and sudo privilege escalation for Linux.",
        epilog="Authorized testing only.  binsuid  |  binsuid --auto -y",
    )
    parser.add_argument("-V", "--version", action="version", version=f"binsuid {__version__}")

    action = parser.add_mutually_exclusive_group()
    action.add_argument("--scan-only", action="store_true", help="Scan only, do not offer escalation")
    action.add_argument("--auto", action="store_true", help="Escalate the best target automatically")

    parser.add_argument("--json", action="store_true", help="JSON output (scripting; use with --scan-only)")

    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--quick", action="store_true", help="Faster scan (common paths)")
    parser.add_argument("--dry-run", action="store_true", help="Instructor demo - do not execute")
    parser.add_argument("--no-color", action="store_true", help="Plain output without ANSI colors")
    parser.add_argument("--silent", action="store_true", help="Minimal output (summary line only)")
    parser.add_argument("--concise", action="store_true", help="Compact one-line-per-target listing")
    parser.add_argument("--show-all", action="store_true", help="Include low-interest system SUID binaries")
    parser.add_argument("--skip-suid", action="store_true", help="Skip SUID scan")
    parser.add_argument("--skip-sgid", action="store_true", help="Skip SGID scan")
    parser.add_argument("--skip-capabilities", action="store_true", help="Skip file capabilities scan")
    parser.add_argument("--scan-process-caps", action="store_true", help="Include process capabilities")
    parser.add_argument("--no-suspicious-paths", action="store_true", help="Skip /opt /tmp /home in quick mode")
    parser.add_argument("--skip-sudo", action="store_true", help="Skip sudo -l scan")
    parser.add_argument("--skip-path-audit", action="store_true", help="Skip writable PATH audit")
    parser.add_argument("--skip-persistence", action="store_true", help="Skip cron persistence audit")
    parser.add_argument("--skip-groups", action="store_true", help="Skip privileged group hints")
    parser.add_argument("--sudo-interactive", action="store_true", help="Use sudo -l with password")
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Update bINsUID to the latest release from GitHub",
    )
    return parser


def run_self_upgrade() -> int:
    print(paint("[*] Updating bINsUID from GitHub...", ANSI_CYAN))
    code, _, stderr = run_command(
        f'curl -fsSL "{UPGRADE_SCRIPT_URL}" | bash',
        shell=True,
        timeout=180,
    )
    if code != 0:
        print(
            paint(
                "[-] Upgrade failed. Try manually:\n"
                f"    curl -fsSL {UPGRADE_SCRIPT_URL} | bash",
                ANSI_CYAN,
            ),
            file=sys.stderr,
        )
        if stderr.strip():
            print(stderr.strip(), file=sys.stderr)
        return 1
    return 0


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
        if not args.skip_sgid:
            print_scan_phase("Scanning SGID binaries")
        if not args.skip_capabilities:
            print_scan_phase("Scanning file capabilities")
        if not args.skip_sudo:
            print_scan_phase("Scanning sudo rules")
        if not args.skip_path_audit:
            print_scan_phase("Auditing writable PATH")
        if not args.skip_persistence:
            print_scan_phase("Checking cron persistence")
        if not args.skip_groups:
            print_scan_phase("Checking privileged groups")
        print(paint("-" * 55, ANSI_CYAN))
    return run_scan(
        quick=args.quick,
        skip_suid=args.skip_suid,
        skip_sgid=args.skip_sgid,
        skip_capabilities=args.skip_capabilities,
        skip_process_capabilities=not args.scan_process_caps,
        skip_sudo=args.skip_sudo,
        skip_path_audit=args.skip_path_audit,
        skip_persistence=args.skip_persistence,
        skip_groups=args.skip_groups,
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

    if args.upgrade:
        return run_self_upgrade()

    quiet = args.silent or args.json

    if not quiet:
        print_banner(__version__)

    result = _run_scan(args, quiet=quiet)

    if args.json:
        if args.auto:
            print(
                "warning: --json ignores --auto; use --json --scan-only for scripting",
                file=sys.stderr,
            )
        output_json(result)
        return 1 if result.exploitable else 0

    if args.silent:
        print_silent_summary(result)
    else:
        print_scan_summary(result)

    if args.scan_only:
        print_scan_findings(result.findings, concise=args.concise, show_all=args.show_all)
        return 0

    if not result.exploitable:
        print_scan_findings(result.findings, concise=args.concise, show_all=args.show_all)
        return 1

    if args.auto:
        return escalate_privileges(
            best_candidate(result.findings) or result.exploitable[0],
            dry_run=args.dry_run,
            assume_yes=args.yes or args.silent,
        )

    if args.silent:
        return 0

    # Default: guided flow — show targets, then escalate best candidate.
    print_scan_findings(result.findings, concise=args.concise, show_all=args.show_all, show_guidance=False)
    top = best_candidate(result.findings)
    if top and top.is_exploitable and len(result.exploitable) == 1:
        print_guidance(top, interactive=True)
        return escalate_privileges(top, dry_run=args.dry_run, assume_yes=args.yes)

    if top and top.is_exploitable:
        print_guidance(top, interactive=True)

    return escalation_loop(
        result,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        concise=args.concise,
    )


if __name__ == "__main__":
    raise SystemExit(main())
