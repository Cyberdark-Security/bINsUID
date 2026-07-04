from __future__ import annotations

from binsuid.capabilities import techniques_for_capability_finding
from binsuid.exploit.builtin import builtin_techniques_for
from binsuid.exploit.selector import attach_best_techniques
from binsuid.gtfobins import GTFOBinsDatabase, enrich_findings
from binsuid.models import ScanResult, VectorType
from binsuid.scanner import (
    scan_capabilities,
    scan_groups,
    scan_persistence,
    scan_process_capabilities,
    scan_sgid,
    scan_sudo,
    scan_suid,
    scan_writable_path,
)


def _sort_techniques(techniques: list) -> list:
    rank = {
        "privilege-escalation": 0,
        "shell": 1,
        "command": 2,
        "inherit": 3,
        "library-load": 4,
        "file-read": 5,
        "file-write": 6,
        "manual-review": 99,
    }
    return sorted(techniques, key=lambda t: (rank.get(t.function, 50), t.function))


def _merge_techniques(existing, extra) -> list:
    seen = {(t.function, t.code.strip()) for t in existing}
    merged = list(existing)
    for tech in extra:
        key = (tech.function, tech.code.strip())
        if key not in seen:
            merged.append(tech)
            seen.add(key)
    return _sort_techniques(merged)


def _enrich_capability_findings(findings, database: GTFOBinsDatabase) -> None:
    for finding in findings:
        if finding.vector != VectorType.CAPABILITIES:
            continue
        gtfobins = database.techniques_for(
            finding.path,
            finding.vector,
            present_caps=finding.capabilities,
        )
        hacktricks = techniques_for_capability_finding(
            finding.path,
            finding.capabilities,
            executable_key=database.resolve_executable(finding.path),
        )
        finding.techniques = _merge_techniques(gtfobins, hacktricks)


def run_scan(
    *,
    quick: bool = False,
    skip_suid: bool = False,
    skip_sgid: bool = False,
    skip_capabilities: bool = False,
    skip_process_capabilities: bool = True,
    skip_sudo: bool = False,
    skip_path_audit: bool = False,
    skip_persistence: bool = False,
    skip_groups: bool = False,
    sudo_interactive: bool = False,
    audit_suspicious_paths: bool = True,
    database: GTFOBinsDatabase | None = None,
) -> ScanResult:
    db = database or GTFOBinsDatabase.load()
    result = ScanResult()

    if not skip_suid:
        result.findings.extend(scan_suid(quick=quick))

    if not skip_sgid:
        result.findings.extend(scan_sgid(quick=quick))

    if not skip_capabilities:
        cap_findings, cap_errors = scan_capabilities(
            quick=quick,
            audit_suspicious_paths=audit_suspicious_paths,
        )
        result.findings.extend(cap_findings)
        result.errors.extend(cap_errors)

    if not skip_process_capabilities:
        proc_findings, proc_errors = scan_process_capabilities()
        result.findings.extend(proc_findings)
        result.errors.extend(proc_errors)

    if not skip_sudo:
        sudo_findings, sudo_errors = scan_sudo(non_interactive=not sudo_interactive)
        result.findings.extend(sudo_findings)
        result.errors.extend(sudo_errors)

    if not skip_path_audit:
        result.findings.extend(scan_writable_path())

    if not skip_persistence:
        persist_findings, persist_errors = scan_persistence()
        result.findings.extend(persist_findings)
        result.errors.extend(persist_errors)

    if not skip_groups:
        result.findings.extend(scan_groups())

    enrich_findings(
        [
            f for f in result.findings
            if f.vector not in {VectorType.CAPABILITIES, VectorType.PATH_HIJACK,
                                VectorType.PERSISTENCE, VectorType.GROUP}
        ],
        db,
    )
    _enrich_capability_findings(result.findings, db)

    for finding in result.findings:
        if finding.vector in {VectorType.PROCESS_CAPABILITIES, VectorType.PATH_HIJACK,
                              VectorType.PERSISTENCE, VectorType.GROUP}:
            continue
        builtins = builtin_techniques_for(finding)
        finding.techniques = _merge_techniques(builtins, finding.techniques)

    attach_best_techniques(result.findings)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.findings.sort(
        key=lambda f: (
            0 if f.is_exploitable else 1,
            severity_rank.get(f.severity, 9),
            f.vector.value,
            f.path,
        )
    )
    return result
