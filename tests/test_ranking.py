from binsuid.analysis.ranking import best_candidate, is_custom_suid, is_known_system_suid, partition_findings, score_finding
from binsuid.exploit.builtin import builtin_techniques_for
from binsuid.exploit.selector import attach_best_techniques
from binsuid.models import Finding, VectorType
import os
import tempfile


def _suid(path: str, details: str = "setuid") -> Finding:
    return Finding(
        vector=VectorType.SUID,
        path=path,
        executable=path.rsplit("/", 1)[-1],
        details=details,
        severity="high" if details == "setuid" else "medium",
    )


def test_custom_suid_scores_above_known():
    custom = _suid("/usr/local/bin/backup")
    known = _suid("/usr/bin/passwd", "known-suid")
    assert score_finding(custom) > score_finding(known)


def test_partition_hides_known_system_suid():
    findings = [
        _suid("/usr/local/bin/backup"),
        _suid("/usr/bin/passwd", "known-suid"),
        _suid("/bin/su", "known-suid"),
    ]
    priority, noise = partition_findings(findings)
    assert any(f.path == "/usr/local/bin/backup" for f in priority)
    assert all(f.path != "/usr/local/bin/backup" for f in noise)
    assert len(noise) >= 2


def _write_lab_backup_binary() -> str:
    fd, path = tempfile.mkstemp(suffix="backup")
    os.write(fd, b"system\0tar -czf /tmp/backup.tar.gz /home/*\0")
    os.close(fd)
    return path


def test_backup_path_hijack_becomes_auto_exploitable():
    binary = _write_lab_backup_binary()
    try:
        finding = _suid(binary)
        finding.techniques = builtin_techniques_for(finding)
        attach_best_techniques([finding])
        assert finding.is_exploitable
        assert "PATH hijack" in finding.best_technique.description
    finally:
        os.unlink(binary)


def test_best_candidate_prefers_auto():
    binary = _write_lab_backup_binary()
    try:
        custom = _suid(binary)
        custom.techniques = builtin_techniques_for(custom)
        attach_best_techniques([custom])
        known = _suid("/usr/bin/passwd", "known-suid")
        assert best_candidate([known, custom]) is custom
    finally:
        os.unlink(binary)


def test_known_system_suid_helpers():
    assert is_known_system_suid("/usr/bin/sudo")
    assert is_custom_suid("/usr/local/bin/backup")
    assert not is_custom_suid("/usr/bin/passwd")
