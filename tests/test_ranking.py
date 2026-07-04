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


def test_setenv_sudo_scores_high():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/awk",
        executable="awk",
        details="cmd=/usr/bin/awk; runas=root; nopasswd=True; setenv=True; user=student",
        severity="critical",
    )
    assert score_finding(finding) >= 350


def test_known_system_suid_helpers():
    assert is_known_system_suid("/usr/bin/sudo")
    assert is_custom_suid("/usr/local/bin/backup")
    assert not is_custom_suid("/usr/bin/passwd")


def test_process_caps_scores_above_noise():
    proc = Finding(
        vector=VectorType.PROCESS_CAPABILITIES,
        path="pid 1234 (python3) -> /usr/bin/python3",
        executable="python3",
        capabilities=["CAP_SETUID"],
        severity="critical",
    )
    noise = _suid("/usr/bin/passwd", "known-suid")
    assert score_finding(proc) > score_finding(noise)


def test_sgid_scores_above_known_sgid():
    custom = Finding(
        vector=VectorType.SGID,
        path="/usr/local/bin/shared",
        executable="shared",
        details="setgid",
        severity="high",
    )
    known = Finding(
        vector=VectorType.SGID,
        path="/usr/bin/ssh-agent",
        executable="ssh-agent",
        details="known-sgid",
        severity="medium",
    )
    assert score_finding(custom) > score_finding(known)


def test_path_hijack_and_group_scores_positive():
    path_f = Finding(
        vector=VectorType.PATH_HIJACK,
        path="/tmp/hijack",
        executable="hijack",
        details="user-writable",
        severity="high",
    )
    group_f = Finding(
        vector=VectorType.GROUP,
        path="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        executable="docker",
        details="Docker group",
        severity="high",
    )
    assert score_finding(path_f) > 0
    assert score_finding(group_f) > 0
