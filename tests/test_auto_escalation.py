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
