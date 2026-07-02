from binsuid.capabilities.knowledge import (
    severity_for_caps,
    techniques_for_capability_finding,
)
from binsuid.utils import (
    bump_severity,
    explain_capability_flags,
    parse_capability_flags,
    parse_capability_string,
)


def test_parse_capability_with_flags():
    caps = parse_capability_string("cap_setuid,cap_net_raw+ep")
    assert caps == ["CAP_SETUID", "CAP_NET_RAW"]
    assert parse_capability_flags("cap_setuid,cap_net_raw+ep") == "+ep"


def test_setuid_python_technique():
    techniques = techniques_for_capability_finding(
        "/usr/bin/python3.11",
        ["CAP_SETUID"],
    )
    assert any(t.function == "privilege-escalation" for t in techniques)
    shell = next(t for t in techniques if t.function == "privilege-escalation")
    assert "os.setuid(0)" in shell.code
    assert shell.metadata["source"] == "hacktricks"


def test_setgid_chown_chain():
    techniques = techniques_for_capability_finding(
        "/usr/bin/python3",
        ["CAP_SETGID", "CAP_CHOWN"],
    )
    assert any("CAP_SETGID" in t.capability_requirements and "CAP_CHOWN" in t.capability_requirements for t in techniques)


def test_manual_review_for_sys_admin():
    techniques = techniques_for_capability_finding(
        "/usr/bin/tar",
        ["CAP_SYS_ADMIN"],
    )
    assert any(t.function == "manual-review" for t in techniques)


def test_explain_capability_flags():
    assert "effective and permitted" in explain_capability_flags("+ep")


def test_bump_severity():
    assert bump_severity("high") == "critical"
    assert bump_severity("critical") == "critical"


def test_net_bind_service_technique():
    techniques = techniques_for_capability_finding(
        "/opt/backdoor",
        ["CAP_NET_BIND_SERVICE"],
    )
    assert any(t.metadata.get("source") == "cybersecplayground" for t in techniques)


def test_severity_order():
    assert severity_for_caps(["CAP_NET_RAW"]) == "low"
    assert severity_for_caps(["CAP_NET_RAW", "CAP_SETUID"]) == "critical"
