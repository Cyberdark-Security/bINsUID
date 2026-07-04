import json
from unittest.mock import patch

from binsuid.cli import build_parser, main, output_json
from binsuid.models import Finding, ScanResult, Technique, VectorType
from binsuid.ui.display import print_silent_summary, prompt_target_choice


def test_json_and_scan_only_can_be_combined():
    args = build_parser().parse_args(["--json", "--scan-only"])
    assert args.json
    assert args.scan_only
    assert not args.auto


def _exploitable_finding() -> Finding:
    tech = Technique(
        executable="find",
        function="shell",
        code="/usr/bin/find . -exec /bin/sh -p \\; -quit",
        context="suid",
        metadata={"source": "builtin", "auto": True},
    )
    finding = Finding(
        vector=VectorType.SUID,
        path="/usr/bin/find",
        executable="find",
        best_technique=tech,
    )
    return finding


def test_output_json_includes_exploitable_targets(capsys):
    result = ScanResult(findings=[_exploitable_finding()], errors=["getcap missing"])
    output_json(result)
    payload = json.loads(capsys.readouterr().out)
    assert payload["vulnerable"][0]["path"] == "/usr/bin/find"
    assert payload["vulnerable"][0]["auto_exploitable"] is True
    assert payload["errors"] == ["getcap missing"]


def test_json_exit_code_reflects_exploitable_targets():
    result = ScanResult(findings=[_exploitable_finding()])
    with patch("binsuid.cli._run_scan", return_value=result):
        assert main(["--json", "--scan-only"]) == 1


def test_json_exit_code_clean_when_no_exploitable():
    finding = Finding(
        vector=VectorType.SUID,
        path="/usr/bin/mount",
        executable="mount",
        notes=["manual review"],
    )
    result = ScanResult(findings=[finding])
    with patch("binsuid.cli._run_scan", return_value=result):
        assert main(["--json", "--scan-only"]) == 0


def test_json_auto_warns_on_stderr(capsys):
    result = ScanResult()
    with patch("binsuid.cli._run_scan", return_value=result):
        main(["--json", "--auto"])
    err = capsys.readouterr().err
    assert "warning:" in err
    assert "--json ignores --auto" in err


def test_prompt_target_choice_eof_returns_none(capsys):
    with patch("builtins.input", side_effect=EOFError):
        assert prompt_target_choice(3) is None
    assert "No input available" in capsys.readouterr().out


def test_silent_summary_includes_process_caps(capsys):
    proc = Finding(
        vector=VectorType.PROCESS_CAPABILITIES,
        path="1234 /usr/bin/python3",
        executable="python3",
        best_technique=Technique(
            executable="python3",
            function="shell",
            code="python3 -c 'import os; os.setuid(0)'",
            context="process-capabilities",
        ),
    )
    print_silent_summary(ScanResult(findings=[proc]))
    line = capsys.readouterr().out.strip()
    assert "Process: 1" in line
    assert "Vulnerable: 1" in line
