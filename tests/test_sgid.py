import os
import stat
import tempfile
from unittest.mock import patch

import pytest

from binsuid.exploit.builtin import builtin_techniques_for
from binsuid.exploit.selector import attach_best_techniques
from binsuid.models import Finding, VectorType
from binsuid.scanner.sgid import _is_sgid, scan_sgid


@pytest.mark.linux
def test_is_sgid_detects_setgid_bit():
    if os.name != "posix":
        with patch("binsuid.scanner.sgid.os.stat") as mock_stat:
            mock_stat.return_value.st_mode = stat.S_ISGID
            assert _is_sgid("/tmp/setgid-bin")
        return

    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_ISGID)
        assert _is_sgid(path)
    finally:
        os.unlink(path)


def test_scan_sgid_extra_paths():
    lab_path = "/usr/local/bin/lab-sgid"
    with patch("binsuid.scanner.sgid._is_sgid", return_value=True):
        with patch("binsuid.scanner.sgid.os.path.isfile", return_value=True):
            findings = scan_sgid(extra_paths=[lab_path])
    assert any(f.path == lab_path and f.vector == VectorType.SGID for f in findings)


def test_sgid_find_builtin_payload():
    finding = Finding(
        vector=VectorType.SGID,
        path="/usr/bin/find",
        executable="find",
        severity="high",
    )
    finding.techniques = builtin_techniques_for(finding)
    attach_best_techniques([finding])
    assert any("find" in t.code for t in finding.techniques)
    assert finding.is_exploitable


def test_scan_sgid_quick_finds_binary():
    lab_path = "/opt/lab/setgid-tool"
    with patch("binsuid.scanner.sgid.QUICK_SEARCH_PATHS", ("/opt/lab",)):
        with patch("binsuid.scanner.sgid.os.path.isdir", return_value=True):
            with patch("binsuid.scanner.sgid._walk_sgid", return_value=[lab_path]):
                findings = scan_sgid(quick=True)
    assert any(f.path == lab_path for f in findings)
