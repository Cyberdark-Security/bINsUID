import os
import tempfile
from unittest.mock import patch

from binsuid.models import VectorType
from binsuid.scanner.persistence import _extract_script_paths, _script_finding, scan_persistence


SAMPLE_CRON = """
# m h dom mon dow user command
0 2 * * * root /opt/backup/run.sh
*/5 * * * * student /home/student/sync.sh
@reboot root /usr/local/bin/startup
"""


def test_extract_script_paths_from_cron():
    paths = _extract_script_paths(SAMPLE_CRON)
    assert "/opt/backup/run.sh" in paths
    assert "/home/student/sync.sh" in paths
    assert "/usr/local/bin/startup" not in paths


def test_scan_persistence_extra_script():
    fd, path = tempfile.mkstemp(suffix=".sh")
    os.close(fd)
    try:
        with patch("binsuid.scanner.persistence._collect_cron_sources", return_value=[]):
            findings, _ = scan_persistence(extra_scripts=[path])
        assert len(findings) == 1
        assert findings[0].vector == VectorType.PERSISTENCE
        assert findings[0].path == path
        assert "owned" in findings[0].details or "writable" in findings[0].details
    finally:
        os.unlink(path)


def test_scan_persistence_skips_special_paths():
    with patch("binsuid.scanner.persistence.is_writable_by_unprivileged", return_value=True):
        assert _script_finding("/dev/null", source="test", uid=1000) is None
        assert _script_finding("/proc/self/status", source="test", uid=1000) is None


def test_scan_persistence_skips_readonly_other_owned():
    script = "/root/locked.sh"
    fake_stat = os.stat_result((0o100755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    with patch("binsuid.scanner.persistence.os.path.isfile", return_value=True):
        with patch("binsuid.scanner.persistence.os.stat", return_value=fake_stat):
            with patch("binsuid.scanner.persistence.is_writable_by_unprivileged", return_value=False):
                with patch("binsuid.scanner.persistence.current_ids", return_value=(1000, 1000, 1000, 1000)):
                    findings, _ = scan_persistence(extra_scripts=[script])
    assert findings == []
