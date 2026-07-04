import os
import tempfile

from binsuid.models import VectorType
from binsuid.scanner.path_audit import scan_writable_path


def test_scan_writable_path_detects_user_writable_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("PATH", tmp)
        findings = scan_writable_path()
        assert len(findings) == 1
        assert findings[0].vector == VectorType.PATH_HIJACK
        assert findings[0].path == tmp
        assert "Writable PATH" in findings[0].notes[0]


def test_scan_writable_path_extra_paths():
    with tempfile.TemporaryDirectory() as tmp:
        findings = scan_writable_path(extra_paths=[tmp])
        assert any(f.path == tmp for f in findings)


def test_scan_writable_path_skips_nonexistent(monkeypatch):
    monkeypatch.setenv("PATH", "/definitely/not/a/real/path/for/binsuid")
    assert scan_writable_path() == []
