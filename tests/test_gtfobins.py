from __future__ import annotations

from pathlib import Path

from binsuid.gtfobins import GTFOBinsDatabase
from binsuid.models import VectorType


def test_database_loads():
    db = GTFOBinsDatabase.load()
    assert len(db.executables) > 100


def test_find_suid_shell_technique():
    db = GTFOBinsDatabase.load()
    techniques = db.techniques_for("/usr/bin/find", VectorType.SUID)
    assert any(t.function == "shell" for t in techniques)
    shell = next(t for t in techniques if t.function == "shell")
    assert "/bin/sh" in shell.code


def test_python_capability_match():
    db = GTFOBinsDatabase.load()
    techniques = db.techniques_for(
        "/usr/bin/python3",
        VectorType.CAPABILITIES,
        present_caps=["CAP_SETUID"],
    )
    assert any(t.function == "shell" for t in techniques)


def test_executable_alias_resolution():
    db = GTFOBinsDatabase.load()
    assert db.resolve_executable("/usr/bin/python3.11") == "python"


def test_bundled_data_file_exists():
    data = Path(__file__).resolve().parents[1] / "binsuid" / "data" / "gtfobins-api.json"
    assert data.is_file()
