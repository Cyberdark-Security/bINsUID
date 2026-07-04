from binsuid.models import VectorType
from binsuid.scanner.groups import scan_groups


def test_scan_groups_docker_hint():
    findings = scan_groups(extra_groups=["docker"])
    docker = next(f for f in findings if f.executable == "docker")
    assert docker.vector == VectorType.GROUP
    assert "docker run" in docker.path
    assert docker.severity == "high"


def test_scan_groups_ignores_unprivileged():
    findings = scan_groups(extra_groups=["users", "student"])
    assert findings == []


def test_scan_groups_wheel_medium_severity():
    findings = scan_groups(extra_groups=["wheel"])
    wheel = next(f for f in findings if f.executable == "wheel")
    assert wheel.severity == "medium"
    assert "su -" in wheel.path
