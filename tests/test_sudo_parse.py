from binsuid.scanner.sudo_scan import _parse_sudo_l


SAMPLE = """
User student may run the following commands on lab:
    (root) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: ALL
    (root) PASSWD: /usr/bin/vim
"""


def test_parse_sudo_rules():
    findings = _parse_sudo_l(SAMPLE)
    paths = {f.path for f in findings}
    assert "/usr/bin/find" in paths
    assert "ALL" in paths
    assert "/usr/bin/vim" in paths

    find_entry = next(f for f in findings if f.path == "/usr/bin/find")
    assert "nopasswd=True" in find_entry.details
