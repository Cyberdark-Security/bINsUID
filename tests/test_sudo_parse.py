from binsuid.scanner.sudo_scan import _parse_sudo_l


SAMPLE = """
User student may run the following commands on lab:
    (root) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: ALL
    (root) PASSWD: /usr/bin/vim
"""


def test_parse_sudo_setenv():
    sample = """
User student may run the following commands on lab:
    (root) NOPASSWD: SETENV: /usr/bin/awk
    (root) SETENV: NOPASSWD: /usr/bin/python3
"""
    findings = _parse_sudo_l(sample)
    awk = next(f for f in findings if f.path == "/usr/bin/awk")
    assert "setenv=True" in awk.details
    assert "nopasswd=True" in awk.details
    assert awk.severity == "critical"
    py = next(f for f in findings if f.path == "/usr/bin/python3")
    assert py.severity == "critical"


def test_parse_sudo_rules():
    findings = _parse_sudo_l(SAMPLE)
    paths = {f.path for f in findings}
    assert "/usr/bin/find" in paths
    assert "ALL" in paths
    assert "/usr/bin/vim" in paths

    find_entry = next(f for f in findings if f.path == "/usr/bin/find")
    assert "nopasswd=True" in find_entry.details


def test_parse_sudo_wildcard_note():
    sample = """
User student may run the following commands on lab:
    (root) NOPASSWD: /usr/bin/vi /etc/*
"""
    findings = _parse_sudo_l(sample)
    vi = next(f for f in findings if f.path == "/usr/bin/vi")
    assert any("Wildcard" in n for n in vi.notes)
    assert vi.severity == "high"


def test_parse_sudo_runas_all_note():
    sample = """
User student may run the following commands on lab:
    (ALL) NOPASSWD: /usr/bin/id
"""
    findings = _parse_sudo_l(sample)
    entry = findings[0]
    assert any("Runas (ALL)" in n for n in entry.notes)


def test_parse_sudo_fixed_args_shell_escape_note():
    sample = """
User student may run the following commands on lab:
    (root) NOPASSWD: /usr/bin/less /var/log/syslog
"""
    findings = _parse_sudo_l(sample)
    less = next(f for f in findings if f.path == "/usr/bin/less")
    assert any("Fixed-args" in n for n in less.notes)


def test_parse_sudo_sensitive_path_note():
    sample = """
User student may run the following commands on lab:
    (root) NOPASSWD: /usr/bin/cat /etc/shadow
"""
    findings = _parse_sudo_l(sample)
    cat = next(f for f in findings if "cat" in f.path)
    assert any("sensitive path" in n.lower() for n in cat.notes)


def test_parse_sudo_sudoedit_note():
    sample = """
User student may run the following commands on lab:
    (root) NOPASSWD: sudoedit /etc/hosts
"""
    findings = _parse_sudo_l(sample)
    entry = next(f for f in findings if f.executable == "sudoedit")
    assert any("sudoedit" in n.lower() for n in entry.notes)
