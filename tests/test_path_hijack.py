from binsuid.exploit.path_hijack import detect_from_strings, path_hijack_payload


def test_detect_path_hijack_from_strings():
    sample = 'system("tar -czf /tmp/backup.tar.gz /home/* 2>/dev/null")\n'
    assert detect_from_strings(sample) == "tar"


def test_detect_path_hijack_split_strings():
    sample = "system\ntar -czf /tmp/backup.tar.gz /home/* 2>/dev/null\n"
    assert detect_from_strings(sample) == "tar"


def test_path_hijack_payload():
    code = path_hijack_payload(suid_path="/usr/local/bin/backup", command="tar")
    assert "/usr/local/bin/backup" in code
    assert "PATH=/tmp/binsuid-hijack:$PATH" in code
    assert "> /tmp/binsuid-hijack/tar" in code


def test_read_binary_strings_fallback():
    import os
    import tempfile
    from binsuid.exploit.path_hijack import detect_from_strings, read_binary_strings

    fd, path = tempfile.mkstemp()
    os.write(fd, b"\x00system\x00tar -czf /tmp/backup.tar.gz /home/*\x00")
    os.close(fd)
    try:
        text = read_binary_strings(path)
        assert detect_from_strings(text) == "tar"
    finally:
        os.unlink(path)
