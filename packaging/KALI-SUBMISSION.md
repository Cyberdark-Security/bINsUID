# Kali Linux submission guide

bINsUID follows the same acceptance patterns as tools already in Kali such as:

| Tool | Language | License | Packaging | UX |
|------|----------|---------|-------------|-----|
| [linkook](https://github.com/JackJuly/linkook) | Python | MIT | `pipx` / `setup.py` / PyPI | `linkook user` |
| [gochecksec](https://github.com/L1ghtn1ng/gochecksec) | Go | GPL-3 | GoReleaser + `.deb` | `gochecksec binary` |
| **bINsUID** | Python | GPL-3 | `nfpm` + `.deb` + `setup.py` | `binsuid` |

## Checklist (all done upstream)

- [x] GPL-3.0-or-later `LICENSE`
- [x] `README.md` with install + usage + examples
- [x] `CONTRIBUTING.md` + `SECURITY.md`
- [x] `man/binsuid.1`
- [x] `setup.py` + `pyproject.toml` (Debian `pybuild` / dh-python)
- [x] Zero runtime Python dependencies (stdlib only)
- [x] System depends: `python3`, `libcap2-bin`, `sudo`
- [x] GitHub Actions CI (test on push/PR)
- [x] Tagged releases with `.deb`, `.rpm`, wheel, sdist
- [x] Automatic escalation — no manual command editing
- [x] Flags: `--version`, `--json`, `--silent`, `--no-color`, `--auto`, `-y`

## Submit to kalilinux/packages

1. Fork https://gitlab.com/kalilinux/packages
2. Add `binsuid/` package using another Python CLI as template (e.g. tools with `pybuild`).
3. Suggested metadata:

```
Package: binsuid
Section: utils
Architecture: all
Depends: python3, libcap2-bin, sudo, ${misc:Depends}
Description: automatic SUID/capabilities/sudo privilege escalation
```

4. Register in [kali-meta](https://gitlab.com/kalilinux/packages/kali-meta) under privilege-escalation / post-exploitation tools.

## Release maintainer workflow

```bash
make update-gtfobins   # refresh bundled API before release
make test
git tag v1.0.0 && git push origin v1.0.0
# GitHub Actions publishes .deb to Releases
```

## Why Kali should accept it

- **Same category** as existing privesc enumeration tools, but with **automatic exploitation**
- **No venv** required (like gochecksec's motivation vs pwntools)
- **Instructor-friendly** for SUID/capabilities labs
- **Reproducible packaging** identical to other accepted Python security tools
