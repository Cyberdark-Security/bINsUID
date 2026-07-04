# Kali Linux submission guide

## Checklist (upstream readiness)

- [x] GPL-3.0-or-later `LICENSE` + `debian/copyright` (DEP-5)
- [x] `README.md` with install + usage + examples
- [x] `CONTRIBUTING.md` + `SECURITY.md` (GitHub Security Advisories)
- [x] `man/binsuid.1` (all CLI flags + exit status)
- [x] `setup.py` + `pyproject.toml` + `debian/` (dh-python / pybuild)
- [x] Zero runtime Python dependencies (stdlib only)
- [x] System depends: `python3`, `libcap2-bin`, `sudo`
- [x] GitHub Actions CI (pytest + CLI smoke test on Ubuntu)
- [x] Tagged releases with `.deb`, `.rpm`, wheel, sdist
- [x] Automatic escalation — no manual command editing
- [x] Core flags: `--version`, `--json`, `--silent`, `--no-color`, `--auto`, `-y`
- [x] Extended recon: SGID, PATH audit, cron persistence, group hints
- [x] SETENV sudo detection + automatic payloads

## Submit to kalilinux/packages

1. Fork https://gitlab.com/kalilinux/packages
2. Add `binsuid/` using `debian/` from this repo (pybuild template).
3. Suggested metadata:

```
Package: binsuid
Section: utils
Architecture: all
Depends: python3, libcap2-bin, sudo, ${misc:Depends}
Description: automatic SUID/SGID/capabilities/sudo privilege escalation
```

4. Register in [kali-meta](https://gitlab.com/kalilinux/packages/kali-meta) under privilege-escalation / post-exploitation tools.

## Release maintainer workflow

```bash
make update-gtfobins   # refresh bundled API before release
make test
git tag v1.1.0 && git push origin v1.1.0
# GitHub Actions publishes .deb to Releases
```

## Why Kali should accept it

- **Same category** as privesc enumeration tools, with **automatic exploitation**
- **No venv** required — runs with system Python
- **Instructor-friendly** for SUID/capabilities/sudo labs
- **Debian-native packaging** (`debian/` + CI + `.deb` releases)
- **Offline GTFOBins** — no network required during assessments
