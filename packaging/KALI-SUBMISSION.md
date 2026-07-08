# Kali Linux submission guide

## Checklist (upstream readiness)

- [x] GPL-3.0-or-later `LICENSE` + `debian/copyright` (DEP-5)
- [x] `README.md` + `docs/INSTALL.md` (install per distro)
- [x] `CONTRIBUTING.md` + `SECURITY.md`
- [x] `man/binsuid.1`
- [x] `debian/` (dh-python / pybuild)
- [x] Zero runtime Python dependencies (stdlib only)
- [x] System depends: `python3`, `libcap2-bin`, `sudo`
- [x] GitHub Actions CI (pytest + smoke test)
- [x] Tagged releases with `.deb`, wheel, sdist

## Verify packaging (Kali / Debian)

Use tag **v1.2.4** or later.

```bash
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID
git checkout v1.2.4

sudo apt install -y devscripts debhelper dh-python python3-all python3-venv
make test
dpkg-buildpackage -us -uc -b

sudo dpkg -i ../binsuid_*_all.deb
binsuid --version
binsuid --scan-only
```

## Submit to bugs.kali.org

1. Open https://bugs.kali.org → **Report Issue**
2. Category: **New Tool Requests**
3. Summary: `binsuid - automatic Linux privilege escalation scanner`
4. Use version **1.2.4** and release URL:
   `https://github.com/Cyberdark-Security/bINsUID/releases/tag/v1.2.4`

## Submit to kalilinux/packages (after acceptance)

1. Fork https://gitlab.com/kalilinux/packages
2. Add `binsuid/` using `debian/` from this repo.
3. Metadata:

```
Package: binsuid
Section: utils
Architecture: all
Depends: python3, libcap2-bin, sudo, ${misc:Depends}
Description: automatic SUID/SGID/capabilities/sudo privilege escalation
```

4. Register in [kali-meta](https://gitlab.com/kalilinux/packages/kali-meta).

## Release workflow

```bash
make test
git tag v1.2.4 && git push origin v1.2.4
```

GitHub Actions builds `.deb`, `.rpm`, wheel, and sdist on tag push.

## Notes

- Kali package ships the **Python CLI** via `debian/` (dh-python).
- Bash scanner (`scripts/binsuid-scan.sh`) is installed by the curl installer, not the `.deb`.
- Use `debian/changelog` as the authoritative packaging changelog.
- Maintainer email must be a valid RFC address (`ing.mauricio1983@gmail.com`), not a URL.
