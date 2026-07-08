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

## Submit to kalilinux/packages

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
git tag v1.2.2 && git push origin v1.2.2
```

## Notes

- Kali package ships the **Python CLI** via `debian/` (dh-python).
- Bash scanner (`scripts/binsuid-scan.sh`) is installed by the curl installer, not the `.deb`.
- Use `debian/changelog` as the authoritative packaging changelog.
