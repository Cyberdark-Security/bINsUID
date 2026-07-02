# bINsUID

Automatic Linux privilege escalation: scan **SUID** binaries, **capabilities**, and **sudo**
misconfigurations, then escalate with one command â€” no manual payloads, no venv, no editing.

Designed for Kali Linux packaging following the same model as accepted tools
[linkook](https://github.com/JackJuly/linkook) (Python, `pipx install`) and
[gochecksec](https://github.com/L1ghtn1ng/gochecksec) (GPL-3, `.deb` releases, zero friction UX).

> Authorized testing and training only.

## Why bINsUID

| Tool | What it does | User input |
|------|--------------|------------|
| [gochecksec](https://github.com/L1ghtn1ng/gochecksec) | Binary hardening flags | `gochecksec ./binary` |
| [linkook](https://github.com/JackJuly/linkook) | OSINT username pivoting | `linkook username` |
| **bINsUID** | SUID / caps / sudo privesc | `binsuid` â†’ pick number â†’ `Y` |

## Install

```bash
# Like linkook â€” pipx, no venv
pipx install binsuid

# Or from source
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID && pip install .

# Or .deb from Releases (like gochecksec)
sudo dpkg -i binsuid_*.deb
```

**Runtime:** Python 3.9+, `libcap2-bin`, `sudo`. **Zero pip dependencies.**

## Usage

```bash
binsuid              # scan â†’ select target â†’ escalate
binsuid --auto -y    # fully automatic (best target)
binsuid --scan-only  # enumerate only
binsuid --json       # scripting / CI
binsuid --silent     # one-line summary
binsuid --concise    # compact listing
binsuid --no-color   # plain output
binsuid -V           # version
```

### Example

```
$ binsuid
  [1] SUID         /usr/bin/find -> Automatic SUID root shell
  [2] CAPABILITIES /usr/bin/python3 [CAP_SETUID] -> Automatic capability root shell

  Escalate which target? [1-2/auto/q]: 1
  Execute privilege escalation? [Y/n]: y
  [+] SUCCESS â€” you now have root (EUID 0).
```

## Features

- Automatic scan: SUID + file capabilities + sudo rules
- Built-in payloads for 40+ binaries (no GTFOBins copy-paste)
- Offline GTFOBins + HackTricks capability knowledge
- GPL-3.0-or-later, man page, CI, `.deb`/`.rpm` releases

## Kali Linux

See [packaging/KALI-SUBMISSION.md](packaging/KALI-SUBMISSION.md).

## License

GPL-3.0-or-later â€” see [LICENSE](LICENSE).
