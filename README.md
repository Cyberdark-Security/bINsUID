<p align="center">
  <img src="docs/assets/banner.png" alt="bINsUID - automatic Linux privilege escalation" width="100%">
</p>

# bINsUID

Automatic Linux privilege escalation for authorized penetration testing, CTF, and security training.

Scans SUID/SGID binaries, capabilities, sudo rules, writable PATH, cron surfaces, and privileged groups — then escalates with built-in payloads and offline GTFOBins data.

> Use only on systems you are authorized to test.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash
source ~/.bashrc
binsuid --scan-only
```

Update an existing install:

```bash
binsuid --upgrade
```

## Installation

| Method | Command | Python | Notes |
|--------|---------|--------|-------|
| **Universal installer** | `curl -fsSL …/get-binsuid.sh \| bash` | Optional | Works on most Linux distros; bash-only fallback without Python |
| **Kali / Debian package** | `sudo apt install binsuid` | System Python | After packaging is accepted in Kali |
| **Release `.deb`** | `sudo dpkg -i binsuid_*_all.deb` | System Python | From [Releases](https://github.com/Cyberdark-Security/bINsUID/releases) |
| **pipx** | `pipx install https://github.com/Cyberdark-Security/bINsUID.git` | Yes | Recommended on Kali when building from git |
| **From source** | `pip install -e ".[dev]"` | Yes | Development |

**Requirements on the target host:** Linux, bash, `find`. Optional: Python 3 (full auto-escalation), `getcap` (capabilities scan), passwordless `sudo -l` (sudo rules).

Detailed guides:

- English: [docs/INSTALL.md](docs/INSTALL.md)
- Español: [docs/INSTALL.es.md](docs/INSTALL.es.md)

### Bash-only scanner (no Python)

If Python is not available, use the standalone bash scanner:

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/binsuid-scan.sh -o /tmp/binsuid-scan.sh
bash /tmp/binsuid-scan.sh --quick
```

After the scan you can choose: **m** (menu), **a** (auto), or **q** (quit). Copy the script to restricted targets using your usual file-transfer method.

## Usage

```bash
binsuid --scan-only              # enumerate vectors
binsuid                          # guided escalation
binsuid --auto -y                # escalate best target
binsuid --auto --dry-run -y      # show command only
binsuid --json --scan-only       # machine-readable output
```

Bash scanner (no Python):

```bash
binsuid-scan.sh --quick                  # scan, then prompt m/a/q
binsuid-scan.sh --quick --scan-only      # scan only
binsuid-scan.sh --quick --auto -y        # scan and auto-escalate
```

## Features

- SUID/SGID, capabilities, sudo (incl. SETENV), writable PATH, cron, privileged groups
- Ranks priority targets and hides common system noise
- Built-in payloads for common binaries; offline GTFOBins database
- JSON mode and scripting-friendly exit codes

## Scripting

```bash
binsuid --json --scan-only --quick   # exit 1 when auto-exploitable targets exist
binsuid --scan-only --skip-sudo --skip-capabilities --quick
```

## Documentation

- `man binsuid` — full option reference
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities
- [CONTRIBUTING.md](CONTRIBUTING.md) — development
- [packaging/KALI-SUBMISSION.md](packaging/KALI-SUBMISSION.md) — Kali packaging notes

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
