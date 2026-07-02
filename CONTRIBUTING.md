# Contributing to bINsUID

Thank you for helping improve bINsUID. This project follows the same packaging
discipline as tools accepted in Kali Linux such as
[linkook](https://github.com/JackJuly/linkook) and
[gochecksec](https://github.com/L1ghtn1ng/gochecksec).

## Development setup

```bash
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID
pip install -e ".[dev]"
make test
```

## Guidelines

- **No runtime pip dependencies** — use the Python stdlib only.
- **Automatic escalation** — new techniques must run without user-edited commands.
- **Linux only** — test on Kali, Debian, or Ubuntu VMs.
- **GPL-3.0-or-later** — all contributions must be compatible.

## Pull requests

1. Run `pytest -v` and ensure all tests pass.
2. Update `man/binsuid.1` if CLI flags change.
3. Refresh `binsuid/data/gtfobins-api.json` only when intentionally updating GTFOBins data.
4. Keep the default UX to **scan → select → escalate** (max two prompts).

## Reporting issues

Open an issue at https://github.com/Cyberdark-Security/bINsUID/issues with:

- Distribution and version (e.g. Kali 2025.4)
- Output of `binsuid --version`
- `binsuid --json --scan-only` (redact sensitive paths if needed)
