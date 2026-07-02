<p align="center">
  <img src="docs/assets/banner.png" alt="bINsUID - automatic Linux privilege escalation" width="100%">
</p>

# bINsUID

Automatic Linux privilege escalation: scan **SUID** binaries, **capabilities**, and **sudo**
misconfigurations, then escalate with one command - no manual payloads, no venv, no editing.

> Authorized testing and training only.

## What it does

- Enumerates SUID binaries, dangerous file capabilities, and sudo rules
- Matches findings against offline GTFOBins data and built-in exploit payloads
- Escalates with minimal interaction: pick a target, confirm, done

## Install

### Kali Linux (recommended)

Kali blocks global `pip install` ([PEP 668](https://www.kali.org/docs/general-use/python3-external-packages/)). Use **pipx**:

```bash
sudo apt install -y pipx
pipx ensurepath
# reopen the shell, then:

pipx install binsuid

# Or from a cloned repo:
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID
pipx install .
```

Quick installer from the repo:

```bash
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID
./scripts/install-kali.sh
```

**Instructor VM / root-only lab** (installs for all users on the system):

```bash
cd bINsUID
pip install --break-system-packages .
```

### Other Linux

```bash
pipx install binsuid
# or
pip install .
```

### Debian package

```bash
sudo dpkg -i binsuid_*.deb   # from GitHub Releases
```

**Runtime:** Python 3.9+, `libcap2-bin`, `sudo`. **Zero pip dependencies.**

## Usage

```bash
binsuid              # scan -> select target -> escalate
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
  [+] SUCCESS - you now have root (EUID 0).
```

## Features

- Automatic scan: SUID + file capabilities + sudo rules
- Built-in payloads for 40+ binaries (no GTFOBins copy-paste)
- Offline GTFOBins + HackTricks capability knowledge
- GPL-3.0-or-later, man page, CI, `.deb`/`.rpm` releases

## Kali Linux

See [packaging/KALI-SUBMISSION.md](packaging/KALI-SUBMISSION.md).

## License

GPL-3.0-or-later - see [LICENSE](LICENSE).
