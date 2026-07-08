# Installation guide

bINsUID runs on **Linux**. Choose the method that fits your environment.

## Requirements

| Component | Required | If missing |
|-----------|----------|------------|
| Linux + bash | Yes | Cannot run |
| `find` | Yes | Scan fails |
| `curl` or `wget` | For online install | Use offline copy of scripts or `.deb` |
| Python 3.9+ | For full CLI | Bash scanner only (`binsuid-scan.sh`) |
| `getcap` (`libcap2-bin`) | No | Capabilities scan skipped (warning) |
| `sudo -l` without password | No | Sudo rules scan limited (warning) |

---

## Kali Linux

### From Kali repositories (when packaged)

```bash
sudo apt update
sudo apt install binsuid
binsuid --version
```

### pipx (latest git, user install)

```bash
sudo apt install -y pipx
pipx ensurepath
# open a new shell
pipx install https://github.com/Cyberdark-Security/bINsUID.git
binsuid --scan-only
```

### From release `.deb`

Download `binsuid_*_all.deb` from [GitHub Releases](https://github.com/Cyberdark-Security/bINsUID/releases), then:

```bash
sudo dpkg -i binsuid_*_all.deb
sudo apt -f install
```

---

## Debian / Ubuntu

Same as Kali: `.deb` package, `pipx`, or universal installer below.

On PEP 668 systems, prefer `pipx` or the curl installer instead of `pip install` system-wide.

---

## Any Linux (universal installer)

```bash
curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash
source ~/.bashrc
binsuid --scan-only
```

Without `curl`, use `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/get-binsuid.sh | bash
```

Upgrade later:

```bash
binsuid --upgrade
```

---

## Minimal targets (no Python)

Download the bash scanner on a machine with network access, transfer it to the target, then:

```bash
bash binsuid-scan.sh --quick
```

The scan lists vectors, then asks: **m** (pick vector), **a** (auto), **q** (quit).

Flags:

```bash
bash binsuid-scan.sh --quick --scan-only    # no escalation prompt
bash binsuid-scan.sh --quick --auto -y      # auto after scan
```

---

## From source (developers)

```bash
git clone https://github.com/Cyberdark-Security/bINsUID.git
cd bINsUID
git checkout v1.2.4
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make test
```

### Build Debian package

```bash
sudo apt install -y devscripts debhelper dh-python python3-all python3-venv
make test
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../binsuid_*_all.deb
```

---

## Usage after install

```bash
binsuid --scan-only
binsuid --auto --dry-run -y
binsuid --auto -y
binsuid --json --scan-only --quick
```

---

## Normal warnings (not errors)

| Message | Meaning |
|---------|---------|
| `getcap not found` | Install `libcap2-bin` for capability scanning |
| `sudo not found` / password required | Sudo enumeration unavailable; other scans continue |
| System SUID hidden | Standard binaries filtered from priority list |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `binsuid: command not found` | `source ~/.bashrc` or `export PATH="$HOME/bin:$PATH"` |
| `externally-managed-environment` | Use `pipx` or the curl installer |
| `No module named binsuid` | Re-run installer or `pip install -e .` in clone |
| Need JSON without Python | Not supported in bash mode; install Python or use scan-only bash output |

---

Spanish guide: [INSTALL.es.md](INSTALL.es.md)
