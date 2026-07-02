#!/usr/bin/env bash
# Install bINsUID on Kali / PEP 668 managed Python (pipx, isolated venv).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v pipx >/dev/null 2>&1; then
  echo "[*] Installing pipx..."
  apt-get update -qq
  apt-get install -y pipx
fi

pipx ensurepath >/dev/null 2>&1 || true
pipx install --force "$ROOT"

echo
echo "[+] bINsUID installed."
echo "    If 'binsuid' is not found, run: export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "    Or open a new shell after: pipx ensurepath"
binsuid -V
