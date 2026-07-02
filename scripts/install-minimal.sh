#!/usr/bin/env bash
# Install bINsUID on minimal hosts (Docker labs, no git/pipx).
set -euo pipefail

REPO_URL="${BINSUID_REPO_URL:-https://github.com/Cyberdark-Security/bINsUID/archive/refs/heads/main.tar.gz}"
WORKDIR="${BINSUID_INSTALL_DIR:-$HOME/.local/src/bINsUID}"
VENV="${BINSUID_VENV:-$HOME/.local/venvs/binsuid}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_repo() {
  mkdir -p "$(dirname "$WORKDIR")"
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"
  local archive
  archive="$(mktemp /tmp/binsuid.XXXXXX.tar.gz)"
  if need_cmd curl; then
    curl -fsSL "$REPO_URL" -o "$archive"
  elif need_cmd wget; then
    wget -qO "$archive" "$REPO_URL"
  else
    echo "[-] Need curl or wget to download the source." >&2
    exit 1
  fi
  tar xzf "$archive" -C "$WORKDIR" --strip-components=1
  rm -f "$archive"
}

install_with_venv() {
  if ! need_cmd python3; then
    echo "[-] python3 is required." >&2
    exit 1
  fi
  if ! python3 -m venv --help >/dev/null 2>&1; then
    return 1
  fi
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q "$WORKDIR"
  echo "$VENV/bin" > "$HOME/.local/binsuid-path"
}

install_with_pip_user() {
  if ! need_cmd python3; then
    echo "[-] python3 is required." >&2
    exit 1
  fi
  if need_cmd pip3; then
    pip3 install --user "$WORKDIR"
  else
    python3 -m pip install --user "$WORKDIR"
  fi
  mkdir -p "$HOME/.local/bin"
  echo "$HOME/.local/bin" > "$HOME/.local/binsuid-path"
}

echo "[*] Downloading bINsUID..."
download_repo

echo "[*] Installing..."
if install_with_venv; then
  :
elif install_with_pip_user; then
  :
else
  echo "[-] Install failed. Try: sudo apt install -y python3 python3-venv python3-pip curl" >&2
  exit 1
fi

PATH_LINE='export PATH="$(cat "$HOME/.local/binsuid-path" 2>/dev/null):$PATH"'
if ! grep -q 'binsuid-path' "$HOME/.bashrc" 2>/dev/null; then
  printf '\n# bINsUID\n%s\n' "$PATH_LINE" >> "$HOME/.bashrc"
fi

# shellcheck disable=SC1090
eval "$PATH_LINE"

echo
echo "[+] bINsUID installed."
binsuid -V
echo
echo "Run: binsuid --scan-only"
