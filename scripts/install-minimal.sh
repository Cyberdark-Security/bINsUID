#!/usr/bin/env bash
# Install bINsUID on minimal hosts (Docker labs, no git/pipx).
set -euo pipefail

REPO_URL="${BINSUID_REPO_URL:-https://github.com/Cyberdark-Security/bINsUID/archive/refs/heads/main.tar.gz}"
WORKDIR="${BINSUID_INSTALL_DIR:-$HOME/.local/src/bINsUID}"
VENV="${BINSUID_VENV:-$HOME/.local/venvs/binsuid}"
BIN_DIR="$VENV/bin"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

system_python() {
  if [ -x /usr/bin/python3 ]; then
    echo /usr/bin/python3
  elif need_cmd python3; then
    command -v python3
  else
    return 1
  fi
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
  local py
  py="$(system_python)" || {
    echo "[-] python3 is required." >&2
    return 1
  }
  if ! "$py" -m venv --help >/dev/null 2>&1; then
    return 1
  fi
  rm -rf "$VENV"
  "$py" -m venv "$VENV"
  "$BIN_DIR/pip" install --upgrade pip
  "$BIN_DIR/pip" install "$WORKDIR"
}

install_with_pip_user() {
  local py
  py="$(system_python)" || {
    echo "[-] python3 is required." >&2
    return 1
  }
  "$py" -m pip install --user "$WORKDIR"
  mkdir -p "$HOME/.local/bin"
  BIN_DIR="$HOME/.local/bin"
}

write_path() {
  local path_line="export PATH=\"$BIN_DIR:\$PATH\""
  if ! grep -qF "$BIN_DIR" "$HOME/.bashrc" 2>/dev/null; then
    printf '\n# bINsUID\n%s\n' "$path_line" >> "$HOME/.bashrc"
  fi
  # shellcheck disable=SC1090
  export PATH="$BIN_DIR:$PATH"
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

if [ ! -x "$BIN_DIR/binsuid" ]; then
  echo "[-] binsuid binary not found in $BIN_DIR" >&2
  exit 1
fi

write_path

echo
echo "[+] bINsUID installed."
"$BIN_DIR/binsuid" -V
echo
echo "Run: binsuid --scan-only"
echo "If needed: source ~/.bashrc"
