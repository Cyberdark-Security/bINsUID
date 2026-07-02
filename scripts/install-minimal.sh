#!/usr/bin/env bash
# Install bINsUID on minimal hosts (Docker labs, no git/pipx).
set -euo pipefail

REPO_URL="${BINSUID_REPO_URL:-https://github.com/Cyberdark-Security/bINsUID/archive/refs/heads/main.tar.gz}"
WORKDIR="${BINSUID_INSTALL_DIR:-$HOME/.local/src/bINsUID}"
VENV="${BINSUID_VENV:-$HOME/.local/venvs/binsuid}"
BIN_DIR=""

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

try_install_venv_package() {
  if ! need_cmd sudo || ! need_cmd apt-get; then
    return 1
  fi
  echo "[*] Installing python3-venv (needs sudo)..."
  sudo apt-get update -qq
  sudo apt-get install -y python3-venv python3-pip
}

venv_is_ready() {
  [ -x "$VENV/bin/pip" ] && [ -x "$VENV/bin/python3" ]
}

install_with_venv() {
  local py
  py="$(system_python)" || return 1

  rm -rf "$VENV"
  if ! "$py" -m venv "$VENV" 2>/dev/null || ! venv_is_ready; then
    try_install_venv_package || return 1
    rm -rf "$VENV"
    "$py" -m venv "$VENV" || return 1
  fi

  venv_is_ready || return 1
  BIN_DIR="$VENV/bin"
  "$BIN_DIR/pip" install --upgrade pip
  "$BIN_DIR/pip" install "$WORKDIR"
}

pip_install_user() {
  local py pip_args=()
  py="$(system_python)" || return 1

  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"

  if ! "$py" -m pip --version >/dev/null 2>&1; then
    echo "[*] Bootstrapping pip for current user (no sudo)..."
    local get_pip
    get_pip="$(mktemp /tmp/get-pip.XXXXXX.py)"
    if need_cmd curl; then
      curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$get_pip"
    elif need_cmd wget; then
      wget -qO "$get_pip" https://bootstrap.pypa.io/get-pip.py
    else
      return 1
    fi
    "$py" "$get_pip" --user
    rm -f "$get_pip"
    export PATH="$HOME/.local/bin:$PATH"
  fi

  if "$py" -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    pip_args+=(--break-system-packages)
  fi

  "$py" -m pip install --user "${pip_args[@]}" "$WORKDIR"
}

install_with_pip_user() {
  pip_install_user || return 1
}

write_path() {
  local path_line="export PATH=\"$BIN_DIR:\$PATH\""
  if ! grep -qF "$BIN_DIR" "$HOME/.bashrc" 2>/dev/null; then
    printf '\n# bINsUID\n%s\n' "$path_line" >> "$HOME/.bashrc"
  fi
  export PATH="$BIN_DIR:$PATH"
}

echo "[*] Downloading bINsUID..."
download_repo

echo "[*] Installing..."
if install_with_venv; then
  echo "[*] Installed in venv: $VENV"
elif install_with_pip_user; then
  echo "[*] Installed with pip --user"
else
  echo "[-] Install failed." >&2
  echo "    Try manually:" >&2
  echo "      sudo apt update && sudo apt install -y python3-venv python3-pip curl" >&2
  echo "      curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/install-minimal.sh | bash" >&2
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
