#!/usr/bin/env bash
# Run bINsUID without install (Docker labs: no sudo, no pip, no venv).
set -euo pipefail

INSTALL_DIR="${BINSUID_DIR:-$HOME/tools/bINsUID}"
REPO_URL="${BINSUID_REPO_URL:-https://github.com/Cyberdark-Security/bINsUID/archive/refs/heads/main.tar.gz}"
PY="${BINSUID_PYTHON:-/usr/bin/python3}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_repo() {
  mkdir -p "$(dirname "$INSTALL_DIR")"
  local archive
  archive="$(mktemp /tmp/binsuid.XXXXXX.tar.gz)"
  if need_cmd curl; then
    curl -fsSL "$REPO_URL" -o "$archive"
  elif need_cmd wget; then
    wget -qO "$archive" "$REPO_URL"
  else
    echo "[-] Need curl or wget." >&2
    exit 1
  fi
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar xzf "$archive" -C "$INSTALL_DIR" --strip-components=1
  rm -f "$archive"
}

write_wrapper() {
  mkdir -p "$HOME/bin"
  cat > "$HOME/bin/binsuid" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$INSTALL_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$PY" -m binsuid "\$@"
EOF
  chmod +x "$HOME/bin/binsuid"
}

if [ ! -f "$INSTALL_DIR/binsuid/cli.py" ]; then
  echo "[*] Downloading bINsUID to $INSTALL_DIR ..."
  download_repo
fi

write_wrapper

PATH_LINE='export PATH="$HOME/bin:$PATH"'
if ! grep -qF '$HOME/bin' "$HOME/.bashrc" 2>/dev/null; then
  printf '\n# bINsUID (no-install)\n%s\n' "$PATH_LINE" >> "$HOME/.bashrc"
fi
export PATH="$HOME/bin:$PATH"

echo "[+] Ready. No pip/sudo needed."
binsuid -V
echo
echo "Run: binsuid --scan-only"
