#!/usr/bin/env bash
# Universal bINsUID setup — works without git, pip, pipx, or sudo.
# Only needs: Linux + Python 3 + (curl or wget)
set -euo pipefail

REPO_URL="${BINSUID_REPO_URL:-https://github.com/Cyberdark-Security/bINsUID/archive/refs/heads/main.tar.gz}"
INSTALL_DIR="${BINSUID_DIR:-$HOME/tools/bINsUID}"
WRAPPER="$HOME/bin/binsuid"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

find_python() {
  for candidate in /usr/bin/python3 python3 python; do
    if need_cmd "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
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
    echo "[-] Need curl or wget to download bINsUID." >&2
    exit 1
  fi
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar xzf "$archive" -C "$INSTALL_DIR" --strip-components=1
  rm -f "$archive"
}

write_wrapper() {
  local py="$1"
  mkdir -p "$HOME/bin"
  cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$INSTALL_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$py" -m binsuid "\$@"
EOF
  chmod +x "$WRAPPER"
}

ensure_path() {
  if ! grep -qF '$HOME/bin' "$HOME/.bashrc" 2>/dev/null; then
    printf '\n# bINsUID\nexport PATH="$HOME/bin:$PATH"\n' >> "$HOME/.bashrc"
  fi
  export PATH="$HOME/bin:$PATH"
}

echo "=============================================="
echo "  bINsUID — setup automático"
echo "=============================================="

if need_cmd binsuid && binsuid -V >/dev/null 2>&1; then
  echo "[+] bINsUID ya está instalado."
  binsuid -V
  exit 0
fi

PY="$(find_python)" || {
  echo "[-] Python 3 no encontrado. Necesitas python3 en el sistema." >&2
  exit 1
}
echo "[*] Python: $PY"

if [ ! -f "$INSTALL_DIR/binsuid/cli.py" ]; then
  echo "[*] Descargando desde GitHub..."
  download_repo
fi

write_wrapper "$PY"
ensure_path

echo
echo "[+] Listo. Sin git, sin pip, sin sudo."
binsuid -V
echo
echo "  binsuid --scan-only      # escanear"
echo "  binsuid --auto -y        # escalar automático"
echo
echo "Si 'binsuid' no se encuentra:  source ~/.bashrc"
