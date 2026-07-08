#!/usr/bin/env bash
# Install or upgrade bINsUID from any prior method (pip, wrapper, deb, /opt).
# Works WITH or WITHOUT Python 3 (bash scanner fallback).
# Usage:
#   curl -fsSL …/upgrade-binsuid.sh | bash
#   binsuid --upgrade
set -euo pipefail

GITHUB_REPO="Cyberdark-Security/bINsUID"
INSTALL_DIR="${BINSUID_DIR:-}"
WRAPPER_PATH="${BINSUID_WRAPPER:-}"
SCAN_PATH=""
FORCE=0

for arg in "$@"; do
  case "$arg" in
    --force|--upgrade|-u) FORCE=1 ;;
  esac
done

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

download_to() {
  local url="$1" dest="$2"
  local archive
  archive="$(mktemp /tmp/binsuid.XXXXXX.tar.gz)"
  if need_cmd curl; then
    curl -fsSL "$url" -o "$archive"
  elif need_cmd wget; then
    wget -qO "$archive" "$url"
  else
    echo "[-] Need curl or wget on the install host." >&2
    exit 1
  fi
  rm -rf "$dest"
  mkdir -p "$dest"
  tar xzf "$archive" -C "$dest" --strip-components=1
  rm -f "$archive"
}

resolve_download_url() {
  if [ -n "${BINSUID_REPO_URL:-}" ]; then
    echo "$BINSUID_REPO_URL"
    return
  fi
  local tag=""
  if need_cmd curl; then
    tag="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/tags" 2>/dev/null \
      | grep -m1 '"name"' | sed 's/.*"name": "\([^"]*\)".*/\1/' || true)"
  fi
  if [ -n "$tag" ]; then
    echo "https://github.com/${GITHUB_REPO}/archive/refs/tags/${tag}.tar.gz"
  else
    echo "https://github.com/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"
  fi
}

installed_version() {
  if need_cmd binsuid; then
    binsuid -V 2>/dev/null | awk '{print $NF}'
  fi
}

remote_version() {
  local url py
  url="$(resolve_download_url)"
  py="$(find_python)" || return 0
  if need_cmd curl; then
    curl -fsSL "$url" | tar xz -O --wildcards '*/binsuid/__init__.py' 2>/dev/null \
      | "$py" -c "import sys; exec(sys.stdin.read()); print(__version__)" 2>/dev/null || true
  fi
}

detect_paths() {
  local bin=""
  bin="$(command -v binsuid 2>/dev/null || true)"

  if [ -z "$WRAPPER_PATH" ] && [ -n "$bin" ]; then
    WRAPPER_PATH="$bin"
  fi

  if [ -z "$INSTALL_DIR" ] && [ -n "$WRAPPER_PATH" ] && [ -f "$WRAPPER_PATH" ]; then
    if grep -q 'INSTALL_DIR=' "$WRAPPER_PATH" 2>/dev/null; then
      INSTALL_DIR="$(grep -m1 'INSTALL_DIR=' "$WRAPPER_PATH" | sed -E 's/.*INSTALL_DIR="([^"]+)".*/\1/')"
    elif grep -q 'PYTHONPATH=' "$WRAPPER_PATH" 2>/dev/null; then
      INSTALL_DIR="$(grep -m1 'PYTHONPATH=' "$WRAPPER_PATH" | sed -E 's/.*PYTHONPATH=([^[:space:]${]+).*/\1/')"
    fi
  fi

  if [ -z "$INSTALL_DIR" ]; then
    for candidate in /opt/bINsUID "$HOME/tools/bINsUID" "$HOME/.local/src/bINsUID"; do
      if [ -f "$candidate/binsuid/cli.py" ] || [ -f "$candidate/scripts/binsuid-scan.sh" ]; then
        INSTALL_DIR="$candidate"
        break
      fi
    done
  fi

  if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" -eq 0 ]; then
      INSTALL_DIR="/opt/bINsUID"
    else
      INSTALL_DIR="$HOME/tools/bINsUID"
    fi
  fi

  if [ -z "$WRAPPER_PATH" ] || [ ! -e "$WRAPPER_PATH" ]; then
    if [ "$(id -u)" -eq 0 ]; then
      WRAPPER_PATH="/usr/local/bin/binsuid"
    else
      WRAPPER_PATH="$HOME/bin/binsuid"
    fi
  fi

  SCAN_PATH="$(dirname "$WRAPPER_PATH")/binsuid-scan"
}

remove_pip_install() {
  if ! need_cmd pip3; then
    return
  fi
  if pip3 show binsuid >/dev/null 2>&1; then
    echo "[*] Removing old pip install..."
    pip3 uninstall -y binsuid 2>/dev/null \
      || pip3 uninstall -y binsuid --break-system-packages 2>/dev/null \
      || true
  fi
}

install_scan_script() {
  local src="$INSTALL_DIR/scripts/binsuid-scan.sh"
  if [ ! -f "$src" ]; then
    echo "[-] Missing $src after download." >&2
    exit 1
  fi
  mkdir -p "$(dirname "$SCAN_PATH")"
  cp "$src" "$SCAN_PATH"
  chmod +x "$SCAN_PATH"
}

write_wrapper() {
  local py="${1:-}"
  mkdir -p "$(dirname "$WRAPPER_PATH")"
  cat > "$WRAPPER_PATH" <<EOF
#!/usr/bin/env bash
# bINsUID hybrid launcher (Python + bash fallback)
INSTALL_DIR="$INSTALL_DIR"
SCAN_SCRIPT="$SCAN_PATH"
PY="$py"

needs_python() {
  for arg in "\$@"; do
    case "\$arg" in
      --auto|--upgrade|--json) return 0 ;;
    esac
  done
  return 1
}

if [ -n "\$PY" ] && command -v "\$PY" >/dev/null 2>&1; then
  export PYTHONPATH="\$INSTALL_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
  exec "\$PY" -m binsuid "\$@"
fi

if needs_python "\$@"; then
  echo "[-] Python 3 required for auto-exploit / JSON / upgrade on this host." >&2
  echo "[*] Running bash recon (binsuid-scan) instead..." >&2
fi

exec "\$SCAN_SCRIPT" "\$@"
EOF
  chmod +x "$WRAPPER_PATH"
}

ensure_path() {
  local bindir
  bindir="$(dirname "$WRAPPER_PATH")"
  if [ "$bindir" = "$HOME/bin" ]; then
    if ! grep -qF '$HOME/bin' "$HOME/.bashrc" 2>/dev/null; then
      printf '\n# bINsUID\nexport PATH="$HOME/bin:$PATH"\n' >> "$HOME/.bashrc"
    fi
    export PATH="$HOME/bin:$PATH"
  fi
}

print_done() {
  local py="${1:-}"
  cat <<EOF

[+] binsuid launcher:  $WRAPPER_PATH
[+] bash scanner:      $SCAN_PATH
[+] source tree:       $INSTALL_DIR
EOF
  if [ -n "$py" ]; then
    cat <<EOF

  binsuid --scan-only     # full Python scan
  binsuid --auto -y       # auto-escalate
  binsuid --upgrade       # update
EOF
  else
    cat <<EOF

  [!] Python 3 not found — bash recon mode only
  binsuid --scan-only     # SUID/SGID/sudo/caps/PATH/cron/groups
  binsuid-scan --quick    # same, explicit bash scanner

  Install python3 on this host for auto-escalation.
EOF
  fi
}

echo "=============================================="
echo "  bINsUID — install / upgrade"
echo "=============================================="

PY="$(find_python || true)"
detect_paths

CURRENT="$(installed_version || true)"
REMOTE="$(remote_version || true)"

if [ "$FORCE" -eq 0 ] && [ -n "$CURRENT" ] && [ -n "$REMOTE" ] && [ "$CURRENT" = "$REMOTE" ]; then
  echo "[+] Already up to date: binsuid $CURRENT"
  print_done "$PY"
  exit 0
fi

if [ -n "$CURRENT" ]; then
  echo "[*] Current: binsuid $CURRENT"
fi
if [ -n "$REMOTE" ]; then
  echo "[*] Target:  binsuid $REMOTE"
fi

URL="$(resolve_download_url)"
echo "[*] Downloading from GitHub..."
echo "[*] URL: $URL"

remove_pip_install
download_to "$URL" "$INSTALL_DIR"
install_scan_script
write_wrapper "$PY"
ensure_path

hash -r 2>/dev/null || true

echo
echo "[+] Installed: $(binsuid -V 2>/dev/null || echo 'binsuid (bash mode)')"
print_done "$PY"
