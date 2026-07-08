#!/bin/sh
# Install git hooks that block Cursor from appearing as co-author on GitHub.
set -e
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/.git/hooks"
cp "$root/scripts/hooks/prepare-commit-msg" "$root/.git/hooks/prepare-commit-msg"
chmod +x "$root/.git/hooks/prepare-commit-msg"
echo "[+] Installed .git/hooks/prepare-commit-msg (strips Cursor co-author)"
