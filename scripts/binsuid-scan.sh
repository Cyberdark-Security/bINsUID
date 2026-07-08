#!/usr/bin/env bash
# bINsUID bash scanner — focused privesc recon without Python.
# Same vectors as binsuid (SUID/SGID/caps/sudo/PATH/cron/groups), no auto-exploit.
# Usage: binsuid-scan.sh [--quick] [--silent] [--no-color]
set -uo pipefail

VERSION="1.1.5"
QUICK=0
SILENT=0
NO_COLOR=0

for arg in "$@"; do
  case "$arg" in
    --quick|-q) QUICK=1 ;;
    --silent) SILENT=1 ;;
    --no-color) NO_COLOR=1 ;;
    --scan-only|--version|-V|-h|--help) ;;
    --upgrade|-u)
      script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
      if [ -f "$script_dir/upgrade-binsuid.sh" ]; then
        exec "$script_dir/upgrade-binsuid.sh" --force "$@"
      fi
      echo "[-] --upgrade needs upgrade-binsuid.sh. Run: curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/upgrade-binsuid.sh | bash" >&2
      exit 1
      ;;
    --auto|--json)
      echo "[!] $arg ignored in bash mode (install python3 for full binsuid)" >&2
      ;;
    *) echo "Unknown option: $arg (bash mode supports --quick --silent --no-color)" >&2; exit 2 ;;
  esac
done

for arg in "$@"; do
  case "$arg" in
    -V|--version) echo "binsuid-scan $VERSION (bash mode)"; exit 0 ;;
    -h|--help)
      cat <<EOF
binsuid-scan $VERSION — bash privesc recon (no Python required)

  --quick      Scan common paths only (faster)
  --silent     One-line summary
  --no-color   Plain output

Vectors: SUID, SGID, capabilities, sudo, writable PATH, cron, groups

For auto-escalation install Python 3 and run: binsuid --auto -y
EOF
      exit 0
    ;;
  esac
done

[ "${NO_COLOR+set}" = set ] && NO_COLOR=1
[ "${NO_COLOR:-0}" -eq 1 ] && RED="" GREEN="" YELLOW="" CYAN="" BOLD="" RESET="" || {
  RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; BOLD='\033[1m'; RESET='\033[0m'
}

# Well-known SUID noise (matches binsuid/scanner/suid.py).
is_known_suid() {
  case "$1" in
    /usr/bin/sudo|/usr/bin/su|/usr/bin/passwd|/usr/bin/chfn|/usr/bin/chsh|/usr/bin/newgrp|/usr/bin/gpasswd|/usr/bin/mount|/usr/bin/umount|/usr/bin/pkexec|/bin/mount|/bin/umount|/bin/su)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

SUID_PRIORITY=()
SUID_NOISE=()
SGID_FOUND=()
CAP_FOUND=()
PATH_FOUND=()
CRON_FOUND=()
GROUP_FOUND=()
ERRORS=()

scan_suid() {
  local roots paths=""
  if [ "$QUICK" -eq 1 ]; then
    roots="/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin /opt /snap/bin"
    for root in $roots; do
      [ -d "$root" ] || continue
      found="$(find "$root" -xdev -type f -perm -4000 2>/dev/null || true)"
      if [ -n "$found" ]; then
        paths="${paths}${found}"$'\n'
      fi
    done
  elif command -v find >/dev/null 2>&1; then
    paths="$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
      -type f -perm -4000 -print 2>/dev/null || true)"
  else
    ERRORS+=("find not found")
    return
  fi

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if is_known_suid "$path"; then
      SUID_NOISE+=("$path")
    else
      SUID_PRIORITY+=("$path")
    fi
  done <<EOF
$paths
EOF
}

scan_sgid() {
  local paths=""
  if [ "$QUICK" -eq 1 ]; then
    for root in /usr/bin /usr/sbin /usr/local/bin /opt /bin /sbin; do
      [ -d "$root" ] || continue
      paths+="$(find "$root" -xdev -type f -perm -2000 2>/dev/null || true)"$'\n'
    done
  elif command -v find >/dev/null 2>&1; then
    paths="$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
      -type f -perm -2000 -print 2>/dev/null || true)"
  fi
  while IFS= read -r path; do
    [ -n "$path" ] && SGID_FOUND+=("$path")
  done <<EOF
$paths
EOF
}

scan_capabilities() {
  command -v getcap >/dev/null 2>&1 || { ERRORS+=("getcap not found (install libcap2-bin)"); return; }
  local roots="/"
  [ "$QUICK" -eq 1 ] && roots="/usr/bin /usr/sbin /bin /sbin /usr/local/bin /opt /tmp /home"
  for root in $roots; do
    [ -e "$root" ] || continue
    while IFS= read -r line; do
      [ -n "$line" ] && CAP_FOUND+=("$line")
    done <<EOF
$(getcap -r "$root" 2>/dev/null | grep -E 'cap_setuid|cap_setgid|cap_sys_admin|cap_dac_read_search|cap_setfcap' || true)
EOF
  done
}

scan_sudo() {
  command -v sudo >/dev/null 2>&1 || { ERRORS+=("sudo not found"); return; }
  local out
  out="$(sudo -n -l 2>/dev/null)" || {
    ERRORS+=("sudo -l requires password (try --sudo-interactive with full binsuid)")
    return
  }
  SUDO_OUT="$out"
}

scan_path() {
  local d mode other
  local old_ifs="$IFS"
  IFS=':'
  for d in ${PATH:-/usr/bin:/bin}; do
    [ -d "$d" ] || continue
    if [ -w "$d" ]; then
      PATH_FOUND+=("$d (writable)")
      continue
    fi
    mode="$(stat -c '%a' "$d" 2>/dev/null || true)"
    if [ -n "$mode" ]; then
      other=$((mode % 10))
      [ "$other" -ge 2 ] && PATH_FOUND+=("$d (world-writable)")
    fi
  done
  IFS="$old_ifs"
}

scan_cron() {
  local f line script
  for f in /etc/crontab /etc/cron.d/*; do
    [ -r "$f" ] || continue
    while IFS= read -r line; do
      case "$line" in \#*|"") continue ;; esac
      for script in $(echo "$line" | grep -oE '/[[:alnum:]_.~/-]+' || true); do
        [ -f "$script" ] && [ -w "$script" ] && CRON_FOUND+=("$script (writable, from $f)")
      done
    done < "$f"
  done
  if command -v crontab >/dev/null 2>&1; then
    while IFS= read -r line; do
      case "$line" in \#*|"") continue ;; esac
      for script in $(echo "$line" | grep -oE '/[[:alnum:]_.~/-]+' || true); do
        [ -f "$script" ] && [ -w "$script" ] && CRON_FOUND+=("$script (writable, user crontab)")
      done
    done <<EOF
$(crontab -l 2>/dev/null || true)
EOF
  fi
}

scan_groups() {
  local groups g hint
  groups="$(id -Gn 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
  [ -n "$groups" ] || return 0
  for g in docker lxd disk adm sudo wheel; do
    echo " $groups " | grep -q " $g " || continue
    case "$g" in
      docker) hint="docker run -v /:/mnt --rm -it alpine chroot /mnt sh" ;;
      lxd)    hint="privileged lxc container with host disk mount" ;;
      disk)   hint="debugfs /dev/sda1 — block device access" ;;
      adm)    hint="read /var/log/auth.log" ;;
      sudo|wheel) hint="sudo -l" ;;
    esac
    GROUP_FOUND+=("$g — $hint")
  done
}

scan_suid
scan_sgid
scan_capabilities
scan_sudo
scan_path
scan_cron
scan_groups

PRIORITY_COUNT=$((${#SUID_PRIORITY[@]} + ${#SGID_FOUND[@]} + ${#CAP_FOUND[@]} + \
  $( [ -n "${SUDO_OUT:-}" ] && echo 1 || echo 0 ) + ${#PATH_FOUND[@]} + ${#CRON_FOUND[@]} + ${#GROUP_FOUND[@]} ))

if [ "$SILENT" -eq 1 ]; then
  echo "Priority findings: $PRIORITY_COUNT | SUID: ${#SUID_PRIORITY[@]} | SGID: ${#SGID_FOUND[@]} | Mode: bash"
  [ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
fi

echo -e "${CYAN}==============================================${RESET}"
echo -e "${BOLD}  bINsUID scan (bash mode $VERSION)${RESET}"
echo -e "${CYAN}==============================================${RESET}"
echo -e "${YELLOW}  No Python — recon only.${RESET}"
echo

if [ ${#SUID_PRIORITY[@]} -gt 0 ]; then
  echo -e "${GREEN}${BOLD}>>> SUID priority targets${RESET}"
  for p in "${SUID_PRIORITY[@]}"; do
    echo -e "  ${GREEN}>>>${RESET} $p"
  done
  echo
fi

if [ ${#SGID_FOUND[@]} -gt 0 ]; then
  echo -e "${GREEN}${BOLD}>>> SGID binaries${RESET}"
  for p in "${SGID_FOUND[@]}"; do echo "  $p"; done
  echo
fi

if [ -n "${SUDO_OUT:-}" ]; then
  echo -e "${GREEN}${BOLD}>>> Sudo rules (NOPASSWD)${RESET}"
  echo "$SUDO_OUT" | sed 's/^/  /'
  echo
fi

if [ ${#CAP_FOUND[@]} -gt 0 ]; then
  echo -e "${GREEN}${BOLD}>>> Dangerous capabilities${RESET}"
  for p in "${CAP_FOUND[@]}"; do echo "  $p"; done
  echo
fi

if [ ${#PATH_FOUND[@]} -gt 0 ]; then
  echo -e "${YELLOW}${BOLD}>>> Writable PATH${RESET}"
  for p in "${PATH_FOUND[@]}"; do echo "  $p"; done
  echo
fi

if [ ${#CRON_FOUND[@]} -gt 0 ]; then
  echo -e "${YELLOW}${BOLD}>>> Writable cron scripts${RESET}"
  for p in "${CRON_FOUND[@]}"; do echo "  $p"; done
  echo
fi

if [ ${#GROUP_FOUND[@]} -gt 0 ]; then
  echo -e "${YELLOW}${BOLD}>>> Privileged groups${RESET}"
  for p in "${GROUP_FOUND[@]}"; do echo "  $p"; done
  echo
fi

echo -e "${CYAN}Summary${RESET}"
echo "  Priority targets    : $PRIORITY_COUNT"
echo "  System SUID hidden  : ${#SUID_NOISE[@]}"

if [ ${#ERRORS[@]} -gt 0 ]; then
  echo -e "${YELLOW}Warnings:${RESET}"
  for e in "${ERRORS[@]}"; do echo "  - $e"; done
fi

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo
  echo -e "${BOLD}Next step:${RESET} install python3, then:"
  echo "  curl -fsSL https://raw.githubusercontent.com/Cyberdark-Security/bINsUID/main/scripts/upgrade-binsuid.sh | bash"
  echo "  binsuid --auto -y"
else
  echo
  echo -e "${BOLD}Next step:${RESET} binsuid --auto -y"
fi

# Exit 1 if priority findings (matches binsuid --json convention for scripting)
[ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
