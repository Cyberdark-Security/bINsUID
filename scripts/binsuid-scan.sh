#!/usr/bin/env bash
# bINsUID bash scanner — focused privesc recon without Python.
# Usage: binsuid-scan.sh [--quick] [--silent] [--no-color] [--debug]
VERSION="1.1.6"

QUICK=0
SILENT=0
NO_COLOR=0
DEBUG=0

for arg in "$@"; do
  case "$arg" in
    --quick|-q) QUICK=1 ;;
    --silent) SILENT=1 ;;
    --no-color) NO_COLOR=1 ;;
    --debug) DEBUG=1 ;;
    --scan-only|--version|-V|-h|--help) ;;
    --upgrade|-u)
      d="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
      if [ -f "$d/upgrade-binsuid.sh" ]; then
        exec "$d/upgrade-binsuid.sh" --force "$@"
      fi
      echo "[-] --upgrade needs upgrade-binsuid.sh on this host." >&2
      exit 1
      ;;
    --auto|--json)
      echo "[!] $arg ignored in bash mode (needs python3 for full binsuid)" >&2
      ;;
    -V|--version) echo "binsuid-scan $VERSION (bash mode)"; exit 0 ;;
    -h|--help)
      echo "binsuid-scan $VERSION — bash privesc recon (no Python)"
      echo "  --quick  --silent  --no-color  --debug"
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

dbg() { [ "$DEBUG" -eq 1 ] && echo "[debug] $*" >&2; }

if [ -n "${NO_COLOR:-}" ] || [ "$NO_COLOR" -eq 1 ]; then
  RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; RESET=""
else
  RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
  CYAN='\033[36m'; BOLD='\033[1m'; RESET='\033[0m'
fi

is_known_suid() {
  case "$1" in
    /usr/bin/sudo|/usr/bin/su|/usr/bin/passwd|/usr/bin/chfn|/usr/bin/chsh|\
/usr/bin/newgrp|/usr/bin/gpasswd|/usr/bin/mount|/usr/bin/umount|/usr/bin/pkexec|\
/usr/lib/openssh/ssh-keysign|/bin/mount|/bin/umount|/bin/su)
      return 0 ;;
  esac
  return 1
}

SUID_PRIORITY=""
SUID_NOISE=""
SGID_FOUND=""
CAP_FOUND=""
PATH_FOUND=""
CRON_FOUND=""
GROUP_FOUND=""
ERRORS=""
SUDO_OUT=""
PRIORITY_COUNT=0

add_line() {
  # add_line VAR "line"
  eval "$1=\"\${$1}\${$1:+\$'\n'}\$2\""
}

scan_suid() {
  dbg "scan_suid quick=$QUICK"
  local roots paths f
  if [ "$QUICK" -eq 1 ]; then
    roots="/usr/local/bin /usr/local/sbin /opt /home /var /tmp /snap/bin /usr/bin /usr/sbin /bin /sbin"
  else
    roots="/"
  fi

  if ! command -v find >/dev/null 2>&1; then
    ERRORS="${ERRORS}${ERRORS:+$'\n'}find not found"
    return
  fi

  if [ "$QUICK" -eq 1 ]; then
    for root in $roots; do
      [ -d "$root" ] || continue
      paths="$(find "$root" -xdev -type f -perm -4000 2>/dev/null)" || paths=""
      for f in $paths; do
        [ -n "$f" ] || continue
        if is_known_suid "$f"; then
          add_line SUID_NOISE "$f"
        else
          add_line SUID_PRIORITY "$f"
        fi
      done
    done
  else
    paths="$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
      -type f -perm -4000 -print 2>/dev/null)" || paths=""
    for f in $paths; do
      [ -n "$f" ] || continue
      if is_known_suid "$f"; then
        add_line SUID_NOISE "$f"
      else
        add_line SUID_PRIORITY "$f"
      fi
    done
  fi
}

scan_sgid() {
  dbg "scan_sgid"
  local roots="/usr/bin /usr/sbin /usr/local/bin /opt /bin /sbin /home /var"
  local f paths
  command -v find >/dev/null 2>&1 || return
  for root in $roots; do
    [ -d "$root" ] || continue
    paths="$(find "$root" -xdev -type f -perm -2000 2>/dev/null)" || paths=""
    for f in $paths; do
      [ -n "$f" ] && add_line SGID_FOUND "$f"
    done
  done
}

scan_capabilities() {
  dbg "scan_capabilities"
  command -v getcap >/dev/null 2>&1 || {
    ERRORS="${ERRORS}${ERRORS:+$'\n'}getcap not found"
    return
  }
  local root line
  for root in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /opt /home; do
    [ -e "$root" ] || continue
  done
  while IFS= read -r line; do
    [ -n "$line" ] && add_line CAP_FOUND "$line"
  done <<EOF
$(getcap -r /usr /opt /home 2>/dev/null | grep -E 'cap_setuid|cap_setgid|cap_sys_admin|cap_dac_read_search|cap_setfcap' 2>/dev/null || true)
EOF
}

scan_sudo() {
  dbg "scan_sudo"
  command -v sudo >/dev/null 2>&1 || {
    ERRORS="${ERRORS}${ERRORS:+$'\n'}sudo not found"
    return
  }
  SUDO_OUT="$(sudo -n -l 2>/dev/null)" || {
    ERRORS="${ERRORS}${ERRORS:+$'\n'}sudo -l requires password"
    SUDO_OUT=""
  }
}

scan_path() {
  dbg "scan_path"
  local d mode other old_ifs
  old_ifs="$IFS"
  IFS=':'
  for d in ${PATH:-/usr/bin:/bin}; do
    [ -d "$d" ] || continue
    if [ -w "$d" ]; then
      add_line PATH_FOUND "$d (writable)"
      continue
    fi
    mode="$(stat -c '%a' "$d" 2>/dev/null)" || mode=""
    if [ -n "$mode" ]; then
      other=$((mode % 10))
      [ "$other" -ge 2 ] && add_line PATH_FOUND "$d (world-writable)"
    fi
  done
  IFS="$old_ifs"
}

scan_cron() {
  dbg "scan_cron"
  local f line script
  for f in /etc/crontab /etc/cron.d/*; do
    [ -r "$f" ] || continue
    while IFS= read -r line; do
      case "$line" in \#*|"") continue ;; esac
      for script in $(echo "$line" | grep -oE '/[[:alnum:]_.~/-]+' 2>/dev/null || true); do
        if [ -f "$script" ] && [ -w "$script" ]; then
          add_line CRON_FOUND "$script (writable, from $f)"
        fi
      done
    done < "$f"
  done
}

scan_groups() {
  dbg "scan_groups"
  local groups g hint
  groups="$(id -Gn 2>/dev/null | tr '[:upper:]' '[:lower:]')" || groups=""
  [ -n "$groups" ] || return 0
  for g in docker lxd disk adm sudo wheel; do
    echo " $groups " | grep -q " $g " 2>/dev/null || continue
    case "$g" in
      docker) hint="docker run -v /:/mnt --rm -it alpine chroot /mnt sh" ;;
      lxd)    hint="privileged lxc container" ;;
      disk)   hint="debugfs block device access" ;;
      adm)    hint="read /var/log/auth.log" ;;
      *)      hint="sudo -l" ;;
    esac
    add_line GROUP_FOUND "$g — $hint"
  done
}

count_lines() {
  if [ -z "$1" ]; then echo 0; return; fi
  echo "$1" | grep -c '.' || echo 0
}

# --- run scans ---
scan_suid
scan_sgid
scan_capabilities
scan_sudo
scan_path
scan_cron
scan_groups

PRIORITY_COUNT=$(( $(count_lines "$SUID_PRIORITY") + $(count_lines "$SGID_FOUND") + \
  $(count_lines "$CAP_FOUND") + $(count_lines "$PATH_FOUND") + \
  $(count_lines "$CRON_FOUND") + $(count_lines "$GROUP_FOUND") ))
[ -n "$SUDO_OUT" ] && PRIORITY_COUNT=$((PRIORITY_COUNT + 1))

if [ "$SILENT" -eq 1 ]; then
  echo "Priority: $PRIORITY_COUNT | SUID: $(count_lines "$SUID_PRIORITY") | bash $VERSION"
  [ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
fi

echo "${CYAN}==============================================${RESET}"
echo "${BOLD}  bINsUID scan (bash $VERSION)${RESET}"
echo "${CYAN}==============================================${RESET}"
echo "${YELLOW}  Recon only — no Python on this host.${RESET}"
echo

if [ -n "$SUID_PRIORITY" ]; then
  echo "${GREEN}${BOLD}>>> SUID priority targets${RESET}"
  echo "$SUID_PRIORITY" | while IFS= read -r p; do
    [ -n "$p" ] && echo "  ${GREEN}>>>${RESET} $p"
  done
  echo
fi

if [ -n "$SGID_FOUND" ]; then
  echo "${GREEN}${BOLD}>>> SGID binaries${RESET}"
  echo "$SGID_FOUND" | sed 's/^/  /'
  echo
fi

if [ -n "$SUDO_OUT" ]; then
  echo "${GREEN}${BOLD}>>> Sudo rules${RESET}"
  echo "$SUDO_OUT" | sed 's/^/  /'
  echo
fi

if [ -n "$CAP_FOUND" ]; then
  echo "${GREEN}${BOLD}>>> Dangerous capabilities${RESET}"
  echo "$CAP_FOUND" | sed 's/^/  /'
  echo
fi

if [ -n "$PATH_FOUND" ]; then
  echo "${YELLOW}${BOLD}>>> Writable PATH${RESET}"
  echo "$PATH_FOUND" | sed 's/^/  /'
  echo
fi

if [ -n "$CRON_FOUND" ]; then
  echo "${YELLOW}${BOLD}>>> Writable cron scripts${RESET}"
  echo "$CRON_FOUND" | sed 's/^/  /'
  echo
fi

if [ -n "$GROUP_FOUND" ]; then
  echo "${YELLOW}${BOLD}>>> Privileged groups${RESET}"
  echo "$GROUP_FOUND" | sed 's/^/  /'
  echo
fi

echo "${CYAN}Summary${RESET}"
echo "  Priority targets    : $PRIORITY_COUNT"
echo "  System SUID hidden  : $(count_lines "$SUID_NOISE")"

if [ -n "$ERRORS" ]; then
  echo "${YELLOW}Warnings:${RESET}"
  echo "$ERRORS" | sed 's/^/  - /'
fi

if [ "$PRIORITY_COUNT" -eq 0 ]; then
  echo
  echo "${YELLOW}No custom targets in quick paths. Try full scan or manual:${RESET}"
  echo "  find / -perm -4000 -type f 2>/dev/null | grep -vE 'passwd|mount|su\$|newgrp|chfn|chsh|gpasswd|ssh-keysign'"
  echo "  find /home /var /opt -writable -type f 2>/dev/null | head -20"
  echo "  getcap -r / 2>/dev/null"
fi

[ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
