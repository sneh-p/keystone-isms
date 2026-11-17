#!/bin/sh
# Keystone configuration agent for Linux. Report-only: it reads security settings and sends them to Keystone over
# HTTPS. It never changes the host, and Keystone cannot send it commands.
#
#   sudo KEYSTONE_ENROLMENT_KEY="kenr_..." sh keystone-agent.sh install --server https://keystone.example.org
#   sudo sh keystone-agent.sh run         # collect and report now (the timer does this every few hours)
#   sh keystone-agent.sh collect          # print what would be sent, as JSON; sends nothing
#   sudo sh keystone-agent.sh status
#   sudo sh keystone-agent.sh uninstall
#
# Files: /usr/local/lib/keystone-agent/keystone-agent.sh (this script), /etc/keystone-agent/agent.conf (server address,
# mode 600) and /etc/keystone-agent/token (this device's token, mode 600, readable by root only). The enrolment key is
# used once, at install, and is not kept. Needs: sh, curl. Runs as root so it can read sshd, sudoers and firewall state.
set -u

AGENT_VERSION="1.0.0"
CONF_DIR="${KEYSTONE_AGENT_CONF_DIR:-/etc/keystone-agent}"
LIB_DIR="${KEYSTONE_AGENT_LIB_DIR:-/usr/local/lib/keystone-agent}"
UNIT_DIR="${KEYSTONE_AGENT_UNIT_DIR:-/etc/systemd/system}"
CRON_FILE="${KEYSTONE_AGENT_CRON_FILE:-/etc/cron.d/keystone-agent}"
CONF="$CONF_DIR/agent.conf"
TOKEN_FILE="$CONF_DIR/token"
umask 077

die() { printf 'keystone-agent: %s\n' "$*" >&2; exit 1; }
say() { printf 'keystone-agent: %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------------------------------------ JSON helpers

json_str() {
  # Escape a value as a JSON string (backslash, quote, control characters dropped), at most 200 characters.
  printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\t\n\r' '   ' | cut -c1-200 |
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$/"/'
}

FACTS=""
add() {  # add KEY TYPE VALUE ; empty VALUE means "not known" and is left out
  [ -n "$3" ] || return 0
  case "$2" in
    bool) case "$3" in true|false) v="$3" ;; *) return 0 ;; esac ;;
    int) case "$3" in ''|*[!0-9]*) return 0 ;; *) v="$3" ;; esac ;;
    str) v=$(json_str "$3") ;;
    *) return 0 ;;
  esac
  FACTS="${FACTS}${FACTS:+,}\"$1\":$v"
}

yn() { if [ "$1" = 0 ]; then echo true; else echo false; fi; }  # exit status to true/false

# ------------------------------------------------------------------------------------------------ collection

collect_firewall() {
  tool="none"
  if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    tool="ufw"
  elif have firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = "running" ]; then
    tool="firewalld"
  elif have nft && nft list ruleset 2>/dev/null | awk '/hook input/ {inp=1} inp && /(policy drop|drop|reject)/ {f=1} END {exit !f}'; then
    tool="nftables"
  elif have iptables && iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT DROP|-j (DROP|REJECT)'; then
    tool="iptables"
  fi
  if [ "$tool" = "none" ]; then add firewall_active bool false; else add firewall_active bool true; fi
  add firewall_tool str "$tool"
}

collect_ssh() {
  if have sshd || [ -x /usr/sbin/sshd ]; then
    add ssh_server_installed bool true
    sshd_bin=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
    cfg=$("$sshd_bin" -T 2>/dev/null) || cfg=""
    if [ -n "$cfg" ]; then
      add ssh_permit_root_login str "$(printf '%s\n' "$cfg" | awk '$1=="permitrootlogin" {print $2; exit}')"
      pa=$(printf '%s\n' "$cfg" | awk '$1=="passwordauthentication" {print $2; exit}')
      case "$pa" in yes) add ssh_password_authentication bool true ;; no) add ssh_password_authentication bool false ;; esac
    fi
  else
    add ssh_server_installed bool false
  fi
}

collect_updates() {
  if have apt-get; then
    # From the package lists already on the host: the agent doesn't refresh them (report-only).
    n=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst .*-security') || true
    add security_updates_pending int "${n:-}"
    if have dpkg-query && dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
      v=$(apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n 's/.*"\([0-9]*\)".*/\1/p' | tail -n1)
      if [ "${v:-0}" -ge 1 ] 2>/dev/null; then add automatic_updates_enabled bool true; else add automatic_updates_enabled bool false; fi
    else
      add automatic_updates_enabled bool false
    fi
  elif have dnf; then
    out=$(dnf -q -C updateinfo list --security --available 2>/dev/null) && add security_updates_pending int "$(printf '%s\n' "$out" | grep -c .)"
    if have systemctl && { systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; }; then
      add automatic_updates_enabled bool true
    else
      add automatic_updates_enabled bool false
    fi
  fi
}

collect_disk() {
  have findmnt && have lsblk || return 0
  src=$(findmnt -n -o SOURCE / 2>/dev/null)
  case "$src" in /dev/*) ;; *) return 0 ;; esac  # overlay, tmpfs, network roots: unknown
  types=$(lsblk -s -n -o TYPE "$src" 2>/dev/null) || return 0
  if printf '%s\n' "$types" | grep -qx crypt; then add root_fs_encrypted bool true; else add root_fs_encrypted bool false; fi
}

collect_mac() {
  if have getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    add mac_enforcing bool true
  elif [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ] && [ -s /sys/kernel/security/apparmor/profiles ]; then
    add mac_enforcing bool true
  elif [ -r /sys/module/apparmor/parameters/enabled ] || have getenforce; then
    add mac_enforcing bool false
  fi
}

running() {  # running NAME: systemd unit active, or a process of that name
  if have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; then return 0; fi
  have pgrep && pgrep -x "$1" >/dev/null 2>&1
}

collect_services() {
  if running auditd; then add auditd_running bool true; elif have systemctl || have pgrep; then add auditd_running bool false; fi
  if have timedatectl && ntp=$(timedatectl show -p NTP --value 2>/dev/null) && [ -n "$ntp" ]; then
    if [ "$ntp" = "yes" ] || running chronyd || running ntpd; then add time_sync_active bool true; else add time_sync_active bool false; fi
  elif running chronyd || running ntpd || running systemd-timesyncd; then
    add time_sync_active bool true
  fi
}

collect_accounts() {
  [ -r /etc/login.defs ] && add password_max_days int "$(awk '$1=="PASS_MAX_DAYS" {print $2; exit}' /etc/login.defs)"
  [ -r /etc/passwd ] && add uid0_accounts int "$(awk -F: '$3==0 && $1!="root"' /etc/passwd | grep -c .)"
  if [ -r /etc/sudoers ]; then
    n=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^[[:space:]]*#' | grep -c 'NOPASSWD') || true
    add sudo_nopasswd_rules int "${n:-0}"
  fi
}

collect_kernel() {
  v=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null) && { [ "$v" = 2 ]; add aslr_full bool "$(yn $?)"; }
  v=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) && { [ "$v" = 1 ]; add ip_forwarding_enabled bool "$(yn $?)"; }
}

os_field() { [ -r /etc/os-release ] && sed -n "s/^$1=//p" /etc/os-release | head -n1 | tr -d '"'; }

collect_json() {
  FACTS=""
  collect_firewall
  collect_ssh
  collect_updates
  collect_disk
  collect_mac
  collect_services
  collect_accounts
  collect_kernel
  host=$(hostname 2>/dev/null || uname -n)
  printf '{"hostname":%s,"os_name":%s,"os_version":%s,"agent_version":"%s","facts":{%s}}\n' \
    "$(json_str "$host")" "$(json_str "$(os_field PRETTY_NAME)")" "$(json_str "$(os_field VERSION_ID) $(uname -r)")" "$AGENT_VERSION" "$FACTS"
}

# ------------------------------------------------------------------------------------------------ transport

check_server() {
  case "$1" in
    https://*) ;;
    http://localhost|http://localhost:*|http://127.0.0.1|http://127.0.0.1:*) ;;  # local testing only
    *) die "the server address must start with https://" ;;
  esac
}

post() {  # post PATH BODYFILE [TOKENFILE] ; prints the response body
  hdr="$WORK/headers"
  printf 'Content-Type: application/json\n' >"$hdr"
  if [ -n "${3:-}" ]; then printf 'Authorization: Bearer %s\n' "$(cat "$3")" >>"$hdr"; fi
  # The token goes in a header file, never on the command line (visible to other users in ps).
  curl -fsS --max-time 60 --proto '=https,http' --proto-redir '=https' --tlsv1.2 -H "@$hdr" --data-binary "@$2" "$SERVER/api/agent/v1/$1"
}

load_conf() {
  [ -r "$CONF" ] || die "not installed (no $CONF). Run: sudo sh keystone-agent.sh install --server https://..."
  SERVER=$(sed -n 's/^SERVER=//p' "$CONF" | head -n1)
  [ -n "$SERVER" ] || die "no SERVER in $CONF"
  check_server "$SERVER"
}

enrol() {  # enrol KEY
  body="$WORK/enrol.json"
  printf '{"enrolment_key":%s,"hostname":%s,"platform":"linux","os_name":%s,"os_version":%s,"agent_version":"%s"}' \
    "$(json_str "$1")" "$(json_str "$(hostname 2>/dev/null || uname -n)")" "$(json_str "$(os_field PRETTY_NAME)")" "$(json_str "$(os_field VERSION_ID)")" "$AGENT_VERSION" >"$body"
  resp=$(post enrol "$body") || die "enrolment failed (check the server address and the enrolment key)"
  token=$(printf '%s' "$resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\(kagt_[A-Za-z0-9_-]*\)".*/\1/p')
  [ -n "$token" ] || die "the server's reply had no device token"
  ( umask 077; printf '%s' "$token" >"$TOKEN_FILE.tmp" ) && mv "$TOKEN_FILE.tmp" "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  say "enrolled with $SERVER"
}

run_report() {
  load_conf
  [ -s "$TOKEN_FILE" ] || die "not enrolled (no $TOKEN_FILE). Reinstall with an enrolment key."
  collect_json >"$WORK/report.json"
  post report "$WORK/report.json" "$TOKEN_FILE" >/dev/null || die "the report was not accepted"
  say "report sent"
}

# ------------------------------------------------------------------------------------------------ install

install_agent() {
  server="" hours=4
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) server="${2:-}"; shift 2 ;;
      --hours) hours="${2:-4}"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ "$(id -u)" = 0 ] || die "install needs root (sudo)"
  [ -n "$server" ] || die "give --server https://your-keystone-address"
  server=${server%/}
  check_server "$server"
  have curl || die "curl is required"
  case "$hours" in 1|2|4|8|12|24) ;; *) die "--hours must be 1, 2, 4, 8, 12 or 24" ;; esac
  key="${KEYSTONE_ENROLMENT_KEY:-}"
  if [ -z "$key" ] && [ -t 0 ]; then
    printf 'Enrolment key: ' >&2; stty -echo 2>/dev/null; read -r key; stty echo 2>/dev/null; printf '\n' >&2
  fi
  [ -n "$key" ] || die "set KEYSTONE_ENROLMENT_KEY (shown in Keystone under Configuration > Agents)"
  mkdir -p "$CONF_DIR" "$LIB_DIR" && chmod 700 "$CONF_DIR"
  cp "$0" "$LIB_DIR/keystone-agent.sh" && chmod 755 "$LIB_DIR/keystone-agent.sh"
  printf 'SERVER=%s\n' "$server" >"$CONF" && chmod 600 "$CONF"
  SERVER="$server"
  enrol "$key"
  if have systemctl && [ -d /run/systemd/system ]; then
    cat >"$UNIT_DIR/keystone-agent.service" <<EOF
[Unit]
Description=Keystone configuration agent (report-only)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh $LIB_DIR/keystone-agent.sh run
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
EOF
    cat >"$UNIT_DIR/keystone-agent.timer" <<EOF
[Unit]
Description=Run the Keystone configuration agent every $hours hour(s)

[Timer]
OnBootSec=5min
OnUnitActiveSec=${hours}h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now keystone-agent.timer >/dev/null 2>&1 || die "could not enable the systemd timer"
    say "installed: systemd timer every $hours hour(s)"
  else
    m=$(awk 'BEGIN {srand(); print int(rand()*60)}')
    printf '# Keystone configuration agent (report-only)\n%s */%s * * * root /bin/sh %s/keystone-agent.sh run >/dev/null 2>&1\n@reboot root sleep 300 && /bin/sh %s/keystone-agent.sh run >/dev/null 2>&1\n' \
      "$m" "$hours" "$LIB_DIR" "$LIB_DIR" >"$CRON_FILE"
    chmod 644 "$CRON_FILE"
    say "installed: cron every $hours hour(s) (no systemd found)"
  fi
  run_report || say "first report failed; the schedule will retry"
}

uninstall_agent() {
  [ "$(id -u)" = 0 ] || die "uninstall needs root (sudo)"
  if have systemctl && [ -f "$UNIT_DIR/keystone-agent.timer" ]; then
    systemctl disable --now keystone-agent.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/keystone-agent.timer" "$UNIT_DIR/keystone-agent.service"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$CRON_FILE"
  rm -rf "$CONF_DIR" "$LIB_DIR"
  say "removed. Delete the device in Keystone (Configuration > Targets) to remove its results."
}

status_agent() {
  load_conf
  printf 'server: %s\nenrolled: %s\n' "$SERVER" "$([ -s "$TOKEN_FILE" ] && echo yes || echo no)"
  if have systemctl && [ -f "$UNIT_DIR/keystone-agent.timer" ]; then systemctl list-timers keystone-agent.timer --no-pager 2>/dev/null | head -n2; fi
  [ -f "$CRON_FILE" ] && printf 'schedule: %s\n' "$CRON_FILE"
  return 0
}

WORK=$(mktemp -d 2>/dev/null) || die "cannot create a temporary directory"
trap 'rm -rf "$WORK"' EXIT INT TERM

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  install) install_agent "$@" ;;
  run) [ "$(id -u)" = 0 ] || say "not running as root: some settings can't be read and will show as unknown"; run_report ;;
  collect) collect_json ;;
  status) status_agent ;;
  uninstall) uninstall_agent ;;
  version) echo "$AGENT_VERSION" ;;
  *) printf 'usage: %s install --server URL [--hours N] | run | collect | status | uninstall | version\n' "$0" >&2; exit 2 ;;
esac
