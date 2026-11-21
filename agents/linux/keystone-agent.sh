#!/bin/sh
# Keystone configuration agent for Linux. Report-only: it reads security settings and sends them to Keystone over
# HTTPS. It never changes the host and never runs commands it is sent.
#
#   sudo KEYSTONE_ENROLMENT_KEY="kenr_..." sh keystone-agent.sh install --server https://keystone.example.org [--tags web,dmz] [--hours 4] [--no-custom-checks] [--pin sha256//...]
#   sudo sh keystone-agent.sh run         # check in, and report if one is due (the timer does this every hour)
#   sudo sh keystone-agent.sh report      # collect and report now
#   sh keystone-agent.sh collect          # print the built-in settings as JSON; sends nothing
#   sh keystone-agent.sh collect-custom FILE   # evaluate custom check definitions from FILE (tab-separated); sends nothing
#   sudo sh keystone-agent.sh status
#   sudo sh keystone-agent.sh uninstall
#
# Custom checks: administrators can define extra read-only checks in Keystone. The agent downloads their definitions
# and evaluates each one itself, within limits written into this script, not set by the server:
#   - a fixed list of probes (file setting, file contains, file exists, file mode/owner, service, package, sysctl,
#     kernel module, sshd setting); no commands, no scripts, no regular expressions
#   - strict character checks on every parameter (no "..", no shell syntax)
#   - probes that read file contents refuse password, key and home-directory files (deny_path below)
#   - at most 100 checks; values capped at 200 characters
# Install with --no-custom-checks to turn them off on this host; Keystone then shows them as unknown.
#
# --pin sha256//BASE64[;sha256//BASE64]: accept only a server whose public key has this hash (in addition to the
# normal certificate checks, never instead of them). Give a second pin for the next key before renewing a certificate.
#
# Files: /usr/local/lib/keystone-agent/keystone-agent.sh (this script), /etc/keystone-agent/agent.conf (server address
# and options, mode 600) and /etc/keystone-agent/token (this device's token, mode 600, readable by root only). The
# enrolment key is used once, at install, and is not kept. Needs: sh, curl. Runs as root so it can read sshd, sudoers
# and firewall state.
set -u

AGENT_VERSION="1.2.0"
CONF_DIR="${KEYSTONE_AGENT_CONF_DIR:-/etc/keystone-agent}"
LIB_DIR="${KEYSTONE_AGENT_LIB_DIR:-/usr/local/lib/keystone-agent}"
UNIT_DIR="${KEYSTONE_AGENT_UNIT_DIR:-/etc/systemd/system}"
CRON_FILE="${KEYSTONE_AGENT_CRON_FILE:-/etc/cron.d/keystone-agent}"
CONF="$CONF_DIR/agent.conf"
TOKEN_FILE="$CONF_DIR/token"
STATE_FILE="$CONF_DIR/last_report"
MAX_CHECKS=100
CUSTOM_CHECKS=1
HOURS=4
PIN=""
umask 077

die() { printf 'keystone-agent: %s\n' "$*" >&2; exit 1; }
say() { printf 'keystone-agent: %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
tm() { if have timeout; then timeout 20 "$@"; else "$@"; fi; }

# ------------------------------------------------------------------------------------------------ JSON helpers

json_str() {
  # Escape a value as a JSON string (backslash, quote, control characters dropped), at most 200 characters.
  printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\t\n\r' '   ' | cut -c1-200 |
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$/"/'
}

FACTS=""
CHECK_ERRS=""
add() {  # add KEY TYPE VALUE ; empty VALUE means "not known" and is left out
  [ -n "$3" ] || return 1
  case "$2" in
    bool) case "$3" in true|false) v="$3" ;; *) return 1 ;; esac ;;
    int) case "${3#-}" in ''|*[!0-9]*) return 1 ;; *) v="$3" ;; esac ;;
    str) v=$(json_str "$3") ;;
    *) return 1 ;;
  esac
  FACTS="${FACTS}${FACTS:+,}\"$1\":$v"
}
cerr() { CHECK_ERRS="${CHECK_ERRS}${CHECK_ERRS:+,}\"$1\":\"$2\""; }  # cerr KEY refused|missing|unsupported|error

yn() { if [ "$1" = 0 ]; then echo true; else echo false; fi; }  # exit status to true/false

# ------------------------------------------------------------------------------------------------ built-in settings

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

SSHD_T=""
sshd_value() { printf '%s\n' "$SSHD_T" | awk -v k="$1" '$1==k {sub(/^[^ \t]+[ \t]+/, ""); print; exit}'; }

collect_ssh() {
  if have sshd || [ -x /usr/sbin/sshd ]; then
    add ssh_server_installed bool true
    sshd_bin=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
    SSHD_T=$("$sshd_bin" -T 2>/dev/null) || SSHD_T=""
    if [ -n "$SSHD_T" ]; then
      add ssh_permit_root_login str "$(sshd_value permitrootlogin)"
      for pair in passwordauthentication:ssh_password_authentication x11forwarding:ssh_x11_forwarding permitemptypasswords:ssh_permit_empty_passwords; do
        case "$(sshd_value "${pair%%:*}")" in yes) add "${pair#*:}" bool true ;; no) add "${pair#*:}" bool false ;; esac
      done
      add ssh_max_auth_tries int "$(sshd_value maxauthtries)"
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

collect_builtin() {
  collect_firewall
  collect_ssh
  collect_updates
  collect_disk
  collect_mac
  collect_services
  collect_accounts
  collect_kernel
  return 0
}

# ------------------------------------------------------------------------------------------------ custom checks

deny_path() {  # true when a content-reading probe must not read this file. Mirrors keystone/configcheck/custom.py.
  lp=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
  case "$lp" in
    /etc/shadow*|/etc/gshadow*|/etc/security/opasswd*|/etc/ssl/private/*|/root/*|/home/*|*/.ssh/*|/proc/*/environ|/proc/*/mem|*.key|*.pem|*.p12|*.pfx|*.keytab|*/krb5.keytab|/var/lib/sss/*) return 0 ;;
    /users/*|/var/root/*|/private/var/root/*|/var/db/dslocal/*|/private/var/db/dslocal/*|*/keychains/*|*.keychain*|/etc/master.passwd|/private/etc/master.passwd) return 0 ;;
  esac
  return 1
}
ok_path() { case "$1" in /*) ;; *) return 1 ;; esac; case "$1" in *..*|*//*|*/./*|*[!A-Za-z0-9._/+@:-]*) return 1 ;; esac; [ ${#1} -le 251 ]; }
ok_name() { case "$1" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._@+:-]*) return 1 ;; esac; [ ${#1} -le 128 ]; }
ok_key() { case "$1" in ''|*[!A-Za-z0-9_.-]*) return 1 ;; esac; [ ${#1} -le 100 ]; }
ok_sysctl() { case "$1" in ''|.*|*..*|*[!a-z0-9_.-]*) return 1 ;; *.*) return 0 ;; esac; return 1; }
ok_sshd() { case "$1" in ''|*[!a-z0-9]*) return 1 ;; esac; [ ${#1} -le 60 ]; }
ok_text() { case "$1" in ''|*[![:print:]]*) return 1 ;; esac; [ ${#1} -le 200 ]; }

file_setting() {  # file_setting PATH KEY SEPARATOR: value of the first uncommented line with that key
  awk -v k="$2" -v sep="$3" '
    BEGIN { lk = tolower(k); ch = (sep == "equals") ? "=" : (sep == "colon") ? ":" : "" }
    /^[ \t]*#/ { next }
    {
      line = $0
      if (ch == "") {
        if (tolower($1) == lk) { sub(/^[ \t]*[^ \t]+[ \t]*/, "", line); print line; exit }
      } else {
        i = index(line, ch)
        if (i > 0) {
          kk = substr(line, 1, i - 1); gsub(/^[ \t]+|[ \t]+$/, "", kk)
          if (tolower(kk) == lk) { v = substr(line, i + 1); gsub(/^[ \t]+|[ \t]+$/, "", v); print v; exit }
        }
      }
    }' "$1"
}

probe() {  # probe NAME: prints the value; returns 0 ok, 2 refused, 3 missing, 4 unsupported, 5 error
  case "$1" in
    file_setting)
      ok_path "$P_path" && ok_key "$P_key" || return 2
      deny_path "$P_path" && return 2
      case "$P_separator" in whitespace|equals|colon) ;; *) return 2 ;; esac
      [ -r "$P_path" ] || return 3
      file_setting "$P_path" "$P_key" "$P_separator" ;;
    file_contains)
      ok_path "$P_path" && ok_text "$P_text" || return 2
      deny_path "$P_path" && return 2
      [ -r "$P_path" ] || return 3
      if grep -v '^[[:space:]]*#' "$P_path" | grep -F -q -- "$P_text"; then echo true; else echo false; fi ;;
    file_exists)
      ok_path "$P_path" || return 2
      if [ -e "$P_path" ]; then echo true; else echo false; fi ;;
    file_mode)
      ok_path "$P_path" || return 2
      [ -e "$P_path" ] || return 3
      case "$P_field" in mode) stat -c %a "$P_path" ;; owner) stat -c %U "$P_path" ;; group) stat -c %G "$P_path" ;; *) return 2 ;; esac ;;
    service)
      ok_name "$P_name" || return 2
      have systemctl || return 4
      case "$P_field" in
        state) out=$(tm systemctl is-active "$P_name" 2>/dev/null) ;;
        start_type) out=$(tm systemctl is-enabled "$P_name" 2>/dev/null) ;;
        *) return 2 ;;
      esac
      echo "${out:-absent}" ;;
    package_installed)
      ok_name "$P_name" || return 2
      if have dpkg-query; then
        st=$(tm dpkg-query -W -f='${Status}|${Version}' "$P_name" 2>/dev/null) || st=""
        case "$st" in *"install ok installed"*) present=true; ver=${st#*|} ;; *) present=false; ver="" ;; esac
      elif have rpm; then
        if ver=$(tm rpm -q --qf '%{VERSION}-%{RELEASE}' "$P_name" 2>/dev/null); then present=true; else present=false; ver=""; fi
      else
        return 4
      fi
      case "$P_field" in present) echo "$present" ;; version) [ -n "$ver" ] || return 3; echo "$ver" ;; *) return 2 ;; esac ;;
    sysctl)
      ok_sysctl "$P_key" || return 2
      f="/proc/sys/$(printf '%s' "$P_key" | tr . /)"
      [ -r "$f" ] || return 3
      tr '\t' ' ' <"$f" | head -n1 ;;
    kernel_module_loaded)
      ok_name "$P_name" || return 2
      [ -r /proc/modules ] || return 4
      if awk -v m="$P_name" '$1==m {f=1} END {exit !f}' /proc/modules; then echo true; else echo false; fi ;;
    sshd_effective)
      ok_sshd "$P_key" || return 2
      [ -n "$SSHD_T" ] || return 3
      out=$(sshd_value "$P_key")
      [ -n "$out" ] || return 3
      echo "$out" ;;
    *) return 4 ;;
  esac
}

run_custom() {  # run_custom FILE: evaluate tab-separated definitions (key, probe, type, name=value...)
  [ -s "$1" ] || return 0
  tab=$(printf '\t')
  count=0
  set -f
  while IFS="$tab" read -r key probe_name type rest; do
    [ -n "$key" ] || continue
    count=$((count + 1))
    [ "$count" -le "$MAX_CHECKS" ] || break
    case "$key" in custom.[a-z]*) ;; *) continue ;; esac
    case "$key" in *[!a-z0-9_.]*) continue ;; esac
    P_path="" P_key="" P_name="" P_text="" P_field="" P_separator="" P_default=""
    old_ifs=$IFS
    IFS="$tab"
    set -- $rest
    IFS=$old_ifs
    for pair in "$@"; do
      v=${pair#*=}
      case "${pair%%=*}" in
        path) P_path=$v ;; key) P_key=$v ;; name) P_name=$v ;; text) P_text=$v ;; field) P_field=$v ;;
        separator) P_separator=$v ;; default) P_default=$v ;;
      esac
    done
    value=$(probe "$probe_name")
    rc=$?
    if [ "$rc" = 3 ] && [ -n "$P_default" ]; then value=$P_default; rc=0; fi
    if [ "$rc" = 0 ] && [ -z "$value" ] && [ -n "$P_default" ]; then value=$P_default; fi
    case "$rc" in
      0) add "$key" "$type" "$value" || cerr "$key" error ;;
      2) cerr "$key" refused ;;
      3) cerr "$key" missing ;;
      4) cerr "$key" unsupported ;;
      *) cerr "$key" error ;;
    esac
  done <"$1"
  set +f
}

self_sha() { if have sha256sum; then sha256sum "$0" 2>/dev/null | cut -d' ' -f1; fi; }

report_json() {
  host=$(hostname 2>/dev/null || uname -n)
  extra=""
  [ "$CUSTOM_CHECKS" = 1 ] || extra=',"custom_checks":"disabled"'
  printf '{"hostname":%s,"os_name":%s,"os_version":%s,"agent_version":"%s","agent_sha256":"%s","facts":{%s},"check_errors":{%s}%s}\n' \
    "$(json_str "$host")" "$(json_str "$(os_field PRETTY_NAME)")" "$(json_str "$(os_field VERSION_ID) $(uname -r)")" "$AGENT_VERSION" "$(self_sha)" "$FACTS" "$CHECK_ERRS" "$extra"
}

# ------------------------------------------------------------------------------------------------ transport

check_server() {
  case "$1" in
    https://*) ;;
    http://localhost|http://localhost:*|http://127.0.0.1|http://127.0.0.1:*) ;;  # local testing only
    *) die "the server address must start with https://" ;;
  esac
}

check_pin() {  # one or two sha256//BASE64 pins separated by ";"
  [ -n "$1" ] || return 0
  old_ifs=$IFS; IFS=";"; set -f
  n=0
  for p in $1; do
    n=$((n + 1))
    case "$p" in sha256//*) ;; *) die "--pin: give sha256//BASE64 (the base64 SHA-256 of the server's public key)" ;; esac
    b=${p#sha256//}
    case "$b" in *[!A-Za-z0-9+/=]*) die "--pin: not base64" ;; esac
    [ ${#b} = 44 ] || die "--pin: a SHA-256 in base64 is 44 characters"
  done
  set +f; IFS=$old_ifs
  [ "$n" -le 2 ] || die "--pin: at most two pins (the current key and the next one)"
}

headers() {  # headers [TOKENFILE]: a curl header file. The token never goes on the command line (visible in ps).
  hdr="$WORK/headers"
  printf 'Content-Type: application/json\n' >"$hdr"
  if [ -n "${1:-}" ]; then printf 'Authorization: Bearer %s\n' "$(cat "$1")" >>"$hdr"; fi
  echo "$hdr"
}

kcurl() {  # HTTP only for localhost (check_server); a pin is checked on top of the normal certificate checks
  if [ -n "$PIN" ]; then
    curl -fsS --max-time 60 --proto '=https,http' --proto-redir '=https' --tlsv1.2 --pinnedpubkey "$PIN" "$@"
  else
    curl -fsS --max-time 60 --proto '=https,http' --proto-redir '=https' --tlsv1.2 "$@"
  fi
}

post() {  # post PATH BODYFILE [TOKENFILE] ; prints the response body
  kcurl -H "@$(headers "${3:-}")" --data-binary "@$2" "$SERVER/api/agent/v1/$1"
}

get_checks() {  # the custom check definitions for this host, tab-separated, capped at 64 KB
  kcurl --max-filesize 65536 -H "@$(headers "$TOKEN_FILE")" "$SERVER/api/agent/v1/checks?format=lines"
}

conf_value() { sed -n "s/^$1=//p" "$CONF" | head -n1; }

load_conf() {
  [ -r "$CONF" ] || die "not installed (no $CONF). Run: sudo sh keystone-agent.sh install --server https://..."
  SERVER=$(conf_value SERVER)
  [ -n "$SERVER" ] || die "no SERVER in $CONF"
  check_server "$SERVER"
  case "$(conf_value CUSTOM_CHECKS)" in 0) CUSTOM_CHECKS=0 ;; *) CUSTOM_CHECKS=1 ;; esac
  case "$(conf_value HOURS)" in 1|2|4|8|12|24) HOURS=$(conf_value HOURS) ;; *) HOURS=4 ;; esac
  PIN=$(conf_value PIN)
  check_pin "$PIN"
}

tags_json() {  # tags_json "a,b": validated JSON list
  out=""
  old_ifs=$IFS
  IFS=,
  set -f
  for t in $1; do
    case "$t" in ''|[!a-z0-9]*|*[!a-z0-9_-]*) die "tag '$t': lower-case letters, digits, - and _ only" ;; esac
    out="${out}${out:+,}\"$t\""
  done
  set +f
  IFS=$old_ifs
  printf '[%s]' "$out"
}

enrol() {  # enrol KEY TAGS
  body="$WORK/enrol.json"
  printf '{"enrolment_key":%s,"hostname":%s,"platform":"linux","os_name":%s,"os_version":%s,"agent_version":"%s","tags":%s}' \
    "$(json_str "$1")" "$(json_str "$(hostname 2>/dev/null || uname -n)")" "$(json_str "$(os_field PRETTY_NAME)")" "$(json_str "$(os_field VERSION_ID)")" "$AGENT_VERSION" \
    "$(tags_json "${2:-}")" >"$body"
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
  collect_builtin
  if [ "$CUSTOM_CHECKS" = 1 ]; then
    if get_checks >"$WORK/checks.tsv"; then run_custom "$WORK/checks.tsv"; else say "could not fetch custom checks; sending the built-in settings only"; fi
  fi
  report_json >"$WORK/report.json"
  post report "$WORK/report.json" "$TOKEN_FILE" >/dev/null || die "the report was not accepted"
  date +%s >"$STATE_FILE" 2>/dev/null || true
  say "report sent"
}

run_agent() {  # the hourly entry point: check in, and report when Keystone says one is due or --hours has passed
  load_conf
  [ -s "$TOKEN_FILE" ] || die "not enrolled (no $TOKEN_FILE). Reinstall with an enrolment key."
  printf '{"agent_version":"%s","agent_sha256":"%s"}' "$AGENT_VERSION" "$(self_sha)" >"$WORK/checkin.json"
  due=1
  if resp=$(post checkin "$WORK/checkin.json" "$TOKEN_FILE" 2>/dev/null); then
    case "$resp" in *'"report_due":false'*|*'"report_due": false'*) due=0 ;; esac
  fi
  last=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  [ $(( $(date +%s) - last )) -ge $(( HOURS * 3600 - 600 )) ] && due=1
  if [ "$due" = 1 ]; then run_report; fi
}

# ------------------------------------------------------------------------------------------------ install

install_agent() {
  server="" hours=4 tags="" custom=1 pin=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) server="${2:-}"; shift 2 ;;
      --hours) hours="${2:-4}"; shift 2 ;;
      --tags) tags="${2:-}"; shift 2 ;;
      --pin) pin="${2:-}"; shift 2 ;;
      --no-custom-checks) custom=0; shift ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ "$(id -u)" = 0 ] || die "install needs root (sudo)"
  [ -n "$server" ] || die "give --server https://your-keystone-address"
  server=${server%/}
  check_server "$server"
  check_pin "$pin"
  have curl || die "curl is required"
  case "$hours" in 1|2|4|8|12|24) ;; *) die "--hours must be 1, 2, 4, 8, 12 or 24" ;; esac
  tags_json "$tags" >/dev/null
  key="${KEYSTONE_ENROLMENT_KEY:-}"
  if [ -z "$key" ] && [ -t 0 ]; then
    printf 'Enrolment key: ' >&2; stty -echo 2>/dev/null; read -r key; stty echo 2>/dev/null; printf '\n' >&2
  fi
  [ -n "$key" ] || die "set KEYSTONE_ENROLMENT_KEY (shown in Keystone under Configuration > Agents)"
  mkdir -p "$CONF_DIR" "$LIB_DIR" && chmod 700 "$CONF_DIR"
  cp "$0" "$LIB_DIR/keystone-agent.sh" && chmod 755 "$LIB_DIR/keystone-agent.sh"
  printf 'SERVER=%s\nCUSTOM_CHECKS=%s\nHOURS=%s\nPIN=%s\n' "$server" "$custom" "$hours" "$pin" >"$CONF" && chmod 600 "$CONF"
  SERVER="$server" PIN="$pin"
  enrol "$key" "$tags"
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
Description=Check in with Keystone every hour (reports at least every $hours hour(s))

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now keystone-agent.timer >/dev/null 2>&1 || die "could not enable the systemd timer"
    say "installed: systemd timer, checks in every hour and reports at least every $hours hour(s)"
  else
    m=$(awk 'BEGIN {srand(); print int(rand()*60)}')
    printf '# Keystone configuration agent (report-only)\n%s * * * * root /bin/sh %s/keystone-agent.sh run >/dev/null 2>&1\n@reboot root sleep 300 && /bin/sh %s/keystone-agent.sh run >/dev/null 2>&1\n' \
      "$m" "$LIB_DIR" "$LIB_DIR" >"$CRON_FILE"
    chmod 644 "$CRON_FILE"
    say "installed: cron, checks in every hour and reports at least every $hours hour(s) (no systemd found)"
  fi
  [ "$custom" = 1 ] || say "custom checks are turned off on this host"
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
  printf 'server: %s\nenrolled: %s\ncustom checks: %s\nreports at least every: %s hour(s)\npinned: %s\nversion: %s\n' "$SERVER" "$([ -s "$TOKEN_FILE" ] && echo yes || echo no)" \
    "$([ "$CUSTOM_CHECKS" = 1 ] && echo on || echo off)" "$HOURS" "$([ -n "$PIN" ] && echo yes || echo no)" "$AGENT_VERSION"
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
  run) [ "$(id -u)" = 0 ] || say "not running as root: some settings can't be read and will show as unknown"; run_agent ;;
  report) run_report ;;
  collect) collect_builtin; report_json ;;
  collect-custom) [ -n "${1:-}" ] || die "give a file of check definitions"; collect_builtin; FACTS=""; run_custom "$1"; report_json ;;
  status) status_agent ;;
  uninstall) uninstall_agent ;;
  version) echo "$AGENT_VERSION" ;;
  *) printf 'usage: %s install --server URL [--tags a,b] [--hours N] [--no-custom-checks] [--pin sha256//...] | run | report | collect | collect-custom FILE | status | uninstall | version\n' "$0" >&2; exit 2 ;;
esac
