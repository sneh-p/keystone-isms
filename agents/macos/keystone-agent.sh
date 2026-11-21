#!/bin/sh
# Keystone configuration agent for macOS. Report-only: it reads security settings and sends them to Keystone over
# HTTPS. It never changes the Mac and never runs commands it is sent.
#
#   sudo KEYSTONE_ENROLMENT_KEY="kenr_..." sh keystone-agent-macos.sh install --server https://keystone.example.org [--tags laptops] [--hours 4] [--no-custom-checks] [--pin sha256//...]
#   sudo sh keystone-agent-macos.sh run       # check in, and report if one is due (launchd does this every hour)
#   sudo sh keystone-agent-macos.sh report    # collect and report now
#   sh keystone-agent-macos.sh collect        # print the built-in settings as JSON; sends nothing
#   sh keystone-agent-macos.sh collect-custom FILE   # evaluate custom check definitions from FILE (tab-separated); sends nothing
#   sudo sh keystone-agent-macos.sh status
#   sudo sh keystone-agent-macos.sh uninstall
#
# Custom checks: administrators can define extra read-only checks in Keystone. The agent downloads their definitions
# and evaluates each one itself, within limits written into this script, not set by the server:
#   - a fixed list of probes (file setting, file contains, file exists, file mode/owner, kernel parameter, property
#     list value, installed app, background service); no commands, no scripts, no regular expressions
#   - strict character checks on every parameter (no "..", no shell syntax)
#   - probes that read contents refuse password stores, keychains, keys and home folders (deny_path below)
#   - at most 100 checks; values capped at 200 characters
# Install with --no-custom-checks to turn them off on this Mac; Keystone then shows them as unknown.
#
# --pin sha256//BASE64[;sha256//BASE64]: accept only a server whose public key has this hash (in addition to the
# normal certificate checks, never instead of them). Give a second pin for the next key before renewing a certificate.
#
# Files: /usr/local/lib/keystone-agent/keystone-agent.sh (this script), /etc/keystone-agent/agent.conf (server address
# and options, mode 600), /etc/keystone-agent/token (this device's token, mode 600, root only) and
# /Library/LaunchDaemons/org.keystone.agent.plist (runs `run` every hour). The enrolment key is used once, at install,
# and is not kept. Needs: sh, curl (both part of macOS). Runs as root so it can read FileVault and firewall state.
set -u

AGENT_VERSION="1.2.0"
CONF_DIR="${KEYSTONE_AGENT_CONF_DIR:-/etc/keystone-agent}"
LIB_DIR="${KEYSTONE_AGENT_LIB_DIR:-/usr/local/lib/keystone-agent}"
PLIST="${KEYSTONE_AGENT_PLIST:-/Library/LaunchDaemons/org.keystone.agent.plist}"
LABEL="org.keystone.agent"
CONF="$CONF_DIR/agent.conf"
TOKEN_FILE="$CONF_DIR/token"
STATE_FILE="$CONF_DIR/last_report"
MAX_CHECKS=100
CUSTOM_CHECKS=1
HOURS=4
PIN=""
umask 077
# System tools only. KEYSTONE_AGENT_EXTRA_PATH puts stand-in tools first, for Keystone's own tests on other systems.
PATH="${KEYSTONE_AGENT_EXTRA_PATH:+$KEYSTONE_AGENT_EXTRA_PATH:}/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec:/usr/libexec/ApplicationFirewall"
export PATH

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

loaded() { launchctl print "system/$1" >/dev/null 2>&1; }  # a system launchd service is loaded
pref() { defaults read "$1" "$2" 2>/dev/null; }  # a top-level preference value, empty when not set

# ------------------------------------------------------------------------------------------------ built-in settings

collect_firewall() {
  have socketfilterfw || return 0
  out=$(socketfilterfw --getglobalstate 2>/dev/null) || out=""
  case "$out" in
    *disabled*|*"State = 0"*) add firewall_active bool false ;;
    *enabled*|*"State = 1"*|*"State = 2"*) add firewall_active bool true ;;
  esac
  out=$(socketfilterfw --getstealthmode 2>/dev/null) || out=""
  case "$out" in
    *disabled*|*" off"*) add firewall_stealth_mode bool false ;;
    *enabled*|*" on"*) add firewall_stealth_mode bool true ;;
  esac
}

collect_protection() {
  if have fdesetup; then
    case "$(fdesetup status 2>/dev/null)" in
      *"FileVault is On"*) add filevault_enabled bool true ;;
      *"FileVault is Off"*) add filevault_enabled bool false ;;
    esac
  fi
  if have spctl; then
    case "$(spctl --status 2>&1)" in
      *"assessments disabled"*) add gatekeeper_enabled bool false ;;
      *"assessments enabled"*) add gatekeeper_enabled bool true ;;
    esac
  fi
  if have csrutil; then
    case "$(csrutil status 2>/dev/null)" in
      *"status: disabled"*) add sip_enabled bool false ;;
      *"status: enabled"*) add sip_enabled bool true ;;
    esac  # "unknown (Custom Configuration)" stays unknown
  fi
}

collect_updates() {
  p=/Library/Preferences/com.apple.SoftwareUpdate
  check=$(pref "$p" AutomaticCheckEnabled)
  crit=$(pref "$p" CriticalUpdateInstall)
  if [ "$check" = 0 ] || [ "$crit" = 0 ]; then
    add automatic_updates_enabled bool false
  elif [ "$check" = 1 ] && [ "$crit" = 1 ]; then
    add automatic_updates_enabled bool true
  elif have softwareupdate; then
    case "$(softwareupdate --schedule 2>/dev/null)" in
      *" off"*|*"turned off"*) add automatic_updates_enabled bool false ;;
      *" on"*|*"turned on"*) [ "$crit" != 0 ] && add automatic_updates_enabled bool true ;;
    esac
  fi
}

SSHD_T=""
sshd_value() { printf '%s\n' "$SSHD_T" | awk -v k="$1" '$1==k {sub(/^[^ \t]+[ \t]+/, ""); print; exit}'; }

collect_sharing() {
  if loaded com.openssh.sshd; then
    add remote_login_enabled bool true
    SSHD_T=$(sshd -T 2>/dev/null) || SSHD_T=""
    if [ -n "$SSHD_T" ]; then
      add ssh_permit_root_login str "$(sshd_value permitrootlogin)"
      case "$(sshd_value passwordauthentication)" in yes) add ssh_password_authentication bool true ;; no) add ssh_password_authentication bool false ;; esac
    fi
  else
    add remote_login_enabled bool false
  fi
  if loaded com.apple.screensharing; then add screen_sharing_enabled bool true; else add screen_sharing_enabled bool false; fi
}

collect_accounts() {
  lw=/Library/Preferences/com.apple.loginwindow
  case "$(pref "$lw" GuestEnabled)" in 1) add guest_account_enabled bool true ;; 0) add guest_account_enabled bool false ;; esac
  if [ -n "$(pref "$lw" autoLoginUser)" ]; then add auto_login_enabled bool true; else add auto_login_enabled bool false; fi
  if have dscl; then
    members=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null) && \
      add local_admin_count int "$(printf '%s\n' "${members#GroupMembership:}" | tr ' ' '\n' | grep -v '^root$' | grep -c .)"
  fi
  if have systemsetup; then
    case "$(systemsetup -getusingnetworktime 2>/dev/null)" in
      *"Network Time: On"*) add time_sync_active bool true ;;
      *"Network Time: Off"*) add time_sync_active bool false ;;
    esac
  fi
}

collect_builtin() {
  collect_firewall
  collect_protection
  collect_updates
  collect_sharing
  collect_accounts
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
ok_path() { case "$1" in /*) ;; *) return 1 ;; esac; case "$1" in *..*|*//*|*/./*|*[!A-Za-z0-9._/+@:\ -]*) return 1 ;; esac; [ ${#1} -le 251 ]; }
ok_key() { case "$1" in ''|*[!A-Za-z0-9_.-]*) return 1 ;; esac; [ ${#1} -le 100 ]; }
ok_sysctl() { case "$1" in ''|.*|*..*|*[!a-z0-9_.-]*) return 1 ;; *.*) return 0 ;; esac; return 1; }
ok_text() { case "$1" in ''|*[![:print:]]*) return 1 ;; esac; [ ${#1} -le 200 ]; }
ok_app() { case "$1" in ''|[!A-Za-z0-9]*|*..*|*[!A-Za-z0-9\ ._\(\)+-]*) return 1 ;; esac; [ ${#1} -le 100 ]; }
ok_label() { case "$1" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._-]*) return 1 ;; esac; [ ${#1} -le 128 ]; }

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

plist_print() { PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }  # KEY is checked by ok_key: no spaces, colons or quotes

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
      case "$P_field" in mode) stat -f %Lp "$P_path" ;; owner) stat -f %Su "$P_path" ;; group) stat -f %Sg "$P_path" ;; *) return 2 ;; esac ;;
    sysctl)
      ok_sysctl "$P_key" || return 2
      out=$(sysctl -n "$P_key" 2>/dev/null) || return 3
      printf '%s\n' "$out" | head -n1 ;;
    plist_value)
      ok_path "$P_path" && ok_key "$P_key" || return 2
      deny_path "$P_path" && return 2
      case "$P_path" in *.plist) ;; *) return 2 ;; esac
      [ -r "$P_path" ] || return 3
      case "$P_mode" in
        exists) if plist_print "$P_path" "$P_key" >/dev/null; then echo true; else echo false; fi ;;
        value)
          out=$(plist_print "$P_path" "$P_key") || return 3
          case "$out" in *"{"*|*"("*) return 5 ;; esac  # a dictionary or array, not a single value
          printf '%s\n' "$out" | head -n1 ;;
        *) return 2 ;;
      esac ;;
    app_installed)
      ok_app "$P_name" || return 2
      app="/Applications/$P_name.app"
      case "$P_field" in
        present) if [ -d "$app" ]; then echo true; else echo false; fi ;;
        version) [ -d "$app" ] || return 3; plist_print "$app/Contents/Info.plist" CFBundleShortVersionString || return 3 ;;
        *) return 2 ;;
      esac ;;
    launchd_service)
      ok_label "$P_label" || return 2
      if loaded "$P_label"; then echo true; else echo false; fi ;;
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
    P_path="" P_key="" P_name="" P_text="" P_field="" P_separator="" P_default="" P_mode="" P_label=""
    old_ifs=$IFS
    IFS="$tab"
    set -- $rest
    IFS=$old_ifs
    for pair in "$@"; do
      v=${pair#*=}
      case "${pair%%=*}" in
        path) P_path=$v ;; key) P_key=$v ;; name) P_name=$v ;; text) P_text=$v ;; field) P_field=$v ;;
        separator) P_separator=$v ;; default) P_default=$v ;; mode) P_mode=$v ;; label) P_label=$v ;;
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

host_name() { scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || uname -n; }
self_sha() { shasum -a 256 "$0" 2>/dev/null | awk '{print $1}'; }

report_json() {
  extra=""
  [ "$CUSTOM_CHECKS" = 1 ] || extra=',"custom_checks":"disabled"'
  printf '{"hostname":%s,"os_name":%s,"os_version":%s,"agent_version":"%s","agent_sha256":"%s","facts":{%s},"check_errors":{%s}%s}\n' \
    "$(json_str "$(host_name)")" "$(json_str "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)")" \
    "$(json_str "$(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))")" "$AGENT_VERSION" "$(self_sha)" "$FACTS" "$CHECK_ERRS" "$extra"
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
  [ -r "$CONF" ] || die "not installed (no $CONF). Run: sudo sh keystone-agent-macos.sh install --server https://..."
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
  printf '{"enrolment_key":%s,"hostname":%s,"platform":"macos","os_name":%s,"os_version":%s,"agent_version":"%s","tags":%s}' \
    "$(json_str "$1")" "$(json_str "$(host_name)")" "$(json_str "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)")" \
    "$(json_str "$(sw_vers -productVersion 2>/dev/null)")" "$AGENT_VERSION" "$(tags_json "${2:-}")" >"$body"
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
  cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>$LIB_DIR/keystone-agent.sh</string><string>run</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>LowPriorityIO</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
EOF
  chmod 644 "$PLIST" && chown root:wheel "$PLIST"
  launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap system "$PLIST" || die "could not load the launchd service"
  say "installed: checks in every hour, reports at least every $hours hour(s)"
  [ "$custom" = 1 ] || say "custom checks are turned off on this Mac"
}

uninstall_agent() {
  [ "$(id -u)" = 0 ] || die "uninstall needs root (sudo)"
  launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
  rm -f "$PLIST"
  rm -rf "$CONF_DIR" "$LIB_DIR"
  say "removed. Delete the device in Keystone (Configuration > Targets) to remove its results."
}

status_agent() {
  load_conf
  printf 'server: %s\nenrolled: %s\ncustom checks: %s\nreports at least every: %s hour(s)\npinned: %s\nversion: %s\n' "$SERVER" \
    "$([ -s "$TOKEN_FILE" ] && echo yes || echo no)" "$([ "$CUSTOM_CHECKS" = 1 ] && echo on || echo off)" "$HOURS" "$([ -n "$PIN" ] && echo yes || echo no)" "$AGENT_VERSION"
  if loaded "$LABEL"; then echo "launchd: loaded"; else echo "launchd: not loaded"; fi
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
