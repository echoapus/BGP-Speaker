#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -h|--help) echo 'Usage: ./install.sh — interactive setup or upgrade in /opt/megaphone'; exit 0 ;;
  '') ;;
  *) echo 'Unknown option. Use --help.' >&2; exit 2 ;;
esac
stage='setup'
trap 'echo "Installation failed during $stage. Review the error above; existing config backups are in /opt/megaphone/config.toml.bak.* when created." >&2' ERR
trap 'echo "Setup interrupted; installation may be incomplete." >&2; exit 130' INT

# Build as the invoking user; use elevated privileges only for system installation.
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_dir=/opt/megaphone
build_dir=
rustup_script=
config_tmp=
cleanup() {
  if [ -n "$rustup_script" ]; then rm -f -- "$rustup_script"; fi
  if [ -n "$config_tmp" ]; then rm -f -- "$config_tmp"; fi
  if [ -n "$build_dir" ]; then rm -rf -- "$build_dir"; fi
}
trap cleanup EXIT
os=$(uname -s)
case "$os" in
  Linux|Darwin) ;;
  *) echo 'Only Linux and macOS are supported.' >&2; exit 1 ;;
esac
# Never empty: macOS bash 3.2 fails on an empty array under set -u.
priv=(env)
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || { echo 'sudo is required.' >&2; exit 1; }
  priv=(sudo)
fi
if [ ! -t 0 ]; then
  echo 'Run ./install.sh from an interactive terminal to configure installation.' >&2
  exit 1
fi
echo 'Megaphone setup'
echo 'Install location: /opt/megaphone (existing peers and routes are preserved).'
echo 'The web dashboard has no login. Use localhost or a trusted private network.'
echo 'Press Enter to accept a default; Ctrl+C cancels setup.'
while :; do
  read -r -p 'Web port [8080]: ' port
  port=${port:-8080}
  if [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)); then
    port=$((10#$port))
    break
  fi
  echo 'Enter a port between 1 and 65535.'
done
while :; do
  read -r -p 'Web listen address [127.0.0.1]: ' bind
  bind=${bind:-127.0.0.1}
  if [[ "$bind" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    valid=yes
    IFS=. read -r a b c d <<< "$bind"
    for octet in "$a" "$b" "$c" "$d"; do
      if ((10#$octet > 255)); then valid=no; fi
    done
    if [ "$valid" = yes ]; then break; fi
  fi
  echo 'Enter an IPv4 address, for example 0.0.0.0 or 127.0.0.1.'
done
while :; do
  read -r -p 'Install and enable a startup service? [y/N]: ' service
  case "$service" in
    y|Y|yes|YES) service=yes; break ;;
    ''|n|N|no|NO) service=no; break ;;
    *) echo 'Enter y or n.' ;;
  esac
done
init_system=none
if [ "$os" = Linux ]; then
  if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    init_system=systemd
  elif command -v rc-service >/dev/null && command -v rc-update >/dev/null && command -v supervise-daemon >/dev/null; then
    init_system=openrc
  fi
  if [ "$service" = yes ] && [ "$init_system" = none ]; then
    echo 'Service installation requires systemd or OpenRC with supervise-daemon.' >&2; exit 1
  fi
fi
if [ "$os" = Darwin ]; then init_system=launchd; fi
echo
echo 'Install plan'
echo '============'
echo 'Application:       megaphone'
echo "Install directory: $install_dir"
echo 'Command link:      none (run /opt/megaphone/megaphone directly)'
echo 'Configuration:     /opt/megaphone/config.toml'
echo "Web listener:      $bind:$port"
echo "Service manager:   $init_system"
echo "Enable startup:    $service"
if [ "$service" = yes ]; then
  case "$init_system" in
    systemd) echo 'Systemd unit:      /etc/systemd/system/megaphone.service' ;;
    openrc) echo 'OpenRC service:    /etc/init.d/megaphone' ;;
    launchd) echo 'Launchd service:   /Library/LaunchDaemons/com.megaphone.speaker.plist' ;;
  esac
fi
echo 'Existing data:     preserved; existing config backed up before changes'
echo 'Temporary files:   removed on exit'
echo
read -r -p "Install megaphone? Type 'yes' to continue: " confirm
case "$confirm" in yes) ;; *) echo 'Cancelled; no installation changes made.'; exit 0 ;; esac
if [ "$os" = Linux ] && { ! command -v cc >/dev/null || ! command -v curl >/dev/null; }; then
  stage='system dependencies'
  echo 'Preparing required system packages...'
  if command -v apt-get >/dev/null; then
    "${priv[@]}" apt-get update
    "${priv[@]}" apt-get install -y build-essential curl ca-certificates
  elif command -v dnf >/dev/null; then
    # RHEL minimal images may ship curl-minimal, which conflicts with curl.
    "${priv[@]}" dnf install -y gcc make ca-certificates
    command -v curl >/dev/null || "${priv[@]}" dnf install -y curl
  elif command -v yum >/dev/null; then
    "${priv[@]}" yum install -y gcc make ca-certificates
    command -v curl >/dev/null || "${priv[@]}" yum install -y curl
  elif command -v pacman >/dev/null; then
    "${priv[@]}" pacman -S --needed --noconfirm base-devel curl ca-certificates
  else
    echo 'Install a C compiler, curl and CA certificates using your package manager.' >&2; exit 1
  fi
fi
if [ "$os" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then
  xcode-select --install
  echo 'Complete the Command Line Tools installer, then run this script again.'
  exit 1
fi
if ! command -v cargo >/dev/null && [ -f "$HOME/.cargo/env" ]; then
  . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null; then
  stage='Rust toolchain setup'
  echo 'Installing the minimal Rust toolchain...'
  rustup_script=$(mktemp)
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$rustup_script"
  sh "$rustup_script" -y --profile minimal
  . "$HOME/.cargo/env"
fi
# Keep installer build artifacts separate from the developer's target directory.
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/megaphone-build.XXXXXX")
echo 'Building Megaphone (the first build may take a few minutes)...'
stage='compilation'
cargo build --release --locked --manifest-path "$source_dir/Cargo.toml" --target-dir "$build_dir"
stage='installing files and configuring the service'
echo 'Installing files and applying startup settings...'
"${priv[@]}" mkdir -p "$install_dir"
if [ -e "$install_dir/config.toml" ]; then
  echo 'Existing config found; saving a backup before changing the Web port.'
  "${priv[@]}" cp -p "$install_dir/config.toml" "$install_dir/config.toml.bak.$(date +%s)"
fi
config_tmp=$(mktemp)
# api_listen is inserted in [server], preserving existing peers and routes.
# A new install starts blank: no peers or routes, everything is added in the web UI.
{ if [ -e "$install_dir/config.toml" ]; then "${priv[@]}" cat -- "$install_dir/config.toml"; else echo '[server]'; fi; } | awk -v port="$port" -v bind="$bind" '
  /^\[server\][[:space:]]*$/ {
    server=1; found=1; print; print "api_listen = \"" bind ":" port "\""
    next
  }
  /^\[/ { server=0 }
  server && /^[[:space:]]*api_listen[[:space:]]*=/ { next }
  { print }
  END { if (!found) exit 1 }
' > "$config_tmp" || { echo 'Config needs a [server] section.' >&2; exit 1; }
if [ "$os" = Linux ] && command -v systemctl >/dev/null && "${priv[@]}" systemctl is-active --quiet megaphone.service; then
  "${priv[@]}" systemctl stop megaphone.service
fi
if [ "$os" = Darwin ] && "${priv[@]}" launchctl print system/com.megaphone.speaker >/dev/null 2>&1; then
  "${priv[@]}" launchctl bootout system/com.megaphone.speaker
fi
if [ "$init_system" = openrc ] && [ -f /etc/init.d/megaphone ]; then
  if "${priv[@]}" rc-service megaphone status >/dev/null 2>&1; then
    "${priv[@]}" rc-service megaphone stop
  fi
fi
# Linux services run as an unprivileged user that may only bind port 179.
owner=(-o root)
if [ "$init_system" = systemd ] && [ "$service" = yes ]; then
  nologin_shell=/usr/sbin/nologin
  if [ ! -x "$nologin_shell" ]; then nologin_shell=/sbin/nologin; fi
  id megaphone >/dev/null 2>&1 || "${priv[@]}" useradd --system --no-create-home --shell "$nologin_shell" megaphone
  owner=(-o megaphone)
fi
"${priv[@]}" install -m 755 "$build_dir/release/megaphone" "$install_dir/megaphone"
"${priv[@]}" install -m 600 "${owner[@]}" "$config_tmp" "$install_dir/config.toml"
"${priv[@]}" install -m 755 "$source_dir/uninstall.sh" "$install_dir/uninstall.sh"
echo 'Executable:        installed /opt/megaphone/megaphone'
echo 'Configuration:     installed /opt/megaphone/config.toml'
echo 'Uninstaller:       installed /opt/megaphone/uninstall.sh'
if [ "$os" = Linux ] && command -v restorecon >/dev/null; then
  "${priv[@]}" restorecon -R "$install_dir"
fi
if [ "$service" = yes ]; then
  if [ "$init_system" = openrc ]; then
    cat > "$config_tmp" <<'OPENRC'
#!/sbin/openrc-run
description="Megaphone BGP Speaker"
command="/opt/megaphone/megaphone"
command_args="--config /opt/megaphone/config.toml"
directory="/opt/megaphone"
supervisor="supervise-daemon"
respawn_delay=5
output_log="/opt/megaphone/service.log"
error_log="/opt/megaphone/service.log"
depend() {
    need net
}
OPENRC
    "${priv[@]}" install -m 755 "$config_tmp" /etc/init.d/megaphone
    "${priv[@]}" rc-update add megaphone default
    "${priv[@]}" rc-service megaphone start
    echo 'OpenRC service:    installed and started /etc/init.d/megaphone'
  elif [ "$os" = Linux ]; then
    cat > "$config_tmp" <<'UNIT'
[Unit]
Description=Megaphone BGP Speaker
After=network.target

[Service]
ExecStart=/opt/megaphone/megaphone --config /opt/megaphone/config.toml
WorkingDirectory=/opt/megaphone
Restart=always
RestartSec=5
StandardInput=null
User=megaphone
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
    "${priv[@]}" install -m 644 "$config_tmp" /etc/systemd/system/megaphone.service
    if command -v restorecon >/dev/null; then
      "${priv[@]}" restorecon /etc/systemd/system/megaphone.service
    fi
    "${priv[@]}" systemctl daemon-reload
    "${priv[@]}" systemctl enable --now megaphone.service
    echo 'Systemd unit:      installed and started /etc/systemd/system/megaphone.service'
  else
    cat > "$config_tmp" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.megaphone.speaker</string>
<key>ProgramArguments</key><array><string>/opt/megaphone/megaphone</string><string>--config</string><string>/opt/megaphone/config.toml</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>/opt/megaphone/service.log</string>
<key>StandardErrorPath</key><string>/opt/megaphone/service.log</string>
</dict></plist>
PLIST
    "${priv[@]}" install -m 644 "$config_tmp" /Library/LaunchDaemons/com.megaphone.speaker.plist
    "${priv[@]}" launchctl enable system/com.megaphone.speaker
    "${priv[@]}" launchctl bootstrap system /Library/LaunchDaemons/com.megaphone.speaker.plist
    echo 'Launchd service:   installed and started /Library/LaunchDaemons/com.megaphone.speaker.plist'
  fi
else
  if [ "$init_system" = openrc ] && [ -f /etc/init.d/megaphone ]; then
    "${priv[@]}" rc-update del megaphone default
  fi
  if [ "$os" = Linux ] && [ -f /etc/systemd/system/megaphone.service ]; then
    "${priv[@]}" systemctl disable megaphone.service
  elif [ "$os" = Darwin ] && [ -f /Library/LaunchDaemons/com.megaphone.speaker.plist ]; then
    "${priv[@]}" launchctl disable system/com.megaphone.speaker
  fi
  echo 'Start manually: sudo /opt/megaphone/megaphone --config /opt/megaphone/config.toml'
fi
cleanup
build_dir=
rustup_script=
config_tmp=
echo 'Temporary files:   removed'
echo
echo 'Install complete.'
web_host=$bind
if [ "$bind" = 0.0.0.0 ]; then web_host=127.0.0.1; fi
echo "Installed in $install_dir. Open http://$web_host:$port after starting Megaphone."
echo 'First steps: add a peer in BGP Summary, add prefixes, then select exports in Policy Setting.'
if [ "$bind" = 0.0.0.0 ]; then echo "Remote access: use this machine's IP and port $port on your trusted network."; fi
echo 'Everything is also stored in /opt/megaphone/config.toml. Systemd uses user megaphone; OpenRC and macOS use root.'
if [ "$service" = yes ]; then
  case "$init_system" in
    systemd) echo 'Check service: sudo systemctl status megaphone; logs: sudo journalctl -u megaphone' ;;
    openrc) echo 'Check service: sudo rc-service megaphone status; logs: /opt/megaphone/service.log' ;;
    *) echo 'Check service: sudo launchctl print system/com.megaphone.speaker; logs: /opt/megaphone/service.log' ;;
  esac
fi
echo 'Uninstall later: sudo /opt/megaphone/uninstall.sh'
if [ "$os" = Linux ] && command -v firewall-cmd >/dev/null; then
  echo "If firewalld is active, allow inbound BGP TCP 179 from your peers."
  echo "For remote dashboard access, allow TCP $port only from trusted management addresses."
  echo 'Firewall rules are managed separately and are not changed by this installer.'
fi
