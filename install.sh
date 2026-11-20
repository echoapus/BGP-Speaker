#!/usr/bin/env bash
set -euo pipefail

# Build as the invoking user; use elevated privileges only for system installation.
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_dir=/opt/megaphone
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
  read -r -p 'Web listen address [0.0.0.0]: ' bind
  bind=${bind:-0.0.0.0}
  [[ "$bind" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && break
  echo 'Enter an IPv4 address, for example 0.0.0.0 or 127.0.0.1.'
done
# The web API changes routes, so anything but loopback needs a login (user admin).
password=
if [[ "$bind" != 127.* ]] && ! "${priv[@]}" grep -qs '^[[:space:]]*api_password' "$install_dir/config.toml"; then
  re='^[^[:space:]"#\\]{8,}$'
  while :; do
    read -r -s -p 'Web password for user admin (8+ characters, no spaces, quotes, # or backslash): ' password
    echo
    [[ "$password" =~ $re ]] && break
    echo 'Password rejected.'
  done
fi
while :; do
  read -r -p 'Install and enable a startup service? [y/N]: ' service
  case "$service" in
    y|Y|yes|YES) service=yes; break ;;
    ''|n|N|no|NO) service=no; break ;;
    *) echo 'Enter y or n.' ;;
  esac
done
if [ "$service" = yes ] && [ "$os" = Linux ]; then
  command -v systemctl >/dev/null && [ -d /run/systemd/system ] || {
    echo 'Service installation requires a running systemd system.' >&2; exit 1;
  }
fi
if [ "$os" = Linux ] && { ! command -v cc >/dev/null || ! command -v curl >/dev/null; }; then
  if command -v apt-get >/dev/null; then
    "${priv[@]}" apt-get update
    "${priv[@]}" apt-get install -y build-essential curl ca-certificates
  elif command -v dnf >/dev/null; then
    "${priv[@]}" dnf install -y gcc make curl ca-certificates
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
  rustup_script=$(mktemp)
  trap 'rm -f "$rustup_script"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$rustup_script"
  sh "$rustup_script" -y --profile minimal
  . "$HOME/.cargo/env"
fi
# Ignore custom Cargo target directories so the installed artifact is unambiguous.
cargo build --release --locked --manifest-path "$source_dir/Cargo.toml" --target-dir "$source_dir/target"
"${priv[@]}" mkdir -p "$install_dir"
if [ -e "$install_dir/config.toml" ]; then
  echo 'Existing config found; saving a backup before changing the Web port.'
  "${priv[@]}" cp -p "$install_dir/config.toml" "$install_dir/config.toml.bak.$(date +%s)"
  config_input="$install_dir/config.toml"
else
  config_input="$source_dir/config.example.toml"
fi
config_tmp=$(mktemp)
trap 'rm -f "${rustup_script:-}" "$config_tmp"' EXIT
# api_listen is inserted in [server], preserving existing peers and routes.
"${priv[@]}" cat -- "$config_input" | PW="$password" awk -v port="$port" -v bind="$bind" '
  /^\[server\][[:space:]]*$/ {
    server=1; found=1; print; print "api_listen = \"" bind ":" port "\""
    if (ENVIRON["PW"] != "") print "api_password = \"" ENVIRON["PW"] "\""
    next
  }
  /^\[/ { server=0 }
  server && /^[[:space:]]*api_listen[[:space:]]*=/ { next }
  server && ENVIRON["PW"] != "" && /^[[:space:]]*api_password[[:space:]]*=/ { next }
  { print }
  END { if (!found) exit 1 }
' > "$config_tmp" || { echo 'Config needs a [server] section.' >&2; exit 1; }
if [ "$os" = Linux ] && command -v systemctl >/dev/null && "${priv[@]}" systemctl is-active --quiet megaphone.service; then
  "${priv[@]}" systemctl stop megaphone.service
fi
if [ "$os" = Darwin ] && "${priv[@]}" launchctl print system/com.megaphone.speaker >/dev/null 2>&1; then
  "${priv[@]}" launchctl bootout system/com.megaphone.speaker
fi
# Linux services run as an unprivileged user that may only bind port 179.
owner=(-o root)
if [ "$os" = Linux ] && [ "$service" = yes ]; then
  id megaphone >/dev/null 2>&1 || "${priv[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin megaphone
  owner=(-o megaphone)
fi
"${priv[@]}" install -m 755 "$source_dir/target/release/megaphone" "$install_dir/megaphone"
"${priv[@]}" install -m 600 "${owner[@]}" "$config_tmp" "$install_dir/config.toml"
"${priv[@]}" install -m 755 "$source_dir/uninstall.sh" "$install_dir/uninstall.sh"
if [ "$service" = yes ]; then
  if [ "$os" = Linux ]; then
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
    "${priv[@]}" systemctl daemon-reload
    "${priv[@]}" systemctl enable --now megaphone.service
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
  fi
else
  if [ "$os" = Linux ] && [ -f /etc/systemd/system/megaphone.service ]; then
    "${priv[@]}" systemctl disable megaphone.service
  elif [ "$os" = Darwin ] && [ -f /Library/LaunchDaemons/com.megaphone.speaker.plist ]; then
    "${priv[@]}" launchctl disable system/com.megaphone.speaker
  fi
  echo 'Start manually: sudo /opt/megaphone/megaphone --config /opt/megaphone/config.toml'
fi
echo "Installed in $install_dir. Web: http://$bind:$port (login: admin). Peers and settings are managed in the web UI."
echo 'Everything is also stored in /opt/megaphone/config.toml. On Linux the service runs as user megaphone; on macOS as root.'
