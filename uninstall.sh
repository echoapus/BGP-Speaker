#!/usr/bin/env bash
set -euo pipefail
priv=()
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || { echo 'sudo is required.' >&2; exit 1; }
  priv=(sudo)
fi
read -r -p 'Remove /opt/megaphone, including configuration, backups and logs? [y/N]: ' answer
case "$answer" in y|Y|yes|YES) ;; *) echo 'Cancelled.'; exit 0 ;; esac
case "$(uname -s)" in
  Linux)
    if [ -f /etc/systemd/system/megaphone.service ]; then
      "${priv[@]}" systemctl disable --now megaphone.service
      "${priv[@]}" rm -f /etc/systemd/system/megaphone.service
      "${priv[@]}" systemctl daemon-reload
    fi
    ;;
  Darwin)
    if [ -f /Library/LaunchDaemons/com.megaphone.speaker.plist ]; then
      if "${priv[@]}" launchctl print system/com.megaphone.speaker >/dev/null 2>&1; then
        "${priv[@]}" launchctl bootout system/com.megaphone.speaker
      fi
      "${priv[@]}" rm -f /Library/LaunchDaemons/com.megaphone.speaker.plist
    fi
    ;;
  *) echo 'Only Linux and macOS are supported.' >&2; exit 1 ;;
esac
"${priv[@]}" rm -rf /opt/megaphone
echo 'Megaphone removed. Rust and system build tools were kept.'
