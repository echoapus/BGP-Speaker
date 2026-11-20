#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -h|--help) echo 'Usage: ./uninstall.sh — interactively remove Megaphone, optionally keeping data'; exit 0 ;;
  '') ;;
  *) echo 'Unknown option. Use --help.' >&2; exit 2 ;;
esac
trap 'echo "Uninstall failed. Review the error above and rerun to finish removal." >&2' ERR
trap 'echo "Uninstall interrupted; removal may be incomplete." >&2; exit 130' INT
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) echo 'Only Linux and macOS are supported.' >&2; exit 1 ;;
esac
if [ ! -t 0 ]; then
  echo 'Run ./uninstall.sh from an interactive terminal.' >&2
  exit 1
fi
echo 'Megaphone uninstall'
echo 'This stops BGP sessions and removes the installed binary and startup service.'
while :; do
  read -r -p 'Keep configuration, backups and logs for reinstallation? [Y/n]: ' keep
  case "$keep" in
    ''|y|Y|yes|YES) keep=yes; break ;;
    n|N|no|NO) keep=no; break ;;
    *) echo 'Enter y or n.' ;;
  esac
done
if [ "$keep" = yes ]; then
  echo 'Configuration, backups and logs will remain in /opt/megaphone.'
else
  echo 'All files in /opt/megaphone will be permanently deleted.'
fi
priv=(env)
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || { echo 'sudo is required.' >&2; exit 1; }
  priv=(sudo)
fi
read -r -p 'Proceed with uninstall? [y/N]: ' answer
case "$answer" in y|Y|yes|YES) ;; *) echo 'Cancelled.'; exit 0 ;; esac
echo 'Stopping services and removing installed files...'
case "$(uname -s)" in
  Linux)
    if [ -f /etc/init.d/megaphone ] && command -v rc-service >/dev/null; then
      if "${priv[@]}" rc-service megaphone status >/dev/null 2>&1; then
        "${priv[@]}" rc-service megaphone stop
      fi
      "${priv[@]}" rc-update del megaphone default
      "${priv[@]}" rm -f /etc/init.d/megaphone
    fi
    if [ -f /etc/systemd/system/megaphone.service ]; then
      "${priv[@]}" systemctl disable --now megaphone.service
      "${priv[@]}" rm -f /etc/systemd/system/megaphone.service
      "${priv[@]}" systemctl daemon-reload
    fi
    ! id megaphone >/dev/null 2>&1 || "${priv[@]}" userdel megaphone
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
if [ "$keep" = yes ]; then
  "${priv[@]}" rm -f /opt/megaphone/megaphone /opt/megaphone/uninstall.sh
else
  "${priv[@]}" rm -rf /opt/megaphone
fi
echo 'Megaphone removed. Rust and system build tools were kept.'
if [ "$keep" = yes ]; then
  echo 'Retained data: /opt/megaphone. Run ./install.sh from the source checkout to reinstall.'
else
  echo 'Installation data was permanently removed; recovery requires your own backup.'
fi
