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
echo
echo 'Uninstall plan'
echo '=============='
echo 'Application:       megaphone'
echo 'Install directory: /opt/megaphone'
echo 'Command link:      none (not created by the installer)'
case "$(uname -s)" in
  Linux)
    echo 'Systemd unit:      /etc/systemd/system/megaphone.service'
    echo 'OpenRC service:    /etc/init.d/megaphone'
    ;;
  Darwin) echo 'Launchd service:   /Library/LaunchDaemons/com.megaphone.speaker.plist' ;;
esac
if [ "$keep" = yes ]; then
  echo 'Data removal:      none; configuration, backups and logs retained'
else
  echo 'Data removal:      /opt/megaphone (including configuration, backups and logs)'
fi
echo
priv=(env)
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || { echo 'sudo is required.' >&2; exit 1; }
  priv=(sudo)
fi
read -r -p "Remove megaphone installation? Type 'yes' to continue: " answer
case "$answer" in yes) ;; *) echo 'Cancelled.'; exit 0 ;; esac
echo 'Stopping services and removing installed files...'
case "$(uname -s)" in
  Linux)
    if [ -f /etc/init.d/megaphone ] && command -v rc-service >/dev/null; then
      if "${priv[@]}" rc-service megaphone status >/dev/null 2>&1; then
        "${priv[@]}" rc-service megaphone stop
      fi
      "${priv[@]}" rc-update del megaphone default
      "${priv[@]}" rm -f /etc/init.d/megaphone
      echo 'OpenRC service:    removed /etc/init.d/megaphone'
    else
      echo 'OpenRC service:    not installed or OpenRC unavailable'
    fi
    if [ -f /etc/systemd/system/megaphone.service ]; then
      "${priv[@]}" systemctl disable --now megaphone.service
      "${priv[@]}" rm -f /etc/systemd/system/megaphone.service
      "${priv[@]}" systemctl daemon-reload
      echo 'Systemd unit:      removed /etc/systemd/system/megaphone.service'
    else
      echo 'Systemd unit:      not installed'
    fi
    ! id megaphone >/dev/null 2>&1 || "${priv[@]}" userdel megaphone
    ;;
  Darwin)
    if [ -f /Library/LaunchDaemons/com.megaphone.speaker.plist ]; then
      if "${priv[@]}" launchctl print system/com.megaphone.speaker >/dev/null 2>&1; then
        "${priv[@]}" launchctl bootout system/com.megaphone.speaker
      fi
      "${priv[@]}" rm -f /Library/LaunchDaemons/com.megaphone.speaker.plist
      echo 'Launchd service:   removed /Library/LaunchDaemons/com.megaphone.speaker.plist'
    else
      echo 'Launchd service:   not installed'
    fi
    ;;
  *) echo 'Only Linux and macOS are supported.' >&2; exit 1 ;;
esac
if [ "$keep" = yes ]; then
  "${priv[@]}" rm -f /opt/megaphone/megaphone /opt/megaphone/uninstall.sh
  echo 'Executables:       removed megaphone and uninstall.sh from /opt/megaphone'
  echo 'Install directory: retained /opt/megaphone (configuration, backups and logs)'
else
  "${priv[@]}" rm -rf /opt/megaphone
  echo 'Install directory: removed /opt/megaphone'
fi
echo
echo 'Uninstall complete.'
echo 'Megaphone removed. Rust and system build tools were kept.'
if [ "$keep" = yes ]; then
  echo 'Retained data: /opt/megaphone. Run ./install.sh from the source checkout to reinstall.'
else
  echo 'Installation data was permanently removed; recovery requires your own backup.'
fi
