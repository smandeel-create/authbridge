#!/bin/bash
# Removes what install.sh set up. Keeps ~/.authbridge (pairing, stored logins) unless --purge is given.
set -uo pipefail
LABEL=com.authbridge.daemon
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
NMH="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.authbridge.host.json"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "==> Stopping and removing the launchd agent"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST"

echo "==> Removing the Chrome native messaging host manifest"
rm -f "$NMH"

echo "==> Removing the MCP registration"
if command -v claude >/dev/null 2>&1; then claude mcp remove authbridge -s user 2>/dev/null || true; fi

echo "==> Removing the website-login skill"
rm -rf "$HOME/.claude/skills/website-login"

if [ "$PURGE" = 1 ]; then
  HOME_DIR="${AUTHBRIDGE_HOME:-$HOME/.authbridge}"
  echo "==> --purge: this permanently deletes $HOME_DIR (pairing and ALL stored logins)."
  printf 'Type "delete authbridge data" to confirm: '
  read -r ANSWER
  if [ "$ANSWER" = "delete authbridge data" ]; then
    rm -rf "$HOME_DIR"
    echo "    deleted $HOME_DIR"
  else
    echo "    not confirmed; $HOME_DIR kept"
  fi
else
  echo "Kept ~/.authbridge (use --purge to delete it)."
fi
echo "Keychain items (authbridge-mail, authbridge-apns) are left in place; remove with cli.mjs mail-remove or Keychain Access."
