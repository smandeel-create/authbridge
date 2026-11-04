#!/bin/bash
# Renders the plist and bootstraps the launchd agent. Run manually when ready; nothing calls this automatically.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
LABEL=com.authbridge.daemon
NODE="$(command -v node)"
[ -n "$NODE" ] || { echo 'node not found in PATH' >&2; exit 1; }
DEST="$HOME/Library/LaunchAgents/$LABEL.plist"
mkdir -p "$HOME/.authbridge" && chmod 700 "$HOME/.authbridge"
[ -x "$REPO/se/bin/authbridge-se" ] || "$REPO/se/build.sh"
sed -e "s#__REPO__#$REPO#g" -e "s#__HOME__#$HOME#g" -e "s#__NODE_DIR__#$(dirname "$NODE")#g" -e "s#__NODE__#$NODE#g" "$HERE/$LABEL.plist" > "$DEST"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$DEST"
echo "installed and started $LABEL (logs in ~/.authbridge/launchd.*.log)"
