#!/bin/bash
# AuthBridge installer for macOS. Idempotent: safe to re-run.
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"

echo "==> Checking requirements"
[ "$(uname -s)" = "Darwin" ] || { echo "AuthBridge needs macOS." >&2; exit 1; }
if [ "$(uname -m)" != "arm64" ]; then
  if ! system_profiler SPiBridgeDataType 2>/dev/null | grep -qi "T2\|Apple"; then
    echo "AuthBridge needs a Secure Enclave (Apple silicon or an Intel Mac with a T2 chip)." >&2
    exit 1
  fi
fi
NODE="$(command -v node || true)"
[ -n "$NODE" ] || { echo "node not found. Install Node 20+ (brew install node)." >&2; exit 1; }
NODE_MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 20 ] || { echo "Node 20+ required (found $("$NODE" -v))." >&2; exit 1; }
[ -d "/Applications/Google Chrome.app" ] || [ -d "$HOME/Applications/Google Chrome.app" ] || { echo "Google Chrome not found in /Applications." >&2; exit 1; }
echo "    ok: macOS, $(uname -m), node $("$NODE" -v), Chrome"

echo "==> Installing npm dependencies"
npm ci

echo "==> Building the Secure Enclave helper"
"$REPO/se/build.sh"

echo "==> Installing the Chrome native messaging host"
"$REPO/host/install.sh"

echo "==> Installing the launchd agent"
"$REPO/launchd/install.sh"

echo "==> Registering the MCP server with Claude Code"
if command -v claude >/dev/null 2>&1; then
  if claude mcp get authbridge >/dev/null 2>&1; then
    echo "    authbridge MCP already registered; skipping"
  else
    claude mcp add -s user authbridge -- "$NODE" "$REPO/mcp/server.mjs"
  fi
else
  echo "    claude CLI not found; skipping. Later run: claude mcp add -s user authbridge -- \"$NODE\" \"$REPO/mcp/server.mjs\""
fi

echo "==> Installing the website-login skill"
SKILL_SRC="$REPO/skill/website-login"
SKILL_DST="$HOME/.claude/skills/website-login"
mkdir -p "$HOME/.claude/skills"
if [ -e "$SKILL_DST" ]; then
  if diff -rq "$SKILL_SRC" "$SKILL_DST" >/dev/null 2>&1; then
    echo "    skill already up to date"
  else
    rm -rf "$SKILL_DST.bak"
    mv "$SKILL_DST" "$SKILL_DST.bak"
    echo "    existing skill differs; backed up to $SKILL_DST.bak"
    cp -R "$SKILL_SRC" "$SKILL_DST"
  fi
else
  cp -R "$SKILL_SRC" "$SKILL_DST"
fi

cat <<NEXT

==> Done. Next steps:
  1. Chrome: open chrome://extensions, turn on Developer mode, click "Load unpacked" and choose
       $REPO/extension
  2. Build the iPhone app (see README: copy ios/Config.example.xcconfig to ios/Config.xcconfig, xcodegen, build).
  3. Pair the phone:   node $REPO/daemon/cli.mjs pair
  4. Optional, email codes:        node $REPO/daemon/cli.mjs mail-add <name> <email> --provider gmail
  5. Optional, push notifications: node $REPO/daemon/cli.mjs push-setup --key-id K --team-id T --bundle-id B --p8 AuthKey_K.p8
NEXT
