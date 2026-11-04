#!/bin/bash
# Installs the Chrome native messaging host manifest for the current user.
# Does NOT load the extension: do that via chrome://extensions -> Load unpacked -> extension/
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
NODE="$(command -v node)"
[ -n "$NODE" ] || { echo 'node not found in PATH' >&2; exit 1; }
mkdir -p "$DEST_DIR"
chmod +x "$HERE/nmh.mjs"
# Chrome starts the host with a minimal PATH, so `env node` may fail (Homebrew). Use a generated wrapper
# (gitignored) that execs the absolute node path.
cat > "$HERE/nmh-launch.sh" <<WRAP
#!/bin/bash
exec "$NODE" "$HERE/nmh.mjs" "\$@"
WRAP
chmod +x "$HERE/nmh-launch.sh"
sed "s#__NMH_PATH__#$HERE/nmh-launch.sh#" "$HERE/com.authbridge.host.json" > "$DEST_DIR/com.authbridge.host.json"
echo "installed $DEST_DIR/com.authbridge.host.json (extension id $(cat "$HERE/../extension/EXTENSION_ID"))"
