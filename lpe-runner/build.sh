#!/bin/bash
# build.sh - compile lpe-runner into a single static Linux/amd64 binary.
#
# The resulting `lpe-runner` is a fully static, stripped Go binary you can
# drop onto any x86-64 Linux target alongside the exploit files. No libc,
# no runtime deps, no Python needed on the *runner* side.
#
# Usage:   ./build.sh
# Output:  ./lpe-runner   (static ELF, ~2-5 MB)
set -e

cd "$(dirname "$0")"

echo "[*] Building lpe-runner (static linux/amd64)..."

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -ldflags="-s -w -X main.version=2.0" \
    -o lpe-runner \
    .

chmod +x lpe-runner

echo "[+] Done: $(pwd)/lpe-runner"
file lpe-runner
echo
echo "[*] Ship it next to your exploit files, then:"
echo "    ./lpe-runner -list        # show catalog"
echo "    ./lpe-runner -recon       # show host recon"
echo "    ./lpe-runner              # run the full sweep"
echo "    ./lpe-runner -only NAME   # run a single exploit"
