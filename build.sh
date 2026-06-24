#!/usr/bin/env bash
# Build the SNISPF flashable module zip: cross-compile the engine (Go, pure,
# CGO_ENABLED=0 → runs on Android as a static binary), then package the module.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$ROOT/engine"
OUT="${1:-$ROOT/snispf.zip}"

echo "== building engine binaries =="
mkdir -p "$ROOT/bin"
( cd "$ENGINE"
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64        go build -ldflags "-s -w" -o "$ROOT/bin/snispf-arm64" ./cmd/snispf
  CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7   go build -ldflags "-s -w" -o "$ROOT/bin/snispf-arm"   ./cmd/snispf
)
ls -lh "$ROOT/bin/"

echo "== packaging $OUT =="
rm -f "$OUT"
( cd "$ROOT"
  zip -r9 "$OUT" \
    module.prop customize.sh service.sh uninstall.sh config.json \
    bin webroot META-INF \
    -x '*.DS_Store' -x '*/.git/*'
)
echo "== done: $OUT =="
