#!/usr/bin/env bash
# Build the SNISPF flashable module zip. Stages the module scaffolding
# (module/), the WebUI (webroot/), and the cross-compiled engine binaries
# (engine/, pure Go, CGO_ENABLED=0 → static, runs on Android) into one zip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$ROOT/engine"
OUT="${1:-$ROOT/snispf.zip}"
STAGE="$ROOT/.build/stage"

echo "== staging =="
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/webroot"
cp -r "$ROOT/module/." "$STAGE/"      # module.prop, customize/service/uninstall.sh, config.json, META-INF
cp -r "$ROOT/webroot/." "$STAGE/webroot/"

echo "== building engine binaries =="
( cd "$ENGINE"
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64        go build -ldflags "-s -w" -o "$STAGE/bin/snispf-arm64" ./cmd/snispf
  CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7   go build -ldflags "-s -w" -o "$STAGE/bin/snispf-arm"   ./cmd/snispf
)
ls -lh "$STAGE/bin/"

echo "== packaging $OUT =="
rm -f "$OUT"
( cd "$STAGE" && zip -r9 -q "$OUT" . -x '.*' )
echo "== done: $OUT =="
