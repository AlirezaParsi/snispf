#!/system/bin/sh
# SNISPF boot service (late_start). Runs as root, so wrong_seq raw injection
# works and traffic egresses the real network (root is outside per-app VPNs).
MODDIR=${0%/*}
RT=/data/adb/snispf
BIN=$MODDIR/bin/snispf
CFG=$RT/config.json
ADDR=127.0.0.1:8797
LOG=$RT/service.log

mkdir -p "$RT"
: > "$LOG"

# Wait for boot to settle (network + filesystems up).
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
sleep 5

echo "[service] starting control daemon on $ADDR" >> "$LOG"
# Control service supervises the proxy core child; start/stop via /v1/*.
"$BIN" --service --service-addr "$ADDR" --config "$CFG" >> "$LOG" 2>&1 &

# Wait for the API to come up, then autostart the proxy core from config.
i=0
while [ "$i" -lt 30 ]; do
  if busybox wget -q -O- "http://$ADDR/v1/status" >/dev/null 2>&1; then
    echo "[service] control API up" >> "$LOG"
    busybox wget -q -O- --post-data='' "http://$ADDR/v1/start" >> "$LOG" 2>&1
    echo "[service] core start requested" >> "$LOG"
    exit 0
  fi
  sleep 1
  i=$((i+1))
done
echo "[service] ERROR: control API did not come up within 30s" >> "$LOG"
