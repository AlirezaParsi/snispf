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

# wrong_seq injects a fake ClientHello with a deliberately INVALID TCP sequence
# number. Strict conntrack flags it as out-of-window/INVALID and drops it before
# it leaves the device, so the bypass confirmation never sees it and times out
# ("wrong_seq: confirmation failed status=timeout"). Relaxing conntrack lets the
# fake packet through. Best-effort: not all kernels expose the knob.
if sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1; then
  echo "[service] conntrack tcp_be_liberal=1 (sysctl)" >> "$LOG"
elif echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal 2>/dev/null; then
  echo "[service] conntrack tcp_be_liberal=1 (procfs)" >> "$LOG"
else
  echo "[service] WARN: could not relax conntrack (nf_conntrack_tcp_be_liberal); wrong_seq may time out" >> "$LOG"
fi

echo "[service] starting control daemon on $ADDR" >> "$LOG"
# Control service supervises the proxy core child; start/stop via /v1/*.
# Detach into its OWN session (setsid) and ignore SIGHUP (nohup): when this
# boot-service shell exits, Magisk sends SIGHUP to the service process group,
# which would otherwise kill the daemon (the Go service only traps SIGINT).
# KernelSU/APatch tolerate the un-detached child; Magisk does not — without
# this the API comes up at boot then dies, giving "connection refused".
nohup busybox setsid "$BIN" --service --service-addr "$ADDR" --config "$CFG" >> "$LOG" 2>&1 &

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
