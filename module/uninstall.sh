#!/system/bin/sh
# Runs when the module is removed. Stop the daemon; keep /data/adb/snispf so a
# reinstall preserves the user's config + hit-list. Delete it manually to wipe.
# Prefer toybox pkill (/system/bin); fall back to busybox pkill.
if command -v pkill >/dev/null 2>&1; then PK="pkill"; else PK="busybox pkill"; fi
$PK -f "bin/snispf --service" 2>/dev/null
$PK -f "snispf --run-core" 2>/dev/null
