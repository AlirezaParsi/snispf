#!/system/bin/sh
# Runs when the module is removed. Stop the daemon; keep /data/adb/snispf so a
# reinstall preserves the user's config + hit-list. Delete it manually to wipe.
busybox pkill -f "bin/snispf --service" 2>/dev/null
busybox pkill -f "snispf --run-core" 2>/dev/null
