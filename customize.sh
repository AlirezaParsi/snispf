#!/sbin/sh
# SNISPF module install-time setup. Runs under Magisk/KSU/APatch installer.
# Provided by the installer: $MODPATH, $ARCH, ui_print, set_perm, abort.

SKIPUNZIP=0

ui_print "- SNISPF DPI bypass module"
ui_print "- device arch: $ARCH"

case "$ARCH" in
  arm64) PICK=snispf-arm64 ;;
  arm)   PICK=snispf-arm ;;
  *) abort "! Unsupported arch '$ARCH' (need arm64 or arm)" ;;
esac

# Collapse the per-arch binaries down to a single 'snispf'.
mv -f "$MODPATH/bin/$PICK" "$MODPATH/bin/snispf" || abort "! missing $PICK in package"
rm -f "$MODPATH/bin/snispf-arm64" "$MODPATH/bin/snispf-arm"
set_perm "$MODPATH/bin/snispf" 0 0 0755

# Persistent runtime dir (survives module updates): config, logs, hit-list.
RT=/data/adb/snispf
mkdir -p "$RT"
if [ ! -f "$RT/config.json" ]; then
  cp -f "$MODPATH/config.json" "$RT/config.json"
  ui_print "- seeded default config at $RT/config.json"
else
  ui_print "- kept existing config at $RT/config.json"
fi
set_perm "$RT" 0 0 0700
set_perm "$RT/config.json" 0 0 0600

ui_print "- control API will listen on 127.0.0.1:8797 after boot"
ui_print "- edit $RT/config.json (set CONNECT_IP / FAKE_SNI), then reboot"
ui_print "- runs as root: wrong_seq raw injection available"
