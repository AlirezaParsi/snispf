# SNISPF

SNI-spoofing DPI-bypass root module — Magisk / KernelSU / APatch.

---

## v0.1.1
### In-app updates + WebUI polish
- **OTA updates** — the module now reports updates to your root manager (`updateJson`), so future versions install in-place.
- **WebUI** — fixed tabs (no page scroll; long content scrolls inside its own card), tap-to-open list pickers for selectable settings, WAN-interface picker populated from the device, ping shown next to scan results, and the scanner keeps its state when you switch tabs.
- **Themes & language** — AMOLED-black dark + light themes, English + Persian (فارسی, RTL text), offline-bundled fonts (Inter / Vazirmatn), edge-to-edge layout.
- **Health probe** binds to the WAN, so latency is the real edge RTT (no more 0 ms behind a VPN).
- Idempotent start/stop and clearer error messages in the control API.

## v0.1.0
### First release
- SNI-spoofing tunnel as a root boot service: `wrong_seq`, `combined`, `fake_sni`, `fragment`.
- uTLS browser fingerprints + timing jitter for the fake ClientHello.
- DNS-free Cloudflare edge scanner with a survivor hit-list, and an auto-tune matrix.
- Full-tunnel VPN escape (`INTERFACE: auto` → `SO_BINDTODEVICE` on the physical WAN).
- Localhost control API + KsuWebUI control panel.
