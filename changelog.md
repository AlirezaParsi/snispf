# SNISPF

SNI-spoofing DPI-bypass root module — Magisk / KernelSU / APatch.

---

## v0.1.2
### Smarter scanner + tougher resilience
- **Custom scan lists** — paste your own IPs and domains in the Scan tab. IPs are probed directly; domains are resolved and tested with the domain as the SNI (great for finding working fake-SNI candidates). See `examples/ips.txt` and `examples/domains.txt`.
- **Forced/lost WAN now waits** — if you pin a specific `INTERFACE` and it drops (or no WAN is up), the engine waits for it to come back and rebinds, instead of switching away or thrashing. `auto` still switches to a working interface.

## v0.1.1
### Resilience + in-app updates + WebUI polish
- **Auto-recovery on network change** — when the antenna reconnects or mobile/Wi-Fi rotates the WAN, the engine re-detects the live interface and rebinds the injector automatically (debounced); the daemon and listener stay up, no manual restart.
- **OTA updates** — the module now reports updates to your root manager (`updateJson`), so future versions install in-place.
- **Draggable pickers** — the setting pop-up sheets can be swiped down (grab the handle) to dismiss.
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
