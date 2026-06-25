# SNISPF

SNI-spoofing DPI-bypass root module — Magisk / KernelSU / APatch.

---

## v0.1.7
### Decoy + fingerprint rotation
- **Per-connection decoy rotation** — set `FAKE_SNI_POOL` (a list of clean decoy SNIs) and/or `UTLS_POOL` (a list of fingerprints) in the config to rotate the fake ClientHello's SNI and browser fingerprint on every connection, so a DPI can't learn and block a single decoy/fingerprint over time. Opt-in: empty pools keep the current single decoy. wrong_seq-safe — a rotated combo whose fake hello exceeds the one-segment limit falls back automatically. Verified on-device: decoy + fingerprint rotate per connection with no effect on confirmation.

## v0.1.6
### wrong_seq stays strict + re-injects the fake
- **The fake ClientHello is now re-injected** (up to 4×, 250 ms apart) until the server's dup-ack confirms it landed. A single fake can be lost to strict conntrack or transient drops; without the dup-ack the flow timed out and the connection was dropped ("ping but no real-delay"). The happy path is unchanged — if the first inject confirms, nothing extra is sent.
- **Reverted v0.1.5's fallback-on-failure.** wrong_seq no longer falls back to sending the ClientHello another way: the real SNI must never go out unspoofed (it would expose a DPI-blocked SNI and could flag the server). If confirmation genuinely fails, the connection is dropped, as before. The conntrack relaxation from v0.1.5 stays.

## v0.1.5
### wrong_seq reliability — "ping but no real-delay" fixed
- **Auto-relaxes conntrack at boot** (`net.netfilter.nf_conntrack_tcp_be_liberal=1`). `wrong_seq` injects a fake ClientHello with an invalid TCP sequence; strict conntrack flagged it INVALID and dropped it, so the bypass confirmation timed out and the connection was dropped — the client (v2rayNG) got a ping but no real-delay. The module now sets this knob itself (best-effort).
- **Graceful fallback instead of dropping** — if `wrong_seq` confirmation still fails, the real ClientHello is now written to the live upstream connection instead of dropping it. The fake packet was already injected (so the DPI may still have seen the decoy), and many CDN-fronted configs don't need the bypass at all — so traffic flows instead of failing outright.
- Installer message cleaned up (no stale reboot instruction).

## v0.1.4
### Magisk fix #2 — read-only log path
- **Fixes the daemon crashing at startup on Magisk** with `mkdir snispf: read-only file system`. The API log directory was derived from `os.UserConfigDir()`, which for a root daemon (HOME unset, cwd `/`) resolved to a relative path on the read-only rootfs. It's now placed next to the config (`/data/adb/snispf/logs`, always writable), with fallbacks, and a log-file failure no longer kills the daemon — it degrades to stdout (still captured in `service.log`).

## v0.1.3
### Magisk fix — daemon stays up
- **Fixes the daemon dying on Magisk** (control API "connection refused" / WebUI stuck OFFLINE). The boot service now detaches the daemon into its own session (`setsid`) and the daemon ignores `SIGHUP`, so Magisk tearing down the boot-service process group no longer kills it. KernelSU / APatch were unaffected.
- **Logs tab self-diagnoses** — when the control API is unreachable, the Logs tab now falls back to the on-disk boot log (`/data/adb/snispf/service.log`), so a startup failure shows its real reason instead of just "connection refused".

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
