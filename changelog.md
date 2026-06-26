# SNISPF

SNI-spoofing DPI-bypass root module — Magisk / KernelSU / APatch.

---

## v0.2.2
### Smarter WAN pick — avoids a dead/zombie SIM interface
- **Auto WAN now probes every candidate and picks the fastest-connecting one**, instead of the first that answers. On a dual-SIM phone (or after a live SIM hot-swap that leaves an orphaned `rmnet` interface behind — a known ROM quirk: the old interface stays UP with a stale/empty route until reboot), the dead one no longer gets chosen just because it was listed first. The interface that actually reaches the upstream wins. Note: if the underlying cellular link is lossy/high-latency (common during a shutdown), connections can still stall mid-stream — that's the network, not the tunnel; a reboot is still the cleanest fix for a truly orphaned interface.

## v0.2.1
### Critical: proxy no longer hangs under load (fixes v0.2.0)
- **Connections are served concurrently again.** v0.2.0's new persistent listener accidentally handled connections one-at-a-time — under an app like v2rayNG that opens many connections at once (and with a slow upstream), they piled up unaccepted and the proxy looked dead ("real-delay fails / network down"). Each connection now gets its own goroutine, as before. This was the main cause of v0.2.0 feeling broken.
- **The core survives a fast restart.** Binding the listener now retries (with SO_REUSEADDR) instead of dying with `bind: address already in use` when a previous instance's socket is still lingering — a restart no longer kills the tunnel.
- **Auto-swap no longer churns your endpoint on a flapping WAN.** Before swapping, it re-checks whether the current edge is actually reachable; a dial that failed only because the WAN was mid-rebind (stale interface) no longer counts as a dead endpoint, so your configured IP stays put.

## v0.2.0
### Rock-solid local listener (no more drops on WAN flaps)
- **The local proxy port stays bound continuously.** Until now, every WAN change (mobile cell/IP rotation, full-tunnel VPN escape) rebuilt the whole runtime — including the listener — so on a flapping network `127.0.0.1:LISTEN_PORT` refused connections for seconds at a time ("not even tcping works"), and a fast flap could race `bind: address already in use` and kill the core. Now the listener is bound **once** for the core's life; WAN/endpoint rebuilds swap only the upstream injector behind it. Verified on a live flapping WAN: **40/40** local connects succeed across 6 injector rebuilds, with the core never dropping. Note: data still needs the physical WAN up — on a full-tunnel VPN, SNISPF deliberately dials the physical link (to apply the bypass on the real path), so if that link is down the bypass can't carry traffic even though the listener is healthy.

## v0.1.9
### Survives WAN flaps + auto-swaps to the fastest edge
- **The tunnel no longer dies when the mobile WAN flaps.** On a network that rotates cells/IPs (rmnet rotation), each change rebuilds the runtime to rebind the injector — but a rapid flap storm used to trip an internal guard that killed the whole core (`exit status 1`, tunnel stuck off until you reopened it, since nothing restarts a dead core). Now WAN changes never count as a crash loop, other failures back off instead of aborting, and a transient rebuild error retries — the core stays alive and recovers on its own. Verified on-device through a live flap storm: continuous rebuilds, zero deaths.
- **Auto-swap to the fastest working edge** (`AUTO_SWAP`, on by default). When the current `wrong_seq` endpoint keeps failing confirmation, the core re-scans your hit-list (known-good survivors only — fast) and switches to the lowest-RTT edge that still passes, then rebuilds. Throttled to once per 30s so a bad network can't thrash. Single-endpoint only (the one wrong_seq supports); set `"AUTO_SWAP": false` to pin your endpoint. Run a scan first so there's a hit-list to swap from.
- Config is now written atomically (no chance of a half-written `config.json` when the core auto-swap and the WebUI save overlap).

## v0.1.8
### Live speed, self-pruning decoys, no busybox dependency
- **Real-time speed + data usage on the Status tab** — download/upload throughput and total data used now show alongside connected devices, updated every ~2.5s while connected. The core flushes byte counters; the WebUI derives the live rate.
- **Self-pruning decoy rotation** — a decoy SNI in `FAKE_SNI_POOL` whose wrong_seq confirm rate drops (it left a DPI whitelist, or got learned and blocked) is taken out of rotation automatically and re-probed after a backed-off cooldown. The pool self-heals to whatever still passes the DPI, so rotation is safe even under a strict single-domain whitelist (only the passing decoy stays in use; the pool never starves).
- **Dropped the busybox dependency** — the boot service, WebUI bridge, and uninstaller now prefer Android's own `curl`/`setsid`/`tail`/`pkill` (`/system/bin`, always present) and fall back to busybox only if needed. Magisk does not ship busybox in every context, which could leave the WebUI showing OFFLINE or the daemon failing to detach.
- **Fixed a stale upstream ping** — after a scan applied a new `CONNECT_IP`, the Status tab kept showing the old server's RTT badge. It now clears when the upstream changes, so the ping reflects the current endpoint.

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
