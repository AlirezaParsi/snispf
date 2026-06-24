# SNISPF

**A root module (Magisk / KernelSU / APatch) that runs an SNI-spoofing DPI-bypass tunnel as a boot service, with a built-in WebUI, edge scanner, and auto-tune.**

SNISPF is a local TCP forwarder. Point your client (v2rayNG, browser, anything) at `127.0.0.1:40443` and it relays to a real upstream IP while reshaping the outbound TLS **ClientHello** so a DPI middlebox can't read the real SNI — the destination still gets the correct request.

Because it runs as a **root daemon (uid 0)**, it sits outside per-app VPNs and can use `CAP_NET_RAW` for the strongest bypass, and (with `INTERFACE: auto`) binds to the physical WAN to escape even a full-tunnel VPN.

---

## Features

- **Bypass strategies** — `wrong_seq` (raw fake-ClientHello with an invalid TCP sequence; strongest), `combined`, `fake_sni`, `fragment`.
- **uTLS browser fingerprints** — the fake hello mimics real Firefox / Chrome / Safari / iOS / Edge instead of a tool-shaped hello.
- **Timing jitter** — randomized inter-fragment / inter-injection pacing so the cadence isn't fingerprintable.
- **DNS-free edge scanner** — probes Cloudflare IP ranges directly (works when DNS is hijacked during a shutdown), classifies each by TLS-handshake outcome, and keeps a per-IP survivor hit-list.
- **Auto-tune** — tries fingerprint × method combinations through a real request and reports which actually work.
- **Full-tunnel VPN escape** — `INTERFACE: auto` resolves the live physical WAN and pins the dial, the raw injector, and the source IP to it (`SO_BINDTODEVICE`).
- **Control API** — `127.0.0.1:8797/v1/{status,start,stop,config,health,clients,scan,test,interfaces,logs}`.
- **WebUI** — connection orb, live connected-clients count, config, scanner, auto-tune, logs. Dark (AMOLED) + light themes, English + Persian (فارسی), offline-bundled fonts, edge-to-edge.

---

## Install

1. Download `snispf-*.zip` from [Releases](../../releases).
2. Flash in Magisk / KernelSU / APatch and reboot.
3. Open the WebUI from your root manager → Modules → **SNISPF** → Open.
4. In **Scan**, find a reachable edge and tap it to use it; or edit **Config** directly. Start the tunnel from the orb.
5. Point your client at `127.0.0.1:40443` (or your LISTEN port; `0.0.0.0` shares it over LAN).

Config lives at `/data/adb/snispf/config.json` (survives module updates). Run `snispf --config <path> --config-doctor` to validate.

> `wrong_seq` needs root / `CAP_NET_RAW` — provided automatically since the module runs as root. Fragment-only modes are unprivileged.

---

## Build

Pure Go, `CGO_ENABLED=0` everywhere (static binaries run on Android). Needs Go 1.22+ and `zip`.

```bash
bash build.sh            # -> snispf.zip (arm64 + arm)
```

Tagging `vX.Y.Z` triggers the GitHub Actions workflow that builds the zip and attaches it to a release.

The engine source is under [`engine/`](engine/); the module wrapper (scripts, `webroot/`) is at the root.

---

## Operational notes

- IPv4-only plain TCP forwarder. The upstream must be a real IP serving TLS on `:443`; a working decoy `FAKE_SNI` depends on the local DPI and is found by experiment (use the scanner).
- During an Iran-style whitelist shutdown, DNS is hijacked — use the scanner's direct IP-range mode (default) and `INTERFACE: auto`.
- Strict conntrack can drop the out-of-window fake packets. On the device:
  `sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1` and don't drop `INVALID` TCP in `OUTPUT`.

---

## Credits

The wrong-sequence fake-ClientHello technique is by **[@patterniha](https://github.com/patterniha/SNI-Spoofing)**. The engine builds on **[snispf-core](https://github.com/NaxonM/snispf-core)** (NaxonM); the uTLS fingerprint approach is from **[SNI-Spoofing-Go](https://github.com/aleskxyz/SNI-Spoofing-Go)** (aleskxyz). All credit for the original concept goes to them.

## License

**GNU General Public License v3.0** — same as the upstream engine. See [LICENSE](LICENSE).
