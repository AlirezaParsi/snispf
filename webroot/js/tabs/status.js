/* Status tab — hero orb + compact stats + connected devices. Fits one screen. */
(function () {
  "use strict";
  var App = window.App, ui = App.ui, el = ui.el, t = function (k, p) { return App.t(k, p); };

  function stat(label, iconName, value, valueClass) {
    return el("div.stat", null, [
      el("div.stat__k", null, [ui.icon(iconName, "ico--sm"), label]),
      el("div.stat__v" + (valueClass || ""), null, [value])
    ]);
  }

  // Human-readable transfer rate (bytes/sec) and size (bytes), binary units.
  function fmtUnit(n, units) {
    if (!n || n < 1) return "0 " + units[0];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (n < 10 ? n.toFixed(1) : Math.round(n)) + " " + units[i];
  }
  function fmtRate(bps) { return fmtUnit(bps, ["B/s", "KB/s", "MB/s", "GB/s"]); }
  function fmtBytes(b) { return fmtUnit(b, ["B", "KB", "MB", "GB", "TB"]); }

  App.registerTab({
    id: "status",
    label: "nav_status",
    fixed: true,
    mount: function (view) { this.view = view; this.render(); },
    refresh: function () { if (this.view) this.render(); },

    render: function () {
      var s = App.state.status, c = App.state.config, cl = App.state.clients;
      var v = ui.clear(this.view);

      // Drop a stale link-health ping when the upstream IP changed (e.g. a scan
      // applied a new CONNECT_IP) — the old RTT no longer describes this server.
      if (c && this.healthIP && c.CONNECT_IP !== this.healthIP) { this.health = null; this.healthIP = null; }

      var peers = cl ? (cl.peers || 0) : 0;
      var conns = cl ? (cl.active || 0) : 0;
      var running = !!(s && s.running);

      var mode = App.state.bridge === "probing" ? "connecting"
        : App.state.busy ? "busy" : !s ? "connecting" : s.running ? "running" : "stopped";

      var label = App.state.busy ? t("orb_working") : !s ? t("orb_nodaemon") : s.running ? t("orb_connected") : t("orb_connect");
      var sub = App.state.busy ? t("sub_wait")
        : !s ? (App.state.bridge === "preview" ? t("sub_preview") : t("sub_waitdaemon"))
        : s.running ? (peers ? t("sub_conn", { peers: peers, conns: conns, ps: App.lang === "fa" ? "" : (peers === 1 ? "" : "s"), cs: App.lang === "fa" ? "" : (conns === 1 ? "" : "s") }) : t("sub_noclients"))
        : t("sub_tapstart");

      var orb = el("button.orb", { "data-state": mode, "aria-label": label, onclick: function () { App.togglePower(); } }, [
        el("div.orb__ring", null, [ui.icon("power", "orb__glyph")]),
        el("div.orb__label", null, [label]),
        el("div.orb__sub", null, [sub])
      ]);
      if (!s || App.state.busy) orb.disabled = true;
      v.appendChild(orb);

      // upstream stat doubles as tappable link-health probe
      var hk = [ui.icon("globe", "ico--sm"), t("stat_upstream")];
      if (this.healthBusy) hk.push(el("span", { style: "margin-inline-start:auto" }, [el("span.spinner")]));
      else if (this.health) hk.push(el("span.stat__badge" + (this.health.ok ? ".ok" : ".bad"), null, [this.health.ok ? (this.health.rtt + "ms") : t("badge_down")]));
      else hk.push(el("span.stat__badge.hint", null, [t("hint_taptest")]));
      var upStat = el("button.stat.stat--btn", { onclick: this.probeHealth.bind(this), "aria-label": t("health_btn") }, [
        el("div.stat__k", null, hk),
        el("div.stat__v.mono", null, [c ? c.CONNECT_IP : "—"])
      ]);

      v.appendChild(el("div.stats", null, [
        stat(t("stat_devices"), "users", String(peers), running && peers ? ".stat__v--green" : ""),
        stat(t("stat_conns"), "activity", String(conns)),
        stat(t("stat_method"), "zap", (c && c.BYPASS_METHOD) || "—"),
        upStat
      ]));

      // Live throughput + cumulative data — a slim one-row strip so the fixed
      // (non-scrolling) Status view still fits without pushing the devices card off.
      var down = running && cl ? (cl.down_bps || 0) : 0;
      var up = running && cl ? (cl.up_bps || 0) : 0;
      var used = running && cl && typeof cl.bytes_up === "number" ? (cl.bytes_up + cl.bytes_down) : 0;
      function speedItem(iconName, label, value, valClass) {
        return el("div.speed__item", { title: label }, [
          ui.icon(iconName, "ico--sm"),
          el("span.speed__val" + (valClass || ""), null, [value])
        ]);
      }
      v.appendChild(el("div.speed", null, [
        speedItem("download", t("stat_down"), running ? fmtRate(down) : "—", running && down ? ".stat__v--green" : ""),
        speedItem("upload", t("stat_up"), running ? fmtRate(up) : "—"),
        speedItem("database", t("stat_data"), running ? fmtBytes(used) : "—")
      ]));

      var body = [];
      var list = (cl && cl.clients) || [];
      if (!s || !s.running) body.push(el("div.empty", null, [t("devices_off")]));
      else if (!list.length) body.push(el("div.empty", null, [t("devices_none")]));
      else list.slice(0, 4).forEach(function (p) {
        body.push(el("div.peer", null, [
          el("span.peer__ico", null, [ui.icon(p.local ? "cpu" : "wifi", "ico--sm")]),
          el("span.peer__ip", null, [p.ip]),
          el("span.peer__tag", null, [p.local ? t("tag_ondevice") : t("tag_lan")]),
          el("span.peer__n", null, [p.conns + "×"])
        ]));
      });
      v.appendChild(ui.card(t("card_devices"), c ? (c.LISTEN_HOST + ":" + c.LISTEN_PORT) : null, body, "users"));
    },

    probeHealth: function () {
      if (this.healthBusy) return;
      this.healthBusy = true; this.render();
      var self = this;
      var probedIP = (App.state.config || {}).CONNECT_IP || null;
      App.api.health().then(function (h) {
        var ep = h && h.endpoints && h.endpoints[0];
        self.health = ep ? { ok: !!ep.healthy, rtt: ep.latency_ms } : { ok: false };
        self.healthIP = probedIP; // remember which IP this RTT belongs to
      }).catch(function () { self.health = { ok: false }; self.healthIP = probedIP; }).then(function () {
        self.healthBusy = false; self.render();
      });
    }
  });
})();
