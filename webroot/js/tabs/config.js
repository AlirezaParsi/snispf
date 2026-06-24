/* Config tab — edit channel + bypass with graphical chip pickers. */
(function () {
  "use strict";
  var App = window.App, ui = App.ui, el = ui.el, t = function (k) { return App.t(k); };

  var METHODS = ["wrong_seq", "combined", "fake_sni", "fragment"];
  var UTLS = ["none", "firefox", "chrome", "safari", "ios", "edge", "randomized"];
  var FRAG = ["sni_split", "half", "multi", "tls_record_frag"];

  function field(label, control) { return el("label.field", null, [el("span", null, [label]), control]); }
  function input(id, val, attrs) { var a = attrs || {}; a.id = id; a.value = val == null ? "" : val; return el("input", a); }

  // tap-to-open list picker (bottom sheet). value held in a hidden input #id.
  function picker(id, title, items, val) {
    var cur = items.filter(function (i) { return i.value === val; })[0] || { value: val, text: val };
    var hidden = el("input", { type: "hidden", id: id, value: val });
    var valSpan = el("span.picker__val", null, [cur.text]);
    var trigger = el("button.picker", { type: "button" }, [valSpan, ui.icon("chevron", "ico--sm picker__chev")]);
    trigger.addEventListener("click", function () {
      ui.openSheet({
        title: title, items: items, value: hidden.value,
        onPick: function (v) {
          hidden.value = v;
          var p = items.filter(function (i) { return i.value === v; })[0];
          valSpan.textContent = p ? p.text : v;
        }
      });
    });
    return el("div.field-control", null, [hidden, trigger]);
  }
  function pickerOf(id, title, opts, val) { return picker(id, title, opts.map(function (o) { return { value: o, text: o }; }), val); }

  App.registerTab({
    id: "config",
    label: "nav_config",
    mount: function (view) { this.view = view; if (this.ifaceItems == null) this.loadIfaces(); this.render(); },
    refresh: function () {},

    loadIfaces: function () {
      this.ifaceItems = [];
      var self = this;
      App.api.interfaces().then(function (r) {
        var items = [{ value: "auto", text: r.auto ? ("auto → " + r.auto) : "auto" }];
        (r.interfaces || []).forEach(function (i) { items.push({ value: i.name, text: i.name }); });
        self.ifaceItems = items;
        if (self.view) self.render();
      }).catch(function () { self.ifaceItems = [{ value: "auto", text: "auto" }]; });
    },

    render: function () {
      var c = App.state.config;
      var v = ui.clear(this.view);
      if (!c) { v.appendChild(ui.loadingCard(t("cfg_loading"))); return; }

      var ifaceItems = (this.ifaceItems && this.ifaceItems.length) ? this.ifaceItems : [{ value: "auto", text: "auto" }];
      var cur = c.INTERFACE || "auto";
      if (!ifaceItems.some(function (i) { return i.value === cur; })) ifaceItems = ifaceItems.concat([{ value: cur, text: cur }]);

      // one fill card: head + internally-scrolling field body + pinned Save.
      var body = el("div.scrolly", null, [
        el("div.field-2", null, [
          field(t("cfg_ip"), input("cfg_ip", c.CONNECT_IP, { inputmode: "decimal", placeholder: "104.19.x.x" })),
          field(t("cfg_port"), input("cfg_port", c.CONNECT_PORT, { inputmode: "numeric" }))
        ]),
        field(t("cfg_sni"), input("cfg_sni", c.FAKE_SNI, { placeholder: "www.cloudflare.com" })),
        el("div.field-2", null, [
          field(t("cfg_method"), pickerOf("cfg_method", t("cfg_method"), METHODS, c.BYPASS_METHOD)),
          field(t("cfg_fp"), pickerOf("cfg_utls", t("cfg_fp"), UTLS, c.UTLS || "none"))
        ]),
        el("div.field-2", null, [
          field(t("cfg_frag"), pickerOf("cfg_frag", t("cfg_frag"), FRAG, c.FRAGMENT_STRATEGY)),
          field(t("cfg_fdelay"), input("cfg_fdelay", c.FRAGMENT_DELAY, { inputmode: "decimal" }))
        ]),
        field(t("cfg_iface"), picker("cfg_iface", t("cfg_iface"), ifaceItems, cur)),
        el("div.field-2", null, [
          field(t("cfg_host"), input("cfg_lhost", c.LISTEN_HOST, { placeholder: "0.0.0.0" })),
          field(t("cfg_port"), input("cfg_lport", c.LISTEN_PORT, { inputmode: "numeric" }))
        ])
      ]);
      var head = el("div.card__head", null, [
        el("span.card__icon", null, [ui.icon("sliders", "ico--sm")]),
        el("h2.card__title", null, [t("cfg_channel")])
      ]);
      var save = el("button.btn.btn--primary.btn--full", { style: "margin-top:12px;flex:none", onclick: this.save.bind(this) }, [ui.icon("check", "ico--sm"), t("cfg_save")]);
      v.appendChild(el("section.card.card--fill", null, [head, body, save]));
    },

    save: function (e) {
      var btn = e.currentTarget;
      function val(id) { var n = document.getElementById(id); return n ? n.value.trim() : ""; }
      var cfg = Object.assign({}, App.state.config, {
        CONNECT_IP: val("cfg_ip"), CONNECT_PORT: parseInt(val("cfg_port"), 10) || 443,
        FAKE_SNI: val("cfg_sni"), BYPASS_METHOD: val("cfg_method"), UTLS: val("cfg_utls"),
        FRAGMENT_STRATEGY: val("cfg_frag"), FRAGMENT_DELAY: parseFloat(val("cfg_fdelay")) || 0,
        INTERFACE: val("cfg_iface") || "auto",
        LISTEN_HOST: val("cfg_lhost"), LISTEN_PORT: parseInt(val("cfg_lport"), 10) || 40443
      });
      btn.disabled = true; btn.textContent = t("cfg_saving");
      App.api.setConfig(cfg).then(function () {
        App.set({ config: cfg }); ui.toast(t("saved"), "ok"); App.refreshStatus();
      }).catch(function (err) {
        ui.toast(t("save_fail") + err.message, "bad");
      }).then(function () { btn.disabled = false; ui.clear(btn); btn.appendChild(ui.icon("check", "ico--sm")); btn.appendChild(document.createTextNode(t("cfg_save"))); });
    }
  });
})();
