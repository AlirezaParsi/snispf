/* app.js — boot, bottom-nav routing, power toggle, theme/lang, polling. */
(function () {
  "use strict";
  var App = window.App, ui = App.ui, el = ui.el, t = function (k, p) { return App.t(k, p); };

  var active = null;
  var view = document.getElementById("view");
  var nav = document.getElementById("bottomnav");
  var appStatus = document.getElementById("appStatus");
  var appStatusText = document.getElementById("appStatusText");
  var themeBtn = document.getElementById("themeBtn");
  var langBtn = document.getElementById("langBtn");
  document.getElementById("appMark").appendChild(ui.icon("shield"));

  var NAV_ICONS = { status: "activity", config: "sliders", scan: "radar", logs: "terminal" };

  App.refreshStatus = function () {
    return App.api.status().then(function (s) {
      App.set({ status: s });
      if (s && s.running) App.refreshClients(); else App.set({ clients: null });
    }).catch(function () { App.set({ status: null, clients: null }); });
  };
  App.refreshConfig = function () {
    return App.api.getConfig().then(function (c) { App.set({ config: c }); }).catch(function () {});
  };
  App.refreshClients = function () {
    return App.api.clients().then(function (c) {
      // Derive live up/down speed from byte/timestamp deltas between polls. The
      // core writes cumulative bytes + a flush ts; rate = Δbytes / Δt. Skip the
      // tick when the counter went backwards (core restarted = fresh process) —
      // just rebaseline so we never show a bogus spike.
      if (c && typeof c.bytes_up === "number" && c.stats_ts) {
        var p = App._rate;
        if (p && c.stats_ts > p.ts && c.bytes_up >= p.up && c.bytes_down >= p.down) {
          var dt = (c.stats_ts - p.ts) / 1000;
          if (dt > 0) {
            c.up_bps = (c.bytes_up - p.up) / dt;
            c.down_bps = (c.bytes_down - p.down) / dt;
          }
        }
        App._rate = { up: c.bytes_up, down: c.bytes_down, ts: c.stats_ts };
      } else {
        App._rate = null;
      }
      App.set({ clients: c });
    }).catch(function () {});
  };

  App.togglePower = function () {
    if (!App.state.status || App.state.busy) return;
    var running = App.running();
    App.set({ busy: true });
    var p = running ? App.api.stop() : App.api.start();
    p.then(function () {
      ui.toast(running ? t("t_disconnected") : t("t_connected"), running ? "warn" : "ok");
    }).catch(function (err) {
      ui.toast(t(running ? "t_stopfail" : "t_startfail") + err.message, "bad");
    }).then(function () { App.set({ busy: false }); App.refreshStatus(); });
  };

  function tabById(id) { for (var i = 0; i < App.tabs.length; i++) if (App.tabs[i].id === id) return App.tabs[i]; return null; }

  function buildNav() {
    ui.clear(nav);
    App.tabs.forEach(function (tab) {
      var b = el("button.navbtn", { role: "tab", "data-id": tab.id, onclick: function () { activate(tab.id); } },
        [ui.icon(NAV_ICONS[tab.id] || "activity"), el("span", null, [t(tab.label)])]);
      nav.appendChild(b);
    });
  }

  function activate(id) {
    active = id;
    App.activeId = id;
    Array.prototype.forEach.call(nav.children, function (b) {
      b.setAttribute("aria-selected", b.getAttribute("data-id") === id ? "true" : "false");
    });
    var tab = tabById(id);
    if (view.classList) view.classList.toggle("view--fixed", !!(tab && tab.fixed));
    if (tab) tab.mount(view);
    view.scrollTop = 0;
  }

  function updateToggles() {
    ui.clear(themeBtn).appendChild(ui.icon(App.theme === "dark" ? "sun" : "moon"));
    langBtn.textContent = App.lang === "fa" ? "EN" : "فا";
  }

  App.rerender = function () {
    updateToggles();
    buildNav();
    activate(active || (App.tabs[0] && App.tabs[0].id));
    paint(App.state);
  };

  function paint(state) {
    var s = state.status;
    var mode = state.bridge === "probing" ? "connecting" : state.busy ? "busy" : !s ? "connecting" : s.running ? "running" : "stopped";
    appStatus.setAttribute("data-state", mode);
    appStatusText.textContent = state.busy ? t("st_working")
      : !s ? (state.bridge === "preview" ? t("st_preview") : t("st_offline"))
      : s.running ? t("st_connected") : t("st_off");
    var tab = tabById(active);
    if (tab && tab.refresh) tab.refresh();
  }

  themeBtn.addEventListener("click", function () { App.setTheme(App.theme === "dark" ? "light" : "dark"); updateToggles(); });
  langBtn.addEventListener("click", function () { App.setLang(App.lang === "fa" ? "en" : "fa"); });

  function boot() {
    App.subscribe(paint);
    App.setTheme(App.theme);
    document.documentElement.setAttribute("lang", App.lang);
    document.documentElement.setAttribute("dir", "ltr");
    updateToggles();
    buildNav();
    activate(App.tabs[0] ? App.tabs[0].id : "status");

    App.set({ bridge: App.api.hasBridge() ? "ksu" : "preview" });
    if (App.state.bridge === "preview") ui.toast(t("t_preview"), "warn");

    App.refreshConfig();
    App.refreshStatus();
    setInterval(function () { if (!App.state.busy) App.refreshStatus(); }, 6000);
    // Faster clients-only poll while running, so the Status tab shows near
    // real-time up/down speed without waiting on the 6s status cycle.
    setInterval(function () {
      if (!App.state.busy && App.running() && App.state.bridge === "ksu") App.refreshClients();
    }, 2500);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
