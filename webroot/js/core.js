/* core.js — global app namespace, tiny reactive store, tab registry.
   Classic script (no bundler) so it runs as-is inside KsuWebUI's WebView.
   Extend the app by dropping a tab file that calls App.registerTab(...). */
(function () {
  "use strict";

  var listeners = [];
  var state = {
    status: null,    // last /v1/status
    config: null,    // last /v1/config
    busy: false,     // a long action (scan/test) is running
    bridge: "probing" // "ksu" | "preview"
  };

  function pref(key, def) {
    try { return localStorage.getItem(key) || def; } catch (e) { return def; }
  }

  var App = {
    API: "http://127.0.0.1:8797",
    token: "",        // X-SNISPF-Token; empty by default (localhost only)
    tabs: [],

    lang: pref("snispf_lang", "en"),
    theme: pref("snispf_theme", "dark"),

    setTheme: function (t) {
      App.theme = t === "light" ? "light" : "dark";
      try { localStorage.setItem("snispf_theme", App.theme); } catch (e) {}
      document.documentElement.setAttribute("data-theme", App.theme);
    },

    state: state,

    /** Merge a patch into state and notify subscribers. */
    set: function (patch) {
      for (var k in patch) if (Object.prototype.hasOwnProperty.call(patch, k)) state[k] = patch[k];
      for (var i = 0; i < listeners.length; i++) listeners[i](state);
    },

    /** Subscribe to state changes; returns an unsubscribe fn. */
    subscribe: function (fn) {
      listeners.push(fn);
      return function () {
        var idx = listeners.indexOf(fn);
        if (idx >= 0) listeners.splice(idx, 1);
      };
    },

    /** Register a tab. Order = display order. Shape:
     *  { id, label, mount(viewEl), refresh()? } */
    registerTab: function (tab) {
      App.tabs.push(tab);
    },

    running: function () {
      return !!(state.status && state.status.running);
    }
  };

  window.App = App;
})();
