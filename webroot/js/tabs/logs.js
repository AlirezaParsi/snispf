/* Logs tab — tail the daemon log. */
(function () {
  "use strict";
  var App = window.App, ui = App.ui, el = ui.el, t = function (k) { return App.t(k); };

  function asText(data) {
    if (!data) return "";
    if (typeof data === "string") return data;
    if (Array.isArray(data)) return data.join("\n");
    if (Array.isArray(data.lines)) return data.lines.join("\n");
    if (typeof data.logs === "string") return data.logs;
    if (Array.isArray(data.logs)) return data.logs.join("\n");
    return JSON.stringify(data, null, 2);
  }

  App.registerTab({
    id: "logs",
    label: "nav_logs",
    mount: function (view) {
      this.view = view;
      var v = ui.clear(view);
      this.box = el("pre.logbox", null, [t("loading")]);
      var head = el("div.card__head", null, [
        el("span.card__icon", null, [ui.icon("terminal", "ico--sm")]),
        el("h2.card__title", null, [t("logs_title")]),
        el("span.card__hint", null, [t("logs_hint")])
      ]);
      var refresh = el("button.btn.btn--full", { style: "margin-top:10px;flex:none", onclick: this.load.bind(this) }, [ui.icon("refresh", "ico--sm"), t("logs_refresh")]);
      v.appendChild(el("section.card.card--fill", null, [head, this.box, refresh]));
      this.load();
    },
    refresh: function () {},

    load: function () {
      var box = this.box;
      box.textContent = t("loading");
      App.api.logs(400).then(function (d) {
        var s = asText(d).trim();
        box.textContent = s || t("logs_empty");
        box.scrollTop = box.scrollHeight;
      }).catch(function (err) { box.textContent = err.message; });
    }
  });
})();
