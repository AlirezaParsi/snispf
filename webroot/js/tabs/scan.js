/* Scan tab — find CF edges + auto-tune. State lives on the tab instance so
   switching tabs (the scan keeps running on the backend) doesn't lose it. */
(function () {
  "use strict";
  var App = window.App, ui = App.ui, el = ui.el, t = function (k) { return App.t(k); };

  App.registerTab({
    id: "scan",
    label: "nav_scan",
    mount: function (view) {
      this.view = view;
      if (this.hitsOnly == null) this.hitsOnly = false;
      this.render();
      // if a scan/tune finished while we were away, results show; if still
      // running, the poll loop is already going and will re-render on done.
    },
    refresh: function () {},

    render: function () {
      var v = ui.clear(this.view), self = this;

      var segAll = el("button.seg__btn", { "aria-pressed": this.hitsOnly ? "false" : "true", onclick: function () { self.hitsOnly = false; sync(); } }, [t("scan_all")]);
      var segHits = el("button.seg__btn", { "aria-pressed": this.hitsOnly ? "true" : "false", onclick: function () { self.hitsOnly = true; sync(); } }, [t("scan_surv")]);
      function sync() { segAll.setAttribute("aria-pressed", self.hitsOnly ? "false" : "true"); segHits.setAttribute("aria-pressed", self.hitsOnly ? "true" : "false"); }
      var seg = el("div.seg", null, [segAll, segHits]);

      var ta = el("textarea.custom", { placeholder: t("scan_custom_ph"), rows: "2" });
      ta.value = this.customText || "";
      ta.addEventListener("input", function (e) { self.customText = e.target.value; });
      var customField = el("label.field", { style: "margin:10px 0 0" }, [el("span", null, [t("scan_custom")]), ta]);

      var scanBtn = el("button.btn.btn--primary.btn--full", { style: "margin-top:10px", onclick: this.runScan.bind(this) }, [ui.icon("radar", "ico--sm"), t(this.scanRunning ? "scan_scanning" : "scan_find")]);
      if (this.scanRunning) scanBtn.disabled = true;
      var tuneBtn = el("button.btn.btn--full", { style: "margin-top:8px", onclick: this.runTune.bind(this) }, [ui.icon("zap", "ico--sm"), t(this.tuneRunning ? "tune_tuning" : "tune_btn")]);
      if (this.tuneRunning) tuneBtn.disabled = true;
      v.appendChild(ui.card(t("scan_finder"), t("scan_dnsfree"), [seg, customField, scanBtn, tuneBtn], "radar"));

      this.scanOut = el("div");
      this.tuneOut = el("div");
      var head = el("div.card__head", null, [el("span.card__icon", null, [ui.icon("activity", "ico--sm")]), el("h2.card__title", null, [t("scan_result")])]);
      v.appendChild(el("section.card.card--fill", null, [head, el("div.scrolly", null, [this.scanOut, this.tuneOut])]));

      this.paintScan();
      this.paintTune();
    },

    maybeRender: function () { if (this.view && App.activeId === "scan") this.render(); },

    // split the custom textarea into {ips, domains}
    parseCustom: function () {
      var txt = (this.customText || "").trim();
      if (!txt) return null;
      var ips = [], domains = [];
      txt.split(/[\s,;]+/).forEach(function (tok) {
        tok = tok.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        if (!tok) return;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(tok)) ips.push(tok);
        else if (tok.indexOf(".") > 0) domains.push(tok);
      });
      return (ips.length || domains.length) ? { ips: ips, domains: domains } : null;
    },

    // ---- scan ----
    paintScan: function () {
      if (!this.scanOut) return;
      var o = ui.clear(this.scanOut);
      if (this.scanRunning) o.appendChild(el("div.empty", null, [el("span.spinner"), "  " + t("scan_probing")]));
      else if (this.scanError) o.appendChild(el("div.empty", null, [this.scanError]));
      else if (this.scanReport) this.renderResults(this.scanReport);
      else o.appendChild(el("div.empty", null, [t("scan_intro")]));
    },
    runScan: function () {
      if (this.scanRunning) return;
      this.scanRunning = true; this.scanReport = null; this.scanError = null;
      App.set({ busy: true });
      this.render();
      var self = this, q = "?per_range=6" + (this.hitsOnly ? "&hits_only=1" : "");
      App.api.scanStart(q, this.parseCustom()).then(function () { self.pollScan(); }).catch(function (err) {
        self.scanRunning = false; self.scanError = err.message; App.set({ busy: false }); self.maybeRender();
      });
    },
    pollScan: function () {
      var self = this;
      App.api.scanStatus().then(function (st) {
        if (st.done) {
          self.scanRunning = false; App.set({ busy: false });
          if (st.error) self.scanError = st.error; else self.scanReport = st.report || {};
          self.maybeRender(); return;
        }
        setTimeout(function () { self.pollScan(); }, 1500);
      }).catch(function (err) { self.scanRunning = false; self.scanError = err.message; App.set({ busy: false }); self.maybeRender(); });
    },
    renderResults: function (r) {
      var out = ui.clear(this.scanOut), self = this, results = (r && r.results) || [];
      out.appendChild(el("div.row", null, [
        el("span.row__k", null, [t("scan_result")]),
        el("span.row__v.mono", { style: "font-size:12px" }, [t("scan_clean") + " " + (r.clean || 0) + " · dpi " + (r.dpi_blocked || 0) + " · tcp " + (r.tcp_blocked || 0)])
      ]));
      if (!results.length) { out.appendChild(el("div.empty", null, [t("scan_none")])); return; }
      results.slice(0, 14).forEach(function (row, i) {
        var meta = (row.status === "ok" ? t("scan_clean") : row.status) + (row.known ? " · " + t("scan_known") : "");
        var ms = (row.rtt_ms != null && row.rtt_ms < 9999) ? Math.round(row.rtt_ms) + "ms" : "—";
        var use = el("button.btn.btn--ghost", { style: "padding:6px 12px;font-size:12px", onclick: function () { self.use(row); } }, [t("scan_use")]);
        out.appendChild(el("div.result" + (i === 0 ? ".is-best" : ""), null, [
          el("span.result__rank.mono", null, [i === 0 ? "★" : String(i + 1)]),
          el("div", null, [el("div.result__ip.mono", null, [row.host || row.ip]), el("div.result__meta", null, [meta + (row.host ? " · " + row.ip : "")])]),
          el("div.result__sig", null, [ui.bars(row.rtt_ms), el("span.result__ms.mono", null, [ms])]),
          use
        ]));
      });
    },
    use: function (row) {
      var sni = row.host || (App.state.config && App.state.config.FAKE_SNI) || row.sni;
      ui.toast(t("t_applying") + row.ip + "…");
      App.api.apply(row.ip, sni, 443).then(function () {
        ui.toast(t("t_apply_set") + row.ip, "ok"); App.refreshStatus(); App.refreshConfig();
      }).catch(function (err) { ui.toast(t("t_apply_fail") + err.message, "bad"); });
    },

    // ---- auto-tune ----
    paintTune: function () {
      if (!this.tuneOut) return;
      var o = ui.clear(this.tuneOut);
      if (this.tuneRunning) o.appendChild(el("div.empty", null, [el("span.spinner"), "  " + t("tune_spawning")]));
      else if (this.tuneError) o.appendChild(el("div.empty", null, [this.tuneError]));
      else if (this.tuneReport) this.renderTune(this.tuneReport);
      else { /* leave empty — scan intro already covers the area */ }
    },
    runTune: function () {
      if (this.tuneRunning) return;
      this.tuneRunning = true; this.tuneReport = null; this.tuneError = null;
      App.set({ busy: true });
      this.render();
      var self = this;
      App.api.testStart().then(function () { self.pollTune(); }).catch(function (err) {
        self.tuneRunning = false; self.tuneError = err.message; App.set({ busy: false }); self.maybeRender();
      });
    },
    pollTune: function () {
      var self = this;
      App.api.testStatus().then(function (st) {
        if (st.done) {
          self.tuneRunning = false; App.set({ busy: false });
          if (st.error) self.tuneError = st.error; else self.tuneReport = st;
          self.maybeRender(); return;
        }
        setTimeout(function () { self.pollTune(); }, 2000);
      }).catch(function (err) { self.tuneRunning = false; self.tuneError = err.message; App.set({ busy: false }); self.maybeRender(); });
    },
    renderTune: function (r) {
      var out = ui.clear(this.tuneOut), self = this, results = (r && r.results) || [];
      if (!results.length) return;
      out.appendChild(el("div.row", null, [el("span.row__k", null, [t("tune_title")]), el("span.row__v", null, [""])]));
      results.forEach(function (x) {
        out.appendChild(el("div.result", null, [
          el("span.result__rank", null, [x.pass ? ui.pill(t("pass"), "ok") : ui.pill(t("fail"), "bad")]),
          el("div", null, [el("div.result__ip.mono", null, ["utls=" + x.case.utls + " · " + x.case.method]), el("div.result__meta", null, [x.pass ? "" : (x.err || "")])]),
          el("span.result__rtt.mono", null, [x.pass ? (x.latency_ms + " ms") : ""]),
          el("span")
        ]));
      });
      if (r.best && r.best.case) {
        out.appendChild(el("button.btn.btn--primary.btn--full", { style: "margin-top:12px", onclick: function () { self.applyBest(r.best); } },
          [t("tune_applybest") + r.best.case.utls + " / " + r.best.case.method]));
      }
    },
    applyBest: function (best) {
      if (!best || !best.case || !App.state.config) { ui.toast(t("t_nothing"), "warn"); return; }
      var cfg = Object.assign({}, App.state.config, { UTLS: best.case.utls, BYPASS_METHOD: best.case.method });
      ui.toast(t("t_applying") + "…");
      App.api.setConfig(cfg).then(function () {
        App.set({ config: cfg }); ui.toast(t("tune_applied"), "ok"); App.refreshStatus();
      }).catch(function (err) { ui.toast(t("t_apply_fail") + err.message, "bad"); });
    }
  });
})();
