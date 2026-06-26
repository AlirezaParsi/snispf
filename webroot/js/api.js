/* api.js — the bridge to the snispf control daemon.
   The WebView can't fetch() localhost cleartext (CSP), so every call shells an
   HTTP client through ksu.exec. curl ships in /system/bin on Android (busybox
   does NOT, in some Magisk contexts), so curl is primary with `busybox wget` as
   a fallback: `curl ... || busybox wget ...` — one exec, tries each in turn. */
(function () {
  "use strict";
  var App = window.App;

  function hasBridge() {
    return !!(window.ksu && typeof window.ksu.exec === "function");
  }

  // Run one shell command, normalize the result to {errno, stdout, stderr}.
  function exec(cmd) {
    if (!hasBridge()) return Promise.reject(new Error("no-bridge"));
    try {
      var ret = window.ksu.exec(cmd);
      if (ret && typeof ret.then === "function") {
        return ret.then(function (r) {
          if (typeof r === "string") return { errno: 0, stdout: r, stderr: "" };
          return { errno: (r && r.errno) | 0, stdout: (r && r.stdout) || "", stderr: (r && r.stderr) || "" };
        });
      }
    } catch (e) { /* fall through to callback form */ }
    // Older callback form: ksu.exec(cmd, optsJSON, callbackName)
    return new Promise(function (resolve, reject) {
      var cb = "__snispf_cb_" + Date.now() + "_" + Math.floor(Math.random() * 1e6);
      window[cb] = function (errno, stdout, stderr) {
        delete window[cb];
        resolve({ errno: parseInt(errno, 10) || 0, stdout: stdout || "", stderr: stderr || "" });
      };
      try { window.ksu.exec(cmd, "{}", cb); }
      catch (e) { delete window[cb]; reject(e); }
    });
  }

  function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

  function buildCmd(method, path, bodyObj, timeout) {
    var url = App.API + path, T = timeout || 60;
    var tok = App.token ? "X-SNISPF-Token: " + App.token : "";
    var body = method === "POST" ? (bodyObj != null ? JSON.stringify(bodyObj) : "") : null;

    // Primary: curl (always in /system/bin on Android).
    var curl = "curl -s -m " + T + " ";
    if (tok) curl += "-H " + shq(tok) + " ";
    if (body !== null) curl += "-X POST -H 'Content-Type: application/json' --data " + shq(body) + " ";
    curl += shq(url);

    // Fallback: busybox wget (KSU and older setups ship it).
    var wget = "busybox wget -q -T " + T + " -O - ";
    if (tok) wget += "--header=" + shq(tok) + " ";
    if (body !== null) wget += "--header='Content-Type: application/json' --post-data=" + shq(body) + " ";
    wget += shq(url);

    return curl + " 2>/dev/null || " + wget;
  }

  // Single-flight gate: only ONE ksu.exec runs at a time. Long calls (scan,
  // auto-tune) would otherwise stack with the status poll and spawn a pile of
  // su processes — the freeze. Everything serializes through this chain.
  var gate = Promise.resolve();
  function noop() {}
  function queued(task) {
    var p = gate.then(task, task);
    gate = p.then(noop, noop);
    return p;
  }

  function request(method, path, bodyObj, timeout) {
    if (App.state.bridge === "preview") return Mock.respond(method, path, bodyObj);
    return queued(function () {
      return exec(buildCmd(method, path, bodyObj, timeout)).then(function (r) {
        if (r.errno !== 0 && !r.stdout) throw new Error(r.stderr || ("daemon unreachable (errno " + r.errno + ")"));
        if (!r.stdout) return {};
        var data;
        try { data = JSON.parse(r.stdout); }
        catch (e) { throw new Error("bad response: " + r.stdout.slice(0, 120)); }
        if (data && data.error) throw new Error(data.error);
        return data;
      });
    });
  }

  App.api = {
    hasBridge: hasBridge,
    status:   function () { return request("GET", "/v1/status"); },
    clients:  function () { return request("GET", "/v1/clients"); },
    interfaces: function () { return request("GET", "/v1/interfaces"); },
    health:   function () { return request("GET", "/v1/health"); },
    getConfig:function () { return request("GET", "/v1/config"); },
    setConfig:function (cfg) { return request("POST", "/v1/config", cfg); },
    start:    function () { return request("POST", "/v1/start"); },
    stop:     function () { return request("POST", "/v1/stop"); },
    logs:     function (limit) { return request("GET", "/v1/logs?limit=" + (limit || 300)); },
    scan:      function (q) { return request("GET", "/v1/scan" + (q || ""), null, 150); },
    scanStart: function (q, body) { return request("POST", "/v1/scan/start" + (q || ""), body || null, 20); },
    scanStatus:function () { return request("GET", "/v1/scan/status", null, 15); },
    apply:    function (ip, sni, port) {
      return request("GET", "/v1/apply?ip=" + encodeURIComponent(ip) +
        "&sni=" + encodeURIComponent(sni || "") + "&port=" + (port || 443));
    },
    test:      function (apply) { return request("GET", "/v1/test" + (apply ? "?apply=1" : ""), null, 260); },
    testStart: function () { return request("POST", "/v1/test/start", null, 20); },
    testStatus:function () { return request("GET", "/v1/test/status", null, 15); },
    // Read the on-disk boot log straight off the filesystem — works even when
    // the control API is dead (which is exactly when you need to see why).
    serviceLog: function (n) {
      if (App.state.bridge === "preview") return Promise.resolve("[preview] no on-disk log");
      return queued(function () {
        var path = "/data/adb/snispf/service.log";
        var nn = n || 400;
        return exec("tail -n " + nn + " " + shq(path) + " 2>/dev/null || busybox tail -n " + nn + " " + shq(path) + " 2>/dev/null")
          .then(function (r) { return r.stdout || ""; });
      });
    }
  };

  /* ---- preview/mock so the UI renders in a desktop browser ---- */
  var Mock = {
    cfg: { LISTEN_HOST: "0.0.0.0", LISTEN_PORT: 40443, CONNECT_IP: "172.67.222.34",
      CONNECT_PORT: 443, FAKE_SNI: "www.cloudflare.com", BYPASS_METHOD: "wrong_seq",
      UTLS: "firefox", FRAGMENT_STRATEGY: "sni_split", FRAGMENT_DELAY: 0.05 },
    on: false,
    respond: function (method, path, body) {
      var self = this;
      return new Promise(function (res) {
        setTimeout(function () { res(self.route(method, path, body)); }, 220);
      });
    },
    route: function (method, path, body) {
      if (path === "/v1/status") return { running: this.on, pid: this.on ? 4242 : 0, raw_injection_available: true, architecture: "arm64" };
      if (path === "/v1/clients") return this.on
        ? { active: 3, peers: 2, clients: [{ ip: "192.168.1.42", conns: 2, local: false }, { ip: "127.0.0.1", conns: 1, local: true }], ports: [40443],
            bytes_up: Math.floor(Date.now() / 40) % 9000000, bytes_down: Math.floor(Date.now() / 8) % 90000000, stats_ts: Date.now() }
        : { active: 0, peers: 0, clients: [], ports: [40443] };
      if (path === "/v1/interfaces") return { auto: "rmnet_data1", interfaces: [{ name: "rmnet_data1", ip: "22.18.220.25" }, { name: "wlan0", ip: "192.168.1.5" }] };
      if (path === "/v1/health") return { endpoints: [{ ip: this.cfg.CONNECT_IP, sni: this.cfg.FAKE_SNI, healthy: true, latency_ms: 138 }] };
      if (path === "/v1/config" && method === "GET") return this.cfg;
      if (path === "/v1/config" && method === "POST") { this.cfg = body; return { saved: true }; }
      if (path === "/v1/start") { this.on = true; return { running: true }; }
      if (path === "/v1/stop") { this.on = false; return { running: false }; }
      if (path.indexOf("/v1/logs") === 0) return { lines: ["[mock] preview mode — flash the module for real logs"] };
      var rep = { clean: 3, dpi_blocked: 1, tcp_blocked: 26,
        results: [{ ip: "172.67.222.34", sni: "www.cloudflare.com", rtt_ms: 112, status: "ok", known: true },
                  { ip: "104.18.41.132", sni: "www.cloudflare.com", rtt_ms: 127, status: "ok", known: false },
                  { ip: "190.93.245.36", sni: "www.cloudflare.com", rtt_ms: 146, status: "alert", known: false }],
        best: { ip: "172.67.222.34", rtt_ms: 112 } };
      if (path.indexOf("/v1/scan/start") === 0) { this.scanAt = Date.now(); return { running: true, started: true }; }
      if (path.indexOf("/v1/scan/status") === 0) {
        if (!this.scanAt || Date.now() - this.scanAt < 1500) return { running: true, done: false };
        return { running: false, done: true, report: rep };
      }
      if (path.indexOf("/v1/scan") === 0) return rep;
      if (path.indexOf("/v1/apply") === 0) return { applied: true };
      var tres = [
        { case: { utls: "firefox", method: "wrong_seq" }, pass: true, latency_ms: 529 },
        { case: { utls: "none", method: "combined" }, pass: true, latency_ms: 796 },
        { case: { utls: "chrome", method: "wrong_seq" }, pass: false, err: "fake hello too large" }];
      var tbest = { case: { utls: "firefox", method: "wrong_seq" }, latency_ms: 529 };
      if (path.indexOf("/v1/test/start") === 0) { this.testAt = Date.now(); return { running: true, started: true }; }
      if (path.indexOf("/v1/test/status") === 0) {
        if (!this.testAt || Date.now() - this.testAt < 2500) return { running: true, done: false };
        return { running: false, done: true, results: tres, best: tbest };
      }
      if (path.indexOf("/v1/test") === 0) return { results: tres, best: tbest };
      return {};
    }
  };
})();
