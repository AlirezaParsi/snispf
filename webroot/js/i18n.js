/* i18n.js — English + Persian strings, App.t(key, params), language switch. */
(function () {
  "use strict";
  var App = window.App;

  var DICT = {
    en: {
      nav_status: "Status", nav_config: "Config", nav_scan: "Scan", nav_logs: "Logs",
      st_connected: "connected", st_off: "off", st_connecting: "connecting",
      st_working: "working", st_offline: "offline", st_preview: "preview",
      orb_connect: "Connect", orb_connected: "Connected", orb_working: "Working", orb_nodaemon: "No daemon",
      sub_wait: "please wait", sub_waitdaemon: "waiting for daemon", sub_preview: "preview mode",
      sub_tapstart: "tap to start the tunnel", sub_noclients: "tunnel up · no clients yet",
      sub_conn: "{peers} device{ps} · {conns} conn{cs}",
      stat_devices: "Devices", stat_conns: "Connections", stat_method: "Method", stat_upstream: "Upstream",
      hint_taptest: "tap to test", badge_down: "down",
      card_devices: "Connected devices", devices_off: "Tunnel is off.",
      devices_none: "No clients. Point a device at this listener.",
      tag_ondevice: "on-device", tag_lan: "LAN",
      cfg_channel: "Channel", cfg_channel_hint: "saving restarts the tunnel if running",
      cfg_ip: "Upstream IP", cfg_port: "Port", cfg_sni: "Decoy SNI", cfg_method: "Method",
      cfg_fp: "Fingerprint", cfg_frag: "Fragment", cfg_fdelay: "Frag delay (s)", cfg_iface: "WAN interface",
      cfg_save: "Save & apply", cfg_saving: "Saving…", cfg_listen: "Listen",
      cfg_listen_hint: "where local apps connect", cfg_host: "Host", cfg_loading: "loading config…",
      saved: "Config saved", save_fail: "Save failed: ",
      scan_finder: "Edge finder", scan_dnsfree: "DNS-free", scan_all: "All ranges", scan_surv: "Survivors only",
      scan_find: "Find edges", scan_scanning: "Scanning…",
      scan_intro: "Scan Cloudflare ranges directly — no DNS. Tap a result to use it.",
      scan_probing: "probing edges…", scan_none: "No reachable edges. Try again.",
      scan_use: "Use", scan_result: "Result", scan_clean: "clean", scan_known: "known",
      scan_custom: "Custom IPs / domains", scan_custom_ph: "paste IPs or domains, one per line (optional)",
      tune_title: "Auto-tune", tune_hint: "finds the best bypass", tune_btn: "Auto-tune method",
      tune_tuning: "Tuning…", tune_intro: "Try fingerprint×method combos through a real request.",
      tune_spawning: "spawning probes (up to ~2 min)…", tune_applybest: "Apply best: ",
      pass: "pass", fail: "fail", tune_applied: "Best combo applied",
      logs_title: "Daemon log", logs_hint: "newest at bottom", logs_refresh: "Refresh",
      loading: "loading…", logs_empty: "(empty)",
      logs_offline_hint: "Control API unreachable — showing the on-disk boot log (/data/adb/snispf/service.log):",
      health_title: "Link health", health_btn: "Test link", health_probe: "probing…", health_none: "No endpoints to probe.",
      t_connected: "Connected", t_disconnected: "Disconnected", t_applying: "Applying ",
      t_applied: "Applied ", t_preview: "Preview mode — flash the module for live control",
      t_startfail: "Start failed: ", t_stopfail: "Stop failed: ", t_apply_set: "Upstream set to ",
      t_apply_fail: "Apply failed: ", t_nothing: "Nothing to apply"
    },
    fa: {
      nav_status: "وضعیت", nav_config: "تنظیمات", nav_scan: "اسکن", nav_logs: "لاگ",
      st_connected: "متصل", st_off: "خاموش", st_connecting: "در حال اتصال",
      st_working: "در حال کار", st_offline: "آفلاین", st_preview: "پیش‌نمایش",
      orb_connect: "اتصال", orb_connected: "متصل", orb_working: "در حال کار", orb_nodaemon: "دیمن نیست",
      sub_wait: "لطفاً صبر کنید", sub_waitdaemon: "در انتظار دیمن", sub_preview: "حالت پیش‌نمایش",
      sub_tapstart: "برای شروع تونل بزنید", sub_noclients: "تونل بالا · هنوز کلاینتی نیست",
      sub_conn: "{peers} دستگاه · {conns} اتصال",
      stat_devices: "دستگاه‌ها", stat_conns: "اتصالات", stat_method: "روش", stat_upstream: "سرور",
      hint_taptest: "برای تست بزنید", badge_down: "قطع",
      card_devices: "دستگاه‌های متصل", devices_off: "تونل خاموش است.",
      devices_none: "کلاینتی نیست. یک دستگاه را به این لیسنر وصل کنید.",
      tag_ondevice: "روی دستگاه", tag_lan: "شبکه",
      cfg_channel: "کانال", cfg_channel_hint: "ذخیره، تونل در حال اجرا را ری‌استارت می‌کند",
      cfg_ip: "آی‌پی سرور", cfg_port: "پورت", cfg_sni: "SNI طعمه", cfg_method: "روش",
      cfg_fp: "اثر انگشت", cfg_frag: "تکه‌تکه", cfg_fdelay: "تأخیر تکه (ث)", cfg_iface: "اینترفیس WAN",
      cfg_save: "ذخیره و اعمال", cfg_saving: "در حال ذخیره…", cfg_listen: "شنود",
      cfg_listen_hint: "جایی که اپ‌های محلی وصل می‌شوند", cfg_host: "هاست", cfg_loading: "بارگذاری تنظیمات…",
      saved: "تنظیمات ذخیره شد", save_fail: "خطای ذخیره: ",
      scan_finder: "یاب سرور", scan_dnsfree: "بدون DNS", scan_all: "همه رنج‌ها", scan_surv: "فقط بازمانده‌ها",
      scan_find: "یافتن سرورها", scan_scanning: "در حال اسکن…",
      scan_intro: "رنج‌های کلودفلر مستقیم اسکن می‌شود — بدون DNS. روی نتیجه بزنید.",
      scan_probing: "در حال بررسی…", scan_none: "سروری در دسترس نیست. دوباره تلاش کنید.",
      scan_use: "استفاده", scan_result: "نتیجه", scan_clean: "سالم", scan_known: "شناخته",
      scan_custom: "آی‌پی / دامین دلخواه", scan_custom_ph: "آی‌پی یا دامین، هر کدام یک خط (اختیاری)",
      tune_title: "تنظیم خودکار", tune_hint: "بهترین دور زدن را می‌یابد", tune_btn: "تنظیم خودکار روش",
      tune_tuning: "در حال تنظیم…", tune_intro: "ترکیب اثرانگشت×روش را با درخواست واقعی امتحان می‌کند.",
      tune_spawning: "در حال اجرای بررسی (تا ۲ دقیقه)…", tune_applybest: "اعمال بهترین: ",
      pass: "موفق", fail: "ناموفق", tune_applied: "بهترین ترکیب اعمال شد",
      logs_title: "لاگ دیمن", logs_hint: "جدیدترین در پایین", logs_refresh: "تازه‌سازی",
      loading: "بارگذاری…", logs_empty: "(خالی)",
      logs_offline_hint: "کنترل API در دسترس نیست — لاگ بوت روی دیسک نمایش داده می‌شود (/data/adb/snispf/service.log):",
      health_title: "سلامت لینک", health_btn: "تست لینک", health_probe: "در حال بررسی…", health_none: "اندپوینتی برای تست نیست.",
      t_connected: "متصل شد", t_disconnected: "قطع شد", t_applying: "در حال اعمال ",
      t_applied: "اعمال شد ", t_preview: "حالت پیش‌نمایش — برای کنترل زنده ماژول را فلش کنید",
      t_startfail: "خطای اتصال: ", t_stopfail: "خطای قطع: ", t_apply_set: "سرور تنظیم شد به ",
      t_apply_fail: "خطای اعمال: ", t_nothing: "چیزی برای اعمال نیست"
    }
  };

  App.t = function (key, p) {
    var d = DICT[App.lang] || DICT.en;
    var s = d[key];
    if (s == null) s = DICT.en[key];
    if (s == null) s = key;
    if (p) for (var k in p) if (Object.prototype.hasOwnProperty.call(p, k)) s = s.split("{" + k + "}").join(p[k]);
    return s;
  };

  App.setLang = function (lang) {
    App.lang = DICT[lang] ? lang : "en";
    try { localStorage.setItem("snispf_lang", App.lang); } catch (e) {}
    var html = document.documentElement;
    html.setAttribute("lang", App.lang);
    // Keep the LAYOUT left-to-right; Persian glyphs/words still render RTL via
    // the Unicode bidi algorithm. Don't mirror the whole app.
    html.setAttribute("dir", "ltr");
    if (App.rerender) App.rerender();
  };
})();
