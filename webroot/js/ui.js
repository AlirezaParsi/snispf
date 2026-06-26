/* ui.js — DOM helpers, SVG icons (no emoji), toasts, formatters. */
(function () {
  "use strict";
  var App = window.App;

  function el(spec, attrs, kids) {
    var parts = spec.split(/(?=[.#])/);
    var node = document.createElement(parts[0] || "div");
    for (var i = 1; i < parts.length; i++) {
      if (parts[i][0] === ".") node.classList.add(parts[i].slice(1));
      else if (parts[i][0] === "#") node.id = parts[i].slice(1);
    }
    if (attrs) for (var k in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
      var v = attrs[k];
      if (k === "onclick" || k === "oninput" || k === "onchange") node.addEventListener(k.slice(2), v);
      else if (k === "html") node.innerHTML = v;
      else if (v != null) node.setAttribute(k, v);
    }
    if (kids != null) {
      if (!Array.isArray(kids)) kids = [kids];
      kids.forEach(function (c) {
        if (c == null) return;
        node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
      });
    }
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

  // Lucide-style stroke icons. Inner markup per name.
  var ICONS = {
    shield: '<path d="M12 3l7 3v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6z"/>',
    power: '<path d="M12 3v9"/><path d="M6.6 7.6a8 8 0 1 0 10.8 0"/>',
    activity: '<polyline points="3 12 7 12 10 5 14 19 17 12 21 12"/>',
    sliders: '<line x1="4" y1="8" x2="20" y2="8"/><circle cx="15" cy="8" r="2.4"/><line x1="4" y1="16" x2="20" y2="16"/><circle cx="9" cy="16" r="2.4"/>',
    radar: '<circle cx="12" cy="12" r="1.6"/><path d="M12 12 19 5"/><path d="M5 12a7 7 0 0 1 7-7"/><path d="M8.5 12a3.5 3.5 0 0 1 3.5-3.5"/>',
    terminal: '<polyline points="5 8 9 12 5 16"/><line x1="12" y1="16" x2="19" y2="16"/>',
    users: '<path d="M16 21v-1.6a4 4 0 0 0-4-4H6.5a4 4 0 0 0-4 4V21"/><circle cx="9.2" cy="7.5" r="3.6"/><path d="M21.5 21v-1.6a4 4 0 0 0-3-3.85"/><path d="M16.5 3.9a4 4 0 0 1 0 7.2"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18"/>',
    zap: '<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z"/>',
    wifi: '<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 15.8a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/>',
    check: '<polyline points="5 12 10 17 19 7"/>',
    refresh: '<path d="M4 9a8 8 0 0 1 14-3l2 2"/><path d="M20 15a8 8 0 0 1-14 3l-2-2"/><path d="M18 4v4h-4M6 20v-4h4"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/>',
    moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
    chevron: '<polyline points="6 9 12 15 18 9"/>',
    download: '<path d="M12 3v12"/><polyline points="7 11 12 16 17 11"/><path d="M5 20h14"/>',
    upload: '<path d="M12 21V9"/><polyline points="7 13 12 8 17 13"/><path d="M5 4h14"/>',
    database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>'
  };

  function icon(name, cls) {
    var span = document.createElement("span");
    span.innerHTML = '<svg viewBox="0 0 24 24" class="ico ' + (cls || "") + '">' + (ICONS[name] || "") + "</svg>";
    return span.firstChild;
  }

  function toast(msg, kind) {
    var box = document.getElementById("toaster");
    var t = el("div.toast" + (kind ? ".toast--" + kind : ""), null, [msg]);
    box.appendChild(t);
    setTimeout(function () {
      t.style.transition = "opacity .25s, transform .25s";
      t.style.opacity = "0"; t.style.transform = "translateY(8px)";
      setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 260);
    }, kind === "bad" ? 4200 : 2600);
  }

  function bars(ms) {
    var n = ms == null ? 0 : ms < 120 ? 4 : ms < 200 ? 3 : ms < 350 ? 2 : 1;
    var wrap = el("span.bars", { title: ms != null ? ms + " ms" : "" });
    for (var i = 0; i < 4; i++) {
      var b = el("i" + (i < n ? ".on" : ""));
      b.style.height = (5 + i * 3) + "px";
      wrap.appendChild(b);
    }
    return wrap;
  }

  function pill(text, kind) { return el("span.pill.pill--" + kind, null, [text]); }

  function card(title, hint, body, iconName) {
    var head = el("div.card__head", null, [
      iconName ? el("span.card__icon", null, [icon(iconName, "ico--sm")]) : null,
      el("h2.card__title", null, [title]),
      hint ? el("span.card__hint", null, [hint]) : null
    ]);
    var c = el("section.card", null, [head]);
    if (body) (Array.isArray(body) ? body : [body]).forEach(function (b) { if (b) c.appendChild(b); });
    return c;
  }

  function loadingCard(label) {
    return el("section.card", null, [el("div.empty", null, [el("span.spinner"), "  " + (label || "loading…")])]);
  }

  // bottom-sheet list picker. opts: { title, items:[{value,text}], value, onPick }
  function openSheet(opts) {
    var overlay = el("div.sheet-overlay");
    var sheet = el("div.sheet");
    // drag zone (handle + title) — grab it to pull the sheet down to dismiss
    var header = el("div.sheet__header", null, [el("div.sheet__handle", { "aria-hidden": "true" })]);
    if (opts.title) header.appendChild(el("div.sheet__title", null, [opts.title]));
    sheet.appendChild(header);

    var list = el("div.sheet__list");
    (opts.items || []).forEach(function (it) {
      var sel = it.value === opts.value;
      var row = el("button.sheet__opt", { type: "button", "aria-selected": sel ? "true" : "false" },
        [el("span", null, [it.text]), sel ? icon("check", "ico--sm") : el("span")]);
      row.addEventListener("click", function () { close(); if (opts.onPick) opts.onPick(it.value); });
      list.appendChild(row);
    });
    sheet.appendChild(list);
    overlay.appendChild(sheet);

    function close() {
      overlay.classList.remove("is-open");
      setTimeout(function () { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); }, 220);
    }
    overlay.addEventListener("click", function (e) { if (e.target === overlay) close(); });

    // drag-to-dismiss from the header
    var startY = 0, dy = 0, dragging = false;
    header.addEventListener("touchstart", function (e) { startY = e.touches[0].clientY; dy = 0; dragging = true; sheet.style.transition = "none"; }, { passive: true });
    header.addEventListener("touchmove", function (e) {
      if (!dragging) return;
      dy = e.touches[0].clientY - startY; if (dy < 0) dy = 0;
      sheet.style.transform = "translateY(" + dy + "px)";
    }, { passive: true });
    header.addEventListener("touchend", function () {
      if (!dragging) return;
      dragging = false; sheet.style.transition = "";
      if (dy > 90) { close(); } else { sheet.style.transform = "translateY(0)"; }
      dy = 0;
    });

    document.body.appendChild(overlay);
    setTimeout(function () { overlay.classList.add("is-open"); }, 10);
    return close;
  }

  App.ui = { el: el, clear: clear, icon: icon, toast: toast, bars: bars, pill: pill, card: card, loadingCard: loadingCard, openSheet: openSheet };
})();
