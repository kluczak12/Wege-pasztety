

(() => {
  "use strict";


  const API_BASE = "http://localhost:8000/api/v1";
  const ANALYZE_FETCH_TIMEOUT_MS = 120000;
  const SCAN_INTERVAL_MS = 3000;
  const STALE_UNKNOWN_MS = 2 * 60 * 1000;
  const BADGE_CLASS = "thinklink-badge";
  const PROCESSED_ATTR = "data-thinklink-id";


  let currentMode = "simple";
  let pageLanguage = document.documentElement.lang || navigator.language || "en";
  let scanTimer = null;
  let resultCache = new Map();
  let scanChain = Promise.resolve();

  function cacheResult(urlKey, result) {
    resultCache.set(urlKey, {
      ...result,
      url: result.url || urlKey,
      _tlFetchedAt: Date.now(),
    });
  }

  function peekCache(urlKey) {
    const row = resultCache.get(urlKey);
    if (!row) return null;
    const lvl = String(row.risk_level || "").toLowerCase();
    if (
      lvl === "unknown"
      && row._tlFetchedAt != null
      && Date.now() - row._tlFetchedAt > STALE_UNKNOWN_MS
    ) {
      resultCache.delete(urlKey);
      return null;
    }
    return row;
  }

  function forUiResult(row) {
    if (!row) return row;
    const { _tlFetchedAt, ...rest } = row;
    return rest;
  }
  let blockedCount = 0;


  let extensionAlive = true;
  let scanIntervalHandle = null;
  let mutationObserver = null;

  function isExtensionContextValid() {
    try {
      return Boolean(chrome?.runtime?.id);
    } catch {
      return false;
    }
  }

  function shutdownDueToInvalidContext() {
    if (!extensionAlive) return;
    extensionAlive = false;
    console.warn("[ThinkLink] Extension was reloaded — content script shutting down. Refresh the page to re-enable.");
    if (scanIntervalHandle) clearInterval(scanIntervalHandle);
    if (scanTimer) clearTimeout(scanTimer);
    if (mutationObserver) mutationObserver.disconnect();
  }


  const TRANSLATIONS = {
    en: {
      safe: "Safe",
      dangerous: "Dangerous — blocked",
      suspicious: "Suspicious",
      unknown: "Unknown",
      unknown_tooltip:
        "Still unclassified — ThinkLink will retry automatically. If this stays, the URL could not be checked (e.g. invalid or non-web link).",
      blocked_tooltip: "This link was blocked by ThinkLink because it was flagged as dangerous.",
      report_btn: "Show Report",
      loading: "Checking…",
      aria_safe: "Safe link",
      aria_danger: "Dangerous link — click blocked",
      aria_suspicious: "Suspicious link — proceed with caution",
      report_sandbox_disclaimer:
        "Timeline is inferred from the same scan data as this report, not from a real browser recording.",
      report_sandbox_unavailable: "Sandbox details unavailable.",
      report_ai_no_model:
        "No base-scan text was stored — the sandbox summary follows in this section.",
      report_assessment_title: "Scan & sandbox",
      report_sandbox_short_title: "Sandbox summary",
      report_sandbox_timeline_title: "Sandbox timeline",
      sandbox_simulating: "Simulating visit to:",
      sandbox_detected_events: "Detected Events",
    },
    pl: {
      safe: "Bezpieczne",
      dangerous: "Niebezpieczne — zablokowane",
      suspicious: "Podejrzane",
      unknown: "Nieznane",
      unknown_tooltip:
        "Bez klasyfikacji — ThinkLink ponowi próbę. Jeśli nadal widać ten znaczek, linku nie dało się sprawdzić.",
      blocked_tooltip: "Ten link został zablokowany przez ThinkLink, ponieważ został oznaczony jako niebezpieczny.",
      report_btn: "Pokaż raport",
      loading: "Sprawdzam…",
      aria_safe: "Bezpieczny link",
      aria_danger: "Niebezpieczny link — kliknięcie zablokowane",
      aria_suspicious: "Podejrzany link — zachowaj ostrożność",
      report_sandbox_disclaimer:
        "Oś czasu jest wnioskowana z tych samych danych skanowania co ten raport, a nie z nagrania przeglądarki.",
      report_sandbox_unavailable: "Szczegóły sandbox niedostępne.",
      report_ai_no_model:
        "Brak zapisanego opisu skanu — skrót sandbox jest niżej w tej sekcji.",
      report_assessment_title: "Skan i sandbox",
      report_sandbox_short_title: "Skrót sandbox",
      report_sandbox_timeline_title: "Oś czasu sandbox",
      sandbox_simulating: "Symulacja wizyty pod adresem:",
      sandbox_detected_events: "Wykryte zdarzenia",
    },
    de: {
      safe: "Sicher",
      dangerous: "Gefährlich — gesperrt",
      suspicious: "Verdächtig",
      unknown: "Unbekannt",
      unknown_tooltip:
        "Noch nicht eingestuft — ThinkLink versucht es erneut. Bleibt das, ließ sich die URL nicht prüfen.",
      blocked_tooltip: "Dieser Link wurde von ThinkLink blockiert, da er als gefährlich eingestuft wurde.",
      report_btn: "Bericht anzeigen",
      loading: "Prüfe…",
      aria_safe: "Sicherer Link",
      aria_danger: "Gefährlicher Link — Klick blockiert",
      aria_suspicious: "Verdächtiger Link — Vorsicht geboten",
      report_sandbox_disclaimer:
        "Die Zeitleiste leitet sich von denselben Scan-Daten wie dieser Bericht ab, nicht von einer echten Browseraufzeichnung.",
      report_sandbox_unavailable: "Sandbox-Details nicht verfügbar.",
      report_ai_no_model:
        "Kein gespeicherter Scan-Text — die Sandbox-Kurzfassung steht weiter unten in diesem Abschnitt.",
      report_assessment_title: "Scan & Sandbox",
      report_sandbox_short_title: "Sandbox-Kurzfassung",
      report_sandbox_timeline_title: "Sandbox-Zeitleiste",
      sandbox_simulating: "Simulierter Besuch unter:",
      sandbox_detected_events: "Erkannte Ereignisse",
    }
  };

  function t(key) {
    const lang = pageLanguage.slice(0, 2).toLowerCase();
    return (TRANSLATIONS[lang] || TRANSLATIONS["en"])[key] || TRANSLATIONS["en"][key] || key;
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function riskLevelClass(level) {
    const s = String(level || "unknown").toLowerCase();
    return ["safe", "suspicious", "dangerous", "unknown"].includes(s) ? s : "unknown";
  }

  function sandboxInlineSummaryHtml(sandboxData) {
    if (!sandboxData || !sandboxData.verdict) return "";
    let v = String(sandboxData.verdict).replace(/\s+/g, " ").trim();
    if (v.length > 220) v = `${v.slice(0, 217)}…`;
    const level = sandboxData.assessed_risk_level;
    const levelPart = level
      ? `<span class="tl-ai-sandbox-level tl-risk-${riskLevelClass(level)}">${escapeHtml(level)}</span>`
      : "";
    const evs = Array.isArray(sandboxData.events_detected) ? sandboxData.events_detected : [];
    const skipRe = /^(initial request|żądanie początkowe|page request)/i;
    const pick = evs.find((e) => e && e.event && !skipRe.test(String(e.event)));
    let hint = "";
    if (pick && pick.event) {
      let h = String(pick.event).replace(/\s+/g, " ").trim();
      if (h.length > 150) h = `${h.slice(0, 147)}…`;
      hint = `<p class="tl-ai-sandbox-hint">${escapeHtml(h)}</p>`;
    }
    return `
      <div class="tl-ai-sandbox-inline">
        <p class="tl-ai-sandbox-kicker">${t("report_sandbox_short_title")}</p>
        <p class="tl-ai-sandbox-verdict-line">${levelPart}${level ? " · " : ""}<span class="tl-ai-sandbox-verdict-text">${escapeHtml(v)}</span></p>
        ${hint}
      </div>
    `;
  }

  function sandboxFullTimelineHtml(sandboxData, result) {
    if (!sandboxData?.verdict || !Array.isArray(sandboxData.events_detected)) return "";
    const riskClass = riskLevelClass(result.risk_level);
    const u = result.url || "";
    const urlDisplay = `${u.slice(0, 80)}${u.length > 80 ? "…" : ""}`;
    const eventsHtml = sandboxData.events_detected
      .map(
        ev => `
        <li class="tl-sandbox-event">
          <span class="tl-sandbox-time">${escapeHtml(ev.time)}s</span>
          <span>${escapeHtml(ev.event)}</span>
        </li>
      `
      )
      .join("");
    return `
      <div class="tl-report-sandbox">
        <h4 class="tl-sandbox-timeline-heading">${escapeHtml(t("report_sandbox_timeline_title"))}</h4>
        <p class="tl-sandbox-url"><em>${escapeHtml(t("sandbox_simulating"))}</em><br><code>${escapeHtml(urlDisplay)}</code></p>
        <div class="tl-sandbox-content">
          <div class="tl-sandbox-verdict tl-risk-${riskClass}">${escapeHtml(sandboxData.verdict)}</div>
          <h4 class="tl-sandbox-events-heading">${escapeHtml(t("sandbox_detected_events"))}</h4>
          <ul class="tl-sandbox-events">${eventsHtml}</ul>
          <p class="tl-sandbox-note"><em>${escapeHtml(t("report_sandbox_disclaimer"))}</em></p>
        </div>
      </div>
    `;
  }


  async function loadSettings() {
    if (!isExtensionContextValid()) {
      shutdownDueToInvalidContext();
      return { mode: "simple", totalBlocked: 0 };
    }
    return new Promise(resolve => {
      try {
        chrome.storage.sync.get({ mode: "simple", totalBlocked: 0 }, (data) => {
          if (chrome.runtime.lastError) {
            shutdownDueToInvalidContext();
            resolve({ mode: "simple", totalBlocked: 0 });
            return;
          }
          resolve(data);
        });
      } catch {
        shutdownDueToInvalidContext();
        resolve({ mode: "simple", totalBlocked: 0 });
      }
    });
  }

  async function saveSettings(data) {
    if (!isExtensionContextValid()) {
      shutdownDueToInvalidContext();
      return;
    }
    return new Promise(resolve => {
      try {
        chrome.storage.sync.set(data, () => {
          if (chrome.runtime.lastError) shutdownDueToInvalidContext();
          resolve();
        });
      } catch {
        shutdownDueToInvalidContext();
        resolve();
      }
    });
  }

  async function loadHistory() {
    if (!isExtensionContextValid()) {
      shutdownDueToInvalidContext();
      return [];
    }
    return new Promise(resolve => {
      try {
        chrome.storage.local.get({ history: [] }, data => {
          if (chrome.runtime.lastError) {
            shutdownDueToInvalidContext();
            resolve([]);
            return;
          }
          resolve(data.history);
        });
      } catch {
        shutdownDueToInvalidContext();
        resolve([]);
      }
    });
  }

  async function appendHistory(entry) {
    if (!isExtensionContextValid()) {
      shutdownDueToInvalidContext();
      return;
    }
    const history = await loadHistory();
    history.unshift(entry);
    const trimmed = history.slice(0, 200);
    return new Promise(resolve => {
      try {
        chrome.storage.local.set({ history: trimmed }, () => {
          if (chrome.runtime.lastError) shutdownDueToInvalidContext();
          resolve();
        });
      } catch {
        shutdownDueToInvalidContext();
        resolve();
      }
    });
  }

  function safeSendMessage(msg) {
    if (!isExtensionContextValid()) {
      shutdownDueToInvalidContext();
      return;
    }
    try {
      chrome.runtime.sendMessage(msg, () => {
        void chrome.runtime.lastError;
      });
    } catch {
      shutdownDueToInvalidContext();
    }
  }

  function sendThinkLinkApi(message) {
    if (!isExtensionContextValid()) {
      shutdownDueToInvalidContext();
      return Promise.reject(new Error("Extension context invalidated"));
    }
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(response);
        });
      } catch (e) {
        shutdownDueToInvalidContext();
        reject(e);
      }
    });
  }


  const MAX_COLLECT_PER_SCAN = 72;
  const MAX_URLS_PER_API_BATCH = 50;
  const MAX_DOM_NODES_TOUCHED = 28000;
  const SKIP_SUBTREE_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"]);
  const LINKISH_DATA_ATTRS = [
    "data-href", "data-url", "data-target", "data-target-url", "data-click-url",
    "data-ad-url", "data-adclick-url", "data-outbound-url", "data-destination-url",
    "data-landing-url", "data-link", "data-full-src", "data-redirect", "data-loc",
    "data-responsive-ad-click-tracking-url", "data-goto", "data-deep-link",
  ];

  function canonicalUrlForAnalysis(url) {
    try {
      const u = new URL(url);
      u.hash = "";
      u.hostname = u.hostname.toLowerCase();
      return u.href;
    } catch {
      return (url || "").trim();
    }
  }

  function firstHttpUrlInString(s) {
    if (!s || typeof s !== "string") return null;
    const m = s.match(/https?:\/\/[^\s'"<>]+/i);
    return m ? m[0].replace(/[,);]+$/, "") : null;
  }

  const DATASET_KEY_URL_HINT = /url|href|link|click|ad|dest|target|landing|outbound|goto|redirect|src$/i;

  function findHttpUrlInAncestorChain(el, depth) {
    let n = el;
    for (let i = 0; i < depth && n; i++) {
      for (const name of LINKISH_DATA_ATTRS) {
        const v = n.getAttribute?.(name);
        if (v && /^https?:\/\//i.test(String(v).trim())) return String(v).trim();
      }
      const d = n.dataset;
      if (d) {
        for (const key of Object.keys(d)) {
          if (!DATASET_KEY_URL_HINT.test(key)) continue;
          const val = d[key];
          if (typeof val === "string" && /^https?:\/\//i.test(val.trim())) return val.trim();
        }
      }
      n = n.parentElement;
    }
    return null;
  }

  function getRawLinkUrl(el) {
    const tag = el.tagName;
    if (tag === "A" || tag === "AREA") {
      const attrHref = el.getAttribute("href") || "";
      const resolved = el.href || null;
      let preferAncestor = false;
      try {
        if (resolved) {
          const p = new URL(resolved, window.location.href).protocol.toLowerCase();
          preferAncestor = p !== "http:" && p !== "https:";
        } else {
          preferAncestor = true;
        }
      } catch {
        preferAncestor = true;
      }
      if (preferAncestor) {
        const fb =
          findHttpUrlInAncestorChain(el, 6)
          || firstHttpUrlInString(attrHref);
        if (fb) return fb;
      }
      return resolved;
    }
    if (tag === "IFRAME" || tag === "FRAME") {
      const src = el.getAttribute("src");
      return src ? src.trim() : null;
    }
    if (tag === "FORM") return el.action || null;

    if (el.dataset && el.dataset.href) return el.dataset.href;

    for (const name of LINKISH_DATA_ATTRS) {
      const v = el.getAttribute(name);
      if (v && String(v).trim()) return String(v).trim();
    }

    const ont = el.getAttribute("onclick") || "";
    const onclickPatterns = [
      /window\.open\s*\(\s*['"]([^'"]+)['"]/,
      /\.open\s*\(\s*['"]([^'"]+)['"]/,
      /(?:location|document\.location)\s*(?:\.href)?\s*=\s*['"]([^'"]+)['"]/,
      /(?:href|navigationUri)\s*[=:]\s*['"]([^'"]+)['"]/i,
    ];
    for (const re of onclickPatterns) {
      const m = ont.match(re);
      if (m?.[1]) return m[1];
    }
    const extracted = firstHttpUrlInString(ont);
    if (extracted) return extracted;

    return null;
  }

  function couldCarryOutboundUrl(el) {
    const tag = el.tagName;
    if (tag === "A" || tag === "AREA") return true;
    if (tag === "IFRAME" || tag === "FRAME") return true;
    if (tag === "FORM") return true;
    if (el.getAttribute("role") === "link") return true;
    if (tag === "BUTTON" || (tag === "INPUT" && el.type === "button")) return true;
    if (el.hasAttribute("onclick")) return true;
    if (LINKISH_DATA_ATTRS.some(n => el.hasAttribute(n))) return true;
    return false;
  }

  function forEachElementDeep(root, fn, state = { stop: false, touched: 0 }) {
    function walk(el) {
      if (!el || state.stop || state.touched >= MAX_DOM_NODES_TOUCHED) return;
      if (el.nodeType !== Node.ELEMENT_NODE) return;
      if (SKIP_SUBTREE_TAGS.has(el.tagName)) return;
      state.touched++;
      fn(el, state);
      if (state.stop) return;
      const sr = el.shadowRoot;
      if (sr) {
        for (const child of sr.children) walk(child);
      }
      for (const child of el.children) walk(child);
    }
    if (root) walk(root);
  }

  function getLinkUrl(el) {
    const raw = getRawLinkUrl(el);
    if (!raw) return null;
    return canonicalUrlForAnalysis(raw);
  }

  function isSameDocumentNavigation(rawHref) {
    try {
      const link = new URL(rawHref, window.location.href);
      const here = new URL(window.location.href);
      if (link.protocol !== "http:" && link.protocol !== "https:") return false;
      return link.origin === here.origin &&
        link.pathname === here.pathname &&
        link.search === here.search;
    } catch {
      return false;
    }
  }

  function collectLinks() {
    const elements = [];
    const root = document.body || document.documentElement;
    if (!root) return elements;

    const consider = (el) => {
      if (elements.length >= MAX_COLLECT_PER_SCAN) return;
      if (!couldCarryOutboundUrl(el)) return;
      const raw = getRawLinkUrl(el);
      if (!raw) return;
      const url = canonicalUrlForAnalysis(raw);

      if (!el.hasAttribute(PROCESSED_ATTR) && isSameDocumentNavigation(raw)) {
        const id = Math.random().toString(36).slice(2);
        el.setAttribute(PROCESSED_ATTR, id);
        const stub = {
          url,
          risk_level: "safe",
          risk_score: 0.02,
          is_safe: true,
          indicators: [],
          ai_assessment: '{"explanation":"Same-page link (fragment navigation only).","threats":[]}'
        };
        cacheResult(url, stub);
        injectBadge(el, "safe", stub);
        return;
      }

      if (!isAnalyzableUrl(raw)) return;
      if (el.hasAttribute(PROCESSED_ATTR)) {
        if (url && peekCache(url)) return;
        if (el.dataset.thinklinkPending === "1") return;
        el.removeAttribute(PROCESSED_ATTR);
      }
      elements.push(el);
    };

    forEachElementDeep(root, (el, state) => {
      if (elements.length >= MAX_COLLECT_PER_SCAN) {
        state.stop = true;
        return;
      }
      consider(el);
    });

    return elements;
  }

  function isAnalyzableUrl(url) {
    if (!url) return false;
    try {
      const parsed = new URL(url, window.location.href);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
      if (parsed.href === window.location.href + "#" ||
          (parsed.href.startsWith(window.location.href.split("#")[0] + "#"))) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  function getContextText(el) {
    const parent = el.closest("p, li, td, div, article, section") || el.parentElement;
    return parent ? parent.innerText.slice(0, 200) : "";
  }


  async function analyzeLinks(elements) {
    const pending = [];
    for (const el of elements) {
      const url = getLinkUrl(el);
      if (!url) continue;
      const cached = peekCache(url);
      if (cached) {
        if (!el.hasAttribute(PROCESSED_ATTR)) {
          el.setAttribute(PROCESSED_ATTR, Math.random().toString(36).slice(2));
        }
        applyResult(el, forUiResult(cached));
        continue;
      }
      pending.push(el);
    }

    if (pending.length === 0) return;

    const urlToEls = new Map();
    for (const el of pending) {
      const url = getLinkUrl(el);
      if (!urlToEls.has(url)) urlToEls.set(url, []);
      urlToEls.get(url).push(el);
    }

    const uniqueUrls = [...urlToEls.keys()];
    const batchUrls = uniqueUrls.slice(0, MAX_URLS_PER_API_BATCH);
    const toAnalyze = [];
    for (const u of batchUrls) {
      toAnalyze.push(...urlToEls.get(u));
    }

    toAnalyze.forEach(el => {
      const id = Math.random().toString(36).slice(2);
      el.setAttribute(PROCESSED_ATTR, id);
      el.dataset.thinklinkPending = "1";
      injectBadge(el, "loading", null);
    });

    const payload = {
      links: batchUrls.map(u => {
        const el = urlToEls.get(u)[0];
        return {
          url: u,
          context_text: getContextText(el),
          page_url: window.location.href,
          element_type: el.tagName.toLowerCase()
        };
      }),
      page_language: pageLanguage
    };

    try {
      const apiResult = await sendThinkLinkApi({
        type: "THINKLINK_API",
        method: "POST",
        url: `${API_BASE}/analyze`,
        body: payload,
        timeoutMs: ANALYZE_FETCH_TIMEOUT_MS,
      });
      if (!apiResult.ok) {
        throw new Error(
          apiResult.error || (apiResult.status ? `API error ${apiResult.status}` : "API request failed")
        );
      }
      const data = apiResult.data;

      data.results.forEach(result => {
        const key = canonicalUrlForAnalysis(result.url || "");
        cacheResult(key, { ...result, url: key });
      });

      toAnalyze.forEach(el => {
        const url = getLinkUrl(el);
        let row = url && peekCache(url);
        if (!row && url && Array.isArray(data.results)) {
          const i = batchUrls.indexOf(url);
          if (i >= 0 && data.results[i]) {
            const r = data.results[i];
            const key = canonicalUrlForAnalysis(r.url || "") || url;
            cacheResult(key, { ...r, url: key });
            row = peekCache(url) || peekCache(key);
          }
        }
        delete el.dataset.thinklinkPending;
        if (row) applyResult(el, forUiResult(row));
        else injectBadge(el, "unknown", null);
      });

    } catch (err) {
      console.error("[ThinkLink] Analysis failed:", err);
      toAnalyze.forEach(el => {
        delete el.dataset.thinklinkPending;
        injectBadge(el, "error", null);
      });
    }
  }


  function applyResult(el, result) {
    const level = String(result.risk_level || "unknown").toLowerCase();

    injectBadge(el, level, result);

    if (level === "dangerous") {
      blockElement(el, result);
      appendHistory({
        url: result.url,
        risk_level: level,
        risk_score: result.risk_score,
        timestamp: new Date().toISOString(),
        page: window.location.href,
        indicators: result.indicators.map(i => i.code)
      });
      safeSendMessage({
        type: "THREAT_DETECTED",
        url: result.url,
        risk_level: level
      });
    }
  }


  function removeThinkLinkBadgesAfter(el) {
    let sib = el.nextElementSibling;
    while (sib && sib.classList?.contains(BADGE_CLASS)) {
      const next = sib.nextElementSibling;
      sib.remove();
      sib = next;
    }
  }

  function injectBadge(el, status, result) {
    removeThinkLinkBadgesAfter(el);

    const badge = document.createElement("span");
    badge.className = BADGE_CLASS;
    badge.setAttribute("data-for", el.getAttribute(PROCESSED_ATTR) || "");
    badge.setAttribute("role", "img");

    if (status === "loading") {
      badge.innerHTML = `<span class="tl-spinner" aria-label="${t("loading")}">⟳</span>`;
      badge.className += " tl-loading";
    } else if (status === "safe") {
      badge.innerHTML = `<span class="tl-icon tl-safe" aria-label="${t("aria_safe")}">✓</span>`;
      badge.setAttribute("title", t("safe"));
    } else if (status === "dangerous") {
      badge.innerHTML = `<span class="tl-icon tl-danger" aria-label="${t("aria_danger")}">✕</span>`;
      badge.setAttribute("title", t("dangerous"));
      if (currentMode === "expert" && result) {
        badge.appendChild(createExpertControls(result));
      }
    } else if (status === "suspicious") {
      badge.innerHTML = `<span class="tl-icon tl-suspicious" aria-label="${t("aria_suspicious")}">⚠</span>`;
      badge.setAttribute("title", t("suspicious"));
      if (currentMode === "expert" && result) {
        badge.appendChild(createExpertControls(result));
      }
    } else if (status === "error") {
      badge.innerHTML = `<span class="tl-icon tl-error" aria-label="${t("unknown")}">!</span>`;
      badge.setAttribute("title", "Analysis failed — check that the ThinkLink backend is running.");
    } else {
      badge.innerHTML = `<span class="tl-icon tl-unknown" aria-label="${t("unknown")}">?</span>`;
      badge.setAttribute("title", t("unknown_tooltip"));
    }

    el.insertAdjacentElement("afterend", badge);
  }

  function createExpertControls(result) {
    const controls = document.createElement("span");
    controls.className = "tl-expert-controls";

    const reportBtn = document.createElement("button");
    reportBtn.className = "tl-btn tl-btn-report";
    reportBtn.textContent = t("report_btn");
    reportBtn.setAttribute("type", "button");
    reportBtn.setAttribute("aria-haspopup", "dialog");
    reportBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      void showReportModal(result);
    });

    controls.appendChild(reportBtn);
    return controls;
  }


  function blockElement(el, result) {
    el.setAttribute("data-thinklink-blocked", "true");
    el.setAttribute("aria-disabled", "true");
    el.setAttribute("title", t("blocked_tooltip"));

    if (el.tagName === "A") {
      el.dataset.originalHref = el.href;
      el.href = "javascript:void(0)";
    }

    const blocker = (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      showBlockedNotice(result);
    };
    el.addEventListener("click", blocker, true);
    el.addEventListener("mousedown", blocker, true);
  }

  function showBlockedNotice(result) {
    document.querySelectorAll(".tl-blocked-notice").forEach(n => n.remove());

    const notice = document.createElement("div");
    notice.className = "tl-blocked-notice";
    notice.setAttribute("role", "alert");
    notice.setAttribute("aria-live", "assertive");
    notice.innerHTML = `
      <div class="tl-notice-inner">
        <span class="tl-notice-icon">🛡️</span>
        <div class="tl-notice-text">
          <strong>ThinkLink</strong>
          <p>${t("blocked_tooltip")}</p>
          <code>${result.url.slice(0, 80)}${result.url.length > 80 ? "…" : ""}</code>
        </div>
        <button class="tl-notice-close" aria-label="Close" type="button">✕</button>
      </div>
    `;
    notice.querySelector(".tl-notice-close").addEventListener("click", () => notice.remove());
    document.body.appendChild(notice);
    setTimeout(() => notice?.remove(), 5000);
  }


  async function showReportModal(result) {
    removeModal();
    let aiData = {};
    try { aiData = JSON.parse(result.ai_assessment || "{}"); } catch {}

    let sandboxData = result.sandbox_assessment;
    const rl = String(result.risk_level || "").toLowerCase();
    const needsSandboxFetch =
      (rl === "dangerous" || rl === "suspicious") &&
      (!sandboxData?.verdict || !Array.isArray(sandboxData.events_detected));
    if (needsSandboxFetch) {
      try {
        const apiResult = await sendThinkLinkApi({
          type: "THINKLINK_API",
          method: "GET",
          url: `${API_BASE}/sandbox/video?url=${encodeURIComponent(result.url)}`,
          timeoutMs: 60000,
        });
        if (apiResult.ok && apiResult.data) {
          sandboxData = {
            verdict: apiResult.data.verdict,
            duration_seconds: apiResult.data.duration_seconds,
            events_detected: apiResult.data.events_detected,
            assessed_risk_level: apiResult.data.assessed_risk_level,
          };
        }
      } catch {
        /* keep sandboxData empty */
      }
    }

    const severityColor = { low: "#f59e0b", medium: "#f97316", high: "#ef4444", critical: "#b91c1c" };

    const indicatorsHtml = (result.indicators || []).map(ind => `
      <li class="tl-indicator">
        <span class="tl-indicator-code" style="border-left: 3px solid ${severityColor[ind.severity] || "#888"}">
          ${ind.code}
        </span>
        <span class="tl-indicator-desc">${ind.description}</span>
        <span class="tl-indicator-sev tl-sev-${ind.severity}">${ind.severity}</span>
      </li>
    `).join("") || "<li>No specific indicators detected.</li>";

    const domainHtml = result.domain_info ? `
      <div class="tl-section">
        <h3>Domain Info</h3>
        <ul>
          <li>Domain: <strong>${result.domain_info.domain}</strong></li>
          ${result.domain_info.age_days != null ? `<li>Age: <strong>${result.domain_info.age_days} days</strong></li>` : ""}
          ${result.domain_info.registrar ? `<li>Registrar: ${result.domain_info.registrar}</li>` : ""}
          ${result.domain_info.country ? `<li>Country: ${result.domain_info.country}</li>` : ""}
        </ul>
      </div>
    ` : "";

    const redirectHtml = result.redirect_chain && result.redirect_chain.redirect_count > 0 ? `
      <div class="tl-section">
        <h3>Redirect Chain (${result.redirect_chain.redirect_count} hops)</h3>
        <ol class="tl-redirect-chain">
          ${result.redirect_chain.hops.map(h => `<li><code>${h.slice(0, 60)}${h.length > 60 ? "…" : ""}</code></li>`).join("")}
        </ol>
      </div>
    ` : "";

    const exp = (aiData.explanation || "").trim();
    const hasAiExplanation = Boolean(exp);
    const hasFullSandboxTimeline = Boolean(
      sandboxData?.verdict && Array.isArray(sandboxData.events_detected)
    );
    const hasSandboxSummaryOnly = Boolean(sandboxData?.verdict) && !hasFullSandboxTimeline;
    const hasThreatType = Boolean(aiData.threat_type);
    const showAiSection =
      hasAiExplanation ||
      hasThreatType ||
      hasFullSandboxTimeline ||
      hasSandboxSummaryOnly ||
      ((rl === "dangerous" || rl === "suspicious") && !sandboxData?.verdict);
    const aiSectionHtml = showAiSection
      ? `
          <div class="tl-section">
            <h3>${t("report_assessment_title")}</h3>
            ${hasAiExplanation ? `<p class="tl-ai-text">${escapeHtml(exp)}</p>` : ""}
            ${
              !hasAiExplanation &&
              (hasThreatType || hasSandboxSummaryOnly || hasFullSandboxTimeline)
                ? `<p class="tl-ai-text tl-ai-muted">${escapeHtml(t("report_ai_no_model"))}</p>`
                : ""
            }
            ${
              hasThreatType
                ? `<span class="tl-threat-type">Threat type: <strong>${escapeHtml(aiData.threat_type)}</strong></span>`
                : ""
            }
            ${hasFullSandboxTimeline ? sandboxFullTimelineHtml(sandboxData, result) : ""}
            ${hasSandboxSummaryOnly ? sandboxInlineSummaryHtml(sandboxData) : ""}
            ${
              (rl === "dangerous" || rl === "suspicious") && !sandboxData?.verdict
                ? `<p class="tl-sandbox-unavailable">${escapeHtml(t("report_sandbox_unavailable"))}</p>`
                : ""
            }
          </div>
        `
      : "";

    const modal = document.createElement("div");
    modal.className = "tl-modal-overlay";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", "ThinkLink Threat Report");
    modal.innerHTML = `
      <div class="tl-modal">
        <div class="tl-modal-header">
          <h2>🛡️ ThinkLink Threat Report</h2>
          <button class="tl-modal-close" aria-label="Close" type="button">✕</button>
        </div>
        <div class="tl-modal-body">
          <div class="tl-risk-summary tl-risk-${result.risk_level}">
            <span class="tl-risk-label">${result.risk_level.toUpperCase()}</span>
            <span class="tl-risk-score">Risk score: ${Math.round(result.risk_score * 100)}%</span>
          </div>
          <div class="tl-section">
            <h3>URL</h3>
            <code class="tl-url-display">${result.url}</code>
          </div>
          <div class="tl-section">
            <h3>Threat Indicators</h3>
            <ul class="tl-indicators-list">${indicatorsHtml}</ul>
          </div>
          ${domainHtml}
          ${redirectHtml}
          ${aiSectionHtml}
        </div>
      </div>
    `;
    modal.querySelector(".tl-modal-close").addEventListener("click", removeModal);
    modal.addEventListener("click", (e) => { if (e.target === modal) removeModal(); });
    document.body.appendChild(modal);

    modal.querySelector(".tl-modal-close").focus();
  }

  function removeModal() {
    document.querySelectorAll(".tl-modal-overlay").forEach(m => m.remove());
  }


  async function syncMode() {
    const settings = await loadSettings();
    currentMode = settings.mode || "simple";
  }


  function scan() {
    scanChain = scanChain
      .then(async () => {
        if (!extensionAlive) return;
        if (!isExtensionContextValid()) {
          shutdownDueToInvalidContext();
          return;
        }
        await syncMode();
        if (!extensionAlive) return;
        const elements = collectLinks();
        if (elements.length > 0) {
          await analyzeLinks(elements);
        }
      })
      .catch(err => console.error("[ThinkLink] Scan error:", err));
    return scanChain;
  }

  function startScanning() {
    scan();
    mutationObserver = new MutationObserver(() => {
      if (!extensionAlive) return;
      clearTimeout(scanTimer);
      scanTimer = setTimeout(scan, 1000);
    });
    mutationObserver.observe(document.body, { childList: true, subtree: true });
    scanIntervalHandle = setInterval(scan, SCAN_INTERVAL_MS);
  }


  try {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (!extensionAlive || !isExtensionContextValid()) return false;
      if (msg.type === "MODE_CHANGED") {
        currentMode = msg.mode;
        document.querySelectorAll(`[${PROCESSED_ATTR}]`).forEach(el => {
          const url = getLinkUrl(el);
          const row = url && peekCache(url);
          if (row) applyResult(el, forUiResult(row));
        });
        sendResponse({ ok: true });
      }
      if (msg.type === "GET_STATS") {
        sendResponse({
          cached: resultCache.size,
          dangerous: [...resultCache.values()].filter(r => r.risk_level === "dangerous").length,
          suspicious: [...resultCache.values()].filter(r => r.risk_level === "suspicious").length
        });
      }
      return true;
    });
  } catch {
    shutdownDueToInvalidContext();
  }


  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startScanning);
  } else {
    startScanning();
  }

})();
