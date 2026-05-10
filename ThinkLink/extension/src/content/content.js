

(() => {
  "use strict";


  const API_BASE = "http://localhost:8000/api/v1";
  const ANALYZE_FETCH_TIMEOUT_MS = 120000;
  const SCAN_INTERVAL_MS = 3000;
  const STALE_UNKNOWN_MS = 2 * 60 * 1000;
  const BADGE_CLASS = "thinklink-badge";
  const PROCESSED_ATTR = "data-thinklink-id";


  let currentMode = "simple";
  let userLinkWhitelist = [];
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
    console.warn("[ThinkLink] Rozszerzenie zostało przeładowane — skrypt treści wyłączony. Odśwież stronę, aby włączyć ponownie.");
    if (scanIntervalHandle) clearInterval(scanIntervalHandle);
    if (scanTimer) clearTimeout(scanTimer);
    if (mutationObserver) mutationObserver.disconnect();
  }


  const UI = {
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
    modal_title: "Raport zagrożenia ThinkLink",
    modal_close: "Zamknij",
    modal_aria_report: "Raport zagrożenia ThinkLink",
    risk_score_label: "Ocena ryzyka",
    section_url: "Adres URL",
    section_indicators: "Wskaźniki zagrożenia",
    no_indicators: "Nie wykryto szczegółowych wskaźników.",
    section_domain: "Informacje o domenie",
    domain_label: "Domena",
    age_label: "Wiek",
    age_days: "dni",
    registrar_label: "Rejestrator",
    country_label: "Kraj",
    section_redirects: "Łańcuch przekierowań",
    hops_suffix: "skoków",
    badge_error_title: "Analiza nie powiodła się — upewnij się, że backend ThinkLink działa.",
    trust_url_btn: "Zaufaj temu adresowi (whitelist)",
    text_panel_tab: "Sprawdź tekst pod kątem phishingu",
    text_panel_tab_short: "Tekst",
    text_panel_title: "Analiza tekstu",
    text_panel_lead:
      "Wklej SMS, fragment maila lub wiadomość z komunikatora. Ocena jest wykonywana przez model Groq w backendzie ThinkLink.",
    text_panel_placeholder: "Wklej treść wiadomości do sprawdzenia…",
    text_panel_submit: "Analizuj (Groq)",
    text_panel_loading: "Analizuję tekst…",
    text_panel_empty: "Wklej najpierw tekst wiadomości.",
    text_panel_api_err: "Nie udało się połączyć z backendem ThinkLink (localhost:8000).",
  };

  function t(key) {
    return UI[key] ?? key;
  }

  function riskLevelLabelPl(level) {
    const m = {
      safe: "BEZPIECZNE",
      suspicious: "PODEJRZANE",
      dangerous: "NIEBEZPIECZNE",
      unknown: "NIEZNANE",
    };
    const k = String(level || "").toLowerCase();
    return m[k] ?? String(level || "").toUpperCase();
  }

  function severityPl(sev) {
    const m = {
      low: "niski",
      medium: "średni",
      high: "wysoki",
      critical: "krytyczny",
    };
    const k = String(sev || "").toLowerCase();
    return m[k] ?? String(sev ?? "");
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


  async function syncWhitelist() {
    if (!isExtensionContextValid()) {
      userLinkWhitelist = [];
      return;
    }
    return new Promise(resolve => {
      try {
        chrome.storage.sync.get({ linkWhitelist: [] }, (data) => {
          if (chrome.runtime.lastError) {
            userLinkWhitelist = [];
            resolve();
            return;
          }
          userLinkWhitelist = Array.isArray(data.linkWhitelist) ? data.linkWhitelist : [];
          resolve();
        });
      } catch {
        userLinkWhitelist = [];
        resolve();
      }
    });
  }

  function urlMatchesUserWhitelist(urlStr, entries) {
    let link;
    try {
      link = new URL(urlStr, window.location.href);
    } catch {
      return false;
    }
    if (link.protocol !== "http:" && link.protocol !== "https:") return false;
    const lh = link.hostname.toLowerCase();

    for (const raw of entries) {
      const t = String(raw ?? "").trim();
      if (!t) continue;
      let entryUrl;
      try {
        entryUrl = new URL(t.includes("://") ? t : `https://${t}`);
      } catch {
        continue;
      }
      const eh = entryUrl.hostname.toLowerCase();
      if (lh !== eh && !lh.endsWith(`.${eh}`)) continue;
      const pathAndQuery = entryUrl.pathname + entryUrl.search;
      if (pathAndQuery === "/" || pathAndQuery === "") return true;
      const linkPath = link.pathname + link.search;
      if (linkPath.startsWith(pathAndQuery)) return true;
    }
    return false;
  }

  function makeWhitelistSafeResult(urlStr) {
    const key = canonicalUrlForAnalysis(urlStr);
    return {
      url: key,
      risk_level: "safe",
      risk_score: 0.02,
      is_safe: true,
      indicators: [],
      _tlWhitelistSafe: true,
      ai_assessment:
        '{"explanation":"Adres na liście zaufanych użytkownika (whitelist).","threats":[]}',
    };
  }

  function whitelistSafeResultIfMatch(urlStr) {
    if (!userLinkWhitelist.length) return null;
    return urlMatchesUserWhitelist(urlStr, userLinkWhitelist)
      ? makeWhitelistSafeResult(urlStr)
      : null;
  }

  function suggestedWhitelistEntryFromUrl(urlStr) {
    try {
      const u = new URL(urlStr, window.location.href);
      return u.hostname.toLowerCase();
    } catch {
      return String(urlStr || "").trim();
    }
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
    await syncWhitelist();

    const pending = [];
    for (const el of elements) {
      const url = getLinkUrl(el);
      if (!url) continue;

      const wlFirst = whitelistSafeResultIfMatch(url);
      if (wlFirst) {
        cacheResult(wlFirst.url, wlFirst);
        if (!el.hasAttribute(PROCESSED_ATTR)) {
          el.setAttribute(PROCESSED_ATTR, Math.random().toString(36).slice(2));
        }
        delete el.dataset.thinklinkPending;
        applyResult(el, forUiResult(wlFirst));
        continue;
      }

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
      page_language: "pl"
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
      console.error("[ThinkLink] Błąd analizy:", err);
      toAnalyze.forEach(el => {
        delete el.dataset.thinklinkPending;
        injectBadge(el, "error", null);
      });
    }
  }


  function applyResult(el, result) {
    const url = getLinkUrl(el);
    let effective = result;
    if (url) {
      const wl = whitelistSafeResultIfMatch(url);
      if (wl) {
        cacheResult(wl.url, wl);
        effective = wl;
      }
    }

    const level = String(effective.risk_level || "unknown").toLowerCase();

    if (level !== "dangerous") {
      unblockElement(el);
    }

    injectBadge(el, level, effective);

    if (level === "dangerous") {
      blockElement(el, effective);
      appendHistory({
        url: effective.url,
        risk_level: level,
        risk_score: effective.risk_score,
        timestamp: new Date().toISOString(),
        page: window.location.href,
        indicators: (effective.indicators || []).map(i => i.code),
      });
      safeSendMessage({
        type: "THREAT_DETECTED",
        url: effective.url,
        risk_level: level,
      });
    }
  }

  function unblockElement(el) {
    if (el.getAttribute("data-thinklink-blocked") !== "true") return;
    if (el.tagName === "A" && el.dataset.originalHref) {
      try {
        el.href = el.dataset.originalHref;
      } catch {
        /* ignore */
      }
      delete el.dataset.originalHref;
    }
    el.removeAttribute("data-thinklink-blocked");
    el.removeAttribute("aria-disabled");
    el.removeAttribute("title");
    const h = el.__thinklinkBlockHandler;
    if (h) {
      el.removeEventListener("click", h, true);
      el.removeEventListener("mousedown", h, true);
      delete el.__thinklinkBlockHandler;
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
      badge.setAttribute("title", t("badge_error_title"));
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
    el.__thinklinkBlockHandler = blocker;
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
          <button type="button" class="tl-notice-trust">${escapeHtml(t("trust_url_btn"))}</button>
        </div>
        <button class="tl-notice-close" aria-label="${escapeHtml(t("modal_close"))}" type="button">✕</button>
      </div>
    `;
    notice.querySelector(".tl-notice-close").addEventListener("click", () => notice.remove());
    notice.querySelector(".tl-notice-trust").addEventListener("click", async () => {
      try {
        const entry = suggestedWhitelistEntryFromUrl(result.url);
        if (!entry) return;
        const data = await chrome.storage.sync.get({ linkWhitelist: [] });
        const list = Array.isArray(data.linkWhitelist) ? [...data.linkWhitelist] : [];
        const exists = list.some(
          (x) =>
            String(x).trim().toLowerCase() === entry.toLowerCase()
        );
        if (!exists) {
          list.push(entry);
          await chrome.storage.sync.set({ linkWhitelist: list });
        }
        notice.remove();
      } catch (e) {
        console.error("[ThinkLink] Whitelist:", e);
      }
    });
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
        <span class="tl-indicator-sev tl-sev-${ind.severity}">${escapeHtml(severityPl(ind.severity))}</span>
      </li>
    `).join("") || `<li>${escapeHtml(t("no_indicators"))}</li>`;

    const domainHtml = result.domain_info ? `
      <div class="tl-section">
        <h3>${escapeHtml(t("section_domain"))}</h3>
        <ul>
          <li>${escapeHtml(t("domain_label"))}: <strong>${result.domain_info.domain}</strong></li>
          ${result.domain_info.age_days != null ? `<li>${escapeHtml(t("age_label"))}: <strong>${result.domain_info.age_days} ${t("age_days")}</strong></li>` : ""}
          ${result.domain_info.registrar ? `<li>${escapeHtml(t("registrar_label"))}: ${result.domain_info.registrar}</li>` : ""}
          ${result.domain_info.country ? `<li>${escapeHtml(t("country_label"))}: ${result.domain_info.country}</li>` : ""}
        </ul>
      </div>
    ` : "";

    const redirectHtml = result.redirect_chain && result.redirect_chain.redirect_count > 0 ? `
      <div class="tl-section">
        <h3>${escapeHtml(t("section_redirects"))} (${result.redirect_chain.redirect_count} ${t("hops_suffix")})</h3>
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
    const showAiSection =
      hasAiExplanation ||
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
              (hasSandboxSummaryOnly || hasFullSandboxTimeline)
                ? `<p class="tl-ai-text tl-ai-muted">${escapeHtml(t("report_ai_no_model"))}</p>`
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
    modal.setAttribute("aria-label", t("modal_aria_report"));
    modal.innerHTML = `
      <div class="tl-modal">
        <div class="tl-modal-header">
          <h2>🛡️ ${escapeHtml(t("modal_title"))}</h2>
          <button class="tl-modal-close" aria-label="${escapeHtml(t("modal_close"))}" type="button">✕</button>
        </div>
        <div class="tl-modal-body">
          <div class="tl-risk-summary tl-risk-${result.risk_level}">
            <span class="tl-risk-label">${escapeHtml(riskLevelLabelPl(result.risk_level))}</span>
            <span class="tl-risk-score">${escapeHtml(t("risk_score_label"))}: ${Math.round(result.risk_score * 100)}%</span>
          </div>
          <div class="tl-section">
            <h3>${escapeHtml(t("section_url"))}</h3>
            <code class="tl-url-display">${result.url}</code>
          </div>
          <div class="tl-section">
            <h3>${escapeHtml(t("section_indicators"))}</h3>
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

  function renderTextPhishingResultHtml(data) {
    const lvl = String(data.risk_level || "unknown").toLowerCase();
    const rc = riskLevelClass(lvl);
    const pct = Math.round(Number(data.risk_score || 0) * 100);
    const badge = riskLevelLabelPl(lvl);
    return `
      <div class="tl-side-result-card tl-risk-${rc}">
        <div class="tl-side-result-head">
          <span class="tl-side-result-badge">${escapeHtml(badge)}</span>
          <span class="tl-side-result-pct">${pct}%</span>
        </div>
        <p class="tl-side-summary">${escapeHtml(data.summary_pl || "")}</p>
      </div>
    `;
  }

  function initTextPhishingInspector() {
    if (!isExtensionContextValid()) return;
    /* Tylko główne okno — inaczej panel pojawiałby się w iframe (reklamy, filmiki). */
    if (window.self !== window.top) return;
    if (document.getElementById("thinklink-text-inspector")) return;

    const root = document.createElement("div");
    root.id = "thinklink-text-inspector";
    root.className = "tl-side-root";
    root.setAttribute("aria-hidden", "true");

    const drawer = document.createElement("aside");
    drawer.id = "thinklink-text-drawer";
    drawer.className = "tl-side-drawer";
    drawer.setAttribute("role", "region");
    drawer.setAttribute("aria-label", t("text_panel_title"));

    const inner = document.createElement("div");
    inner.className = "tl-side-inner";

    const lead = document.createElement("p");
    lead.className = "tl-side-lead";
    lead.textContent = t("text_panel_lead");

    const ta = document.createElement("textarea");
    ta.className = "tl-side-textarea";
    ta.rows = 10;
    ta.maxLength = 12000;
    ta.placeholder = t("text_panel_placeholder");
    ta.setAttribute("aria-label", t("text_panel_placeholder"));

    const submitBtn = document.createElement("button");
    submitBtn.type = "button";
    submitBtn.className = "tl-side-submit";
    submitBtn.textContent = t("text_panel_submit");

    const resultEl = document.createElement("div");
    resultEl.className = "tl-side-result";
    resultEl.setAttribute("aria-live", "polite");

    inner.appendChild(lead);
    inner.appendChild(ta);
    inner.appendChild(submitBtn);
    inner.appendChild(resultEl);
    drawer.appendChild(inner);

    const handle = document.createElement("button");
    handle.type = "button";
    handle.className = "tl-side-handle";
    handle.setAttribute("aria-expanded", "false");
    handle.setAttribute("aria-controls", "thinklink-text-drawer");
    handle.title = t("text_panel_tab");

    const handleIcon = document.createElement("span");
    handleIcon.className = "tl-side-handle-icon";
    handleIcon.setAttribute("aria-hidden", "true");
    handleIcon.textContent = "🛡️";

    const handleLabel = document.createElement("span");
    handleLabel.className = "tl-side-handle-label";
    handleLabel.textContent = t("text_panel_tab_short");

    handle.appendChild(handleIcon);
    handle.appendChild(handleLabel);

    root.appendChild(drawer);
    root.appendChild(handle);

    function setOpen(open) {
      root.classList.toggle("tl-side-open", open);
      root.setAttribute("aria-hidden", open ? "false" : "true");
      handle.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        setTimeout(() => {
          try {
            ta.focus();
          } catch {
            /* ignore */
          }
        }, 40);
      }
    }

    handle.addEventListener("click", () => setOpen(!root.classList.contains("tl-side-open")));

    submitBtn.addEventListener("click", () => {
      void (async () => {
        const raw = (ta.value || "").trim();
        if (!raw) {
          resultEl.innerHTML = `<p class="tl-side-msg tl-side-msg-warn">${escapeHtml(t("text_panel_empty"))}</p>`;
          return;
        }
        submitBtn.disabled = true;
        resultEl.innerHTML = `<p class="tl-side-msg">${escapeHtml(t("text_panel_loading"))}</p>`;
        try {
          const apiResult = await sendThinkLinkApi({
            type: "THINKLINK_API",
            method: "POST",
            url: `${API_BASE}/analyze/text-phishing`,
            body: { text: raw },
            timeoutMs: 95000,
          });
          if (!apiResult.ok) {
            throw new Error(apiResult.error || `HTTP ${apiResult.status || ""}`);
          }
          resultEl.innerHTML = renderTextPhishingResultHtml(apiResult.data || {});
        } catch (e) {
          resultEl.innerHTML = `<p class="tl-side-msg tl-side-msg-err">${escapeHtml(t("text_panel_api_err"))}<br><small>${escapeHtml(e?.message || String(e))}</small></p>`;
        } finally {
          submitBtn.disabled = false;
        }
      })();
    });

    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && root.classList.contains("tl-side-open")) {
        setOpen(false);
      }
    });

    (document.documentElement || document.body).appendChild(root);
  }


  async function syncMode() {
    const settings = await loadSettings();
    currentMode = settings.mode || "simple";
    await syncWhitelist();
  }

  async function refreshWhitelistFromStorage() {
    await syncWhitelist();
    document.querySelectorAll(`[${PROCESSED_ATTR}]`).forEach((el) => {
      const url = getLinkUrl(el);
      if (!url) return;
      const key = canonicalUrlForAnalysis(url);
      const wl = whitelistSafeResultIfMatch(url);
      const row = peekCache(url);
      if (wl) {
        cacheResult(wl.url, wl);
        applyResult(el, forUiResult(wl));
        return;
      }
      if (row && row._tlWhitelistSafe) {
        resultCache.delete(key);
        el.removeAttribute(PROCESSED_ATTR);
        delete el.dataset.thinklinkPending;
        removeThinkLinkBadgesAfter(el);
      }
    });
    void scan();
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
      .catch(err => console.error("[ThinkLink] Błąd skanowania:", err));
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

  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (!extensionAlive || area !== "sync" || !changes.linkWhitelist) return;
      void refreshWhitelistFromStorage();
    });
  } catch {
    /* ignore */
  }


  function bootstrapThinkLinkUi() {
    startScanning();
    initTextPhishingInspector();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrapThinkLinkUi);
  } else {
    bootstrapThinkLinkUi();
  }

})();
