

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
      video_btn: "Sandbox Preview",
      loading: "Checking…",
      aria_safe: "Safe link",
      aria_danger: "Dangerous link — click blocked",
      aria_suspicious: "Suspicious link — proceed with caution",
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
      video_btn: "Podgląd w sandboxie",
      loading: "Sprawdzam…",
      aria_safe: "Bezpieczny link",
      aria_danger: "Niebezpieczny link — kliknięcie zablokowane",
      aria_suspicious: "Podejrzany link — zachowaj ostrożność",
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
      video_btn: "Sandbox-Vorschau",
      loading: "Prüfe…",
      aria_safe: "Sicherer Link",
      aria_danger: "Gefährlicher Link — Klick blockiert",
      aria_suspicious: "Verdächtiger Link — Vorsicht geboten",
    }
  };

  function t(key) {
    const lang = pageLanguage.slice(0, 2).toLowerCase();
    return (TRANSLATIONS[lang] || TRANSLATIONS["en"])[key] || TRANSLATIONS["en"][key] || key;
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


  const MAX_NEW_LINKS_PER_SCAN = 15;

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

  function getRawLinkUrl(el) {
    if (el.tagName === "A" || el.tagName === "AREA") return el.href;
    if (el.dataset.href) return el.dataset.href;
    if (el.tagName === "FORM") return el.action;
    const onclick = el.getAttribute("onclick") || "";
    const match = onclick.match(/(?:href|location\.href|window\.open)\s*[=(]\s*['"]([^'"]+)['"]/);
    return match ? match[1] : null;
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
    const selectors = ["a[href]", "area[href]", "button[data-href]", "button[onclick]", "form[action]"];
    const elements = [];

    document.querySelectorAll(selectors.join(",")).forEach(el => {
      if (elements.length >= MAX_NEW_LINKS_PER_SCAN) return;
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
        el.removeAttribute(PROCESSED_ATTR);
      }
      elements.push(el);
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
    const batchUrls = uniqueUrls.slice(0, MAX_NEW_LINKS_PER_SCAN);
    const toAnalyze = [];
    for (const u of batchUrls) {
      toAnalyze.push(...urlToEls.get(u));
    }

    toAnalyze.forEach(el => {
      const id = Math.random().toString(36).slice(2);
      el.setAttribute(PROCESSED_ATTR, id);
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
        const row = url && peekCache(url);
        if (row) applyResult(el, forUiResult(row));
      });

    } catch (err) {
      console.error("[ThinkLink] Analysis failed:", err);
      toAnalyze.forEach(el => injectBadge(el, "error", null));
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


  function injectBadge(el, status, result) {
    const existingBadge = el.parentElement?.querySelector(`.${BADGE_CLASS}[data-for="${el.getAttribute(PROCESSED_ATTR)}"]`);
    if (existingBadge) existingBadge.remove();

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
      showReportModal(result);
    });

    const videoBtn = document.createElement("button");
    videoBtn.className = "tl-btn tl-btn-video";
    videoBtn.textContent = t("video_btn");
    videoBtn.setAttribute("type", "button");
    videoBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      showSandboxModal(result);
    });

    controls.appendChild(reportBtn);
    controls.appendChild(videoBtn);
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


  function showReportModal(result) {
    removeModal();
    let aiData = {};
    try { aiData = JSON.parse(result.ai_assessment || "{}"); } catch {}

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
          ${aiData.explanation ? `
          <div class="tl-section">
            <h3>AI Analysis</h3>
            <p class="tl-ai-text">${aiData.explanation}</p>
            ${aiData.threat_type ? `<span class="tl-threat-type">Threat type: <strong>${aiData.threat_type}</strong></span>` : ""}
          </div>` : ""}
        </div>
      </div>
    `;
    modal.querySelector(".tl-modal-close").addEventListener("click", removeModal);
    modal.addEventListener("click", (e) => { if (e.target === modal) removeModal(); });
    document.body.appendChild(modal);

    modal.querySelector(".tl-modal-close").focus();
  }

  async function showSandboxModal(result) {
    removeModal();
    const modal = document.createElement("div");
    modal.className = "tl-modal-overlay";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", "ThinkLink Sandbox Preview");

    modal.innerHTML = `
      <div class="tl-modal tl-sandbox-modal">
        <div class="tl-modal-header">
          <h2>🔬 Sandbox Preview</h2>
          <button class="tl-modal-close" aria-label="Close" type="button">✕</button>
        </div>
        <div class="tl-modal-body">
          <p class="tl-sandbox-url"><em>Simulating visit to:</em><br><code>${result.url.slice(0, 80)}</code></p>
          <div class="tl-sandbox-loading">
            <div class="tl-sandbox-spinner"></div>
            <span>Loading sandbox simulation…</span>
          </div>
          <div class="tl-sandbox-content" style="display:none"></div>
        </div>
      </div>
    `;
    modal.querySelector(".tl-modal-close").addEventListener("click", removeModal);
    modal.addEventListener("click", (e) => { if (e.target === modal) removeModal(); });
    document.body.appendChild(modal);

    try {
      const apiResult = await sendThinkLinkApi({
        type: "THINKLINK_API",
        method: "GET",
        url: `${API_BASE}/sandbox/video?url=${encodeURIComponent(result.url)}`,
        timeoutMs: 60000,
      });
      if (!apiResult.ok) throw new Error(apiResult.error || "sandbox request failed");
      const data = apiResult.data;

      const content = modal.querySelector(".tl-sandbox-content");
      const loading = modal.querySelector(".tl-sandbox-loading");

      const eventsHtml = data.events_detected.map(ev => `
        <li class="tl-sandbox-event">
          <span class="tl-sandbox-time">${ev.time}s</span>
          <span>${ev.event}</span>
        </li>
      `).join("");

      content.innerHTML = `
        <div class="tl-sandbox-verdict tl-risk-${result.risk_level}">${data.verdict}</div>
        <h3>Detected Events</h3>
        <ul class="tl-sandbox-events">${eventsHtml}</ul>
        <p class="tl-sandbox-note">
          <em>ℹ️ In production, a real browser recording would be shown here. 
          This is a mock simulation based on static analysis.</em>
        </p>
      `;
      loading.style.display = "none";
      content.style.display = "block";
    } catch {
      modal.querySelector(".tl-sandbox-loading").innerHTML =
        "<p>Sandbox simulation unavailable. Make sure the backend is running.</p>";
    }
  }

  function removeModal() {
    document.querySelectorAll(".tl-modal-overlay").forEach(m => m.remove());
  }


  async function syncMode() {
    const settings = await loadSettings();
    currentMode = settings.mode || "simple";
  }


  async function scan() {
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
