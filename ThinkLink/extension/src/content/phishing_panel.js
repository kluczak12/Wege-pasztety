/**
 * ThinkLink — panel antyphishing (osobny moduł).
 * Shadow DOM + stylesheet z paczki — izolacja od globalnego CSS strony (np. Yahoo).
 */
(() => {
  "use strict";

  if (window.self !== window.top) return;

  const ROOT_ID = "tlpp-root";
  const API_BASE = "http://localhost:8000/api/v1";
  const FETCH_TIMEOUT_MS = 90000;
  const CSS_PATH = "src/content/phishing_panel.css";

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function extOk() {
    try {
      return Boolean(chrome?.runtime?.id);
    } catch {
      return false;
    }
  }

  function apiFetch(payload) {
    return new Promise((resolve, reject) => {
      if (!extOk()) {
        reject(new Error("Kontekst rozszerzenia nieważny — odśwież stronę."));
        return;
      }
      try {
        chrome.runtime.sendMessage(payload, (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(response);
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  function panelHealthy(host) {
    return Boolean(
      host
      && host.isConnected
      && host.shadowRoot
      && host.shadowRoot.querySelector(".tlpp-textarea")
    );
  }

  function mountPhishingPanel() {
    if (window.self !== window.top) return;
    if (panelHealthy(document.getElementById(ROOT_ID))) return;

    const old = document.getElementById(ROOT_ID);
    if (old) {
      try {
        old.remove();
      } catch (_) {
        /* ignore */
      }
    }

    const host = document.createElement("div");
    host.id = ROOT_ID;
    host.setAttribute("data-thinklink-phishing-panel", "1");

    const shadow = host.attachShadow({ mode: "open" });
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = chrome.runtime.getURL(CSS_PATH);
    shadow.appendChild(link);

    const inner = document.createElement("div");
    inner.innerHTML = `
    <div class="tlpp-backdrop" aria-hidden="true"></div>
    <aside class="tlpp-panel" id="tlpp-panel-main" role="dialog" aria-label="Analiza treści pod kątem phishingu">
      <header class="tlpp-head">
        <h2 class="tlpp-title">Analiza wiadomości</h2>
        <p class="tlpp-sub">Wklej treść e-maila lub wiadomości — ocena ryzyka (nie jest to czat).</p>
        <button type="button" class="tlpp-close" aria-label="Zamknij panel">✕</button>
      </header>
      <label class="tlpp-label" for="tlpp-textarea">Treść do sprawdzenia</label>
      <textarea id="tlpp-textarea" class="tlpp-textarea" rows="10" placeholder="Wklej tutaj treść podejrzanej wiadomości…" maxlength="16000" spellcheck="true" autocomplete="off"></textarea>
      <div class="tlpp-actions">
        <button type="button" class="tlpp-btn tlpp-btn-primary" id="tlpp-analyze">Analizuj</button>
      </div>
      <div class="tlpp-result" id="tlpp-result" hidden>
        <div class="tlpp-meter-wrap">
          <div class="tlpp-meter" aria-hidden="true">
            <svg viewBox="0 0 120 120" class="tlpp-dial">
              <circle class="tlpp-dial-bg" cx="60" cy="60" r="52" fill="none" stroke-width="10" />
              <circle class="tlpp-dial-fg tlpp-stroke-low" cx="60" cy="60" r="52" fill="none" stroke-width="10"
                stroke-dasharray="326.73" stroke-dashoffset="326.73" transform="rotate(-90 60 60)" />
            </svg>
            <div class="tlpp-pct" id="tlpp-pct">—</div>
          </div>
          <div class="tlpp-riskline">
            <span class="tlpp-risk-badge" id="tlpp-risk-badge">—</span>
            <p class="tlpp-summary" id="tlpp-summary"></p>
          </div>
        </div>
        <div class="tlpp-section" id="tlpp-signals-wrap" hidden>
          <h3 class="tlpp-h3">Wykryte sygnały</h3>
          <ul class="tlpp-list" id="tlpp-signals"></ul>
        </div>
        <div class="tlpp-section" id="tlpp-urls-wrap" hidden>
          <h3 class="tlpp-h3">Linki do uwagi</h3>
          <ul class="tlpp-url-list" id="tlpp-urls"></ul>
        </div>
        <p class="tlpp-note" id="tlpp-engine-note" hidden></p>
      </div>
      <p class="tlpp-error" id="tlpp-error" hidden></p>
    </aside>
    <button type="button" class="tlpp-tab" title="Analiza phishingu" aria-expanded="false" aria-controls="tlpp-panel-main">
      <span class="tlpp-tab-icon" aria-hidden="true">🛡️</span>
      <span class="tlpp-tab-text">Phishing</span>
    </button>
    `;
    shadow.appendChild(inner);

    const parent = document.body || document.documentElement;
    parent.appendChild(host);

    const backdrop = shadow.querySelector(".tlpp-backdrop");
    const tab = shadow.querySelector(".tlpp-tab");
    const btnClose = shadow.querySelector(".tlpp-close");
    const textarea = shadow.querySelector("#tlpp-textarea");
    const btnAnalyze = shadow.querySelector("#tlpp-analyze");
    const resultEl = shadow.querySelector("#tlpp-result");
    const errorEl = shadow.querySelector("#tlpp-error");
    const pctEl = shadow.querySelector("#tlpp-pct");
    const badgeEl = shadow.querySelector("#tlpp-risk-badge");
    const summaryEl = shadow.querySelector("#tlpp-summary");
    const signalsWrap = shadow.querySelector("#tlpp-signals-wrap");
    const signalsList = shadow.querySelector("#tlpp-signals");
    const urlsWrap = shadow.querySelector("#tlpp-urls-wrap");
    const urlsList = shadow.querySelector("#tlpp-urls");
    const engineNoteEl = shadow.querySelector("#tlpp-engine-note");
    const dialFg = shadow.querySelector(".tlpp-dial-fg");

    const CIRC = 2 * Math.PI * 52;

    function setOpen(open) {
      host.classList.toggle("tlpp-open", open);
      tab.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        textarea.focus();
      }
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }

    function clearError() {
      errorEl.hidden = true;
      errorEl.textContent = "";
    }

    function riskLabel(level) {
      const m = {
        low: "Niskie ryzyko",
        medium: "Średnie ryzyko",
        high: "Wysokie ryzyko",
        critical: "Krytyczne — bardzo podejrzane",
      };
      return m[String(level || "").toLowerCase()] || level || "—";
    }

    function riskClass(level) {
      const k = String(level || "").toLowerCase();
      if (k === "critical" || k === "high") return "tlpp-lvl-high";
      if (k === "medium") return "tlpp-lvl-med";
      return "tlpp-lvl-low";
    }

    function setMeter(percent) {
      const p = Math.max(0, Math.min(100, Number(percent) || 0));
      pctEl.textContent = `${p}%`;
      const off = CIRC * (1 - p / 100);
      if (dialFg) {
        dialFg.style.strokeDashoffset = String(off);
        dialFg.classList.remove("tlpp-stroke-low", "tlpp-stroke-med", "tlpp-stroke-high");
        if (p >= 70) dialFg.classList.add("tlpp-stroke-high");
        else if (p >= 35) dialFg.classList.add("tlpp-stroke-med");
        else dialFg.classList.add("tlpp-stroke-low");
      }
    }

    function renderResult(data) {
      clearError();
      resultEl.hidden = false;
      const pct = data.threat_score_percent ?? 0;
      setMeter(pct);
      badgeEl.textContent = riskLabel(data.risk_level);
      badgeEl.className = `tlpp-risk-badge ${riskClass(data.risk_level)}`;
      summaryEl.textContent = data.summary_pl || "";

      const signals = Array.isArray(data.signals) ? data.signals : [];
      if (signals.length) {
        signalsWrap.hidden = false;
        signalsList.innerHTML = signals
          .map(
            (s) =>
              `<li><strong>${esc(s.category)}</strong> — ${esc(s.detail)}</li>`
          )
          .join("");
      } else {
        signalsWrap.hidden = true;
        signalsList.innerHTML = "";
      }

      const urls = Array.isArray(data.urls_flagged) ? data.urls_flagged : [];
      if (urls.length) {
        urlsWrap.hidden = false;
        urlsList.innerHTML = urls
          .map(
            (u) =>
              `<li><code>${esc(u.url)}</code><span class="tlpp-url-reason">${esc(u.reason_pl)}</span></li>`
          )
          .join("");
      } else {
        urlsWrap.hidden = true;
        urlsList.innerHTML = "";
      }

      if (data.engine_note) {
        engineNoteEl.textContent = data.engine_note;
        engineNoteEl.hidden = false;
      } else {
        engineNoteEl.hidden = true;
        engineNoteEl.textContent = "";
      }
    }

    async function runAnalyze() {
      const text = textarea.value.trim();
      clearError();
      if (!text) {
        showError("Wklej treść wiadomości przed analizą.");
        return;
      }
      btnAnalyze.disabled = true;
      btnAnalyze.textContent = "Analizuję…";
      resultEl.hidden = true;

      try {
        const response = await apiFetch({
          type: "THINKLINK_API",
          method: "POST",
          url: `${API_BASE}/analyze/phishing-text`,
          body: { text },
          timeoutMs: FETCH_TIMEOUT_MS,
        });
        if (!response.ok) {
          throw new Error(response.error || `Błąd API (${response.status || "?"})`);
        }
        renderResult(response.data);
      } catch (e) {
        showError(e?.message || String(e));
        resultEl.hidden = true;
      } finally {
        btnAnalyze.disabled = false;
        btnAnalyze.textContent = "Analizuj";
      }
    }

    tab.addEventListener("click", () => setOpen(!host.classList.contains("tlpp-open")));
    btnClose.addEventListener("click", () => setOpen(false));
    backdrop.addEventListener("click", () => setOpen(false));
    btnAnalyze.addEventListener("click", () => void runAnalyze());
  }

  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    const host = document.getElementById(ROOT_ID);
    if (!host?.classList.contains("tlpp-open")) return;
    host.classList.remove("tlpp-open");
    const t = host.shadowRoot?.querySelector(".tlpp-tab");
    t?.setAttribute("aria-expanded", "false");
  });

  mountPhishingPanel();
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountPhishingPanel, { once: true });
  }

  let debounceTimer = null;
  function scheduleRemountCheck() {
    if (debounceTimer) return;
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      if (!panelHealthy(document.getElementById(ROOT_ID))) {
        mountPhishingPanel();
      }
    }, 250);
  }

  try {
    const mo = new MutationObserver(scheduleRemountCheck);
    mo.observe(document.documentElement, { childList: true, subtree: true });
  } catch (_) {
    /* ignore */
  }

  setInterval(() => {
    if (!panelHealthy(document.getElementById(ROOT_ID))) {
      mountPhishingPanel();
    }
  }, 4000);
})();
