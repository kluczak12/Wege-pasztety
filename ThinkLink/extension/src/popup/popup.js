const TRANSLATIONS = {
  en: {
    mode_simple: "Simple",
    mode_simple_desc: "Block & show icons",
    mode_expert: "Expert",
    mode_expert_desc: "Reports & sandbox",
    stats_title: "Protection Stats",
    stat_blocked: "Total blocked",
    stat_session: "This session",
    history_title: "Recent Threats",
    history_empty: "No threats blocked yet. 🎉",
    clear_btn: "Clear",
    footer_text: "AI-powered protection",
    reset_btn: "Reset counter",
    risk_dangerous: "Dangerous",
    risk_suspicious: "Suspicious",
  },
  pl: {
    mode_simple: "Prosty",
    mode_simple_desc: "Blokuj i pokazuj ikony",
    mode_expert: "Ekspert",
    mode_expert_desc: "Raporty i sandbox",
    stats_title: "Statystyki ochrony",
    stat_blocked: "Łącznie zablokowano",
    stat_session: "Ta sesja",
    history_title: "Ostatnie zagrożenia",
    history_empty: "Brak zablokowanych zagrożeń. 🎉",
    clear_btn: "Wyczyść",
    footer_text: "Ochrona wspierana przez AI",
    reset_btn: "Zeruj licznik",
    risk_dangerous: "Niebezpieczne",
    risk_suspicious: "Podejrzane",
  }
};

let uiLang = "en";

function t(key) {
  return (TRANSLATIONS[uiLang] || TRANSLATIONS.en)[key] || key;
}

function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (t(key)) el.textContent = t(key);
  });
}

async function detectLanguage() {
  return new Promise(resolve => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]?.id) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: () => document.documentElement.lang || navigator.language || "en"
        }).then(results => {
          const lang = results?.[0]?.result || "en";
          resolve(lang.slice(0, 2).toLowerCase());
        }).catch(() => resolve("en"));
      } else {
        resolve("en");
      }
    });
  });
}

async function loadSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get({ mode: "simple" }, resolve);
  });
}

async function saveMode(mode) {
  return new Promise(resolve => chrome.storage.sync.set({ mode }, resolve));
}

async function loadHistory() {
  return new Promise(resolve => {
    chrome.storage.local.get({ history: [] }, data => resolve(data.history));
  });
}

async function clearHistory() {
  return new Promise(resolve => {
    chrome.storage.local.set({ history: [] }, resolve);
  });
}

async function getTotalBlocked() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: "GET_TOTAL_BLOCKED" }, resp => {
      resolve(resp?.count || 0);
    });
  });
}

async function resetCounter() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: "RESET_COUNTER" }, () => resolve());
  });
}

function renderHistory(history) {
  const list = document.getElementById("history-list");
  list.innerHTML = "";

  if (!history.length) {
    const empty = document.createElement("li");
    empty.className = "history-empty";
    empty.textContent = t("history_empty");
    list.appendChild(empty);
    return;
  }

  history.slice(0, 15).forEach(entry => {
    const li = document.createElement("li");
    li.className = "history-item";

    const riskClass = entry.risk_level === "dangerous" ? "risk-danger" : "risk-suspicious";
    const riskLabel = t(`risk_${entry.risk_level}`);
    const date = new Date(entry.timestamp);
    const timeStr = date.toLocaleTimeString(uiLang, { hour: "2-digit", minute: "2-digit" });
    const dateStr = date.toLocaleDateString(uiLang, { month: "short", day: "numeric" });

    let urlDisplay = entry.url;
    try { urlDisplay = new URL(entry.url).hostname; } catch {}

    li.innerHTML = `
      <span class="history-badge ${riskClass}">${riskLabel}</span>
      <span class="history-url" title="${entry.url}">${urlDisplay}</span>
      <span class="history-time">${dateStr} ${timeStr}</span>
    `;
    li.setAttribute("aria-label", `${riskLabel}: ${urlDisplay}`);
    list.appendChild(li);
  });
}

async function notifyContentScript(mode) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    chrome.tabs.sendMessage(tab.id, { type: "MODE_CHANGED", mode }).catch(() => {});
  }
}

async function init() {
  uiLang = await detectLanguage();
  applyTranslations();

  const settings = await loadSettings();
  setActiveMode(settings.mode || "simple");

  const totalBlocked = await getTotalBlocked();
  document.getElementById("stat-total").textContent = totalBlocked;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    chrome.tabs.sendMessage(tab.id, { type: "GET_STATS" }, resp => {
      if (resp) {
        document.getElementById("stat-session").textContent =
          (resp.dangerous || 0) + (resp.suspicious || 0);
      }
    });
  }

  const history = await loadHistory();
  renderHistory(history);

  document.querySelectorAll(".mode-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const mode = btn.dataset.mode;
      await saveMode(mode);
      setActiveMode(mode);
      await notifyContentScript(mode);
    });
  });

  document.getElementById("btn-clear").addEventListener("click", async () => {
    await clearHistory();
    renderHistory([]);
  });

  document.getElementById("btn-reset").addEventListener("click", async () => {
    await resetCounter();
    document.getElementById("stat-total").textContent = "0";
  });
}

function setActiveMode(mode) {
  document.querySelectorAll(".mode-btn").forEach(btn => {
    const isActive = btn.dataset.mode === mode;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-checked", String(isActive));
  });
}

document.addEventListener("DOMContentLoaded", init);
