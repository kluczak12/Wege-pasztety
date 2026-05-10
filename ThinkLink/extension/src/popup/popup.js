const UI = {
  mode_simple: "Prosty",
  mode_simple_desc: "Blokuj i pokazuj ikony",
  mode_expert: "Ekspert",
  mode_expert_desc: "Raporty i sandbox",
  stats_title: "Statystyki ochrony",
  stat_blocked: "Łącznie zablokowano",
  stat_session: "Ta sesja",
  history_title: "Ostatnie zagrożenia",
  history_empty: "Brak zablokowanych zagrożeń",
  clear_btn: "Wyczyść",
  footer_text: "Ochrona wspierana przez AI",
  reset_btn: "Zeruj licznik",
  risk_dangerous: "Niebezpieczne",
  risk_suspicious: "Podejrzane",
  whitelist_title: "Zaufane adresy",
  whitelist_hint:
    "Domena (np. example.com) lub prefiks URL — treść witryn z listy jest traktowana jak zaufana (jak domyślna whitelist ThinkLink).",
  whitelist_add: "Dodaj",
  whitelist_remove_aria: "Usuń z listy",
  whitelist_empty: "Brak wpisów — dodaj domenę lub link.",
  whitelist_invalid: "Niepoprawny adres — podaj domenę lub http(s)://…",
};

function t(key) {
  return UI[key] ?? key;
}

function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (t(key)) el.textContent = t(key);
  });
}

async function loadSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get({ mode: "simple", linkWhitelist: [] }, resolve);
  });
}

async function saveMode(mode) {
  return new Promise(resolve => chrome.storage.sync.set({ mode }, resolve));
}

function normalizeWhitelistKey(entry) {
  const raw = String(entry ?? "").trim();
  if (!raw) return "";
  try {
    const u = new URL(raw.includes("://") ? raw : `https://${raw}`);
    return `${u.hostname.toLowerCase()}${u.pathname}${u.search}`;
  } catch {
    return raw.toLowerCase();
  }
}

async function saveWhitelist(list) {
  const next = Array.isArray(list) ? [...list] : [];
  await new Promise(resolve => {
    chrome.storage.sync.set({ linkWhitelist: next }, resolve);
  });
}

function renderWhitelistList(entries) {
  const ul = document.getElementById("whitelist-list");
  if (!ul) return;
  ul.innerHTML = "";

  const list = Array.isArray(entries) ? entries : [];
  if (!list.length) {
    const li = document.createElement("li");
    li.className = "whitelist-empty";
    li.textContent = t("whitelist_empty");
    ul.appendChild(li);
    return;
  }

  list.forEach((entry, index) => {
    const li = document.createElement("li");
    li.className = "whitelist-item";
    const span = document.createElement("span");
    span.className = "whitelist-entry-text";
    span.textContent = entry;
    span.title = entry;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "whitelist-remove-btn";
    btn.setAttribute("aria-label", t("whitelist_remove_aria"));
    btn.dataset.index = String(index);
    btn.textContent = "✕";
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  });

  ul.querySelectorAll(".whitelist-remove-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const i = Number(btn.dataset.index);
      const next = list.filter((_, j) => j !== i);
      await saveWhitelist(next);
      renderWhitelistList(next);
    });
  });
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

  const localeOpts = { hour: "2-digit", minute: "2-digit" };
  const dateOpts = { month: "short", day: "numeric" };

  history.slice(0, 15).forEach(entry => {
    const li = document.createElement("li");
    li.className = "history-item";

    const riskClass = entry.risk_level === "dangerous" ? "risk-danger" : "risk-suspicious";
    const riskLabel = t(`risk_${entry.risk_level}`);
    const date = new Date(entry.timestamp);
    const timeStr = date.toLocaleTimeString("pl-PL", localeOpts);
    const dateStr = date.toLocaleDateString("pl-PL", dateOpts);

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

  renderWhitelistList(settings.linkWhitelist || []);

  document.getElementById("whitelist-add").addEventListener("click", async () => {
    const input = document.getElementById("whitelist-input");
    const raw = (input.value || "").trim();
    if (!raw) return;
    let stored = raw;
    try {
      stored = raw.includes("://") ? raw : `https://${raw}`;
      new URL(stored);
    } catch {
      alert(t("whitelist_invalid"));
      return;
    }
    const data = await loadSettings();
    const list = Array.isArray(data.linkWhitelist) ? [...data.linkWhitelist] : [];
    const key = normalizeWhitelistKey(stored);
    if (list.some(e => normalizeWhitelistKey(e) === key)) {
      input.value = "";
      return;
    }
    list.push(stored);
    await saveWhitelist(list);
    input.value = "";
    renderWhitelistList(list);
  });

  document.getElementById("whitelist-input").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      e.preventDefault();
      document.getElementById("whitelist-add").click();
    }
  });

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
