async function updateBadge() {
  const data = await chrome.storage.local.get({ totalBlocked: 0 });
  const count = data.totalBlocked;
  chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#dc2626" });
}

/** Ten sam URL z kilku iframe / powtórzeń — licz tylko raz na sesję rozszerzenia. */
async function shouldIncrementThreatCounter(url) {
  const key = String(url || "").trim().slice(0, 2048);
  if (!key) return true;
  try {
    const data = await chrome.storage.session.get(["thinklinkSeenThreatUrls"]);
    const seen = data.thinklinkSeenThreatUrls;
    const bag =
      seen && typeof seen === "object" && !Array.isArray(seen) ? { ...seen } : {};
    if (bag[key]) {
      return false;
    }
    bag[key] = Date.now();
    const entries = Object.entries(bag);
    if (entries.length > 800) {
      entries.sort((a, b) => a[1] - b[1]);
      for (let i = 0; i < entries.length - 500; i++) {
        delete bag[entries[i][0]];
      }
    }
    await chrome.storage.session.set({ thinklinkSeenThreatUrls: bag });
    return true;
  } catch {
    return true;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "THINKLINK_API") {
    (async () => {
      try {
        const timeout = msg.timeoutMs ?? 120000;
        const ctrl = AbortSignal.timeout(timeout);
        const init = { method: msg.method || "GET", signal: ctrl, headers: {} };
        if (msg.body !== undefined && msg.body !== null) {
          init.headers["Content-Type"] = "application/json";
          init.body = JSON.stringify(msg.body);
        }
        const resp = await fetch(msg.url, init);
        const text = await resp.text();
        if (!resp.ok) {
          sendResponse({
            ok: false,
            status: resp.status,
            error: text.slice(0, 300) || `HTTP ${resp.status}`,
          });
          return;
        }
        let data;
        try {
          data = JSON.parse(text);
        } catch {
          sendResponse({ ok: false, error: "Nieprawidłowy JSON z API ThinkLink" });
          return;
        }
        sendResponse({ ok: true, data });
      } catch (e) {
        sendResponse({ ok: false, error: e?.message || String(e) });
      }
    })();
    return true;
  }

  if (msg.type === "THREAT_DETECTED") {
    (async () => {
      try {
        const inc = await shouldIncrementThreatCounter(msg.url);
        if (!inc) {
          sendResponse({ ok: true, deduped: true });
          return;
        }
        const data = await chrome.storage.local.get({ totalBlocked: 0 });
        const newCount = data.totalBlocked + 1;
        await chrome.storage.local.set({ totalBlocked: newCount });
        await updateBadge();
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, error: e?.message || String(e) });
      }
    })();
    return true;
  }

  if (msg.type === "GET_TOTAL_BLOCKED") {
    chrome.storage.local.get({ totalBlocked: 0 }, (data) => {
      sendResponse({ count: data.totalBlocked });
    });
    return true;
  }

  if (msg.type === "RESET_COUNTER") {
    (async () => {
      try {
        await chrome.storage.local.set({ totalBlocked: 0 });
        try {
          await chrome.storage.session.remove("thinklinkSeenThreatUrls");
        } catch {
          /* ignore */
        }
        await updateBadge();
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, error: e?.message || String(e) });
      }
    })();
    return true;
  }
});

chrome.runtime.onStartup.addListener(updateBadge);
chrome.runtime.onInstalled.addListener(updateBadge);
