async function updateBadge() {
  const data = await chrome.storage.local.get({ totalBlocked: 0 });
  const count = data.totalBlocked;
  chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#dc2626" });
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
          sendResponse({ ok: false, error: "Invalid JSON from ThinkLink API" });
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
    chrome.storage.local.get({ totalBlocked: 0 }, (data) => {
      const newCount = data.totalBlocked + 1;
      chrome.storage.local.set({ totalBlocked: newCount }, () => {
        updateBadge();
      });
    });
    sendResponse({ ok: true });
  }

  if (msg.type === "GET_TOTAL_BLOCKED") {
    chrome.storage.local.get({ totalBlocked: 0 }, (data) => {
      sendResponse({ count: data.totalBlocked });
    });
    return true;
  }

  if (msg.type === "RESET_COUNTER") {
    chrome.storage.local.set({ totalBlocked: 0 }, () => {
      updateBadge();
      sendResponse({ ok: true });
    });
    return true;
  }
});

chrome.runtime.onStartup.addListener(updateBadge);
chrome.runtime.onInstalled.addListener(updateBadge);
