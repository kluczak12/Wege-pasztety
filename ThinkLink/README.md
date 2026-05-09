# 🛡️ ThinkLink – AI-Powered Link Protector

Real-time browser protection that uses AI to detect dangerous links, buttons and redirects.

---

## Project Structure

```
ThinkLink/
├── extension/
│   ├── manifest.json
│   ├── icons/
│   ├── _locales/en/ pl/
│   └── src/
│       ├── content/
│       ├── background/
│       └── popup/
│
└── backend/
    ├── requirements.txt
    ├── .env.example
    └── app/
        ├── main.py
        ├── models/schemas.py
        ├── routers/analysis.py
        └── services/analyzer.py
```

---

## 🚀 Quick Start

### 1. Backend (Python 3.10+)

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### 2. Browser Extension (Chrome / Edge)

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer Mode** (toggle in top-right)
3. Click **"Load unpacked"**
4. Select the `extension/` folder inside this project
5. The 🛡️ ThinkLink icon will appear in the toolbar

> **Note:** The backend must be running at `http://localhost:8000` for analysis to work.

---

## 🔑 Environment Variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (from console.anthropic.com) |
| `HOST` | Backend host (default: `0.0.0.0`) |
| `PORT` | Backend port (default: `8000`) |

---

## ⚙️ Features

### Simple Mode (default)
- Green ✓ badge = safe link
- Red ✕ badge = dangerous (click is **fully blocked**)
- Orange ⚠ badge = suspicious (allowed but warned)
- Toast notification when a click is blocked

### Expert Mode
Click **Expert** in the popup to enable:
- **"Show Report"** button next to each dangerous/suspicious link
  - Threat indicators with severity levels
  - Domain WHOIS info (age, registrar, country)
  - Redirect chain visualization
  - AI assessment from Claude
- **"Sandbox Preview"** button
  - Simulated visit to the URL in an isolated environment
  - Timeline of detected malicious behaviors

### Protection Stats
The popup shows:
- **Total blocked** — lifetime counter persisted across sessions
- **This session** — dangerous + suspicious links found on the current page
- **Recent threats** — history of the last 15 blocked URLs

---

## 🧠 Analysis Pipeline

For each link, the backend runs:

1. **URL parsing** — scheme, structure, obfuscation patterns
2. **File download detection** — dangerous extensions (.exe, .bat, etc.)
3. **Redirect chain** — follows up to 8 hops via async HTTP HEAD requests
4. **WHOIS lookup** — domain age (flags < 30 days, critically flags < 7 days)
5. **Obfuscation checks** — IP addresses, @-sign tricks, heavy encoding
6. **AI analysis (Claude)** — semantic analysis of URL + surrounding text
   - Detects phishing intent, brand impersonation, social engineering
   - Returns a `risk_bump` score and human-readable explanation
   - Responds in the language of the current page

Risk score is aggregated from all checks (0.0–1.0):
- `< 0.2` → **Safe** ✓
- `0.2–0.5` → **Suspicious** ⚠
- `> 0.5` → **Dangerous** ✕

---

## 🌍 Internationalization

- Extension UI automatically adapts to the language of the current tab
- Currently supported: **English** (en), **Polish** (pl), **German** (de)
- AI analysis responds in the page's language automatically
- Adding a new language: add entries to `src/content/content.js` `TRANSLATIONS` 
  and `src/popup/popup.js` `TRANSLATIONS`

---

## ♿ Accessibility

- All badges have `aria-label` attributes
- Blocked-link notices use `role="alert"` + `aria-live="assertive"`
- Modals have `role="dialog"`, `aria-modal`, focus trapping
- Mode buttons use `role="radio"` + `aria-checked`
- High contrast mode support via `forced-colors` media query
- Reduced motion support via `prefers-reduced-motion`
- Minimum font size 11px, high color contrast ratios

---

## 🔧 API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/analyze` | Batch analyze up to 50 links |
| `POST` | `/api/v1/analyze/single` | Analyze a single link |
| `GET` | `/api/v1/sandbox/video?url=...` | Get sandbox simulation data |
| `GET` | `/health` | Health check |

---

## 📦 Production Notes

- Replace `"http://localhost:8000"` in `content.js` with your deployed API URL
- Restrict CORS in `main.py` to your extension's origin ID
- The sandbox video endpoint is a **mock** — integrate with Browserless/Playwright for real recordings
- Consider rate-limiting the `/analyze` endpoint to prevent abuse
