"""
Analiza treści wiadomości (e-mail, SMS) pod kątem oznak phishingu — osobna ścieżka od skanowania linków.
Heurystyka jest zawsze liczona i łączona z modelem (max), żeby nie zaniżać oceny przy typowych scamach.
"""
import asyncio
import json
import re
from typing import Any, Dict, List, Tuple

from app.models.schemas import PhishingAnalysisResult, PhishingSignal, PhishingUrlFlag
from app.services.analyzer import _fast_model, _get_client

MAX_MESSAGE_CHARS = 16000

_PHISHING_SYSTEM = """Jesteś analitykiem bezpieczeństwa. Oceń WKLEJONĄ treść wiadomości (e-mail, SMS, komunikat) pod kątem phishingu i oszustw finansowych.

WAŻNE ZASADY (polski i ogólny kontekst):
- Każda PILNA prośba o PRZELEW, PRZESŁANIE PIENIĘDZY, wpłatę „na link”, „na poniższy adres”, podanie danych karty lub kodu BLIK w połączeniu z presją czasu to ZAWSZE co najmniej ŚREDNIE lub WYSOKIE ryzyko — NIGDY nie klasyfikuj takiej treści jako „bezpiecznej”.
- Prośba „przelej pieniądze” / „wyślij środki” / „zapłać natychmiast” bez oficjalnego, zweryfikowanego kontekstu to typowy scam — threat_score_percent zwykle 60–95 w zależności od agresywności.
- Błagalna tonacja + płatność + link to klasyka phishingu.
- „Bezpieczna wiadomość” (niskie ryzyko) tylko gdy brak presji, brak płatności, brak linków do logowania i treść jest neutralna (np. potwierdzenie spotkania od znajomego).

Zwróć WYŁĄCZNIE poprawny JSON (bez markdown), dokładnie w schemacie:
{
  "threat_score_percent": <liczba całkowita 0-100>,
  "risk_level": "low" | "medium" | "high" | "critical",
  "summary_pl": "<1-3 zdania po polsku>",
  "signals": [
    {"category": "<krótka etykieta>",
     "detail": "<konkret po polsku>"}
  ],
  "urls_flagged": [
    {"url": "<pełny lub widoczny URL z tekstu>", "reason_pl": "<dlaczego podejrzany>"}
  ]
}

Kryteria: pilność, prośby o pieniądze/przelew, presja czasowa, podejrzane linki, podszywanie się pod firmy, literówki w domenach. Nie wymyślaj URL-i — tylko z tekstu."""


def _score_to_risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _dedupe_signals(existing: List[PhishingSignal], extra: List[PhishingSignal]) -> List[PhishingSignal]:
    seen = {(s.category, s.detail[:80]) for s in existing}
    out = list(existing)
    for s in extra:
        key = (s.category, s.detail[:80])
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out[:24]


def _dedupe_urls(
    existing: List[PhishingUrlFlag], extra: List[PhishingUrlFlag]
) -> List[PhishingUrlFlag]:
    seen = {u.url for u in existing}
    out = list(existing)
    for u in extra:
        if u.url and u.url not in seen:
            seen.add(u.url)
            out.append(u)
    return out[:30]


_COMBO_PATTERNS: List[Tuple[re.Pattern[str], int, str]] = [
    (
        re.compile(
            r"natychmiast.{0,120}(przelew|przelej|prześlij|pieniądz|pieniędzy|zapłać)",
            re.I | re.DOTALL,
        ),
        45,
        "Połączenie pilności z prośbą o środki lub zapłatę — bardzo typowe dla wyłudzeń.",
    ),
    (
        re.compile(
            r"(przelej|prześlij).{0,80}(pieniądz|pieniędzy|środk)",
            re.I | re.DOTALL,
        ),
        48,
        "Bezpośrednia prośba o przesłanie pieniędzy — nie pożyczaj zaufania nadawcy.",
    ),
    (
        re.compile(r"na\s+poniższy\s+link", re.I),
        40,
        "Wezwanie do korzystania z „poniższego linku” przy przelewie lub pilnej sprawie.",
    ),
    (
        re.compile(
            r"(kliknij|kliknij tutaj).{0,60}(zapłać|przelew|potwierdź|zweryfikuj)",
            re.I | re.DOTALL,
        ),
        38,
        "Łączenie kliknięcia z płatnością lub weryfikacją — podejrzane.",
    ),
    (
        re.compile(
            r"(wyślij|przekaż).{0,40}(kod|hasło|pin|blik|kart)",
            re.I | re.DOTALL,
        ),
        44,
        "Prośba o kody, PIN lub dane karty — często phishing lub oszustwo.",
    ),
]


def compute_heuristic(raw_text: str) -> Tuple[int, List[PhishingSignal], List[PhishingUrlFlag]]:
    """Heurystyka PL/EN — nie zależy od Groq."""
    t = (raw_text or "").strip()
    score = 8
    signals: List[PhishingSignal] = []
    urls: List[PhishingUrlFlag] = []

    if not t:
        return 0, [], []

    lower = t.lower()

    urgency = (
        "pilnie", "natychmiast", "zaraz", "dzisiaj", "w ciągu", "ostatnia szansa",
        "zablokujemy", "zawieszymy", "verify now", "urgent", "immediately",
    )
    pay = (
        "przelew", "przelej", "prześlij", "pieniądze", "pieniędzy", "zapłać", "wpłać",
        "blik", "karta", "karty", "payment", "paypal", "faktura", "invoice",
        "numer konta", "iban", "krypto", "bitcoin", "zainwestuj",
    )
    cred = (
        "hasło", "password", "login", "kod otp", "pin", "dane logowania", "cvv",
    )
    linkish = (
        "na poniższy link", "kliknij w link", "podeślij link", "otwórz stronę",
    )

    for words, _cat, label in (
        (urgency, "pilność", "Pilność / presja"),
        (pay, "płatność", "Prośba o płatność lub środki"),
        (cred, "dane uwierzytelniające", "Wrażliwe dane"),
        (linkish, "link", "Wezwanie do kliknięcia / linku"),
    ):
        hits = [w for w in words if w in lower]
        if hits:
            score += 14
            signals.append(
                PhishingSignal(
                    category=label,
                    detail=f"Wykryto frazy typowe dla oszustw: {', '.join(hits[:5])}.",
                )
            )

    best_combo = 0
    for pattern, pts, detail in _COMBO_PATTERNS:
        if pattern.search(t):
            if pts > best_combo:
                best_combo = pts
            signals.append(
                PhishingSignal(category="schemat scam", detail=detail)
            )
    score += best_combo

    if re.search(r"\bprzelej\s+mi\b", lower):
        score += 28
        signals.append(
            PhishingSignal(
                category="bezpośrednia prośba",
                detail='Formuła „przelej mi” — bardzo często używana w oszustwach.',
            )
        )

    url_re = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
    for m in url_re.finditer(t[:8000]):
        u = m.group(0).rstrip(").,;]")
        susp = False
        reason = ""
        low_u = u.lower()
        if any(x in low_u for x in ("bit.ly/", "tinyurl", "t.co/", "short.link", "cutt.ly")):
            susp = True
            reason = "Skrócony link — trudno ocenić docelową domenę."
        elif re.search(
            r"(secure-|verify-|login-|account-|signin-|auth-)[^.]*\.(xyz|top|click)\b", low_u
        ):
            susp = True
            reason = "Adres lub TLD często spotykane przy próbach wyłudzeń."
        if susp:
            urls.append(PhishingUrlFlag(url=u[:500], reason_pl=reason or "Wymaga ostrożności."))

    if urls:
        score += min(28, 6 * len(urls))

    score = max(0, min(100, score))
    return score, signals[:20], urls[:20]


def _heuristic_fallback(text: str) -> PhishingAnalysisResult:
    t = (text or "").strip()
    if not t:
        return PhishingAnalysisResult(
            threat_score_percent=0,
            risk_level="low",
            summary_pl="Brak treści do analizy.",
            signals=[],
            urls_flagged=[],
            engine_note="heurystyka (brak treści)",
        )

    h_score, h_sigs, h_urls = compute_heuristic(t)
    level = _score_to_risk_level(h_score)
    summary = (
        "Heurystyczna ocena — ustaw GROQ_API_KEY w backendzie, aby włączyć pełną analizę modelu."
        if h_score <= 20
        else "Ocena heurystyczna."
    )

    return PhishingAnalysisResult(
        threat_score_percent=h_score,
        risk_level=level,
        summary_pl=summary,
        signals=h_sigs[:12],
        urls_flagged=h_urls,
        engine_note="Uproszczona analiza heurystyczna.",
    )


def _parse_ai_json(raw: str) -> Dict[str, Any]:
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty")
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.I)
        s = re.sub(r"\s*```\s*$", "", s)
    return json.loads(s)


def _merge_ai_with_heuristic(
    raw_text: str,
    pct: int,
    summary: str,
    signals: List[PhishingSignal],
    urls_out: List[PhishingUrlFlag],
) -> PhishingAnalysisResult:
    h_score, h_sigs, h_urls = compute_heuristic(raw_text)
    merged_pct = max(pct, h_score)
    merged_rl = _score_to_risk_level(merged_pct)

    merged_signals = _dedupe_signals(signals, h_sigs)
    merged_urls = _dedupe_urls(urls_out, h_urls)

    sum_out = summary
    if merged_pct > pct and h_score >= 30:
        sum_out = (
            summary.rstrip()
            + " Uwzględniono też wzorce typowe dla oszustw (m.in. pilne przelewy, prośby o środki)."
        )[:2000]

    return PhishingAnalysisResult(
        threat_score_percent=merged_pct,
        risk_level=merged_rl,
        summary_pl=sum_out,
        signals=merged_signals,
        urls_flagged=merged_urls,
        engine_note=None,
    )


async def analyze_phishing_message(text: str) -> PhishingAnalysisResult:
    raw = (text or "").strip()
    if len(raw) > MAX_MESSAGE_CHARS:
        raw = raw[:MAX_MESSAGE_CHARS]

    try:
        _get_client()
    except RuntimeError:
        return _heuristic_fallback(raw)

    user_content = json.dumps(
        {"message_text": raw, "language_hint": "pl"},
        ensure_ascii=False,
    )

    def _call_sync() -> Dict[str, Any]:
        resp = _get_client().chat.completions.create(
            model=_fast_model(),
            max_tokens=1200,
            temperature=0.15,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _PHISHING_SYSTEM},
                {"role": "user", "content": user_content},
            ],
        )
        txt = (resp.choices[0].message.content or "").strip()
        return _parse_ai_json(txt)

    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, _call_sync),
            timeout=75.0,
        )
    except Exception:
        return _heuristic_fallback(raw)

    try:
        pct = int(data.get("threat_score_percent", 0))
        pct = max(0, min(100, pct))
        summary = str(data.get("summary_pl", "") or "").strip() or "Brak podsumowania."
        sigs_raw = data.get("signals") or []
        signals: List[PhishingSignal] = []
        if isinstance(sigs_raw, list):
            for item in sigs_raw[:20]:
                if not isinstance(item, dict):
                    continue
                signals.append(
                    PhishingSignal(
                        category=str(item.get("category", "") or "sygnał")[:120],
                        detail=str(item.get("detail", "") or "")[:500],
                    )
                )
        urls_raw = data.get("urls_flagged") or []
        urls_out: List[PhishingUrlFlag] = []
        if isinstance(urls_raw, list):
            for item in urls_raw[:30]:
                if not isinstance(item, dict):
                    continue
                urls_out.append(
                    PhishingUrlFlag(
                        url=str(item.get("url", "") or "")[:800],
                        reason_pl=str(item.get("reason_pl", "") or "")[:400],
                    )
                )

        return _merge_ai_with_heuristic(raw, pct, summary, signals, urls_out)
    except Exception:
        return _heuristic_fallback(raw)