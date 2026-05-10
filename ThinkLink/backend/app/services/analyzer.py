import re
import json
import asyncio
import os
import aiohttp
import httpx
import whois
import tldextract
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote, urlunparse
from typing import Optional, List, Tuple, Dict, Any
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

from app.models.schemas import (
    LinkAnalysisResult,
    RiskLevel,
    ThreatIndicator,
    RedirectChain,
    DomainInfo,
    LinkAnalysisRequest,
    SandboxAssessment,
    SandboxTimelineEvent,
)

_groq_client = None


def _get_client():
    global _groq_client
    if _groq_client is None:
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "Brak zmiennej środowiskowej GROQ_API_KEY."
            )
        groq_http_timeout = float(
            os.environ.get("GROQ_HTTP_TIMEOUT", "").strip() or "90"
        )
        _groq_client = Groq(
            api_key=api_key,
            timeout=httpx.Timeout(
                groq_http_timeout,
                connect=min(30.0, groq_http_timeout),
            ),
        )
    return _groq_client


DEFAULT_FAST_MODEL = "llama-3.1-8b-instant"


def _fast_model() -> str:
    return os.environ.get("GROQ_MODEL", "").strip() or DEFAULT_FAST_MODEL


def _sandbox_model() -> str:
    return os.environ.get("GROQ_SANDBOX_MODEL", "").strip() or _fast_model()


AI_CONCURRENCY = int(os.environ.get("AI_CONCURRENCY", "4"))
_ai_semaphore: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _ai_semaphore
    if _ai_semaphore is None:
        _ai_semaphore = asyncio.Semaphore(AI_CONCURRENCY)
    return _ai_semaphore


CACHE_TTL_SECONDS = 30 * 60
CACHE_TTL_UNKNOWN_SECONDS = 3 * 60
CACHE_MAX_ENTRIES = 5000

_result_cache: Dict[str, Tuple[float, "LinkAnalysisResult"]] = {}


def _cache_get(url: str) -> Optional["LinkAnalysisResult"]:
    import time
    entry = _result_cache.get(url)
    if entry is None:
        return None
    expires_at, result = entry
    if expires_at < time.time():
        _result_cache.pop(url, None)
        return None
    return result


def _cache_set(
    url: str,
    result: "LinkAnalysisResult",
    *,
    ttl_seconds: Optional[int] = None,
) -> None:
    import time
    if len(_result_cache) >= CACHE_MAX_ENTRIES:
        sorted_items = sorted(_result_cache.items(), key=lambda kv: kv[1][0])
        for k, _ in sorted_items[: max(1, CACHE_MAX_ENTRIES // 10)]:
            _result_cache.pop(k, None)
    ttl = ttl_seconds if ttl_seconds is not None else CACHE_TTL_SECONDS
    _result_cache[url] = (time.time() + ttl, result)


EXECUTABLE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs",
    ".jar", ".msi", ".dll", ".ps1", ".sh", ".dmg", ".apk", ".ipa"
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso",
}

MAX_BODY_SAMPLE_BYTES = 3000

AI_TIMEOUT_SECONDS = int(os.environ.get("AI_TIMEOUT_SECONDS", "60"))


def _sandbox_ai_timeout_seconds() -> int:
    """Groq sandbox narrative call; allow separate (often higher) limit than main AI."""
    raw = os.environ.get("SANDBOX_AI_TIMEOUT_SECONDS", "").strip()
    if raw:
        return max(15, int(raw))
    return max(AI_TIMEOUT_SECONDS, int(os.environ.get("SANDBOX_AI_TIMEOUT_FALLBACK", "90")))

_TRUSTED_REGISTERED_DOMAINS_RAW = """
empik.com allegro.pl ceneo.pl olx.pl otomoto.pl onet.pl wp.pl interia.pl
gazeta.pl github.com gitlab.com microsoft.com apple.com google.com youtube.com
gstatic.com googleusercontent.com ggpht.com amazon.com amazon.de amazon.pl
facebook.com instagram.com linkedin.com x.com twitter.com reddit.com
stackoverflow.com wikipedia.org mozilla.org cloudflare.com akamai.net
netflix.com spotify.com paypal.com stripe.com dropbox.com ikea.com ing.pl
mbank.pl pko.pl santander.pl pekao.com.pl millennium.pl t-mobile.pl orange.pl
play.pl plus.pl poczta-polska.pl dpd.com.pl inpost.pl stock.adobe.com adobe.com
behance.net dribbble.com cloudfront.net akamaihd.net fbcdn.net twimg.com
media-amazon.com ssl-images-amazon.com w3.org schema.org googletagmanager.com
google-analytics.com doubleclick.net facebook.net
"""
TRUSTED_REGISTERED_DOMAINS = {
    d.strip().lower()
    for d in _TRUSTED_REGISTERED_DOMAINS_RAW.split()
    if d.strip()
}

_RISKY_TLDS = frozenset({
    ".xyz", ".top", ".click", ".work", ".loan", ".download",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".cyou", ".beauty", ".sbs",
})


def _canonical_url(url: str) -> str:
    s = (url or "").strip()
    if not s:
        return s
    try:
        p = urlparse(s)
        if not p.scheme or p.scheme not in ("http", "https"):
            return s
        if p.netloc and "[" in p.netloc and "]" in p.netloc:
            return urlunparse(p._replace(fragment=""))
        host = (p.hostname or "").lower()
        if not host:
            return urlunparse(p._replace(fragment=""))
        netloc = host
        if p.port:
            netloc = f"{host}:{p.port}"
        if p.username:
            auth = p.username
            if p.password:
                auth += f":{p.password}"
            netloc = f"{auth}@{netloc}"
        p = p._replace(netloc=netloc, fragment="")
        return urlunparse(p)
    except Exception:
        return s.split("#", 1)[0] if "#" in s else s


def _evidence_registered_domain(evidence: Dict[str, Any]) -> str:
    d = evidence.get("registered_domain") or ""
    return str(d).lower().strip()


def _is_well_known_domain(evidence: Dict[str, Any]) -> bool:
    rd = _evidence_registered_domain(evidence)
    if not rd:
        return False
    if rd in TRUSTED_REGISTERED_DOMAINS:
        return True
    if rd.endswith(".edu.pl") or rd.endswith(".gov.pl") or rd.endswith(".ac.uk"):
        return True
    if re.search(r"(?i)\.(edu|gov)(\.[a-z]{2})?$", rd):
        return True
    for trusted in TRUSTED_REGISTERED_DOMAINS:
        if rd == trusted or rd.endswith("." + trusted):
            return True
    return False


def _has_hard_red_flags_evidence(evidence: Dict[str, Any]) -> bool:
    if evidence.get("redirect_protocol_downgrade"):
        return True
    if evidence.get("is_executable_extension"):
        return True
    for ind in evidence.get("url_shape_indicators") or []:
        code = str(ind.get("code") or "")
        sev = str(ind.get("severity") or "").lower()
        if code in {"AT_SIGN_IN_URL", "IP_ADDRESS_URL"}:
            return True
        if sev == "critical":
            return True
    return False


def _probe_client_error_likely_waf(evidence: Dict[str, Any], final_status: int) -> bool:
    if final_status not in (401, 403, 429):
        return False
    if _has_hard_red_flags_evidence(evidence):
        return False
    tld = (evidence.get("tld") or "").lower()
    if tld in _RISKY_TLDS:
        return False
    age = evidence.get("domain_age_days")
    if age is not None and age < 14:
        return False
    for ind in evidence.get("url_shape_indicators") or []:
        if str(ind.get("severity") or "").lower() in ("medium", "high", "critical"):
            return False
    try:
        final_u = str(evidence.get("final_url") or evidence.get("url") or "")
        if urlparse(final_u).scheme.lower() != "https":
            return False
    except Exception:
        return False
    return True


def _heuristic_refine_unknown(
    evidence: Dict[str, Any],
    risk_score: float,
) -> Tuple[RiskLevel, float, List[ThreatIndicator], str]:
    extra: List[ThreatIndicator] = []
    fetch_error = evidence.get("fetch_error")
    final_status = evidence.get("http_status")
    tld = (evidence.get("tld") or "").lower()
    well_known = _is_well_known_domain(evidence)
    age = evidence.get("domain_age_days")
    final_u = str(evidence.get("final_url") or evidence.get("url") or "")
    is_risky_tld = tld in _RISKY_TLDS

    if evidence.get("redirect_protocol_downgrade"):
        return (
            RiskLevel.DANGEROUS,
            max(risk_score, 0.75),
            [ThreatIndicator(
                code="HTTPS_DOWNGRADE",
                description="Łańcuch przekierowań obniża protokół z HTTPS do HTTP.",
                severity="high",
            )],
            "Skan: obniżenie TLS w łańcuchu przekierowań.",
        )

    if fetch_error or final_status is None:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.40),
            [ThreatIndicator(
                code="PROBE_FAILED",
                description=str(fetch_error or "Brak odpowiedzi HTTP z adresu docelowego"),
                severity="medium",
            )],
            "Skan: nie udało się połączyć ze skanera z miejscem docelowym.",
        )

    if (
        isinstance(final_status, int)
        and _probe_client_error_likely_waf(evidence, final_status)
    ):
        return (
            RiskLevel.SAFE,
            min(max(risk_score, 0.06), 0.14),
            [ThreatIndicator(
                code="PROBE_HTTP_CHALLENGE",
                description=(
                    f"HTTP {final_status} — serwer zablokował automatyczne pobranie "
                    "(filtr WAF/bot). Bez whitelisty; kształt URL i TLS wyglądają normalnie."
                ),
                severity="low",
            )],
            f"Skan: HTTP {final_status} potraktowano jako ochronę antybotową, nie jako sygnał malware.",
        )

    if isinstance(final_status, int) and final_status >= 400:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.38),
            [ThreatIndicator(
                code="HTTP_ERROR_STATUS",
                description=f"Cel zwrócił HTTP {final_status}",
                severity="medium",
            )],
            f"Skan: status HTTP {final_status}.",
        )

    if evidence.get("redirect_insecure_hops"):
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.34),
            [ThreatIndicator(
                code="INSECURE_REDIRECT_HOP",
                description="Ścieżka przekierowań zawiera HTTP po pierwszym skoku.",
                severity="medium",
            )],
            "Skan: wykryto niezabezpieczony skok przekierowania.",
        )

    if is_risky_tld and not well_known:
        sev = "medium" if (age is not None and age < 30) else "low"
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.34 if sev == "medium" else 0.26),
            [ThreatIndicator(
                code="HIGH_RISK_TLD",
                description=f"TLD {tld} jest często nadużywane; zachowaj większą ostrożność.",
                severity=sev,
            )],
            "Skan: wzorzec ryzykownej końcówki domeny przy ograniczonym kontekście reputacji.",
        )

    very_new = age is not None and age < 7
    if very_new and not well_known:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.36),
            [ThreatIndicator(
                code="VERY_NEW_DOMAIN",
                description="Domena zarejestrowana w ciągu ostatnich 7 dni.",
                severity="medium",
            )],
            "Skan: bardzo świeża rejestracja domeny.",
        )

    try:
        scheme = urlparse(final_u).scheme.lower()
    except Exception:
        scheme = ""

    youngish = age is not None and age < 14
    if (
        scheme == "https"
        and isinstance(final_status, int)
        and 200 <= final_status < 400
        and not fetch_error
        and not is_risky_tld
        and not (youngish and not well_known)
    ):
        return (
            RiskLevel.SAFE,
            min(max(risk_score, 0.08), 0.16),
            [],
            "Skan: HTTPS OK i brak silnych sygnałów statycznego ryzyka.",
        )

    if scheme == "http" and not well_known:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.28),
            [ThreatIndicator(
                code="HTTP_NOT_HTTPS",
                description="Końcowy adres używa nieszyfrowanego HTTP.",
                severity="low",
            )],
            "Skan: miejsce docelowe tylko przez HTTP.",
        )

    return (
        RiskLevel.SUSPICIOUS,
        max(risk_score, 0.24),
        [ThreatIndicator(
            code="UNVERIFIED_LINK",
            description="Sprawdzenia statyczne nie wykazały krytycznych problemów; klasyfikacja ostrożna.",
            severity="low",
        )],
        "Skan: brak wyraźnego dopasowania bezpieczne/niebezpieczne — oznaczono ostrożnie.",
    )


def _base_scan_explanation(
    level: str,
    well_known: bool,
    evidence: Dict[str, Any],
) -> str:
    fe = bool(evidence.get("fetch_error") or evidence.get("http_status") is None)
    if level == "dangerous":
        return (
            "Wykryto silne sygnały ryzyka w automatycznej ocenie "
            "(struktura linku, sonda HTTP lub domena)."
        )
    if level == "suspicious":
        return (
            "Automatyczna weryfikacja wykazała sygnały ostrzegawcze; "
            "zobacz wskaźniki i skrót sandbox."
        )
    if well_known and level == "unknown":
        return (
            "Host jest rozpoznawalny; skan ma ograniczone dane techniczne "
            "— sandbox może doprecyzować wynik."
        )
    if fe:
        return (
            "Skaner nie połączył się z adresem docelowym; "
            "ocena opiera się na dostępnych sygnałach."
        )
    return (
        "Wstępna klasyfikacja jest niejednoznaczna na podstawie danych skanowania."
    )


def _base_scan_verdict(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """URL shape, probe, and domain metadata — no LLM. Sandbox adds the AI layer."""
    signals = evidence.get("url_shape_indicators") or []
    has_high = any(i.get("severity") in ("high", "critical") for i in signals)
    has_medium_up = any(
        i.get("severity") in ("high", "critical", "medium") for i in signals
    )
    has_any = bool(signals)
    domain_age = evidence.get("domain_age_days")
    is_new_domain = domain_age is not None and domain_age < 30
    is_executable = evidence.get("is_executable_extension", False)
    well_known = _is_well_known_domain(evidence)
    hard = _has_hard_red_flags_evidence(evidence)

    if hard or has_high or is_executable or (is_new_domain and has_medium_up):
        level, score = "dangerous", 0.7
    elif has_any or is_new_domain:
        level, score = "suspicious", 0.45
    elif well_known:
        level, score = "unknown", 0.12
    else:
        level, score = "unknown", 0.18

    explanation = _base_scan_explanation(level, well_known, evidence)

    return {
        "risk_level": level,
        "risk_score": score,
        "explanation": explanation,
        "threats": [],
    }


async def analyze_link(request: LinkAnalysisRequest) -> LinkAnalysisResult:
    url = _canonical_url(request.url.strip())

    cached = _cache_get(url)
    if cached is not None:
        return cached

    try:
        result = await _analyze_link_uncached(request, url)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        return LinkAnalysisResult(
            url=url,
            risk_level=RiskLevel.SUSPICIOUS,
            risk_score=0.3,
            is_safe=False,
            indicators=[ThreatIndicator(
                code="ANALYZER_ERROR",
                description=f"Błąd analizatora: {type(e).__name__}",
                severity="medium",
            )],
            ai_assessment=json.dumps({
                "risk_level": "suspicious",
                "risk_score": 0.3,
                "explanation": f"Błąd analizatora: {type(e).__name__}: {e}",
                "threats": [],
            }, ensure_ascii=False),
        )

    _cache_set(
        url,
        result,
        ttl_seconds=CACHE_TTL_UNKNOWN_SECONDS
        if result.risk_level == RiskLevel.UNKNOWN
        else None,
    )
    return result


async def _analyze_link_uncached(request: LinkAnalysisRequest, url: str) -> LinkAnalysisResult:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return _make_unknown_result(
                url,
                f"Nieobsługiwany schemat URL: {parsed.scheme or '(brak)'}"
            )
    except Exception:
        return _make_unknown_result(url, "Nie można sparsować adresu URL")

    ext_info = tldextract.extract(url)
    registered_domain = ext_info.registered_domain or parsed.netloc
    tld = f".{ext_info.suffix}" if ext_info.suffix else ""

    indicators: List[ThreatIndicator] = []
    indicators.extend(_url_shape_evidence(url, parsed))

    url_hinted_extension = _extension_in_path(parsed.path)

    probe_task = asyncio.create_task(_probe_url(url))
    whois_task = asyncio.create_task(_get_domain_info(registered_domain))

    probe_result, domain_info = await asyncio.gather(
        probe_task, whois_task, return_exceptions=True
    )
    if isinstance(probe_result, Exception):
        probe_result = _empty_probe(url)
    if isinstance(domain_info, Exception):
        domain_info = None

    redirect_chain = probe_result.get("redirect_chain")
    response_headers = probe_result.get("response_headers", {}) or {}
    body_sample = probe_result.get("body_sample", "")
    final_url = probe_result.get("final_url", url)
    fetch_error = probe_result.get("fetch_error")
    final_status = probe_result.get("final_status")

    served_filename, served_mime = _extract_served_file(response_headers)
    effective_extension = (
        _ext_from_filename(served_filename)
        or _ext_from_mime(served_mime)
        or url_hinted_extension
    )

    redirect_signals = _analyze_redirect_chain(
        original_url=url,
        redirect_chain=redirect_chain,
    )

    # Downgrade triggers dangerous via _has_hard_red_flags_evidence, but the HTTPS_DOWNGRADE
    # indicator was only appended in _heuristic_refine_unknown (UNKNOWN branch) — add it here
    # so the report lists the same signal the verdict already uses.
    if redirect_signals["downgrade"]:
        indicators.append(
            ThreatIndicator(
                code="HTTPS_DOWNGRADE",
                description="Łańcuch przekierowań obniża protokół z HTTPS do HTTP.",
                severity="high",
            )
        )

    evidence = {
        "url": url,
        "final_url": final_url,
        "context_text": _truncate(request.context_text, 800) if request.context_text else None,
        "page_url": request.page_url,
        "registered_domain": registered_domain,
        "tld": tld,
        "subdomain": ext_info.subdomain or None,

        "redirect_chain": [
            {"url": h, "domain": tldextract.extract(h).registered_domain, "scheme": urlparse(h).scheme}
            for h in (redirect_chain.hops if redirect_chain else [url])
        ],
        "redirect_count": redirect_chain.redirect_count if redirect_chain else 0,

        "redirect_protocol_downgrade": redirect_signals["downgrade"],
        "redirect_insecure_hops": redirect_signals["insecure_mid_hops"],

        "http_status": final_status,
        "content_type": response_headers.get("content-type"),
        "content_disposition": response_headers.get("content-disposition"),
        "content_length": response_headers.get("content-length"),
        "server": response_headers.get("server"),
        "fetch_error": fetch_error,

        "served_filename": served_filename,
        "served_mime": served_mime,
        "effective_extension": effective_extension,
        "is_executable_extension": (
            effective_extension is not None
            and effective_extension.lower() in EXECUTABLE_EXTENSIONS
        ),
        "is_document_extension": (
            effective_extension is not None
            and effective_extension.lower() in DOCUMENT_EXTENSIONS
        ),

        "body_sample": _truncate(body_sample, MAX_BODY_SAMPLE_BYTES),
        "body_sample_truncated": len(body_sample) > MAX_BODY_SAMPLE_BYTES if body_sample else False,

        "domain_age_days": domain_info.age_days if isinstance(domain_info, DomainInfo) else None,
        "domain_registrar": domain_info.registrar if isinstance(domain_info, DomainInfo) else None,

        "url_shape_indicators": [
            {"code": i.code, "description": i.description, "severity": i.severity}
            for i in indicators
        ],
    }

    verdict = _base_scan_verdict(evidence)

    for t in verdict.get("threats") or []:
        try:
            indicators.append(ThreatIndicator(
                code=str(t.get("code", "AI_FLAG"))[:64],
                description=str(t.get("description", ""))[:400],
                severity=str(t.get("severity", "low")).lower(),
            ))
        except Exception:
            continue

    raw_level = _coerce_level(verdict.get("risk_level"))
    raw_score = _coerce_score(verdict.get("risk_score"))
    level_from_score = _level_from_score(raw_score)
    risk_level = _max_level(raw_level, level_from_score)

    has_critical_signal = any(
        i.severity == "critical" for i in indicators
        if i.code in {"AT_SIGN_IN_URL", "IP_ADDRESS_URL"}
    )
    if has_critical_signal and risk_level != RiskLevel.DANGEROUS:
        risk_level = RiskLevel.DANGEROUS
        raw_score = max(raw_score, 0.7)

    risk_score = raw_score

    expl = str(verdict.get("explanation") or "").lower()
    parse_failed = "could not parse ai response" in expl or "empty ai response" in expl
    if (
        risk_level == RiskLevel.UNKNOWN
        and level_from_score == RiskLevel.SAFE
        and not has_critical_signal
        and not parse_failed
        and _is_well_known_domain(evidence)
    ):
        has_concrete_risk_signal = any(
            i.severity in ("medium", "high", "critical")
            for i in indicators
        )
        if not has_concrete_risk_signal:
            risk_level = RiskLevel.SAFE

    if risk_level == RiskLevel.UNKNOWN:
        risk_level, risk_score, hi_inds, heel_note = _heuristic_refine_unknown(evidence, risk_score)
        indicators.extend(hi_inds)
        verdict = dict(verdict)
        verdict["risk_level"] = risk_level.value
        verdict["risk_score"] = risk_score
        prev_expl = str(verdict.get("explanation") or "").strip()
        verdict["explanation"] = (
            (prev_expl + " " + heel_note).strip() if heel_note else prev_expl
        )

    if risk_level == RiskLevel.SAFE:
        for ind in indicators:
            if ind.severity in ("critical", "high"):
                ind.severity = "low"

    file_download_field: Optional[str] = None
    if served_filename or _looks_like_attachment(response_headers):
        file_download_field = effective_extension

    sandbox_video_url = None
    sandbox_assessment: Optional[SandboxAssessment] = None
    verdict_out = dict(verdict)

    if risk_level in (RiskLevel.DANGEROUS, RiskLevel.SUSPICIOUS):
        sandbox_video_url = f"http://localhost:8000/api/v1/sandbox/video?url={url}"
        provisional = LinkAnalysisResult(
            url=url,
            risk_level=risk_level,
            risk_score=round(risk_score, 3),
            is_safe=risk_level == RiskLevel.SAFE,
            indicators=indicators,
            redirect_chain=redirect_chain,
            domain_info=domain_info if isinstance(domain_info, DomainInfo) else None,
            ai_assessment=json.dumps(verdict_out, ensure_ascii=False),
            file_download=file_download_field,
            sandbox_video_url=sandbox_video_url,
            sandbox_assessment=None,
        )
        sb_api = await _groq_sandbox_simulation(provisional)
        evs = sb_api.get("events_detected") or []
        try:
            sandbox_assessment = SandboxAssessment(
                verdict=str(sb_api.get("verdict") or ""),
                duration_seconds=float(sb_api.get("duration_seconds") or 12),
                events_detected=[
                    SandboxTimelineEvent(time=float(e["time"]), event=str(e["event"]))
                    for e in evs
                    if isinstance(e, dict) and "time" in e and "event" in e
                ],
                assessed_risk_level=sb_api.get("assessed_risk_level"),
            )
        except Exception:
            sandbox_assessment = None

        assessed_raw = (
            sandbox_assessment.assessed_risk_level if sandbox_assessment else None
        )
        old_lvl, old_sc = risk_level, risk_score
        risk_level, risk_score = _merge_risk_with_sandbox(
            risk_level, risk_score, assessed_raw
        )
        if risk_level != old_lvl or risk_score > old_sc + 0.01:
            verdict_out["risk_level"] = risk_level.value
            verdict_out["risk_score"] = round(risk_score, 3)
            expl_prev = str(verdict_out.get("explanation") or "").strip()
            if "sandbox" not in expl_prev.lower():
                note = "Dodatkowa ocena symulacji sandbox podnosi klasyfikację ryzyka."
                verdict_out["explanation"] = (
                    (expl_prev + " " + note).strip() if expl_prev else note
                )

    return LinkAnalysisResult(
        url=url,
        risk_level=risk_level,
        risk_score=round(risk_score, 3),
        is_safe=risk_level == RiskLevel.SAFE,
        indicators=indicators,
        redirect_chain=redirect_chain,
        domain_info=domain_info if isinstance(domain_info, DomainInfo) else None,
        ai_assessment=json.dumps(verdict_out, ensure_ascii=False),
        file_download=file_download_field,
        sandbox_video_url=sandbox_video_url,
        sandbox_assessment=sandbox_assessment,
    )



def _url_shape_evidence(url: str, parsed) -> List[ThreatIndicator]:
    found: List[ThreatIndicator] = []

    if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        found.append(ThreatIndicator(
            code="IP_ADDRESS_URL",
            description="Adres URL używa surowego IP zamiast nazwy domeny",
            severity="high",
        ))

    decoded = unquote(url)
    if decoded != url and len(decoded) < len(url) * 0.7:
        found.append(ThreatIndicator(
            code="HEAVY_URL_ENCODING",
            description="Nadmierne kodowanie procentowe w URL (możliwa obfuskacja)",
            severity="medium",
        ))

    if "@" in (parsed.netloc or ""):
        found.append(ThreatIndicator(
            code="AT_SIGN_IN_URL",
            description="W adresie jest znak @ — wyświetlana domena może różnić się od faktycznego celu",
            severity="critical",
        ))

    subdomain = tldextract.extract(url).subdomain
    if subdomain and len(subdomain) > 50:
        found.append(ThreatIndicator(
            code="LONG_SUBDOMAIN",
            description="Nietypowo długa subdomena — może maskować prawdziwą domenę",
            severity="low",
        ))

    if "/../" in url or "/.//" in url:
        found.append(ThreatIndicator(
            code="PATH_TRAVERSAL",
            description="W ścieżce URL wykryto sekwencje path traversal",
            severity="medium",
        ))

    return found


def _extension_in_path(path: str) -> Optional[str]:
    if not path:
        return None
    path = path.lower().split("?", 1)[0].split("#", 1)[0]
    m = re.search(r"(\.[a-z0-9]{1,6})$", path)
    return m.group(1) if m else None


def _analyze_redirect_chain(
    original_url: str,
    redirect_chain: Optional[RedirectChain],
) -> Dict[str, Any]:
    if not redirect_chain or not redirect_chain.hops:
        return {"downgrade": False, "insecure_mid_hops": False}

    schemes = [urlparse(h).scheme.lower() for h in redirect_chain.hops]

    downgrade = False
    for i in range(len(schemes) - 1):
        if schemes[i] == "https" and schemes[i + 1] == "http":
            downgrade = True
            break

    insecure_mid = any(s == "http" for s in schemes[1:])

    return {
        "downgrade": downgrade,
        "insecure_mid_hops": insecure_mid,
    }



async def _probe_url(url: str, max_hops: int = 8) -> Dict[str, Any]:
    hops: List[str] = [url]
    current = url
    response_headers: Dict[str, str] = {}
    final_status: Optional[int] = None
    body_sample = ""
    fetch_error: Optional[str] = None

    timeout = aiohttp.ClientTimeout(total=10, connect=5)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ThinkLink/2.0"
        ),
        "Accept": "*/*",
        "Accept-Language": "pl,en;q=0.5",
    }

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for _ in range(max_hops):
                try:
                    async with session.request(
                        "GET",
                        current,
                        allow_redirects=False,
                        ssl=False,
                    ) as resp:
                        final_status = resp.status
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "")
                            if not location:
                                break
                            location = _absolutize(current, location)
                            if location == current:
                                break
                            hops.append(location)
                            current = location
                            continue

                        response_headers = {
                            k.lower(): v for k, v in resp.headers.items()
                        }
                        ct = response_headers.get("content-type", "")
                        readable = (
                            "text" in ct
                            or "html" in ct
                            or "json" in ct
                            or "xml" in ct
                            or ct == ""
                        )
                        if readable:
                            try:
                                chunk = await asyncio.wait_for(
                                    resp.content.read(MAX_BODY_SAMPLE_BYTES),
                                    timeout=5,
                                )
                                body_sample = chunk.decode("utf-8", errors="replace")
                            except Exception:
                                body_sample = ""
                        break
                except Exception as e:
                    fetch_error = f"{type(e).__name__}: {e}"
                    break
    except Exception as e:
        fetch_error = f"{type(e).__name__}: {e}"

    redirect_chain = (
        RedirectChain(
            hops=hops,
            final_url=current,
            redirect_count=len(hops) - 1,
        )
        if len(hops) > 1
        else None
    )

    return {
        "redirect_chain": redirect_chain,
        "final_url": current,
        "final_status": final_status,
        "response_headers": response_headers,
        "body_sample": body_sample,
        "fetch_error": fetch_error,
    }


def _empty_probe(url: str) -> Dict[str, Any]:
    return {
        "redirect_chain": None,
        "final_url": url,
        "final_status": None,
        "response_headers": {},
        "body_sample": "",
        "fetch_error": "probe_failed",
    }


def _absolutize(current_url: str, location: str) -> str:
    if location.startswith(("http://", "https://")):
        return location
    parsed = urlparse(current_url)
    if location.startswith("//"):
        return f"{parsed.scheme}:{location}"
    if location.startswith("/"):
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    base_path = parsed.path.rsplit("/", 1)[0]
    return f"{parsed.scheme}://{parsed.netloc}{base_path}/{location}"


def _extract_served_file(headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    cd = headers.get("content-disposition", "") or ""
    filename = None
    m = re.search(r'filename\*?=(?:UTF-\d\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
    if m:
        filename = unquote(m.group(1).strip())
    mime = (headers.get("content-type", "") or "").split(";", 1)[0].strip().lower() or None
    return filename, mime


def _ext_from_filename(filename: Optional[str]) -> Optional[str]:
    if not filename:
        return None
    m = re.search(r"(\.[a-zA-Z0-9]{1,6})$", filename)
    return m.group(1).lower() if m else None


def _ext_from_mime(mime: Optional[str]) -> Optional[str]:
    if not mime:
        return None
    mapping = {
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "application/x-msdownload": ".exe",
        "application/x-msdos-program": ".exe",
        "application/vnd.microsoft.portable-executable": ".exe",
        "application/x-apple-diskimage": ".dmg",
        "application/vnd.android.package-archive": ".apk",
        "application/x-iso9660-image": ".iso",
        "application/x-rar-compressed": ".rar",
        "application/x-7z-compressed": ".7z",
    }
    return mapping.get(mime)


def _looks_like_attachment(headers: Dict[str, str]) -> bool:
    cd = (headers.get("content-disposition") or "").lower()
    return "attachment" in cd



async def _get_domain_info(domain: str) -> Optional[DomainInfo]:
    if not domain:
        return None
    try:
        loop = asyncio.get_event_loop()
        w = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: whois.whois(domain)),
            timeout=6,
        )
        creation_date = getattr(w, "creation_date", None)
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        age_days = None
        is_new = False
        is_very_new = False

        if creation_date and isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            is_new = age_days < 30
            is_very_new = age_days < 7

        return DomainInfo(
            domain=domain,
            age_days=age_days,
            registrar=getattr(w, "registrar", None),
            country=getattr(w, "country", None),
            is_new=is_new,
            is_very_new=is_very_new,
        )
    except Exception:
        return None



_SANDBOX_SYSTEM_PROMPT = """Jesteś generatorem narracji sandbox dla rozszerzenia ThinkLink.

Nie uruchamiasz prawdziwej przeglądarki. Dostajesz ustrukturyzowane podsumowanie ze skanera ThinkLink (przekierowania, metadane domeny, wskaźniki zagrożeń oraz pola werdyktu w ai_assessment_brief). Twoje zadanie: wygenerować spójną chronologiczną oś czasu, JAKBY przeglądarka headless odwiedziła stronę — zgodnie z tymi dowodami.

Reguły:
- Zwróć JEDEN obiekt JSON. Bez markdownu i komentarzy.
- Klucze: "verdict" (string), "duration_seconds" (liczba), "events_detected" (tablica obiektów z "time" (liczba sekund) i "event" (string)), "assessed_risk_level" (string: dokładnie jedna z wartości "safe", "suspicious", "dangerous" — zgodnie z oceną ryzyka z tych samych dowodów i ze werdyktem).
- Użyj 4–8 zdarzeń. Czasy rosnąco, między ~0.5 a duration_seconds.
- "verdict": jedna linia, mocny ton ryzyka zgodny ze skanem. Prefiks etykietą ryzyka po polsku (np. "WYSOKIE RYZYKO —", "PODEJRZANE —", "NISKIE RYZYKO —").
- Wszystkie teksty widoczne dla użytkownika (werdykt i opisy zdarzeń) pisz PO POLSKU.
- Nie wymyślaj nazw rodzin malware, dokładnych hostów C2 ani marek spoza dowodów.
- To wyłącznie symulacja edukacyjna wnioskowana z danych — nie twierdzenia o rzeczywistej instrumentacji."""


def _sandbox_evidence_pack(analysis: LinkAnalysisResult) -> Dict[str, Any]:
    payload = analysis.model_dump(mode="json")
    aa = payload.get("ai_assessment")
    ai_brief: Any = None
    if isinstance(aa, str) and aa.strip():
        try:
            parsed = json.loads(aa)
            if isinstance(parsed, dict):
                ai_brief = {
                    k: parsed[k]
                    for k in ("risk_level", "risk_score", "explanation", "threats")
                    if k in parsed
                }
        except json.JSONDecodeError:
            ai_brief = _truncate(aa, 400)
    payload["ai_assessment_brief"] = ai_brief
    payload.pop("ai_assessment", None)
    payload.pop("sandbox_video_url", None)
    # Same scan as main heuristic — explicit digest so the LLM aligns timeline with codes/signals.
    lvl_v = (
        analysis.risk_level.value
        if isinstance(analysis.risk_level, RiskLevel)
        else str(analysis.risk_level)
    )
    payload["sandbox_llm_digest"] = {
        "risk_level": lvl_v,
        "risk_score": round(float(analysis.risk_score), 4),
        "indicator_codes_in_order": [i.code for i in (analysis.indicators or [])],
        "redirect_hops": (
            len(analysis.redirect_chain.hops)
            if analysis.redirect_chain and analysis.redirect_chain.hops
            else 0
        ),
        "domain_registered": (
            analysis.domain_info.domain if analysis.domain_info else None
        ),
        "domain_age_days": (
            analysis.domain_info.age_days if analysis.domain_info else None
        ),
        "file_download_hint": analysis.file_download,
    }
    return payload


def _parse_sandbox_json(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m:
        cleaned = m.group(0)
    try:
        data = json.loads(cleaned)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _normalize_sandbox_raw(raw: Dict[str, Any], analysis: LinkAnalysisResult) -> Dict[str, Any]:
    verdict = str(raw.get("verdict") or "").strip()
    if not verdict:
        verdict = "NIEPOTWIERDZONA SYMULACJA — model nie zwrócił werdyktu."
    try:
        duration = float(raw.get("duration_seconds"))
    except (TypeError, ValueError):
        duration = 12.0
    duration = max(5.0, min(30.0, duration))

    events_in = raw.get("events_detected") or []
    events: List[Dict[str, Any]] = []
    if isinstance(events_in, list):
        for item in events_in:
            if not isinstance(item, dict):
                continue
            try:
                ev_t = float(item.get("time"))
            except (TypeError, ValueError):
                continue
            ev_text = str(item.get("event") or "").strip()
            if not ev_text:
                continue
            events.append({"time": round(ev_t, 2), "event": ev_text})
    events.sort(key=lambda x: x["time"])
    for e in events:
        e["time"] = max(0.2, min(float(duration) - 0.2, float(e["time"])))
    if len(events) > 12:
        events = events[:12]
    if not events:
        events = [
            {
                "time": 1.0,
                "event": "Załadowanie dokumentu (symulacja).",
            },
        ]
    assessed: Optional[str] = None
    ar = raw.get("assessed_risk_level")
    if isinstance(ar, str):
        a = ar.lower().strip()
        if a in ("safe", "suspicious", "dangerous"):
            assessed = a
    return {
        "verdict": verdict,
        "duration_seconds": round(duration, 1),
        "events_detected": events,
        "assessed_risk_level": assessed,
    }


def _heuristic_sandbox_timeline_messages(
    analysis: LinkAnalysisResult,
    *,
    max_events: int = 12,
) -> List[str]:
    """Te same dane co heurystyka skanu — łańcuch przekierowań, WHOIS, wynik i wskaźniki."""
    lvl = (
        analysis.risk_level.value
        if isinstance(analysis.risk_level, RiskLevel)
        else str(analysis.risk_level)
    )
    indicators = list(analysis.indicators or [])
    lines: List[str] = []

    lines.append(
        "Żądanie początkowe: zestawienie połączenia z hostem docelowym.",
    )

    pct = round(float(analysis.risk_score or 0) * 100)
    lines.append(f"Heurystyka ThinkLink: poziom {lvl.upper()}, szacowane ryzyko ~{pct}%.")

    rc = analysis.redirect_chain
    if rc and rc.redirect_count and rc.hops:
        lines.append(f"Łańcuch przekierowań: {rc.redirect_count} skok(ów).")
        for i, hop in enumerate(rc.hops[:4], start=1):
            if len(lines) >= max_events - 1:
                break
            show = hop if len(hop) <= 76 else hop[:73] + "…"
            lines.append(f"Hop #{i}: {show}")

    di = analysis.domain_info
    if di and len(lines) < max_events:
        lines.append(f"Domena (registered): {di.domain}")
        if di.age_days is not None and len(lines) < max_events:
            lines.append(f"Szacowany wiek rejestracji WHOIS: ~{di.age_days} dni.")
        if di.is_very_new and len(lines) < max_events:
            lines.append("Bardzo świeża domena — zwiększona ostrożność.")
        elif di.is_new and len(lines) < max_events:
            lines.append("Domena stosunkowo nowa (< 30 dni).")
        if di.country and len(lines) < max_events:
            lines.append(f"Kraj rejestracji (WHOIS): {di.country}")

    if analysis.file_download and len(lines) < max_events:
        ext = str(analysis.file_download).lstrip(".")
        lines.append(f"Odpowiedź sugeruje plik do pobrania (typ: .{ext}).")

    for ind in indicators:
        if len(lines) >= max_events:
            break
        lines.append(f"Wskaźnik [{ind.code}] ({ind.severity}): {ind.description}")

    if not indicators and len(lines) < max_events:
        lines.append(
            "Brak osobnych rekordów wskaźników — klasyfikacja opiera się na ogólnych sygnałach.",
        )

    return lines[:max_events]


def _heuristic_sandbox_verdict(lvl: str) -> str:
    if lvl == "dangerous":
        return (
            "WYSOKIE RYZYKO — sygnały z analizy ThinkLink wskazują na realne zagrożenie."
        )
    if lvl == "suspicious":
        return "PODEJRZANE — kontekst URL i sygnały uzasadniają ostrożność."
    return (
        "SYMULACJA OSTROŻNOŚCI — poziom zagrożenia z analizy jest niejednoznaczny."
    )


def _heuristic_sandbox_report(analysis: LinkAnalysisResult) -> Dict[str, Any]:
    lvl = (
        analysis.risk_level.value
        if isinstance(analysis.risk_level, RiskLevel)
        else str(analysis.risk_level)
    )
    msgs = _heuristic_sandbox_timeline_messages(analysis, max_events=12)
    events: List[Dict[str, Any]] = []
    t = 1.0

    def add(msg: str) -> None:
        nonlocal t
        events.append({"time": round(t, 2), "event": msg})
        t += 1.15 + (len(events) % 5) * 0.12

    for m in msgs:
        add(m)

    verdict = _heuristic_sandbox_verdict(lvl)

    duration = max(8.0, min(26.0, t + 2.0))
    for e in events:
        e["time"] = min(e["time"], duration - 0.3)
    assessed_out = lvl if lvl in ("dangerous", "suspicious", "safe") else "suspicious"
    return _normalize_sandbox_raw(
        {
            "verdict": verdict,
            "duration_seconds": duration,
            "events_detected": events,
            "assessed_risk_level": assessed_out,
        },
        analysis,
    )


def _sandbox_api_response(url: str, normalized: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "status": "ready",
        "url": url,
        "video_url": None,
        "thumbnail_url": None,
        "duration_seconds": normalized["duration_seconds"],
        "events_detected": normalized["events_detected"],
        "verdict": normalized["verdict"],
    }
    ar = normalized.get("assessed_risk_level")
    if ar:
        out["assessed_risk_level"] = ar
    return out


async def _groq_sandbox_simulation(analysis: LinkAnalysisResult) -> Dict[str, Any]:
    pack = _sandbox_evidence_pack(analysis)
    user_msg = json.dumps(
        {"preferred_language": "pl", "thinklink_scan": pack},
        ensure_ascii=False,
        indent=2,
    )
    semaphore = _get_semaphore()
    model = _sandbox_model()

    try:
        _get_client()
    except RuntimeError:
        fb = _heuristic_sandbox_report(analysis)
        fb["verdict"] = "Brak zmiennej środowiskowej GROQ_API_KEY. " + fb["verdict"]
        return _sandbox_api_response(analysis.url, fb)

    async def _call() -> Dict[str, Any]:
        async with semaphore:
            loop = asyncio.get_event_loop()
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: _get_client().chat.completions.create(
                        model=model,
                        max_tokens=800,
                        temperature=0.2,
                        response_format={"type": "json_object"},
                        messages=[
                            {"role": "system", "content": _SANDBOX_SYSTEM_PROMPT},
                            {"role": "user", "content": user_msg},
                        ],
                    ),
                ),
                timeout=float(_sandbox_ai_timeout_seconds()),
            )
        text = (response.choices[0].message.content or "").strip()
        return _parse_sandbox_json(text)

    last_exc: Optional[BaseException] = None
    for attempt in range(2):
        try:
            raw = await _call()
            if not raw:
                raise ValueError("empty sandbox model response")
            normalized = _normalize_sandbox_raw(raw, analysis)
            return _sandbox_api_response(analysis.url, normalized)
        except asyncio.TimeoutError:
            last_exc = asyncio.TimeoutError()
            if attempt == 0:
                await asyncio.sleep(0.75)
                continue
        except Exception as e:
            last_exc = e
            break

    fb = _heuristic_sandbox_report(analysis)
    note = "(API sandbox niedostępne — podgląd z samych danych skanu.) "
    if last_exc:
        note = f"({type(last_exc).__name__}) " + note
    fb["verdict"] = note + fb["verdict"]
    return _sandbox_api_response(analysis.url, fb)


async def sandbox_simulation_for_url(url: str) -> Dict[str, Any]:
    if not url or not str(url).strip():
        raise ValueError("wymagany jest parametr url")
    canonical = _canonical_url(url.strip())
    analysis = await analyze_link(LinkAnalysisRequest(url=canonical))
    return await _groq_sandbox_simulation(analysis)


def _coerce_level(value: Any) -> RiskLevel:
    if isinstance(value, str):
        v = value.lower().strip()
        if v == "safe":
            return RiskLevel.SAFE
        if v == "suspicious":
            return RiskLevel.SUSPICIOUS
        if v == "dangerous":
            return RiskLevel.DANGEROUS
    return RiskLevel.UNKNOWN


def _level_from_score(score: float) -> RiskLevel:
    if score >= 0.60:
        return RiskLevel.DANGEROUS
    if score >= 0.20:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE


_LEVEL_RANK = {
    RiskLevel.SAFE: 0,
    RiskLevel.UNKNOWN: 1,
    RiskLevel.SUSPICIOUS: 2,
    RiskLevel.DANGEROUS: 3,
}


def _max_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _LEVEL_RANK.get(a, 0) >= _LEVEL_RANK.get(b, 0) else b


def _merge_risk_with_sandbox(
    risk_level: RiskLevel,
    risk_score: float,
    sandbox_assessed: Optional[str],
) -> Tuple[RiskLevel, float]:
    if not sandbox_assessed:
        return risk_level, risk_score
    s = str(sandbox_assessed).lower().strip()
    if s not in ("safe", "suspicious", "dangerous"):
        return risk_level, risk_score
    sb_level = _coerce_level(s)
    if sb_level == RiskLevel.UNKNOWN:
        return risk_level, risk_score
    merged = _max_level(risk_level, sb_level)
    new_score = risk_score
    if merged == RiskLevel.DANGEROUS:
        new_score = max(risk_score, 0.62)
    elif merged == RiskLevel.SUSPICIOUS:
        new_score = max(risk_score, 0.25)
    return merged, new_score


def _coerce_score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, score))


def _truncate(text: Optional[str], max_len: int) -> Optional[str]:
    if text is None:
        return None
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def _make_unknown_result(url: str, reason: str) -> LinkAnalysisResult:
    return LinkAnalysisResult(
        url=url,
        risk_level=RiskLevel.UNKNOWN,
        risk_score=0.0,
        is_safe=False,
        indicators=[ThreatIndicator(code="PARSE_ERROR", description=reason, severity="low")],
    )
