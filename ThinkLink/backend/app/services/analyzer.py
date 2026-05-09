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
    LinkAnalysisResult, RiskLevel, ThreatIndicator,
    RedirectChain, DomainInfo, LinkAnalysisRequest
)

_groq_client = None


def _get_client():
    global _groq_client
    if _groq_client is None:
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Put it in backend/.env "
                "(get a key at https://console.groq.com/keys)."
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
DEFAULT_DEEP_MODEL = "llama-3.3-70b-versatile"


def _fast_model() -> str:
    return os.environ.get("GROQ_MODEL", "").strip() or DEFAULT_FAST_MODEL


def _deep_model() -> str:
    return os.environ.get("GROQ_DEEP_MODEL", "").strip() or DEFAULT_DEEP_MODEL


def _get_model() -> str:
    return _fast_model()



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
                description="Redirect chain downgrades from HTTPS to HTTP.",
                severity="high",
            )],
            "Heuristic: TLS downgrade in redirect chain.",
        )

    if fetch_error or final_status is None:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.40),
            [ThreatIndicator(
                code="PROBE_FAILED",
                description=str(fetch_error or "No HTTP response from destination"),
                severity="medium",
            )],
            "Heuristic: link could not be loaded for verification.",
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
                    f"HTTP {final_status} — server blocked the automated fetch "
                    "(WAF/bot filter). No whitelist used; URL shape and TLS look normal."
                ),
                severity="low",
            )],
            f"Heuristic: HTTP {final_status} treated as bot protection, not a malware signal.",
        )

    if isinstance(final_status, int) and final_status >= 400:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.38),
            [ThreatIndicator(
                code="HTTP_ERROR_STATUS",
                description=f"Destination returned HTTP {final_status}",
                severity="medium",
            )],
            f"Heuristic: HTTP status {final_status}.",
        )

    if evidence.get("redirect_insecure_hops"):
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.34),
            [ThreatIndicator(
                code="INSECURE_REDIRECT_HOP",
                description="Redirect path includes HTTP after the first hop.",
                severity="medium",
            )],
            "Heuristic: insecure redirect hop detected.",
        )

    if is_risky_tld and not well_known:
        sev = "medium" if (age is not None and age < 30) else "low"
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.34 if sev == "medium" else 0.26),
            [ThreatIndicator(
                code="HIGH_RISK_TLD",
                description=f"TLD {tld} is commonly abused; AI verdict was unclear.",
                severity=sev,
            )],
            "Heuristic: risky TLD without a clear AI verdict.",
        )

    very_new = age is not None and age < 7
    if very_new and not well_known:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.36),
            [ThreatIndicator(
                code="VERY_NEW_DOMAIN",
                description="Domain registered within the last 7 days.",
                severity="medium",
            )],
            "Heuristic: very new domain registration.",
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
            "Heuristic: HTTPS OK and no high-risk signals (AI verdict was unclear).",
        )

    if scheme == "http" and not well_known:
        return (
            RiskLevel.SUSPICIOUS,
            max(risk_score, 0.28),
            [ThreatIndicator(
                code="HTTP_NOT_HTTPS",
                description="Final URL uses unencrypted HTTP.",
                severity="low",
            )],
            "Heuristic: destination is HTTP-only.",
        )

    return (
        RiskLevel.SUSPICIOUS,
        max(risk_score, 0.24),
        [ThreatIndicator(
            code="UNVERIFIED_LINK",
            description="No confident AI verdict; basic checks found no critical issues.",
            severity="low",
        )],
        "Heuristic-only: inconclusive AI — marked cautious instead of unknown.",
    )


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
                description=f"Analyzer crashed: {type(e).__name__}",
                severity="medium",
            )],
            ai_assessment=json.dumps({
                "risk_level": "suspicious",
                "risk_score": 0.3,
                "threat_type": "unknown",
                "explanation": f"Analyzer error: {type(e).__name__}: {e}",
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
                f"Unsupported URL scheme: {parsed.scheme or '(none)'}"
            )
    except Exception:
        return _make_unknown_result(url, "Could not parse URL")

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

    verdict = await _ai_verdict(evidence)

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
    if risk_level in (RiskLevel.DANGEROUS, RiskLevel.SUSPICIOUS):
        sandbox_video_url = f"http://localhost:8000/api/v1/sandbox/video?url={url}"

    return LinkAnalysisResult(
        url=url,
        risk_level=risk_level,
        risk_score=round(risk_score, 3),
        is_safe=risk_level == RiskLevel.SAFE,
        indicators=indicators,
        redirect_chain=redirect_chain,
        domain_info=domain_info if isinstance(domain_info, DomainInfo) else None,
        ai_assessment=json.dumps(verdict, ensure_ascii=False),
        file_download=file_download_field,
        sandbox_video_url=sandbox_video_url,
    )



def _url_shape_evidence(url: str, parsed) -> List[ThreatIndicator]:
    found: List[ThreatIndicator] = []

    if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        found.append(ThreatIndicator(
            code="IP_ADDRESS_URL",
            description="URL uses raw IP address instead of domain name",
            severity="high",
        ))

    decoded = unquote(url)
    if decoded != url and len(decoded) < len(url) * 0.7:
        found.append(ThreatIndicator(
            code="HEAVY_URL_ENCODING",
            description="URL contains excessive percent-encoding (possible obfuscation)",
            severity="medium",
        ))

    if "@" in (parsed.netloc or ""):
        found.append(ThreatIndicator(
            code="AT_SIGN_IN_URL",
            description="URL contains @ symbol — displayed domain may differ from actual destination",
            severity="critical",
        ))

    subdomain = tldextract.extract(url).subdomain
    if subdomain and len(subdomain) > 50:
        found.append(ThreatIndicator(
            code="LONG_SUBDOMAIN",
            description="Unusually long subdomain — may be disguising legitimate domain",
            severity="low",
        ))

    if "/../" in url or "/.//" in url:
        found.append(ThreatIndicator(
            code="PATH_TRAVERSAL",
            description="URL contains path traversal sequences",
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
        "Accept-Language": "en,pl;q=0.8",
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



_AI_SYSTEM_PROMPT = """You are ThinkLink, a senior security analyst deciding whether a URL is safe to follow.

Balance accuracy: flag real phishing, malware, and scams clearly, but do NOT alarm users for ordinary commerce, news, blogs, or well-known services. A boring marketing redirect or empty body sample on a reputable host is usually fine. When evidence is weak or ambiguous and the domain looks legitimate, prefer "safe" with a low score or "unknown" — do not default to "suspicious" for normal web noise.

You receive an evidence pack with:
- The original URL and the final URL after redirects
- The full redirect chain (each hop's domain)
- HTTP response headers (Content-Type, Content-Disposition, server, status)
- A sample of the response body (HTML/text/JSON, possibly truncated)
- Domain age and registrar from WHOIS (when available)
- url_shape_indicators detected statically — these are SIGNALS, not verdicts
- Optional surrounding page text the user clicked from

DECISION RULES (apply in order):

1) HARD DANGEROUS triggers — return "dangerous" if ANY of these holds:
   - URL/final domain is a homoglyph or lookalike of a known brand
     (e.g. "paypa1.com", "аllegro.pl" with Cyrillic, "microsft.com",
     "empik-platnosc.com", "allegro-zaplata.xyz", "ing-bank.security-login.top").
   - Body content references a known brand (logo, name, login form, "Sign in
     to <Brand>") but the registered_domain is NOT that brand's actual
     primary domain or recognized CDN.
   - Domain registered < 14 days AND any of: login form, payment form,
     parcel-tracking page, "verify your account", "delivery fee" copy,
     instructions to install an APK, executable download.
   - URL serves an executable (.exe/.msi/.apk/.dmg/.bat/.scr/.jar) AND the
     domain is NOT a recognized vendor or established platform (GitHub
     releases, Microsoft, Apple, Google, Mozilla, official vendor sites,
     well-known download mirrors). Random hosts, file-sharing services
     used as primary delivery, fresh domains — all dangerous.
   - IP_ADDRESS_URL or AT_SIGN_IN_URL signal is present.
   - redirect_protocol_downgrade is true (the chain went HTTPS -> HTTP at
     some point — the request can be intercepted on the network).
   - Final domain mismatches the brand strongly implied by the original
     URL or the surrounding click context (e.g. user clicked from an
     "Empik" tracking link but final domain is unrelated and not an Empik
     property).

2) SUSPICIOUS triggers — return "suspicious" if ANY:
   - Domain age < 60 days and the page is anything transactional
     (login, signup, checkout, support).
   - .xyz / .top / .click / .work / .loan / .download / .tk / .ml / .ga /
     .cf / .gq / .icu and similar bulk TLDs hosting transactional content.
   - Heavy URL encoding, very long subdomain combined with brand keywords.
   - Body sample is empty, error page, or unreachable but URL shape has
     any signals.
   - Mismatched content type vs URL extension (e.g. URL ends in .pdf but
     server returns text/html with login form).
   - redirect_insecure_hops is true (the chain transits an HTTP hop after
     starting on HTTPS — the request can be intercepted).

3) REDIRECTS — IMPORTANT, READ CAREFULLY:
   Most redirects on the modern web are SAFE. Tracking redirects, OAuth
   handoffs, link shorteners, marketing campaigns, ad networks, regional
   redirects, www <-> apex, http <-> https upgrades, brand subdomain to
   apex (tracking.empik.com -> empik.com) — ALL NORMAL.
   Do NOT flag a URL as suspicious or dangerous merely because:
     * it has many hops (3, 5, 8 hops can all be perfectly legitimate)
     * the hops cross different registered domains
     * a shortener is involved
     * the final domain is different from the original
   ONLY treat redirects as a security signal when:
     * redirect_protocol_downgrade is true (HTTPS -> HTTP somewhere in the
       chain) -> this is a DANGEROUS signal, treat per rule 1.
     * redirect_insecure_hops is true (HTTP appears after the first hop) ->
       SUSPICIOUS per rule 2.
     * the FINAL URL itself meets a DANGEROUS or SUSPICIOUS trigger from
       rule 1 or 2 (lookalike domain, brand-new domain with login form,
       executable on random host, etc.) — in which case judge the final
       destination on its own merits. The redirect itself is not the issue,
       the destination is.

4) SAFE — only when ALL of these hold:
   - registered_domain matches a recognized brand/service
     (empik.com, allegro.pl, ceneo.pl, olx.pl, otomoto.pl, onet.pl, wp.pl,
     interia.pl, gazeta.pl, github.com, gitlab.com, microsoft.com,
     apple.com, google.com, youtube.com, amazon.com, amazon.de, amazon.pl,
     facebook.com, instagram.com, linkedin.com, x.com, twitter.com,
     reddit.com, stackoverflow.com, wikipedia.org, mozilla.org,
     cloudflare.com, akamai.net, netflix.com, spotify.com, paypal.com,
     stripe.com, dropbox.com, ikea.com, ing.pl, mbank.pl, pko.pl,
     santander.pl, pekao.com.pl, millennium.pl, t-mobile.pl, orange.pl,
     play.pl, plus.pl, poczta-polska.pl, dpd.com.pl, inpost.pl,
     stock.adobe.com, adobe.com, behance.net, dribbble.com),
     OR is a recognized CDN/infrastructure host of one of these
     (media-amazon.com, ssl-images-amazon.com, fbcdn.net, twimg.com,
     ggpht.com, googleusercontent.com, gstatic.com, akamaihd.net,
     cloudfront.net subdomains belonging to a known service, etc.).
   - AND body content / page is consistent with that brand's normal
     product (e.g. e-commerce listing, article, official login page).
   - AND no DANGEROUS or SUSPICIOUS triggers apply.

5) BRAND-MATCH RULE (CRITICAL):
   The presence of a brand name in the BODY does NOT make a URL safe.
   Brand-mention only counts as positive evidence if the registered_domain
   matches that brand's known domain. A login page that says "PayPal" on
   `paypal-secure.xyz` is phishing, not PayPal.

6) UNKNOWN — use when the probe failed or data is insufficient and the
   domain is not recognizable. If the host is a well-known brand or major
   platform and only the body sample is missing, still judge "safe" when
   nothing else looks wrong. Reserve "suspicious" for concrete reasons, not
   for missing optional data alone on reputable sites.

Output format — ONLY a single JSON object, no markdown, no commentary:

{
  "risk_level": "safe" | "suspicious" | "dangerous",
  "risk_score": <float 0.0-1.0; safe < 0.20, suspicious in [0.20, 0.60),
                  dangerous >= 0.60>,
  "threat_type": "phishing" | "malware" | "scam" | "suspicious" | "clean",
  "explanation": "<1-2 sentences in the language of the page (Polish if
                  context_text or body_sample is Polish, otherwise English),
                  written for a non-technical user, naming the specific
                  reason — e.g. 'Domena zarejestrowana 3 dni temu i prosi
                  o dane karty.'>",
  "threats": [
    {"code": "<SHORT_UPPER_CODE>", "description": "<short>", "severity": "low|medium|high|critical"}
  ]
}

The "threats" list should contain only ACTUAL threats you identified, not
the raw url_shape_indicators. If verdict is safe, return [].
"""


async def _ai_verdict(evidence: Dict[str, Any]) -> Dict[str, Any]:
    user_msg = (
        "Analyze this URL and return JSON only.\n\n"
        "EVIDENCE PACK:\n"
        + json.dumps(evidence, ensure_ascii=False, default=str, indent=2)
    )

    semaphore = _get_semaphore()

    async def _call(model: str) -> Dict[str, Any]:
        last_exc: Optional[BaseException] = None
        for attempt in range(2):
            try:
                async with semaphore:
                    loop = asyncio.get_event_loop()
                    response = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda m=model: _get_client().chat.completions.create(
                                model=m,
                                max_tokens=500,
                                temperature=0.1,
                                response_format={"type": "json_object"},
                                messages=[
                                    {"role": "system", "content": _AI_SYSTEM_PROMPT},
                                    {"role": "user", "content": user_msg},
                                ],
                            ),
                        ),
                        timeout=AI_TIMEOUT_SECONDS,
                    )
                text = (response.choices[0].message.content or "").strip()
                return _parse_ai_json(text)
            except asyncio.TimeoutError:
                if attempt == 0:
                    await asyncio.sleep(0.75)
                    continue
                raise
            except Exception:
                raise
        raise RuntimeError("Groq call retry exhausted")

    try:
        verdict = await _call(_fast_model())

        level = str(verdict.get("risk_level", "")).lower()
        score = _coerce_score(verdict.get("risk_score"))
        threats = verdict.get("threats") or []
        is_confidently_safe = (
            level == "safe" and score <= 0.32 and not threats
        )
        well_known = _is_well_known_domain(evidence)
        fast_safe_enough_for_trusted = (
            well_known
            and not _has_hard_red_flags_evidence(evidence)
            and level == "safe"
            and score <= 0.40
            and not threats
        )
        if fast_safe_enough_for_trusted:
            return verdict
        if is_confidently_safe and well_known:
            return verdict

        if _fast_model() == _deep_model():
            return verdict

        try:
            deep_verdict = await _call(_deep_model())
            return deep_verdict
        except Exception:
            return verdict

    except Exception as e:
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

        threat_sev = "medium" if level == "dangerous" else "low"
        return {
            "risk_level": level,
            "risk_score": score,
            "threat_type": "unknown",
            "explanation": (
                f"AI analysis unavailable ({type(e).__name__}). "
                + (
                    "Well-known host — low concern pending a retry."
                    if well_known and level == "unknown"
                    else "Heuristic-only assessment — verify if unsure."
                )
            ),
            "threats": [{
                "code": "AI_UNAVAILABLE",
                "description": "Real-time AI verdict could not be obtained; using light URL heuristics only.",
                "severity": threat_sev,
            }],
        }


def _parse_ai_json(text: str) -> Dict[str, Any]:
    if not text:
        return {"risk_level": "unknown", "risk_score": 0.0,
                "threat_type": "unknown",
                "explanation": "Empty AI response.", "threats": []}

    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m:
        cleaned = m.group(0)

    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            raise ValueError("Top-level JSON is not an object")
        data.setdefault("risk_level", "unknown")
        data.setdefault("risk_score", 0.0)
        data.setdefault("threat_type", "unknown")
        data.setdefault("explanation", "")
        data.setdefault("threats", [])
        return data
    except Exception as e:
        return {
            "risk_level": "unknown",
            "risk_score": 0.0,
            "threat_type": "unknown",
            "explanation": f"Could not parse AI response: {e}",
            "threats": [],
        }



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
