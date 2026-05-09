from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


class LinkAnalysisRequest(BaseModel):
    url: str
    context_text: Optional[str] = None
    page_url: Optional[str] = None
    element_type: Optional[str] = "a"


class BatchAnalysisRequest(BaseModel):
    links: List[LinkAnalysisRequest]
    page_language: Optional[str] = "en"


class RedirectChain(BaseModel):
    hops: List[str]
    final_url: str
    redirect_count: int


class DomainInfo(BaseModel):
    domain: str
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    country: Optional[str] = None
    is_new: bool = False
    is_very_new: bool = False


class ThreatIndicator(BaseModel):
    code: str
    description: str
    severity: str


class SandboxTimelineEvent(BaseModel):
    time: float
    event: str


class SandboxAssessment(BaseModel):
    verdict: str
    duration_seconds: float
    events_detected: List[SandboxTimelineEvent]
    assessed_risk_level: Optional[str] = None


class LinkAnalysisResult(BaseModel):
    url: str
    risk_level: RiskLevel
    risk_score: float
    is_safe: bool
    indicators: List[ThreatIndicator]
    redirect_chain: Optional[RedirectChain] = None
    domain_info: Optional[DomainInfo] = None
    ai_assessment: Optional[str] = None
    file_download: Optional[str] = None
    sandbox_video_url: Optional[str] = None
    sandbox_assessment: Optional[SandboxAssessment] = None


class BatchAnalysisResult(BaseModel):
    results: List[LinkAnalysisResult]
    analyzed_count: int
    dangerous_count: int
    suspicious_count: int
