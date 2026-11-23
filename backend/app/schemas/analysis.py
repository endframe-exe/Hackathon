from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze for phishing threats", min_length=3)


class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., description="Raw text of email, SMS, or message content", min_length=5)
    sender: Optional[str] = Field(None, description="Optional sender email address or phone number")
    subject: Optional[str] = Field(None, description="Optional email subject line")


class Indicator(BaseModel):
    type: str = Field(..., description="Category: LEXICAL, IDENTITY, BEHAVIOR, or THREAT_INTEL")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    title: str = Field(..., description="Short descriptive title of the indicator")
    description: str = Field(..., description="Detailed explanation of the risk signal")
    source: str = Field(..., description="Source of indicator: LOCAL_HEURISTICS or VIRUSTOTAL_API_V3")


class LexicalDNA(BaseModel):
    url_length: int = 0
    domain_length: int = 0
    subdomain_count: int = 0
    hyphen_count: int = 0
    has_ip_address: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    entropy: float = 0.0


class IdentityDNA(BaseModel):
    targeted_brand: Optional[str] = None
    has_homoglyphs: bool = False
    registered_domain: str = ""
    is_brand_impersonation: bool = False


class BehaviorDNA(BaseModel):
    urgency_detected: bool = False
    authority_pressure: bool = False
    credential_intent: bool = False
    financial_threat: bool = False
    call_to_action: bool = False


class ThreatIntelDNA(BaseModel):
    service: str = "VIRUSTOTAL_API_V3"
    status: str = "unconfigured"  # unconfigured | rate_limited | error | clean | suspicious | malicious
    malicious_engines: int = 0
    suspicious_engines: int = 0
    harmless_engines: int = 0
    total_engines: int = 0
    source_attribution: str = "External Third-Party Evidence"


class PhishingDNA(BaseModel):
    lexical: Optional[LexicalDNA] = None
    identity: Optional[IdentityDNA] = None
    behavior: Optional[BehaviorDNA] = None
    threat_intel: Optional[ThreatIntelDNA] = None


class AnalysisResponse(BaseModel):
    analysis_id: str
    input_type: str  # "url" | "message"
    target_analyzed: str
    risk_level: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    risk_score: float  # 0.0 - 100.0
    verdict: str
    phishing_dna: PhishingDNA
    indicators: List[Indicator] = []
    evidence: Dict[str, Any] = {}
    recommendations: List[str] = []
    limitations: List[str] = []
    safety_disclaimer: str
    created_at: str


class HistoryRecordResponse(BaseModel):
    id: Optional[int] = None
    analysis_id: str
    input_type: str
    risk_level: str
    risk_score: float
    verdict: str
    target_summary: Optional[str] = None
    indicators: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    limitations: List[str] = []
    created_at: Optional[str] = None


class HistoryListResponse(BaseModel):
    total: int
    items: List[HistoryRecordResponse]
