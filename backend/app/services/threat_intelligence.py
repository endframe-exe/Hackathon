import base64
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings

logger = logging.getLogger("phishguard.threat_intel")


@dataclass
class ThreatIntelResult:
    has_intel: bool = False
    service: str = "VIRUSTOTAL_API_V3"
    status: str = "unconfigured"  # unconfigured | rate_limited | error | clean | suspicious | malicious
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    reputation: int = 0
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    raw_stats: Dict[str, int] = field(default_factory=dict)


def encode_url_for_vt(url: str) -> str:
    """
    Encodes URL according to VirusTotal API v3 specification:
    Base64 URL-safe encoding without '=' padding.
    """
    return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("utf-8").strip("=")


async def query_virustotal_url(
    url: str,
    client: Optional[httpx.AsyncClient] = None
) -> ThreatIntelResult:
    """
    Queries VirusTotal API v3 for external URL threat intelligence (FR-01, Section 9).
    
    Robustness guarantees:
    - If API key is missing or default placeholder, gracefully returns unconfigured status
      with a limitation note without raising errors or treating lack of intel as safe.
    - If rate limited (HTTP 429), records rate limit limitation.
    - If URL is not found (HTTP 404), notes that novel targets may not be indexed.
    - If network error occurs, notes service unreachability.
    - Findings are explicitly labeled as third-party external evidence.
    """
    result = ThreatIntelResult()
    api_key = settings.VIRUSTOTAL_API_KEY.strip() if settings.VIRUSTOTAL_API_KEY else ""

    # 1. Check for missing or placeholder API Key
    if not api_key or api_key == "your_vt_api_key_here":
        result.status = "unconfigured"
        result.limitations.append(
            "External threat intelligence (VirusTotal API v3): API key is unconfigured. "
            "External multi-engine reputation checks were skipped. Local heuristic and lexical analysis used."
        )
        return result

    url_id = encode_url_for_vt(url)
    endpoint = f"{settings.VIRUSTOTAL_BASE_URL.rstrip('/')}/urls/{url_id}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "PhishGuard-AI/1.0"
    }

    should_close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=settings.VIRUSTOTAL_TIMEOUT_SECONDS)
        should_close_client = True

    try:
        response = await client.get(endpoint, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            
            result.has_intel = True
            result.malicious_count = malicious
            result.suspicious_count = suspicious
            result.harmless_count = harmless
            result.undetected_count = undetected
            result.total_engines = total
            result.reputation = attributes.get("reputation", 0)
            result.raw_stats = stats

            if malicious > 0 or suspicious > 0:
                result.status = "malicious" if malicious >= 2 else "suspicious"
                severity = "CRITICAL" if malicious >= 3 else ("HIGH" if malicious >= 1 else "MEDIUM")
                result.indicators.append({
                    "type": "THREAT_INTEL",
                    "severity": severity,
                    "title": f"VirusTotal Detection: {malicious} vendor(s) flagged malicious",
                    "description": (
                        f"External third-party threat intelligence (VirusTotal v3) reports {malicious} engine(s) "
                        f"classified this target as malicious and {suspicious} as suspicious out of {total} engines."
                    ),
                    "source": "VIRUSTOTAL_API_V3"
                })
            else:
                result.status = "clean"
                result.indicators.append({
                    "type": "THREAT_INTEL",
                    "severity": "INFO",
                    "title": "VirusTotal Telemetry: 0 vendor detections",
                    "description": (
                        f"External third-party scan (VirusTotal v3) shows 0 flags across {total} security vendors. "
                        "Note: Absence of vendor detections does NOT guarantee safety for zero-day phishing campaigns."
                    ),
                    "source": "VIRUSTOTAL_API_V3"
                })
                result.limitations.append(
                    "Third-party threat intelligence (VirusTotal v3) shows no historical flags; "
                    "novel phishing sites frequently evade multi-engine blacklists during early deployment."
                )

        elif response.status_code == 404:
            result.status = "clean"
            result.limitations.append(
                "External threat intelligence (VirusTotal API v3): URL has not been indexed or scanned previously. "
                "Absence of external telemetry is not proof of safety."
            )

        elif response.status_code == 429:
            result.status = "rate_limited"
            result.limitations.append(
                "External threat intelligence (VirusTotal API v3): API rate limit or quota exceeded (HTTP 429). "
                "External scan data was unavailable; analysis proceeded with local heuristics."
            )

        elif response.status_code in (401, 403):
            result.status = "error"
            result.limitations.append(
                f"External threat intelligence (VirusTotal API v3): Authentication failed (HTTP {response.status_code}). "
                "Please verify your VIRUSTOTAL_API_KEY."
            )

        else:
            result.status = "error"
            result.limitations.append(
                f"External threat intelligence (VirusTotal API v3) returned unexpected HTTP status {response.status_code}."
            )

    except httpx.TimeoutException:
        result.status = "error"
        result.limitations.append(
            "External threat intelligence (VirusTotal API v3) request timed out. Proceeded with local heuristics."
        )
    except Exception as exc:
        result.status = "error"
        logger.warning("VirusTotal API query failed: %s", str(exc))
        result.limitations.append(
            f"External threat intelligence (VirusTotal API v3) connection failed: {type(exc).__name__}. "
            "Proceeded with local heuristics."
        )
    finally:
        if should_close_client:
            await client.aclose()

    return result
