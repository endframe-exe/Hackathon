import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis import AnalysisRecord
from app.schemas.analysis import (
    AnalysisResponse,
    PhishingDNA,
    ThreatIntelDNA,
    Indicator
)
from app.services.url_analyzer import analyze_url_heuristics
from app.services.message_analyzer import analyze_message_heuristics
from app.services.threat_intelligence import query_virustotal_url
from app.services.risk_engine import calculate_risk, SAFETY_DISCLAIMER

logger = logging.getLogger("phishguard.phishing_dna")


def persist_analysis_record(
    db: Optional[Session],
    analysis_id: str,
    input_type: str,
    risk_level: str,
    risk_score: float,
    verdict: str,
    target_summary: str,
    indicators: list,
    recommendations: list,
    limitations: list
) -> None:
    """
    Safely writes the analysis record to MySQL via SQLAlchemy (FR-04).
    PRIVACY GUARANTEE: Never stores raw message content, passwords, or secrets.
    Fails gracefully if the database session is None or unreachable.
    """
    if not settings.ENABLE_HISTORY or db is None:
        return

    try:
        record = AnalysisRecord(
            analysis_id=analysis_id,
            input_type=input_type,
            risk_level=risk_level,
            risk_score=risk_score,
            verdict=verdict,
            target_summary=target_summary[:255] if target_summary else "N/A",
            indicators_json=json.dumps(indicators),
            recommendations_json=json.dumps(recommendations),
            limitations_json=json.dumps(limitations)
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.warning("Could not persist analysis record %s to database: %s", analysis_id, str(e))
        db.rollback()


async def analyze_url(url: str, db: Optional[Session] = None) -> AnalysisResponse:
    """
    Executes the full URL Phishing DNA analysis pipeline:
    1. Local lexical, identity, and structural heuristics.
    2. External VirusTotal API v3 threat intelligence.
    3. Multi-factor risk scoring and verdict generation.
    4. Database persistence (metadata only).
    """
    analysis_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    # Step 1: Local URL Heuristics
    url_data = analyze_url_heuristics(url)
    indicators = list(url_data["indicators"])
    limitations = list(url_data["limitations"])
    evidence = dict(url_data["evidence"])

    # Step 2: VirusTotal API v3 Threat Intelligence (FR-01)
    vt_result = await query_virustotal_url(url)
    for ind in vt_result.indicators:
        indicators.append(ind)
    for lim in vt_result.limitations:
        limitations.append(lim)

    threat_intel_dna = ThreatIntelDNA(
        service="VIRUSTOTAL_API_V3",
        status=vt_result.status,
        malicious_engines=vt_result.malicious_count,
        suspicious_engines=vt_result.suspicious_count,
        harmless_engines=vt_result.harmless_count,
        total_engines=vt_result.total_engines
    )

    evidence["virustotal"] = {
        "status": vt_result.status,
        "malicious": vt_result.malicious_count,
        "suspicious": vt_result.suspicious_count,
        "total_engines": vt_result.total_engines,
        "reputation": vt_result.reputation
    }

    # Step 3: Risk Engine Calculation
    risk_score, risk_level, verdict, recommendations = calculate_risk(indicators, input_type="url")

    # Target summary: domain only (privacy preservation)
    target_summary = url_data.get("registered_domain") or url_data.get("host") or url[:64]

    # Step 4: Persist Record
    persist_analysis_record(
        db=db,
        analysis_id=analysis_id,
        input_type="url",
        risk_level=risk_level,
        risk_score=risk_score,
        verdict=verdict,
        target_summary=target_summary,
        indicators=indicators,
        recommendations=recommendations,
        limitations=limitations
    )

    phishing_dna = PhishingDNA(
        lexical=url_data["lexical_dna"],
        identity=url_data["identity_dna"],
        behavior=None,
        threat_intel=threat_intel_dna
    )

    pydantic_indicators = [
        Indicator(
            type=ind["type"],
            severity=ind["severity"],
            title=ind["title"],
            description=ind["description"],
            source=ind["source"]
        )
        for ind in indicators
    ]

    return AnalysisResponse(
        analysis_id=analysis_id,
        input_type="url",
        target_analyzed=target_summary,
        risk_level=risk_level,
        risk_score=risk_score,
        verdict=verdict,
        phishing_dna=phishing_dna,
        indicators=pydantic_indicators,
        evidence=evidence,
        recommendations=recommendations,
        limitations=limitations,
        safety_disclaimer=SAFETY_DISCLAIMER,
        created_at=created_at
    )


async def analyze_message(
    message: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    db: Optional[Session] = None
) -> AnalysisResponse:
    """
    Executes the full Message / Email Phishing DNA analysis pipeline:
    1. Social engineering, urgency, credential harvesting, authority heuristics.
    2. Extraction and heuristic analysis of embedded URLs.
    3. External VirusTotal API v3 query on embedded links.
    4. Multi-factor risk scoring and verdict generation.
    5. Database persistence (metadata only, NEVER raw message text).
    """
    analysis_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    # Step 1: Local Message Heuristics
    msg_data = analyze_message_heuristics(message, sender=sender, subject=subject)
    indicators = list(msg_data["indicators"])
    limitations = list(msg_data["limitations"])
    evidence = dict(msg_data["evidence"])

    # Step 2: VirusTotal scan on primary extracted URL if present
    extracted_urls = msg_data.get("extracted_urls", [])
    threat_intel_dna = ThreatIntelDNA(service="VIRUSTOTAL_API_V3", status="unconfigured")

    if extracted_urls:
        primary_url = extracted_urls[0]
        vt_result = await query_virustotal_url(primary_url)
        for ind in vt_result.indicators:
            indicators.append(ind)
        for lim in vt_result.limitations:
            limitations.append(lim)

        threat_intel_dna = ThreatIntelDNA(
            service="VIRUSTOTAL_API_V3",
            status=vt_result.status,
            malicious_engines=vt_result.malicious_count,
            suspicious_engines=vt_result.suspicious_count,
            harmless_engines=vt_result.harmless_count,
            total_engines=vt_result.total_engines
        )
        evidence["virustotal"] = {
            "scanned_url": primary_url,
            "status": vt_result.status,
            "malicious": vt_result.malicious_count,
            "suspicious": vt_result.suspicious_count,
            "total_engines": vt_result.total_engines
        }
    else:
        limitations.append(
            "External threat intelligence (VirusTotal API v3) was skipped: no extractable URLs found in message."
        )

    # Step 3: Risk Engine Calculation
    risk_score, risk_level, verdict, recommendations = calculate_risk(indicators, input_type="message")

    # Target summary (Privacy: never raw message)
    target_summary = (
        f"Subject: {subject[:40]} | Sender: {sender[:30]}" if (subject and sender)
        else (f"Subject: {subject[:50]}" if subject
        else (f"Sender: {sender[:50]}" if sender
        else f"Message snippet ({len(message)} chars)"))
    )

    # Step 4: Persist Record
    persist_analysis_record(
        db=db,
        analysis_id=analysis_id,
        input_type="message",
        risk_level=risk_level,
        risk_score=risk_score,
        verdict=verdict,
        target_summary=target_summary,
        indicators=indicators,
        recommendations=recommendations,
        limitations=limitations
    )

    phishing_dna = PhishingDNA(
        lexical=None,
        identity=None,
        behavior=msg_data["behavior_dna"],
        threat_intel=threat_intel_dna
    )

    pydantic_indicators = [
        Indicator(
            type=ind["type"],
            severity=ind["severity"],
            title=ind["title"],
            description=ind["description"],
            source=ind["source"]
        )
        for ind in indicators
    ]

    return AnalysisResponse(
        analysis_id=analysis_id,
        input_type="message",
        target_analyzed=target_summary,
        risk_level=risk_level,
        risk_score=risk_score,
        verdict=verdict,
        phishing_dna=phishing_dna,
        indicators=pydantic_indicators,
        evidence=evidence,
        recommendations=recommendations,
        limitations=limitations,
        safety_disclaimer=SAFETY_DISCLAIMER,
        created_at=created_at
    )
