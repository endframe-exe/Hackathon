import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.config import settings
from app.core.database import get_db, is_db_connected
from app.models.analysis import AnalysisRecord
from app.schemas.analysis import (
    URLAnalysisRequest,
    MessageAnalysisRequest,
    AnalysisResponse,
    HistoryListResponse,
    HistoryRecordResponse
)
from app.services.phishing_dna import analyze_url, analyze_message

logger = logging.getLogger("phishguard.api")
router = APIRouter()


@router.get("/health")
def api_health():
    """
    Health check endpoint (FR-01, FR-04).
    Reports service status, database connectivity, and threat intelligence readiness.
    """
    vt_key = settings.VIRUSTOTAL_API_KEY.strip() if settings.VIRUSTOTAL_API_KEY else ""
    vt_configured = bool(vt_key and vt_key != "your_vt_api_key_here")

    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": {
            "history_enabled": settings.ENABLE_HISTORY,
            "connected": is_db_connected
        },
        "threat_intelligence": {
            "provider": "VirusTotal API v3",
            "configured": vt_configured
        }
    }


@router.post("/analyze/url", response_model=AnalysisResponse)
async def analyze_url_endpoint(
    payload: URLAnalysisRequest,
    db: Optional[Session] = Depends(get_db)
):
    """
    Analyzes a URL for phishing characteristics using Phishing DNA heuristics
    and VirusTotal API v3 external threat intelligence (FR-01).
    """
    return await analyze_url(url=payload.url, db=db)


@router.post("/analyze/message", response_model=AnalysisResponse)
async def analyze_message_endpoint(
    payload: MessageAnalysisRequest,
    db: Optional[Session] = Depends(get_db)
):
    """
    Analyzes message/email content for social engineering, urgency manipulation,
    authority impersonation, and embedded malicious links (FR-02).
    """
    return await analyze_message(
        message=payload.message,
        sender=payload.sender,
        subject=payload.subject,
        db=db
    )


@router.get("/history", response_model=HistoryListResponse)
def get_analysis_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Optional[Session] = Depends(get_db)
):
    """
    Retrieves previously recorded Phishing DNA analysis records (FR-04).
    PRIVACY GUARANTEE: Never exposes raw message text or sensitive credentials.
    Fails gracefully returning an empty list if MySQL is unavailable.
    """
    if not settings.ENABLE_HISTORY or db is None:
        return HistoryListResponse(total=0, items=[])

    try:
        total = db.query(AnalysisRecord).count()
        records = (
            db.query(AnalysisRecord)
            .order_by(desc(AnalysisRecord.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return HistoryListResponse(
            total=total,
            items=[HistoryRecordResponse(**r.to_dict()) for r in records]
        )
    except Exception as e:
        logger.warning("Could not fetch analysis history: %s", str(e))
        return HistoryListResponse(total=0, items=[])
