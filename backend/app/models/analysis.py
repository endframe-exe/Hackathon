from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from app.core.database import Base


class AnalysisRecord(Base):
    """
    Analysis Record ORM Model (FR-04).
    Stores Phishing DNA report metadata, scores, and indicators.
    PRIVACY GUARANTEE: Never stores raw message content, credentials, or secrets.
    """
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    analysis_id = Column(String(64), unique=True, index=True, nullable=False)
    input_type = Column(String(32), index=True, nullable=False)  # 'url' | 'message'
    risk_level = Column(String(32), index=True, nullable=False)  # 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    risk_score = Column(Float, nullable=False)
    verdict = Column(String(255), nullable=False)
    target_summary = Column(String(255), nullable=True)  # Domain or sanitized summary only
    indicators_json = Column(Text, nullable=False, default="[]")
    recommendations_json = Column(Text, nullable=False, default="[]")
    limitations_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "input_type": self.input_type,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "target_summary": self.target_summary,
            "indicators": json.loads(self.indicators_json) if self.indicators_json else [],
            "recommendations": json.loads(self.recommendations_json) if self.recommendations_json else [],
            "limitations": json.loads(self.limitations_json) if self.limitations_json else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
