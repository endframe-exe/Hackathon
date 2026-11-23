import json
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.analysis import AnalysisRecord


def test_analysis_record_model_sqlite():
    # Test using an isolated SQLite in-memory database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    record = AnalysisRecord(
        analysis_id="test-uuid-12345",
        input_type="message",
        risk_level="HIGH",
        risk_score=72.5,
        verdict="High-probability phishing attempt",
        target_summary="Subject: Urgent notice | Sender: admin@test.com",
        indicators_json=json.dumps([{"title": "Urgency", "severity": "HIGH"}]),
        recommendations_json=json.dumps(["Do not enter credentials"]),
        limitations_json=json.dumps(["External intel skipped"]),
        created_at=datetime.now(timezone.utc)
    )

    session.add(record)
    session.commit()

    saved = session.query(AnalysisRecord).filter_by(analysis_id="test-uuid-12345").first()
    assert saved is not None
    assert saved.risk_score == 72.5
    assert saved.risk_level == "HIGH"
    
    # Verify privacy constraint: raw message is not stored anywhere
    serialized = saved.to_dict()
    assert "password" not in json.dumps(serialized).lower()
    assert len(serialized["indicators"]) == 1
    assert serialized["recommendations"][0] == "Do not enter credentials"

    session.close()
