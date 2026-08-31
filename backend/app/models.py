from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from app.database import Base


class SafetyLog(Base):
    __tablename__ = "safety_logs"

    id = Column(Integer, primary_key=True, index=True)

    # User's original message
    child_message = Column(Text, nullable=False)

    # AI-generated response
    ai_response = Column(Text, nullable=True)

    # Age category used by the safety engine
    age_group = Column(
        String(50),
        nullable=False,
        default="pre_teen"
    )

    # Emotion detected by ML model
    emotion = Column(
        String(50),
        nullable=True
    )

    # Final calculated safety risk
    risk_score = Column(
        Float,
        nullable=False,
        default=0.0
    )

    # Final safety decision: ALLOW / WARN / BLOCK
    decision = Column(
        String(20),
        nullable=False
    )

    # PII types detected
    # Example: "email, phone"
    pii_detected = Column(
        String(255),
        nullable=True
    )

    # Time of the safety event
    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )