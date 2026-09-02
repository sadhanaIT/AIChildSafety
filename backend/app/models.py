from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean
from app.database import Base

class SafetyLog(Base):
    __tablename__ = "safety_logs"
    __table_args__ = {'extend_existing': True}

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


class CustomRule(Base):
    __tablename__ = "custom_rules"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)

    # Custom restricted keyword or phrase defined by the parent
    keyword = Column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )


class ParentProfile(Base):
    __tablename__ = "parent_profile"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    profile_name = Column(String(255), default="Child Companion Profile")
    sensitivity = Column(String(100), default="High (Strict PII & Toxicity Block)")
    notifications_enabled = Column(Boolean, default=True)