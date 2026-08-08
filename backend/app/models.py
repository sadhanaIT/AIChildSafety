from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from datetime import datetime
from app.database import Base


class SafetyLog(Base):
    __tablename__ = "safety_logs"

    id = Column(Integer, primary_key=True, index=True)
    child_id = Column(String(50), nullable=False)
    original_input = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    decision = Column(String(20), nullable=False)  # ALLOW, WARN, BLOCK
    pii_detected = Column(Text, nullable=True)
    detected_emotion = Column(String(50), nullable=True)
    llm_response = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)