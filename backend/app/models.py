from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from datetime import datetime
from app.database import Base

class SafetyLog(Base):
    __tablename__ = "safety_logs"
    __table_args__ = {'extend_existing': True}  # 👈 Fixes the table re-definition error

    id = Column(Integer, primary_key=True, index=True)
    child_message = Column(Text, nullable=False)
    ai_response = Column(Text, nullable=True)
    age_group = Column(String(50), default="pre_teen")
    emotion = Column(String(50), nullable=True)
    risk_score = Column(Float, nullable=False)
    decision = Column(String(20), nullable=False) # ALLOW, WARN, BLOCK
    pii_detected = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)