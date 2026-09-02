from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SafetyLog

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/metrics")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_interactions = db.query(SafetyLog).count()
    warnings_count = db.query(SafetyLog).filter(SafetyLog.decision == "WARN").count()
    blocked_count = db.query(SafetyLog).filter(SafetyLog.decision == "BLOCK").count()

    recent_alerts = (
        db.query(SafetyLog)
        .filter(SafetyLog.decision.in_(["WARN", "BLOCK"]))
        .order_by(SafetyLog.id.desc())
        .limit(5)
        .all()
    )

    formatted_alerts = [
        {
            "id": alert.id,
            "timestamp": alert.timestamp.strftime("%H:%M:%S"),
            "child_input": alert.child_message,
            "detected_emotion": alert.emotion or "neutral",
            "safety_status": alert.decision,
            "risk_score": alert.risk_score
        }
        for alert in recent_alerts
    ]

    return {
        "total_interactions": total_interactions,
        "warnings_count": warnings_count,
        "blocked_count": blocked_count,
        "recent_alerts": formatted_alerts
    }