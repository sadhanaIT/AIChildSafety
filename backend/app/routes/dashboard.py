from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SafetyLog

router = APIRouter(prefix="/api/v1/dashboard", tags=["Parent Dashboard"])


@router.get("/logs", status_code=status.HTTP_200_OK)
def get_safety_logs(db: Session = Depends(get_db)):
    try:
        logs = db.query(SafetyLog).order_by(SafetyLog.timestamp.desc()).all()

        # Calculate summary metrics for the parent dashboard
        total_messages = len(logs)
        blocked_count = sum(1 for log in logs if log.decision == "BLOCK")
        warning_count = sum(1 for log in logs if log.decision == "WARN")
        avg_risk = sum(log.risk_score for log in logs) / total_messages if total_messages > 0 else 0.0

        formatted_logs = [
            {
                "id": log.id,
                "timestamp": str(log.timestamp),
                "child_message": log.child_message,
                "ai_response": log.ai_response,
                "age_group": log.age_group,
                "emotion": log.emotion,
                "risk_score": log.risk_score,
                "decision": log.decision,
                "pii_detected": log.pii_detected
            }
            for log in logs
        ]

        return {
            "metrics": {
                "total_messages": total_messages,
                "blocked_count": blocked_count,
                "warning_count": warning_count,
                "average_risk_score": round(avg_risk, 2)
            },
            "logs": formatted_logs
        }
    except Exception as e:
        return {"error": str(e), "logs": [], "metrics": {}}