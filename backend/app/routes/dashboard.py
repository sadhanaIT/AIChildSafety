# ============================================================
# AI CHILD SAFETY - DASHBOARD ROUTE
# ============================================================

from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SafetyLog


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


# ============================================================
# SAFE HELPERS
# ============================================================

def _safe_string(
    value: Any,
    default: str = "",
) -> str:
    """
    Convert a value safely to string.
    """

    if value is None:
        return default

    try:
        return str(value)

    except Exception:
        return default


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """
    Convert a value safely to float.
    """

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return default


def _format_timestamp(
    value: Any,
) -> str:
    """
    Format database timestamp for the dashboard.

    Existing frontend expects:
        HH:MM:SS
    """

    if value is None:
        return ""

    try:
        return value.strftime("%H:%M:%S")

    except Exception:
        return ""


# ============================================================
# DASHBOARD METRICS
# ============================================================

@router.get("/metrics")
def get_dashboard_metrics(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Return dashboard statistics and the five most recent
    WARN/BLOCK safety alerts.
    """

    # --------------------------------------------------------
    # Basic metrics
    # --------------------------------------------------------

    total_interactions = (
        db.query(SafetyLog)
        .count()
    )

    warnings_count = (
        db.query(SafetyLog)
        .filter(
            SafetyLog.decision == "WARN"
        )
        .count()
    )

    blocked_count = (
        db.query(SafetyLog)
        .filter(
            SafetyLog.decision == "BLOCK"
        )
        .count()
    )

    # --------------------------------------------------------
    # Recent safety alerts
    # --------------------------------------------------------

    recent_alerts = (
        db.query(SafetyLog)
        .filter(
            SafetyLog.decision.in_(
                ["WARN", "BLOCK"]
            )
        )
        .order_by(
            SafetyLog.id.desc()
        )
        .limit(5)
        .all()
    )

    # --------------------------------------------------------
    # Format alerts for frontend
    # --------------------------------------------------------

    formatted_alerts: List[Dict[str, Any]] = []

    for alert in recent_alerts:

        formatted_alerts.append({

            "id": getattr(
                alert,
                "id",
                None,
            ),

            "timestamp": _format_timestamp(
                getattr(
                    alert,
                    "timestamp",
                    None,
                )
            ),

            "child_input": _safe_string(
                getattr(
                    alert,
                    "child_message",
                    "",
                )
            ),

            "detected_emotion": _safe_string(
                getattr(
                    alert,
                    "emotion",
                    None,
                ),
                "neutral",
            ) or "neutral",

            "safety_status": _safe_string(
                getattr(
                    alert,
                    "decision",
                    "",
                ),
            ).upper(),

            "risk_score": _safe_float(
                getattr(
                    alert,
                    "risk_score",
                    0.0,
                )
            ),
        })

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {
        "total_interactions": total_interactions,
        "warnings_count": warnings_count,
        "blocked_count": blocked_count,
        "recent_alerts": formatted_alerts,
    }