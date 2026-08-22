from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SafetyLog
from app.pipeline.ML_models import evaluate_harm_and_emotion
from app.pipeline.pii_detector import detect_pii
from app.pipeline.risk_calculator import calculate_risk_score
from app.pipeline.llm_connector import query_external_llm

# 👉 CRITICAL: This line must be present so app.main can import chat.router
router = APIRouter(prefix="/api/v1", tags=["Safety Chat"])


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500, description="The message from the child user")
    age_group: str = Field(default="pre_teen", description="Child age category: young_child, pre_teen, teen")


@router.post("/chat", status_code=status.HTTP_200_OK)
def process_chat_message(request: ChatRequest, db: Session = Depends(get_db)):
    try:
        user_message = request.message.strip()
        if not user_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message cannot be empty or whitespace only."
            )

        # 1. Evaluate Harm & Emotion
        ml_analysis = evaluate_harm_and_emotion(user_message)
        harm_score = ml_analysis["harm_score"]
        emotion = ml_analysis["emotion"]

        # 2. PII Detection
        pii_results = detect_pii(user_message)
        pii_detected = len(pii_results) > 0
        pii_summary = ", ".join([p["type"] for p in pii_results]) if pii_detected else None

        # 3. Calculate Risk Score & Decision
        safety_evaluation = calculate_risk_score(
            harm_score=harm_score,
            pii_detected=pii_detected,
            age_category=request.age_group
        )

        risk_score = safety_evaluation["risk_score"]
        decision = safety_evaluation["decision"]

        ai_response_text = None
        warning_msg = None

        # 4. Decision Engine Execution
        if decision == "BLOCK":
            ai_response_text = "Safety Alert: This message violates our child safety guidelines and cannot be processed."
        else:
            ai_response_text = query_external_llm(user_message, provider="openai")
            if decision == "WARN":
                warning_msg = "Warning: Please be careful sharing sensitive information!"

        # 5. Save Log to MySQL Database safely
        try:
            db_log = SafetyLog(
                child_message=user_message,
                ai_response=ai_response_text,
                age_group=request.age_group,
                emotion=emotion,
                risk_score=risk_score,
                decision=decision,
                pii_detected=pii_summary
            )
            db.add(db_log)
            db.commit()
            db.refresh(db_log)
        except Exception as db_error:
            db.rollback()
            print(f"⚠️ MySQL Logging Warning (Non-Fatal): {db_error}")

        # 6. Return response to React frontend
        return {
            "status": decision if decision != "BLOCK" else "BLOCKED",
            "risk_score": risk_score,
            "emotion": emotion,
            "pii_details": pii_results,
            "response": ai_response_text,
            "warning": warning_msg
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Safety Engine Internal Error: {str(e)}"
        )