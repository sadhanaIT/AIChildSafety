from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Form
from typing import Optional
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SafetyLog
from app.pipeline.ML_models import evaluate_harm_and_emotion
from app.pipeline.pii_detector import detect_pii
from app.pipeline.risk_calculator import calculate_risk_score
from app.pipeline.image_analyzer import analyze_image_risk
from app.pipeline.llm_connector import query_external_llm

router = APIRouter(prefix="/api/v1", tags=["Safety Chat"])


@router.post("/chat", status_code=status.HTTP_200_OK)
async def process_chat_message(
        message: str = Form(default=""),
        age_group: str = Form(default="pre_teen"),
        file: Optional[UploadFile] = File(None),
        db: Session = Depends(get_db)
):
    try:
        user_message = message.strip()
        image_risk = 0.0
        image_tags_str = None

        # 1. Handle Image Risk Calculation if file is uploaded
        if file:
            file_bytes = await file.read()
            image_analysis = analyze_image_risk(file_bytes)
            image_risk = image_analysis["image_risk_score"]
            image_tags_str = ", ".join(image_analysis["image_tags"])

        # 2. Text ML Analysis (Harm & Emotion)
        ml_analysis = evaluate_harm_and_emotion(user_message if user_message else "Shared an image")
        harm_score = max(ml_analysis["harm_score"], image_risk)  # Combine text and image risk
        emotion = ml_analysis["emotion"]

        # 3. PII Detection
        pii_results = detect_pii(user_message) if user_message else []
        pii_detected = len(pii_results) > 0
        pii_summary = ", ".join([p["type"] for p in pii_results]) if pii_detected else None

        # 4. Calculate Risk Score & Decision
        safety_evaluation = calculate_risk_score(
            harm_score=harm_score,
            pii_detected=pii_detected,
            age_category=age_group
        )

        risk_score = safety_evaluation["risk_score"]
        decision = safety_evaluation["decision"]

        ai_response_text = None
        warning_msg = None

        # 5. Decision Engine
        if decision == "BLOCK":
            ai_response_text = "Safety Alert: This content violates our safety guidelines and cannot be processed."
        else:
            prompt_text = user_message if user_message else "Child uploaded an image."
            ai_response_text = query_external_llm(prompt_text, provider="openai")
            if decision == "WARN":
                warning_msg = "Warning: Please be careful sharing sensitive information or images!"

        # 6. Save Log to MySQL Database safely
        try:
            db_log = SafetyLog(
                child_message=user_message if user_message else "[Image Upload]",
                ai_response=ai_response_text,
                age_group=age_group,
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
            print(f"⚠️ MySQL Logging Warning: {db_error}")

        return {
            "status": decision if decision != "BLOCK" else "BLOCKED",
            "risk_score": risk_score,
            "emotion": emotion,
            "pii_details": pii_results,
            "response": ai_response_text,
            "warning": warning_msg,
            "image_risk": image_risk
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")