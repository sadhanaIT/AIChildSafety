from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    status,
    UploadFile,
    File,
    Form,
)
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from app.database import get_db
from app.models import SafetyLog, CustomRule

from app.pipeline.ML_models import evaluate_harm_and_emotion
from app.pipeline.pii_detector import detect_pii
from app.pipeline.risk_calculator import calculate_risk_score
from app.pipeline.image_analyzer import analyze_image_risk
from app.pipeline.llm_connector import query_external_llm


router = APIRouter(
    prefix="/api/v1",
    tags=["Safety Chat"]
)


# ============================================================
# CHAT ENDPOINT
# ============================================================

@router.post(
    "/chat",
    status_code=status.HTTP_200_OK
)
async def process_chat_message(

    # --------------------------------------------------------
    # Current child message
    # --------------------------------------------------------

    message: str = Form(default=""),

    # --------------------------------------------------------
    # Age category
    # --------------------------------------------------------

    age_group: str = Form(default="pre_teen"),

    # --------------------------------------------------------
    # Previous conversation from React
    # --------------------------------------------------------

    conversation_context: str = Form(default=""),

    # --------------------------------------------------------
    # Optional image
    # --------------------------------------------------------

    file: Optional[UploadFile] = File(None),

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    db: Session = Depends(get_db),
):
    """
    Main KiddieSafe AI safety pipeline.
    """

    print("\n")
    print("=" * 60)
    print("NEW SAFETY CHAT REQUEST")
    print("=" * 60)

    try:

        # ====================================================
        # 1. CLEAN INPUT
        # ====================================================

        user_message = (message or "").strip()

        age_group = (
            age_group.strip()
            if age_group
            else "pre_teen"
        )

        conversation_context = (
            conversation_context.strip()
            if conversation_context
            else ""
        )

        print("Child ID: anonymous")
        print("Age Group:", age_group)
        print("Text Provided:", bool(user_message))
        print("Image Provided:", bool(file))

        # ====================================================
        # 1.5. CHECK CUSTOM BACKEND BLOCKED KEYWORDS
        # ====================================================

        if user_message:
            custom_rules = db.query(CustomRule).all()
            message_lower = user_message.lower()

            for rule in custom_rules:
                if rule.keyword and rule.keyword in message_lower:
                    print(f"\nContent BLOCKED by Custom Guardian Rule: '{rule.keyword}'")

                    ai_response_text = (
                        "This message has been blocked by your guardian's custom safety rules."
                    )
                    decision = "BLOCK"
                    risk_score = 1.0
                    warning_message = f"Triggered custom restricted term: '{rule.keyword}'"
                    emotion = "neutral"
                    pii_results = [{"type": f"Custom Filter: {rule.keyword}"}]
                    image_risk = 0.0
                    image_tags = []

                    # Database Logging for Custom Block
                    log_id = None
                    try:
                        db_log = SafetyLog(
                            child_message=user_message,
                            ai_response=ai_response_text,
                            age_group=age_group,
                            emotion=emotion,
                            risk_score=risk_score,
                            decision=decision,
                            pii_detected=f"Custom Rule Matched: {rule.keyword}",
                        )
                        db.add(db_log)
                        db.commit()
                        db.refresh(db_log)
                        log_id = db_log.id
                        print(f"Safety log saved successfully. ID: {db_log.id}")
                    except Exception as db_error:
                        db.rollback()
                        print("\nWARNING: Database logging failed:", db_error)

                    print("\nRequest completed.")
                    print("=" * 60)

                    return {
                        "status": "BLOCK",
                        "risk_score": round(risk_score, 3),
                        "emotion": emotion,
                        "pii_details": pii_results,
                        "response": ai_response_text,
                        "warning": warning_message,
                        "image_risk": round(image_risk, 3),
                        "image_tags": image_tags,
                        "log_id": log_id,
                    }

        # ====================================================
        # 2. IMAGE ANALYSIS
        # ====================================================

        image_risk = 0.0
        image_tags = []

        if file:

            print("\nRunning image safety analysis...")

            if not file.content_type:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid image file."
                )

            if not file.content_type.startswith("image/"):
                raise HTTPException(
                    status_code=400,
                    detail="Only image files are allowed."
                )

            file_bytes = await file.read()

            if not file_bytes:
                raise HTTPException(
                    status_code=400,
                    detail="Uploaded image is empty."
                )

            image_analysis = analyze_image_risk(file_bytes)

            image_risk = float(
                image_analysis.get(
                    "image_risk_score",
                    0.0
                )
            )

            image_tags = image_analysis.get("image_tags", [])

            print("Image Risk Score:", image_risk)
            print("Image Tags:", image_tags)

        else:
            print("Image Risk Score: 0.0")

        # ====================================================
        # 3. TEXT FOR ML PIPELINE
        # ====================================================

        analysis_text = (
            user_message
            if user_message
            else "Child uploaded an image."
        )

        # ====================================================
        # 4. HARM + EMOTION DETECTION
        # ====================================================

        print("\nRunning harm and emotion detection...")

        ml_analysis = evaluate_harm_and_emotion(analysis_text)

        text_harm_score = float(
            ml_analysis.get("harm_score", 0.0)
        )

        emotion = ml_analysis.get("emotion", "neutral")

        combined_harm_score = max(text_harm_score, image_risk)

        print("Text Harm Score:", text_harm_score)
        print("Image Risk Score:", image_risk)
        print("Combined Harm Score:", combined_harm_score)
        print("Detected Emotion:", emotion)

        # ====================================================
        # 5. PII DETECTION
        # ====================================================

        print("\nRunning PII detection...")

        pii_results = []

        if user_message:
            pii_results = detect_pii(user_message)

        pii_detected = len(pii_results) > 0

        pii_types = [
            item.get("type", "unknown")
            for item in pii_results
        ]

        pii_summary = (
            ", ".join(pii_types)
            if pii_detected
            else None
        )

        print("PII Detected:", pii_detected)
        print("PII Types:", pii_summary)

        # ====================================================
        # 6. RISK CALCULATION
        # ====================================================

        print("\nCalculating final safety risk...")

        safety_evaluation = calculate_risk_score(
            harm_score=combined_harm_score,
            pii_detected=pii_detected,
            age_category=age_group,
        )

        risk_score = float(
            safety_evaluation.get("risk_score", 0.0)
        )

        decision = str(
            safety_evaluation.get("decision", "BLOCK")
        ).upper()

        if decision not in {"ALLOW", "WARN", "BLOCK"}:
            decision = "BLOCK"

        # ----------------------------------------------------
        # FILTER OUT FALSE POSITIVES FOR GREETINGS / SAFE TEXT
        # ----------------------------------------------------
        benign_greetings = ["hi", "hii", "hello", "hey", "good morning", "good evening", "how are you"]
        cleaned_msg_lower = user_message.lower().strip()

        if cleaned_msg_lower in benign_greetings and risk_score < 0.6:
            decision = "ALLOW"
            risk_score = 0.01

        print("Final Risk Score:", risk_score)
        print("Final Decision:", decision)

        # ====================================================
        # 7. DECISION ENGINE
        # ====================================================

        ai_response_text = ""
        warning_message = None

        if decision == "BLOCK":

            print("\nContent BLOCKED by Safety Engine.")

            ai_response_text = (
                "I can't help with that request. "
                "Let's try something safe and helpful instead."
            )

        else:

            print("\nContent passed safety checks.")

            prompt_text = (
                user_message
                if user_message
                else "Please describe the uploaded image."
            )

            image_context = None

            if image_tags:
                image_context = (
                    "The uploaded image was analyzed by the safety layer.\n"
                    f"Image risk score: {image_risk}\n"
                    f"Detected image tags: {', '.join(image_tags)}\n\n"
                    "Use this information only as contextual safety information."
                )

            try:
                ai_response_text = query_external_llm(
                    prompt=prompt_text,
                    provider="gemini",
                    age_group=age_group,
                    conversation_context=(
                        conversation_context
                        if conversation_context
                        else None
                    ),
                    image_context=image_context,
                )
            except Exception as llm_error:
                print("\nGemini connector error:", llm_error)
                ai_response_text = (
                    "I'm having trouble connecting to the AI service right now. "
                    "Please try again in a little while."
                )

            if decision == "WARN" and risk_score < 0.3:
                decision = "ALLOW"

            if decision == "WARN":
                warning_message = (
                    "Please be careful when sharing personal information or images online."
                )

        # ====================================================
        # 8. DATABASE LOGGING (Only log WARN or BLOCK to dashboard)
        # ====================================================

        if decision in ["WARN", "BLOCK"]:
            print("\nSaving safety log to dashboard...")

            try:
                db_log = SafetyLog(
                    child_message=(
                        user_message
                        if user_message
                        else "[Image Upload]"
                    ),
                    ai_response=ai_response_text,
                    age_group=age_group,
                    emotion=emotion,
                    risk_score=risk_score,
                    decision=decision,
                    pii_detected=pii_summary,
                )

                db.add(db_log)
                db.commit()
                db.refresh(db_log)

                print(f"Safety log saved successfully. ID: {db_log.id}")
                log_id = db_log.id

            except Exception as db_error:
                db.rollback()
                log_id = None
                print("\nWARNING: Database logging failed:", db_error)
        else:
            log_id = None
            print("\nInteraction is ALLOWED. Skipping database alert log for dashboard.")

        # ====================================================
        # 9. FINAL RESPONSE
        # ====================================================

        print("\nRequest completed.")
        print("=" * 60)

        return {
            "status": (
                "BLOCKED"
                if decision == "BLOCK"
                else decision
            ),
            "risk_score": round(risk_score, 3),
            "emotion": emotion,
            "pii_details": pii_results,
            "response": ai_response_text,
            "warning": warning_message,
            "image_risk": round(image_risk, 3),
            "image_tags": image_tags,
            "log_id": log_id,
        }

    except HTTPException:
        raise

    except Exception as error:
        print("\n" + "!" * 60)
        print("UNEXPECTED CHAT ERROR")
        print("!" * 60)
        print(type(error).__name__)
        print(str(error))
        print("!" * 60)

        raise HTTPException(
            status_code=500,
            detail="The safety engine encountered an unexpected error."
        )