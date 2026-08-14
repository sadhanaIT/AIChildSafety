from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models import SafetyLog
from app.pipeline.preprocessing import preprocess_and_detect_pii
from app.pipeline.risk_calculator import calculate_risk_and_decide
from app.pipeline.llm_connector import query_external_llm

router = APIRouter()


class ChatRequest(BaseModel):
    child_id: str
    message: str
    target_llm: str = "chatgpt"


@router.post("/chat")
async def process_chat(request: ChatRequest, db: Session = Depends(get_db)):
    # Step 1: Preprocessing & PII Detection
    prep_res = preprocess_and_detect_pii(request.message)

    # Step 2: Simulated ML Model Scores (DistilBERT & RoBERTa integration placeholders)
    mock_harm_score = 0.8 if "harmful" in request.message.lower() else 0.1
    mock_emotion = "fear" if "scared" in request.message.lower() else "neutral"

    # Step 3: Risk Calculation & Decision Engine
    risk_score, decision = calculate_risk_and_decide(
        pii_list=prep_res["pii_detected"],
        harm_score=mock_harm_score,
        emotion=mock_emotion
    )

    llm_output = ""

    # Step 4: Decision Handling
    if decision == "BLOCK":
        llm_output = "I'm sorry, but I can't process this request because it contains unsafe or personal content."
    elif decision == "WARN":
        llm_output = "Warning: Please be careful sharing sensitive information! " + query_external_llm(request.message,
                                                                                                       request.target_llm)
    else:
        # Step 5: ALLOW - Query LLM Proxy
        llm_output = query_external_llm(request.message, request.target_llm)

    # Step 6: Log Execution to MySQL
    log_entry = SafetyLog(
        child_id=request.child_id,
        original_input=request.message,
        risk_score=risk_score,
        decision=decision,
        pii_detected=", ".join(prep_res["pii_detected"]),
        detected_emotion=mock_emotion,
        llm_response=llm_output
    )
    db.add(log_entry)
    db.commit()

    return {
        "child_id": request.child_id,
        "decision": decision,
        "risk_score": risk_score,
        "pii_flagged": prep_res["pii_detected"],
        "response": llm_output
    }