from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import CustomRule
from app.pipeline.browser_guard import (
    enforce_browser_safety_locks,
    remove_browser_safety_locks,
)
from pydantic import BaseModel
from typing import List

router = APIRouter(
    prefix="/api/v1/profile",
    tags=["Profile"]
)

class RulesPayload(BaseModel):
    keywords: List[str]

@router.get("/rules")
def get_rules(db: Session = Depends(get_db)):
    rules = db.query(CustomRule).all()
    return {"keywords": [rule.keyword for rule in rules]}

@router.post("/rules")
def save_rules(payload: RulesPayload, db: Session = Depends(get_db)):
    db.query(CustomRule).delete()
    for word in payload.keywords:
        if word.strip():
            db.add(CustomRule(keyword=word.strip().lower()))
    db.commit()
    return {"status": "success", "message": "Rules updated successfully"}

@router.post("/enforce-browser-locks")
def enforce_browser_locks():
    success = enforce_browser_safety_locks()
    if not success:
        return {"status": "error", "message": "Failed. Ensure backend is running with Administrator privileges."}
    return {"status": "success", "message": "Chrome SafeSearch and YouTube Restricted Mode successfully enforced!"}

@router.post("/unlock-browser-locks")
def unlock_browser_locks():
    success = remove_browser_safety_locks()
    if not success:
        return {"status": "error", "message": "Failed. Ensure backend is running with Administrator privileges."}
    return {"status": "success", "message": "Browser safety locks successfully lifted!"}