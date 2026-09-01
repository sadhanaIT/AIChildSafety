from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import CustomRule, ParentProfile
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


class ProfilePayload(BaseModel):
    profile_name: str
    sensitivity: str
    notifications_enabled: bool
    keywords: List[str]


@router.get("/rules")
def get_rules(db: Session = Depends(get_db)):
    rules = db.query(CustomRule).all()
    profile = db.query(ParentProfile).first()

    return {
        "keywords": [rule.keyword for rule in rules],
        "profile_name": profile.profile_name if profile else "Child Companion Profile",
        "sensitivity": profile.sensitivity if profile else "High (Strict PII & Toxicity Block)",
        "notifications_enabled": profile.notifications_enabled if profile else True
    }


@router.post("/rules")
def save_rules(payload: ProfilePayload, db: Session = Depends(get_db)):
    # 1. Update Custom Keywords
    db.query(CustomRule).delete()
    for word in payload.keywords:
        if word.strip():
            db.add(CustomRule(keyword=word.strip().lower()))

    # 2. Update or Create Parent Profile Settings
    profile = db.query(ParentProfile).first()
    if not profile:
        profile = ParentProfile()
        db.add(profile)

    profile.profile_name = payload.profile_name
    profile.sensitivity = payload.sensitivity
    profile.notifications_enabled = payload.notifications_enabled

    db.commit()
    return {"status": "success", "message": "Profile settings and rules updated successfully"}


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