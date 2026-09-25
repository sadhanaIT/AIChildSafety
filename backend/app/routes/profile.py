# ============================================================
# AI CHILD SAFETY - PROFILE ROUTE
# ============================================================

from typing import List, Dict, Any
import os
import secrets

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy.orm import Session

from pydantic import BaseModel, Field

from app.database import get_db
from app.models import (
    CustomRule,
    ParentProfile,
)

from app.pipeline.browser_guard import (
    enforce_browser_safety_locks,
    remove_browser_safety_locks,
)


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/api/v1/profile",
    tags=["Profile"],
)


# ============================================================
# CONFIGURATION
# ============================================================

# For your current college/demo project, the fallback keeps
# compatibility with the existing default profile behavior.
#
# Recommended:
# Add this to backend/.env:
#
# PARENT_DEFAULT_PASSWORD=1234
#
# Change the value in .env whenever you want.
DEFAULT_PARENT_PASSWORD = os.getenv(
    "PARENT_DEFAULT_PASSWORD",
    "1234",
)


DEFAULT_PROFILE_NAME = (
    "Child Companion Profile"
)

DEFAULT_SENSITIVITY = (
    "High (Strict PII & Toxicity Block)"
)

DEFAULT_NOTIFICATIONS_ENABLED = True


# ============================================================
# REQUEST MODELS
# ============================================================

class PasswordPayload(BaseModel):
    """
    Request body for parent-password verification.
    """

    password: str = Field(
        default="",
        max_length=256,
    )


class ProfilePayload(BaseModel):
    """
    Profile settings and custom guardian rules.
    """

    profile_name: str = Field(
        default=DEFAULT_PROFILE_NAME,
        max_length=100,
    )

    sensitivity: str = Field(
        default=DEFAULT_SENSITIVITY,
        max_length=150,
    )

    notifications_enabled: bool = True

    keywords: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# SAFE HELPERS
# ============================================================

def _safe_string(
    value: Any,
    default: str = "",
) -> str:
    """
    Safely convert a value to string.
    """

    if value is None:
        return default

    try:
        return str(value)

    except Exception:
        return default


def _clean_keyword(
    value: Any,
) -> str:
    """
    Normalize guardian keyword.
    """

    return _safe_string(
        value
    ).strip().lower()


def _verify_password(
    entered_password: str,
    stored_password: str,
) -> bool:
    """
    Compare passwords without ordinary direct equality.

    Current database compatibility is retained because
    ParentProfile.password may currently contain the
    existing plaintext demo password.
    """

    entered = _safe_string(
        entered_password
    )

    stored = _safe_string(
        stored_password
    )

    if not entered or not stored:
        return False

    return secrets.compare_digest(
        entered,
        stored,
    )


# ============================================================
# VERIFY PARENT PASSWORD
# ============================================================

@router.post(
    "/verify-password",
    status_code=status.HTTP_200_OK,
)
def verify_parent_password(
    payload: PasswordPayload,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Verify the parent profile password.

    If no ParentProfile exists, create the default profile.
    """

    entered_password = _safe_string(
        payload.password
    )

    # --------------------------------------------------------
    # Get existing profile
    # --------------------------------------------------------

    profile = (
        db.query(ParentProfile)
        .first()
    )

    # --------------------------------------------------------
    # Create default profile when none exists
    # --------------------------------------------------------

    if not profile:

        profile = ParentProfile(
            profile_name=DEFAULT_PROFILE_NAME,
            sensitivity=DEFAULT_SENSITIVITY,
            notifications_enabled=(
                DEFAULT_NOTIFICATIONS_ENABLED
            ),
            password=DEFAULT_PARENT_PASSWORD,
        )

        db.add(profile)
        db.commit()
        db.refresh(profile)

    # --------------------------------------------------------
    # Resolve stored password
    # --------------------------------------------------------

    stored_password = _safe_string(
        getattr(
            profile,
            "password",
            "",
        )
    )

    if not stored_password:

        stored_password = (
            DEFAULT_PARENT_PASSWORD
        )

    # --------------------------------------------------------
    # Verify
    # --------------------------------------------------------

    if _verify_password(
        entered_password,
        stored_password,
    ):

        return {
            "success": True,
            "message": "Access granted",
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect password",
    )


# ============================================================
# GET PROFILE RULES
# ============================================================

@router.get(
    "/rules",
    status_code=status.HTTP_200_OK,
)
def get_rules(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Return current guardian rules and profile settings.
    """

    rules = (
        db.query(CustomRule)
        .all()
    )

    profile = (
        db.query(ParentProfile)
        .first()
    )

    keywords: List[str] = []

    for rule in rules:

        keyword = _clean_keyword(
            getattr(
                rule,
                "keyword",
                "",
            )
        )

        if keyword and keyword not in keywords:
            keywords.append(keyword)

    return {

        "keywords": keywords,

        "profile_name": (
            _safe_string(
                getattr(
                    profile,
                    "profile_name",
                    None,
                ),
                DEFAULT_PROFILE_NAME,
            )
            if profile
            else DEFAULT_PROFILE_NAME
        ),

        "sensitivity": (
            _safe_string(
                getattr(
                    profile,
                    "sensitivity",
                    None,
                ),
                DEFAULT_SENSITIVITY,
            )
            if profile
            else DEFAULT_SENSITIVITY
        ),

        "notifications_enabled": (
            bool(
                getattr(
                    profile,
                    "notifications_enabled",
                    DEFAULT_NOTIFICATIONS_ENABLED,
                )
            )
            if profile
            else DEFAULT_NOTIFICATIONS_ENABLED
        ),
    }


# ============================================================
# SAVE PROFILE RULES
# ============================================================

@router.post(
    "/rules",
    status_code=status.HTTP_200_OK,
)
def save_rules(
    payload: ProfilePayload,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Replace existing guardian keywords and save profile
    settings.
    """

    # --------------------------------------------------------
    # Clean incoming keywords
    # --------------------------------------------------------

    cleaned_keywords: List[str] = []

    for word in payload.keywords:

        keyword = _clean_keyword(
            word
        )

        if (
            keyword
            and keyword not in cleaned_keywords
        ):

            cleaned_keywords.append(
                keyword
            )

    # --------------------------------------------------------
    # Replace custom rules
    # --------------------------------------------------------

    db.query(
        CustomRule
    ).delete(
        synchronize_session=False
    )

    for keyword in cleaned_keywords:

        db.add(
            CustomRule(
                keyword=keyword
            )
        )

    # --------------------------------------------------------
    # Get/create parent profile
    # --------------------------------------------------------

    profile = (
        db.query(ParentProfile)
        .first()
    )

    if not profile:

        profile = ParentProfile(
            profile_name=DEFAULT_PROFILE_NAME,
            sensitivity=DEFAULT_SENSITIVITY,
            notifications_enabled=(
                DEFAULT_NOTIFICATIONS_ENABLED
            ),
            password=DEFAULT_PARENT_PASSWORD,
        )

        db.add(profile)

    # --------------------------------------------------------
    # Update profile fields
    # --------------------------------------------------------

    profile.profile_name = (
        _safe_string(
            payload.profile_name,
            DEFAULT_PROFILE_NAME,
        ).strip()
        or DEFAULT_PROFILE_NAME
    )

    profile.sensitivity = (
        _safe_string(
            payload.sensitivity,
            DEFAULT_SENSITIVITY,
        ).strip()
        or DEFAULT_SENSITIVITY
    )

    profile.notifications_enabled = bool(
        payload.notifications_enabled
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    try:

        db.commit()

    except Exception as error:

        db.rollback()

        print(
            "Profile settings save failed:",
            type(error).__name__,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Profile settings could not be saved."
            ),
        )

    return {
        "status": "success",
        "message": (
            "Profile settings and rules "
            "updated successfully"
        ),
    }


# ============================================================
# ENFORCE BROWSER SAFETY LOCKS
# ============================================================

@router.post(
    "/enforce-browser-locks",
    status_code=status.HTTP_200_OK,
)
def enforce_browser_locks() -> Dict[str, str]:
    """
    Enable browser safety restrictions.
    """

    try:

        success = (
            enforce_browser_safety_locks()
        )

    except Exception as error:

        print(
            "Browser lock enforcement failed:",
            type(error).__name__,
        )

        success = False

    if not success:

        return {
            "status": "error",
            "message": (
                "Failed. Ensure backend is running "
                "with Administrator privileges."
            ),
        }

    return {
        "status": "success",
        "message": (
            "Chrome SafeSearch and YouTube "
            "Restricted Mode successfully enforced!"
        ),
    }


# ============================================================
# UNLOCK BROWSER SAFETY LOCKS
# ============================================================

@router.post(
    "/unlock-browser-locks",
    status_code=status.HTTP_200_OK,
)
def unlock_browser_locks() -> Dict[str, str]:
    """
    Remove browser safety restrictions.
    """

    try:

        success = (
            remove_browser_safety_locks()
        )

    except Exception as error:

        print(
            "Browser lock removal failed:",
            type(error).__name__,
        )

        success = False

    if not success:

        return {
            "status": "error",
            "message": (
                "Failed. Ensure backend is running "
                "with Administrator privileges."
            ),
        }

    return {
        "status": "success",
        "message": (
            "Browser safety locks successfully lifted!"
        ),
    }