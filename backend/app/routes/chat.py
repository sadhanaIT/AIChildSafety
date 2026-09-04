# ============================================================
# AI CHILD SAFETY - CHAT ROUTE
# ============================================================
#
# Responsibilities:
#   1. Receive text and/or image
#   2. Apply guardian rules
#   3. Analyze image safety
#   4. Analyze text harm + emotion
#   5. Detect and redact text PII
#   6. Calculate safety risk
#   7. BLOCK unsafe requests before Gemini
#   8. Send only safe/redacted information externally
#   9. Re-check Gemini's response
#  10. Redact/block unsafe provider responses
#  11. Store privacy-safe safety logs
#
# IMPORTANT PRIVACY RULE:
#   Raw PII and raw OCR content must never be:
#       - returned to React
#       - sent to Gemini
#       - stored in normal safety logs
#
# ============================================================

from typing import Optional, Any, Dict, List
from time import perf_counter
import inspect

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

from app.database import get_db
from app.models import SafetyLog, CustomRule

from app.pipeline.ML_models import (
    evaluate_harm_and_emotion,
)

from app.pipeline.pii_detector import (
    detect_pii,
    redact_pii,
    sanitize_pii_results,
    get_pii_types,
)

from app.pipeline.risk_calculator import (
    calculate_risk_score,
)

from app.pipeline.image_analyzer import (
    analyze_image_risk,
)

from app.pipeline.llm_connector import (
    query_external_llm,
)


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/api/v1",
    tags=["Safety Chat"],
)


# ============================================================
# CONSTANTS
# ============================================================

ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
}

MAX_IMAGE_SIZE = 10 * 1024 * 1024

CRITICAL_TEXT_PII_TYPES = {
    "PASSWORD",
    "PIN",
    "OTP",
    "CVV",
    "AADHAAR",
    "PAYMENT_CARD",
    "CARD_NUMBER",
    "CARD_EXPIRY",
    "PAN",
    "PASSPORT",
}

CRITICAL_PII_SEVERITIES = {
    "CRITICAL",
}

# These provider-response harm thresholds are intentionally
# stricter than ordinary WARN behavior.
PROVIDER_HARM_BLOCK_THRESHOLD = 0.85


# ============================================================
# SAFE HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return default


def _clamp(
    value: Any,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> float:

    try:
        value = float(value)

    except (
        TypeError,
        ValueError,
    ):
        value = minimum

    return max(
        minimum,
        min(
            maximum,
            value,
        ),
    )


def _safe_list(
    value: Any,
) -> List[Any]:

    if isinstance(value, list):
        return value

    if value is None:
        return []

    return [value]


def _safe_string(
    value: Any,
    default: str = "",
) -> str:

    if value is None:
        return default

    try:
        return str(value)

    except Exception:
        return default


def _is_critical_pii(
    pii_results: List[Dict[str, Any]],
) -> bool:

    for item in pii_results:

        if not isinstance(item, dict):
            continue

        pii_type = _safe_string(
            item.get("type")
        ).upper()

        severity = _safe_string(
            item.get(
                "severity",
                item.get(
                    "risk_level",
                    "",
                ),
            )
        ).upper()

        if (
            severity in CRITICAL_PII_SEVERITIES
            or pii_type in CRITICAL_TEXT_PII_TYPES
        ):
            return True

    return False


def _has_critical_pii_type(
    pii_results: List[Dict[str, Any]],
) -> bool:

    for item in pii_results:

        if not isinstance(item, dict):
            continue

        pii_type = _safe_string(
            item.get("type")
        ).upper()

        if pii_type in CRITICAL_TEXT_PII_TYPES:
            return True

    return False


# ============================================================
# PII SUMMARY
# ============================================================

def _pii_summary(
    pii_details: List[Dict[str, Any]],
) -> Optional[str]:

    try:

        types = get_pii_types(
            pii_details
        )

    except Exception as error:

        print(
            "PII type summary error:",
            error,
        )

        return None

    if not types:
        return None

    safe_types = []

    for pii_type in types:

        value = _safe_string(
            pii_type
        ).strip().upper()

        if value:
            safe_types.append(value)

    if not safe_types:
        return None

    return ", ".join(
        sorted(
            set(safe_types)
        )
    )


# ============================================================
# WARNING MESSAGE
# ============================================================

def _get_warning(
    decision: str,
) -> Optional[str]:

    decision = _safe_string(
        decision
    ).upper()

    if decision == "BLOCK":

        return (
            "This content was blocked "
            "by the safety system."
        )

    if decision == "WARN":

        return (
            "Please be careful when "
            "sharing personal or sensitive "
            "information online."
        )

    return None


# ============================================================
# DATABASE LOGGING
# ============================================================

def _save_safety_log(
    db: Session,
    child_message: str,
    ai_response: str,
    age_group: str,
    emotion: str,
    risk_score: float,
    decision: str,
    pii_summary: Optional[str],
):

    try:

        db_log = SafetyLog(
            child_message=_safe_string(
                child_message
            ),

            ai_response=_safe_string(
                ai_response
            ),

            age_group=_safe_string(
                age_group
            ),

            emotion=_safe_string(
                emotion
            ),

            risk_score=_clamp(
                risk_score
            ),

            decision=_safe_string(
                decision
            ).upper(),

            pii_detected=(
                _safe_string(
                    pii_summary
                )
                if pii_summary
                else None
            ),
        )

        db.add(
            db_log
        )

        db.commit()

        db.refresh(
            db_log
        )

        return db_log.id

    except Exception as error:

        db.rollback()

        print(
            "WARNING: Database logging failed:",
            error,
        )

        return None


# ============================================================
# SAFE DATABASE MESSAGE
# ============================================================

def _prepare_log_message(
    text: str,
    pii_results: List[Dict[str, Any]],
) -> str:

    if not text:
        return ""

    try:

        redacted = redact_pii(
            text,
            pii_results,
        )

        return _safe_string(
            redacted,
            "[REDACTED FOR PRIVACY]",
        )

    except Exception as error:

        print(
            "Database PII redaction failed:",
            error,
        )

        # Fail closed.
        return "[REDACTED FOR PRIVACY]"


# ============================================================
# FINAL API PII RESPONSE
# ============================================================

def _safe_pii_response(
    pii_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    try:

        sanitized = sanitize_pii_results(
            pii_results
        )

        if not isinstance(
            sanitized,
            list,
        ):
            return []

        return sanitized

    except Exception as error:

        print(
            "PII response sanitization error:",
            error,
        )

        return []


# ============================================================
# SAFE IMAGE DATA FOR LLM
# ============================================================

def _call_external_llm_safely(
    *,
    prompt: str,
    provider: str,
    age_group: str,
    conversation_context: Optional[str],
    image_context: Optional[str],
    image_bytes: Optional[bytes],
    image_mime_type: Optional[str],
):
    """
    Calls the external LLM while remaining compatible with
    different versions of llm_connector.py.

    If the connector supports image_bytes/image_mime_type,
    they are passed.

    If the currently installed connector does not support
    those parameters, they are omitted rather than causing
    an unexpected keyword error.

    IMPORTANT:
    The safety analyzer has already processed the image.
    Raw OCR text is NEVER passed here.
    """

    try:

        signature = inspect.signature(
            query_external_llm
        )

        parameters = signature.parameters

    except Exception as error:

        print(
            "Could not inspect LLM connector:",
            error,
        )

        parameters = {}

    kwargs = {
        "prompt": prompt,
        "provider": provider,
        "age_group": age_group,
        "conversation_context": conversation_context,
        "image_context": image_context,
    }

    # --------------------------------------------------------
    # Support connectors that have image input.
    # --------------------------------------------------------

    if (
        image_bytes is not None
        and "image_bytes" in parameters
    ):

        kwargs["image_bytes"] = image_bytes

    if (
        image_mime_type
        and "image_mime_type" in parameters
    ):

        kwargs["image_mime_type"] = (
            image_mime_type
        )

    # --------------------------------------------------------
    # Some connectors may use different names.
    # Support common names without breaking the current one.
    # --------------------------------------------------------

    if (
        image_bytes is not None
        and "image_data" in parameters
        and "image_bytes" not in parameters
    ):

        kwargs["image_data"] = image_bytes

    if (
        image_mime_type
        and "mime_type" in parameters
        and "image_mime_type" not in parameters
    ):

        kwargs["mime_type"] = image_mime_type

    # --------------------------------------------------------
    # Only pass arguments actually supported by connector.
    # --------------------------------------------------------

    accepts_kwargs = any(
        parameter.kind
        == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )

    if not accepts_kwargs:

        kwargs = {
            key: value
            for key, value in kwargs.items()
            if key in parameters
        }

    return query_external_llm(
        **kwargs
    )


# ============================================================
# BUILD STANDARD RESPONSE
# ============================================================

def _build_response(
    *,
    decision: str,
    risk_score: float,
    emotion: str,
    emotion_confidence: float,
    emotion_confidence_level: str,
    pii_results: List[Dict[str, Any]],
    response: str,
    warning: Optional[str],
    reason: str,
    harm_score: float,
    harmful_intent: bool,
    harmful_intent_type: Optional[str],
    harmful_intent_score: float,
    image_risk: float,
    image_tags: List[Any],
    image_status: str,
    image_category: str,
    image_reason: Optional[str],
    image_pii: List[Dict[str, Any]],
    llm_called: bool,
    processing_time: float,
    log_id: Optional[int],
) -> Dict[str, Any]:

    safe_tags = []

    for tag in _safe_list(
        image_tags
    ):

        tag_text = _safe_string(
            tag
        ).strip()

        if tag_text:
            safe_tags.append(
                tag_text
            )

    return {

        "status": _safe_string(
            decision,
            "BLOCK",
        ).upper(),

        "risk_score": round(
            _clamp(risk_score),
            3,
        ),

        "emotion": _safe_string(
            emotion,
            "unknown",
        ),

        "emotion_confidence": round(
            _clamp(
                emotion_confidence
            ),
            3,
        ),

        "emotion_confidence_level":
            _safe_string(
                emotion_confidence_level,
                "UNKNOWN",
            ),

        # ----------------------------------------------------
        # Only sanitized PII reaches React.
        # ----------------------------------------------------

        "pii_details":
            _safe_pii_response(
                pii_results
            ),

        "response":
            _safe_string(
                response
            ),

        "warning":
            warning,

        "reason":
            _safe_string(
                reason
            ),

        "harm_score":
            round(
                _clamp(
                    harm_score
                ),
                3,
            ),

        "harmful_intent":
            bool(
                harmful_intent
            ),

        "harmful_intent_type":
            harmful_intent_type,

        "harmful_intent_score":
            round(
                _clamp(
                    harmful_intent_score
                ),
                3,
            ),

        "image_risk":
            round(
                _clamp(
                    image_risk
                ),
                3,
            ),

        "image_tags":
            safe_tags,

        "image_status":
            _safe_string(
                image_status,
                "ALLOW",
            ).upper(),

        "image_category":
            _safe_string(
                image_category,
                "not_analyzed",
            ),

        "image_reason":
            (
                _safe_string(
                    image_reason
                )
                if image_reason is not None
                else None
            ),

        "image_pii_detected":
            bool(
                image_pii
            ),

        # ----------------------------------------------------
        # NEVER expose raw image PII.
        # ----------------------------------------------------

        "image_pii":
            _safe_pii_response(
                image_pii
            ),

        "llm_called":
            bool(
                llm_called
            ),

        "processing_time":
            round(
                _safe_float(
                    processing_time
                ),
                3,
            ),

        "log_id":
            log_id,
    }


# ============================================================
# CHAT ENDPOINT
# ============================================================

@router.post(
    "/chat",
    status_code=status.HTTP_200_OK,
)
async def process_chat_message(

    message: str = Form(
        default=""
    ),

    age_group: str = Form(
        default="pre_teen"
    ),

    conversation_context: str = Form(
        default=""
    ),

    file: Optional[UploadFile] = File(
        default=None
    ),

    db: Session = Depends(
        get_db
    ),
):

    request_start = perf_counter()

    print("\n")
    print("=" * 70)
    print("NEW AI CHILD SAFETY REQUEST")
    print("=" * 70)

    # ========================================================
    # 1. CLEAN INPUT
    # ========================================================

    user_message = _safe_string(
        message
    ).strip()

    age_group = _safe_string(
        age_group,
        "pre_teen",
    ).strip()

    conversation_context = _safe_string(
        conversation_context
    ).strip()

    has_text = bool(
        user_message
    )

    has_image = (
        file is not None
    )

    print(
        "Age Group:",
        age_group,
    )

    print(
        "Text Provided:",
        has_text,
    )

    print(
        "Image Provided:",
        has_image,
    )

    # --------------------------------------------------------
    # Validate request.
    # --------------------------------------------------------

    if not has_text and not has_image:

        raise HTTPException(
            status_code=400,
            detail=(
                "Please enter a message "
                "or upload an image."
            ),
        )

    # ========================================================
    # 2. DEFAULT VALUES
    # ========================================================

    if has_text:

        emotion = "unknown"

        emotion_confidence = 0.0

        emotion_confidence_level = (
            "UNKNOWN"
        )

    else:

        # CRITICAL:
        # Image-only requests never run the text
        # emotion classifier.
        emotion = "not_evaluated"

        emotion_confidence = 0.0

        emotion_confidence_level = (
            "NOT_EVALUATED"
        )

    harm_score = 0.0

    harmful_intent = False
    harmful_intent_type = None
    harmful_intent_score = 0.0

    pii_results = []
    image_pii = []

    image_risk = 0.0
    image_tags = []
    image_status = "ALLOW"
    image_category = "not_analyzed"
    image_reason = None

    image_bytes = None
    image_mime_type = None

    decision = "ALLOW"
    risk_score = 0.0

    reason = (
        "No significant safety risk detected."
    )

    ai_response_text = None
    warning_message = None

    log_id = None
    llm_called = False

    # ========================================================
    # 3. CUSTOM GUARDIAN RULES
    # ========================================================

    if has_text:

        try:

            custom_rules = (
                db.query(
                    CustomRule
                ).all()
            )

            message_lower = (
                user_message.lower()
            )

            for rule in custom_rules:

                keyword = _safe_string(
                    getattr(
                        rule,
                        "keyword",
                        "",
                    )
                ).strip().lower()

                if not keyword:
                    continue

                if keyword in message_lower:

                    print(
                        "Custom Guardian Rule matched:",
                        keyword,
                    )

                    decision = "BLOCK"
                    risk_score = 1.0

                    reason = (
                        "Custom guardian safety "
                        "rule was triggered."
                    )

                    emotion = (
                        "not_evaluated"
                    )

                    emotion_confidence = 0.0

                    emotion_confidence_level = (
                        "NOT_EVALUATED"
                    )

                    ai_response_text = (
                        "This message has been "
                        "blocked by your guardian's "
                        "custom safety rules."
                    )

                    warning_message = (
                        "A guardian-configured "
                        "safety rule blocked this content."
                    )

                    total_time = (
                        perf_counter()
                        - request_start
                    )

                    log_id = _save_safety_log(
                        db=db,

                        child_message=(
                            "[BLOCKED BY CUSTOM RULE]"
                        ),

                        ai_response=(
                            ai_response_text
                        ),

                        age_group=age_group,

                        emotion=emotion,

                        risk_score=1.0,

                        decision="BLOCK",

                        pii_summary=(
                            "CUSTOM_RULE"
                        ),
                    )

                    return _build_response(
                        decision="BLOCK",
                        risk_score=1.0,
                        emotion=emotion,
                        emotion_confidence=0.0,
                        emotion_confidence_level=(
                            "NOT_EVALUATED"
                        ),
                        pii_results=[],
                        response=ai_response_text,
                        warning=warning_message,
                        reason=reason,
                        harm_score=0.0,
                        harmful_intent=False,
                        harmful_intent_type=None,
                        harmful_intent_score=0.0,
                        image_risk=0.0,
                        image_tags=[],
                        image_status="ALLOW",
                        image_category="not_analyzed",
                        image_reason=None,
                        image_pii=[],
                        llm_called=False,
                        processing_time=total_time,
                        log_id=log_id,
                    )

        except Exception as rule_error:

            print(
                "Custom rule check error:",
                rule_error,
            )

            raise HTTPException(
                status_code=500,
                detail=(
                    "Safety rule verification "
                    "failed. Please try again."
                ),
            )

    # ========================================================
    # 4. READ + VALIDATE IMAGE
    # ========================================================

    if has_image:

        print(
            "\nRunning image safety analysis..."
        )

        if not file.content_type:

            raise HTTPException(
                status_code=400,
                detail="Invalid image file.",
            )

        content_type = (
            _safe_string(
                file.content_type
            ).lower().strip()
        )

        if content_type not in ALLOWED_IMAGE_TYPES:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Unsupported image type. "
                    "Please upload JPG, PNG or WEBP."
                ),
            )

        try:

            image_bytes = await file.read()

        except Exception as read_error:

            print(
                "Image read failed:",
                read_error,
            )

            raise HTTPException(
                status_code=400,
                detail=(
                    "The uploaded image could "
                    "not be read."
                ),
            )

        if not image_bytes:

            raise HTTPException(
                status_code=400,
                detail=(
                    "The uploaded image is empty."
                ),
            )

        if len(image_bytes) > MAX_IMAGE_SIZE:

            raise HTTPException(
                status_code=413,
                detail=(
                    "Image is too large. "
                    "Maximum size is 10 MB."
                ),
            )

        image_mime_type = content_type

        image_start = perf_counter()

        try:

            image_analysis = (
                analyze_image_risk(
                    image_bytes
                )
            )

            if not isinstance(
                image_analysis,
                dict,
            ):

                raise RuntimeError(
                    "Invalid image analysis result."
                )

        except Exception as image_error:

            print(
                "Image analysis failed:",
                image_error,
            )

            decision = "BLOCK"
            risk_score = 1.0

            reason = (
                "Image safety analysis could "
                "not be completed."
            )

            ai_response_text = (
                "I couldn't safely analyze "
                "this image, so it has been "
                "blocked for your protection."
            )

            warning_message = (
                "Image safety analysis failed."
            )

            total_time = (
                perf_counter()
                - request_start
            )

            log_id = _save_safety_log(
                db=db,

                child_message=(
                    "[IMAGE ANALYSIS FAILED]"
                ),

                ai_response=(
                    ai_response_text
                ),

                age_group=age_group,

                emotion=emotion,

                risk_score=1.0,

                decision="BLOCK",

                pii_summary=(
                    "IMAGE_ANALYSIS_ERROR"
                ),
            )

            return _build_response(
                decision="BLOCK",
                risk_score=1.0,
                emotion=emotion,
                emotion_confidence=0.0,
                emotion_confidence_level=(
                    emotion_confidence_level
                ),
                pii_results=[],
                response=ai_response_text,
                warning=warning_message,
                reason=reason,
                harm_score=0.0,
                harmful_intent=False,
                harmful_intent_type=None,
                harmful_intent_score=0.0,
                image_risk=1.0,
                image_tags=[
                    "image_analysis_error"
                ],
                image_status="BLOCK",
                image_category="analysis_error",
                image_reason=reason,
                image_pii=[],
                llm_called=False,
                processing_time=total_time,
                log_id=log_id,
            )

        image_risk = _clamp(
            image_analysis.get(
                "image_risk_score",
                0.0,
            )
        )

        image_tags = _safe_list(
            image_analysis.get(
                "image_tags",
                [],
            )
        )

        image_status = _safe_string(
            image_analysis.get(
                "image_status",
                "ALLOW",
            )
        ).upper()

        image_category = _safe_string(
            image_analysis.get(
                "image_category",
                "unknown",
            )
        )

        image_reason = image_analysis.get(
            "image_reason"
        )

        image_pii = _safe_list(
            image_analysis.get(
                "image_pii",
                [],
            )
        )

        print(
            "Image Risk:",
            image_risk,
        )

        print(
            "Image Status:",
            image_status,
        )

        print(
            "Image Tags:",
            image_tags,
        )

        print(
            "Image PII Types:",
            get_pii_types(
                image_pii
            ),
        )

        print(
            "Image Analysis Time:",
            round(
                perf_counter()
                - image_start,
                3,
            ),
            "seconds",
        )

    # ========================================================
    # 5. TEXT HARM + EMOTION
    # ========================================================

    if has_text:

        print(
            "\nRunning text harm/emotion analysis..."
        )

        ml_start = perf_counter()

        try:

            ml_analysis = (
                evaluate_harm_and_emotion(
                    user_message
                )
            )

            if not isinstance(
                ml_analysis,
                dict,
            ):

                raise RuntimeError(
                    "Invalid ML analysis result."
                )

            harm_score = _clamp(
                ml_analysis.get(
                    "harm_score",
                    0.0,
                )
            )

            emotion = _safe_string(
                ml_analysis.get(
                    "emotion",
                    "unknown",
                ),
                "unknown",
            )

            emotion_confidence = _clamp(
                ml_analysis.get(
                    "emotion_confidence",
                    0.0,
                )
            )

            emotion_confidence_level = (
                _safe_string(
                    ml_analysis.get(
                        "emotion_confidence_level",
                        "UNKNOWN",
                    ),
                    "UNKNOWN",
                )
            )

            harmful_intent = bool(
                ml_analysis.get(
                    "harmful_intent",
                    False,
                )
            )

            harmful_intent_type = (
                ml_analysis.get(
                    "harmful_intent_type"
                )
            )

            harmful_intent_score = _clamp(
                ml_analysis.get(
                    "harmful_intent_score",
                    0.0,
                )
            )

        except Exception as ml_error:

            print(
                "Text ML analysis failed:",
                ml_error,
            )

            decision = "BLOCK"
            risk_score = 1.0

            reason = (
                "Text safety analysis could "
                "not be completed."
            )

            ai_response_text = (
                "I couldn't safely analyze "
                "that message, so I can't "
                "process it right now."
            )

            warning_message = (
                "Text safety analysis failed."
            )

            total_time = (
                perf_counter()
                - request_start
            )

            log_id = _save_safety_log(
                db=db,

                child_message=(
                    "[TEXT ANALYSIS FAILED]"
                ),

                ai_response=(
                    ai_response_text
                ),

                age_group=age_group,

                emotion="unknown",

                risk_score=1.0,

                decision="BLOCK",

                pii_summary=(
                    "TEXT_ANALYSIS_ERROR"
                ),
            )

            return _build_response(
                decision="BLOCK",
                risk_score=1.0,
                emotion="unknown",
                emotion_confidence=0.0,
                emotion_confidence_level="UNKNOWN",
                pii_results=[],
                response=ai_response_text,
                warning=warning_message,
                reason=reason,
                harm_score=1.0,
                harmful_intent=False,
                harmful_intent_type=None,
                harmful_intent_score=0.0,
                image_risk=image_risk,
                image_tags=image_tags,
                image_status=image_status,
                image_category=image_category,
                image_reason=image_reason,
                image_pii=image_pii,
                llm_called=False,
                processing_time=total_time,
                log_id=log_id,
            )

        print(
            "Text Harm:",
            harm_score,
        )

        print(
            "Emotion:",
            emotion,
        )

        print(
            "Emotion Confidence:",
            emotion_confidence,
        )

        print(
            "Harmful Intent:",
            harmful_intent_type,
        )

        print(
            "Text ML Time:",
            round(
                perf_counter()
                - ml_start,
                3,
            ),
            "seconds",
        )

    else:

        # ----------------------------------------------------
        # Image-only request.
        # ----------------------------------------------------

        emotion = "not_evaluated"
        emotion_confidence = 0.0
        emotion_confidence_level = (
            "NOT_EVALUATED"
        )

        harm_score = 0.0

        harmful_intent = False
        harmful_intent_type = None
        harmful_intent_score = 0.0

    # ========================================================
    # 6. TEXT PII
    # ========================================================

    if has_text:

        print(
            "\nRunning text PII detection..."
        )

        try:

            pii_results = detect_pii(
                user_message
            )

            if not isinstance(
                pii_results,
                list,
            ):

                pii_results = []

        except Exception as pii_error:

            print(
                "PII detection failed:",
                pii_error,
            )

            # Privacy fail-closed.
            pii_results = [
                {
                    "type": "PII_ANALYSIS_ERROR",
                    "risk_level": "CRITICAL",
                    "severity": "CRITICAL",
                    "masked": "[ANALYSIS ERROR]",
                    "source": "system",
                }
            ]

    # ========================================================
    # 7. IMAGE PII + TEXT PII REPORTING
    # ========================================================

    all_pii_details = (
        pii_results
        +
        image_pii
    )

    pii_detected = bool(
        all_pii_details
    )

    pii_summary = _pii_summary(
        all_pii_details
    )

    print(
        "PII Detected:",
        pii_detected,
    )

    print(
        "PII Types:",
        pii_summary,
    )

    # ========================================================
    # 8. REDACT USER MESSAGE
    # ========================================================

    redacted_user_message = user_message

    if has_text:

        try:

            redacted_user_message = (
                redact_pii(
                    user_message,
                    pii_results,
                )
            )

        except Exception as redaction_error:

            print(
                "PII redaction failed:",
                redaction_error,
            )

            decision = "BLOCK"
            risk_score = 1.0

            reason = (
                "The message could not be "
                "safely protected before "
                "external processing."
            )

            ai_response_text = (
                "I couldn't safely protect "
                "your personal information, "
                "so I can't process this "
                "message right now."
            )

            warning_message = (
                "Privacy protection failed."
            )

            total_time = (
                perf_counter()
                - request_start
            )

            log_id = _save_safety_log(
                db=db,

                child_message=(
                    "[PII REDACTION FAILED]"
                ),

                ai_response=(
                    ai_response_text
                ),

                age_group=age_group,

                emotion=emotion,

                risk_score=1.0,

                decision="BLOCK",

                pii_summary=(
                    "PII_REDACTION_ERROR"
                ),
            )

            return _build_response(
                decision="BLOCK",
                risk_score=1.0,
                emotion=emotion,
                emotion_confidence=emotion_confidence,
                emotion_confidence_level=(
                    emotion_confidence_level
                ),
                pii_results=pii_results,
                response=ai_response_text,
                warning=warning_message,
                reason=reason,
                harm_score=harm_score,
                harmful_intent=harmful_intent,
                harmful_intent_type=(
                    harmful_intent_type
                ),
                harmful_intent_score=(
                    harmful_intent_score
                ),
                image_risk=image_risk,
                image_tags=image_tags,
                image_status=image_status,
                image_category=image_category,
                image_reason=image_reason,
                image_pii=image_pii,
                llm_called=False,
                processing_time=total_time,
                log_id=log_id,
            )

    # ========================================================
    # 9. REDACT CONVERSATION CONTEXT
    #
    # IMPORTANT:
    # Context can also contain old PII.
    # Never send raw conversation history to Gemini.
    # ========================================================

    redacted_conversation_context = (
        conversation_context
    )

    if conversation_context:

        try:

            context_pii = detect_pii(
                conversation_context
            )

            if context_pii:

                redacted_conversation_context = (
                    redact_pii(
                        conversation_context,
                        context_pii,
                    )
                )

        except Exception as context_error:

            print(
                "Conversation context "
                "privacy check failed:",
                context_error,
            )

            # Fail closed.
            decision = "BLOCK"
            risk_score = 1.0

            reason = (
                "Conversation context could "
                "not be safely protected."
            )

            ai_response_text = (
                "I couldn't safely protect "
                "the conversation context, "
                "so I can't process this "
                "request right now."
            )

            warning_message = (
                "Conversation privacy protection failed."
            )

            total_time = (
                perf_counter()
                - request_start
            )

            log_id = _save_safety_log(
                db=db,

                child_message=(
                    _prepare_log_message(
                        user_message,
                        pii_results,
                    )
                    if has_text
                    else "[IMAGE UPLOAD]"
                ),

                ai_response=(
                    ai_response_text
                ),

                age_group=age_group,

                emotion=emotion,

                risk_score=1.0,

                decision="BLOCK",

                pii_summary=(
                    pii_summary
                    or
                    "CONTEXT_PII_ERROR"
                ),
            )

            return _build_response(
                decision="BLOCK",
                risk_score=1.0,
                emotion=emotion,
                emotion_confidence=emotion_confidence,
                emotion_confidence_level=(
                    emotion_confidence_level
                ),
                pii_results=pii_results,
                response=ai_response_text,
                warning=warning_message,
                reason=reason,
                harm_score=harm_score,
                harmful_intent=harmful_intent,
                harmful_intent_type=(
                    harmful_intent_type
                ),
                harmful_intent_score=(
                    harmful_intent_score
                ),
                image_risk=image_risk,
                image_tags=image_tags,
                image_status=image_status,
                image_category=image_category,
                image_reason=image_reason,
                image_pii=image_pii,
                llm_called=False,
                processing_time=total_time,
                log_id=log_id,
            )

    # ========================================================
    # 10. FINAL RISK CALCULATION
    # ========================================================

    print(
        "\nCalculating final safety risk..."
    )

    try:

        try:

            # New risk calculator.
            safety_evaluation = (
                calculate_risk_score(
                    harm_score=harm_score,

                    pii_detected=bool(
                        pii_results
                    ),

                    age_category=age_group,

                    image_risk_score=image_risk,

                    pii_details=pii_results,

                    harmful_intent=harmful_intent,

                    image_pii_details=image_pii,
                )
            )

        except TypeError:

            # Backward-compatible call for an older
            # risk calculator.
            safety_evaluation = (
                calculate_risk_score(
                    harm_score=harm_score,

                    pii_detected=bool(
                        pii_results
                    ),

                    age_category=age_group,

                    image_risk_score=image_risk,

                    pii_details=pii_results,

                    harmful_intent=harmful_intent,
                )
            )

        if not isinstance(
            safety_evaluation,
            dict,
        ):

            raise RuntimeError(
                "Invalid risk calculation result."
            )

        risk_score = _clamp(
            safety_evaluation.get(
                "risk_score",
                1.0,
            )
        )

        decision = _safe_string(
            safety_evaluation.get(
                "decision",
                "BLOCK",
            ),
            "BLOCK",
        ).upper()

        if decision not in {
            "ALLOW",
            "WARN",
            "BLOCK",
        }:

            decision = "BLOCK"

            risk_score = 1.0

            reason = (
                "Safety system returned "
                "an invalid decision."
            )

        else:

            reason = _safe_string(
                safety_evaluation.get(
                    "reason",
                    "Safety decision generated.",
                ),
                "Safety decision generated.",
            )

    except Exception as risk_error:

        print(
            "Risk calculation failed:",
            risk_error,
        )

        risk_score = 1.0
        decision = "BLOCK"

        reason = (
            "Safety risk calculation "
            "could not be completed."
        )

    # ========================================================
    # 11. CRITICAL IMAGE PII OVERRIDE
    #
    # IMPORTANT:
    # Critical image PII must BLOCK even if the image analyzer
    # accidentally reports image_status=ALLOW.
    # ========================================================

    critical_image_pii = (
        _is_critical_pii(
            image_pii
        )
    )

    if critical_image_pii:

        decision = "BLOCK"
        risk_score = 1.0

        reason = (
            "The image contains highly "
            "sensitive personal or security "
            "information and was blocked."
        )

        image_status = "BLOCK"

    # ========================================================
    # 12. IMAGE BLOCK OVERRIDE
    # ========================================================

    if image_status == "BLOCK":

        decision = "BLOCK"

        risk_score = max(
            risk_score,
            image_risk,
        )

        if critical_image_pii:

            risk_score = 1.0

            reason = (
                "The image contains highly "
                "sensitive personal information "
                "and was blocked."
            )

        else:

            reason = (
                image_reason
                or
                "Image safety policy blocked "
                "the upload."
            )

    # ========================================================
    # 13. TEXT CRITICAL PII OVERRIDE
    # ========================================================

    critical_text_pii = (
        _has_critical_pii_type(
            pii_results
        )
    )

    if critical_text_pii:

        decision = "BLOCK"
        risk_score = 1.0

        reason = (
            "The message contains highly "
            "sensitive personal or security "
            "information."
        )

    # ========================================================
    # 14. BLOCK BEFORE GEMINI
    # ========================================================

    if decision == "BLOCK":

        ai_response_text = (
            "I can't help with that request. "
            "Let's try something safe and "
            "helpful instead."
        )

        warning_message = (
            "This content was blocked by "
            "the safety system."
        )

        log_id = _save_safety_log(
            db=db,

            child_message=(
                _prepare_log_message(
                    user_message,
                    pii_results,
                )
                if has_text
                else "[IMAGE UPLOAD]"
            ),

            ai_response=ai_response_text,

            age_group=age_group,

            emotion=emotion,

            risk_score=risk_score,

            decision="BLOCK",

            pii_summary=pii_summary,
        )

        total_time = (
            perf_counter()
            - request_start
        )

        print(
            "Final Risk Score:",
            risk_score,
        )

        print(
            "Final Decision:",
            decision,
        )

        print(
            "Reason:",
            reason,
        )

        return _build_response(
            decision="BLOCK",
            risk_score=risk_score,
            emotion=emotion,
            emotion_confidence=emotion_confidence,
            emotion_confidence_level=(
                emotion_confidence_level
            ),
            pii_results=pii_results,
            response=ai_response_text,
            warning=warning_message,
            reason=reason,
            harm_score=harm_score,
            harmful_intent=harmful_intent,
            harmful_intent_type=(
                harmful_intent_type
            ),
            harmful_intent_score=(
                harmful_intent_score
            ),
            image_risk=image_risk,
            image_tags=image_tags,
            image_status=image_status,
            image_category=image_category,
            image_reason=image_reason,
            image_pii=image_pii,
            llm_called=False,
            processing_time=total_time,
            log_id=log_id,
        )

    # ========================================================
    # 15. SAFE PROMPT FOR GEMINI
    # ========================================================

    if has_image and not has_text:

        prompt_text = (
            "The user uploaded an image but "
            "did not provide a text question. "
            "Analyze and describe the image "
            "helpfully, using only the image "
            "itself and the safe image context "
            "provided by the application."
        )

    else:

        prompt_text = (
            redacted_user_message
        )

    # ========================================================
    # 16. SAFE IMAGE CONTEXT
    # ========================================================

    image_context = None

    if has_image:

        safe_tags = []

        for tag in image_tags:

            tag_text = _safe_string(
                tag
            ).strip()

            if tag_text:
                safe_tags.append(
                    tag_text
                )

        if safe_tags:

            image_context = (
                "The application's image safety "
                "analyzer detected these safety "
                "categories: "
                + ", ".join(
                    safe_tags
                )
                + "."
            )

        else:

            image_context = (
                "The uploaded image passed the "
                "application's image safety checks."
            )

    # ========================================================
    # 17. GEMINI API
    # ========================================================

    llm_start = perf_counter()

    try:

        ai_response_text = (
            _call_external_llm_safely(
                prompt=prompt_text,

                provider="gemini",

                age_group=age_group,

                conversation_context=(
                    redacted_conversation_context
                    if redacted_conversation_context
                    else None
                ),

                image_context=image_context,

                image_bytes=image_bytes
                if has_image
                else None,

                image_mime_type=image_mime_type
                if has_image
                else None,
            )
        )

        if not ai_response_text:

            raise RuntimeError(
                "Gemini returned an empty response."
            )

        ai_response_text = _safe_string(
            ai_response_text
        ).strip()

        llm_called = True

    except Exception as llm_error:

        print(
            "\nGemini API error:",
            llm_error,
        )

        error_text = _safe_string(
            llm_error
        ).lower()

        if (
            "429" in error_text
            or "quota" in error_text
            or "rate limit" in error_text
        ):

            ai_response_text = (
                "The AI service has reached "
                "its current request limit. "
                "Please try again later."
            )

            reason = (
                "Gemini API rate limit reached."
            )

        else:

            ai_response_text = (
                "I'm having trouble connecting "
                "to the AI service right now. "
                "Please try again shortly."
            )

            reason = (
                "Gemini API request failed."
            )

        warning_message = (
            "The safety check completed, "
            "but the AI response service "
            "is temporarily unavailable."
        )

        # ----------------------------------------------------
        # IMPORTANT:
        # This is NOT a safety ALLOW.
        # The AI service simply did not respond.
        #
        # We use WARN because the request itself already
        # passed the safety engine but generation failed.
        # ----------------------------------------------------

        decision = "WARN"

    llm_time = (
        perf_counter()
        - llm_start
    )

    print(
        "Gemini API Time:",
        round(
            llm_time,
            3,
        ),
        "seconds",
    )

    # ========================================================
    # 18. PROVIDER RESPONSE SAFETY CHECK
    # ========================================================

    provider_pii = []
    provider_harm_score = 0.0
    provider_harmful_intent = False

    if llm_called:

        print(
            "\nRunning safety check on AI response..."
        )

        # ----------------------------------------------------
        # Provider PII
        # ----------------------------------------------------

        try:

            provider_pii = detect_pii(
                ai_response_text
            )

            if not isinstance(
                provider_pii,
                list,
            ):

                provider_pii = []

        except Exception as provider_pii_error:

            print(
                "AI response PII detection failed:",
                provider_pii_error,
            )

            provider_pii = [
                {
                    "type": "PII_ANALYSIS_ERROR",
                    "risk_level": "CRITICAL",
                    "severity": "CRITICAL",
                    "masked": "[ANALYSIS ERROR]",
                    "source": "system",
                }
            ]

        # ----------------------------------------------------
        # Provider Harm
        # ----------------------------------------------------

        try:

            provider_ml = (
                evaluate_harm_and_emotion(
                    ai_response_text
                )
            )

            if not isinstance(
                provider_ml,
                dict,
            ):

                raise RuntimeError(
                    "Invalid provider ML result."
                )

            provider_harm_score = _clamp(
                provider_ml.get(
                    "harm_score",
                    0.0,
                )
            )

            provider_harmful_intent = bool(
                provider_ml.get(
                    "harmful_intent",
                    False,
                )
            )

        except Exception as provider_ml_error:

            print(
                "AI response safety analysis failed:",
                provider_ml_error,
            )

            # Fail closed.
            provider_harm_score = 1.0
            provider_harmful_intent = True

        # ----------------------------------------------------
        # Provider PII severity
        # ----------------------------------------------------

        provider_critical_pii = (
            _is_critical_pii(
                provider_pii
            )
        )

        provider_has_pii = bool(
            provider_pii
        )

        # ----------------------------------------------------
        # BLOCK unsafe provider response.
        # ----------------------------------------------------

        if (
            provider_critical_pii
            or
            provider_harm_score
            >= PROVIDER_HARM_BLOCK_THRESHOLD
            or
            provider_harmful_intent
        ):

            print(
                "WARNING: AI provider response "
                "failed safety validation."
            )

            decision = "BLOCK"
            risk_score = 1.0

            reason = (
                "The AI response did not pass "
                "the application's safety checks."
            )

            ai_response_text = (
                "I couldn't provide that response "
                "because the AI-generated content "
                "did not pass the safety check."
            )

            warning_message = (
                "The AI response was blocked "
                "by the safety system."
            )

            # ------------------------------------------------
            # Add ONLY types to the summary.
            # Never raw values.
            # ------------------------------------------------

            provider_types = _pii_summary(
                provider_pii
            )

            if provider_types:

                if pii_summary:

                    pii_summary = (
                        pii_summary
                        + ", PROVIDER_RESPONSE_"
                        + provider_types.replace(
                            ", ",
                            ",PROVIDER_RESPONSE_",
                        )
                    )

                else:

                    pii_summary = (
                        "PROVIDER_RESPONSE_"
                        + provider_types.replace(
                            ", ",
                            ",PROVIDER_RESPONSE_",
                        )
                    )

            log_id = _save_safety_log(
                db=db,

                child_message=(
                    _prepare_log_message(
                        user_message,
                        pii_results,
                    )
                    if has_text
                    else "[IMAGE UPLOAD]"
                ),

                ai_response=(
                    "[AI RESPONSE BLOCKED]"
                ),

                age_group=age_group,

                emotion=emotion,

                risk_score=1.0,

                decision="BLOCK",

                pii_summary=pii_summary,
            )

            total_time = (
                perf_counter()
                - request_start
            )

            return _build_response(
                decision="BLOCK",
                risk_score=1.0,
                emotion=emotion,
                emotion_confidence=(
                    emotion_confidence
                ),
                emotion_confidence_level=(
                    emotion_confidence_level
                ),
                pii_results=pii_results,
                response=ai_response_text,
                warning=warning_message,
                reason=reason,
                harm_score=harm_score,
                harmful_intent=harmful_intent,
                harmful_intent_type=(
                    harmful_intent_type
                ),
                harmful_intent_score=(
                    harmful_intent_score
                ),
                image_risk=image_risk,
                image_tags=image_tags,
                image_status=image_status,
                image_category=image_category,
                image_reason=image_reason,
                image_pii=image_pii,
                llm_called=True,
                processing_time=total_time,
                log_id=log_id,
            )

        # ----------------------------------------------------
        # Provider has non-critical PII.
        # Redact before returning.
        # ----------------------------------------------------

        if provider_has_pii:

            try:

                ai_response_text = redact_pii(
                    ai_response_text,
                    provider_pii,
                )

                warning_message = (
                    "Some personal information "
                    "in the AI response was "
                    "automatically removed."
                )

            except Exception as provider_redact_error:

                print(
                    "AI response redaction failed:",
                    provider_redact_error,
                )

                decision = "BLOCK"
                risk_score = 1.0

                reason = (
                    "The AI response could not "
                    "be safely protected."
                )

                ai_response_text = (
                    "I couldn't safely return "
                    "the AI response, so it "
                    "was blocked."
                )

                warning_message = (
                    "AI response privacy protection "
                    "failed."
                )

                log_id = _save_safety_log(
                    db=db,

                    child_message=(
                        _prepare_log_message(
                            user_message,
                            pii_results,
                        )
                        if has_text
                        else "[IMAGE UPLOAD]"
                    ),

                    ai_response=(
                        "[AI RESPONSE BLOCKED]"
                    ),

                    age_group=age_group,

                    emotion=emotion,

                    risk_score=1.0,

                    decision="BLOCK",

                    pii_summary=(
                        pii_summary
                        or
                        "PROVIDER_PII_REDACTION_ERROR"
                    ),
                )

                total_time = (
                    perf_counter()
                    - request_start
                )

                return _build_response(
                    decision="BLOCK",
                    risk_score=1.0,
                    emotion=emotion,
                    emotion_confidence=(
                        emotion_confidence
                    ),
                    emotion_confidence_level=(
                        emotion_confidence_level
                    ),
                    pii_results=pii_results,
                    response=ai_response_text,
                    warning=warning_message,
                    reason=reason,
                    harm_score=harm_score,
                    harmful_intent=harmful_intent,
                    harmful_intent_type=(
                        harmful_intent_type
                    ),
                    harmful_intent_score=(
                        harmful_intent_score
                    ),
                    image_risk=image_risk,
                    image_tags=image_tags,
                    image_status=image_status,
                    image_category=image_category,
                    image_reason=image_reason,
                    image_pii=image_pii,
                    llm_called=True,
                    processing_time=total_time,
                    log_id=log_id,
                )

    # ========================================================
    # 19. WARN MESSAGE
    # ========================================================

    if decision == "WARN":

        if not warning_message:

            warning_message = (
                _get_warning(
                    "WARN"
                )
            )

    # ========================================================
    # 20. DATABASE LOGGING
    # ========================================================

    if decision in {
        "WARN",
        "BLOCK",
    }:

        log_id = _save_safety_log(
            db=db,

            child_message=(
                _prepare_log_message(
                    user_message,
                    pii_results,
                )
                if has_text
                else "[IMAGE UPLOAD]"
            ),

            ai_response=(
                ai_response_text
                if decision != "BLOCK"
                else "[AI RESPONSE BLOCKED]"
            ),

            age_group=age_group,

            emotion=emotion,

            risk_score=risk_score,

            decision=decision,

            pii_summary=pii_summary,
        )

    # ========================================================
    # 21. FINAL RESPONSE
    # ========================================================

    total_time = (
        perf_counter()
        - request_start
    )

    print(
        "\nRequest completed."
    )

    print(
        "Final Risk Score:",
        round(
            risk_score,
            3,
        ),
    )

    print(
        "Final Decision:",
        decision,
    )

    print(
        "Reason:",
        reason,
    )

    print(
        "LLM Called:",
        llm_called,
    )

    print(
        "Total Processing Time:",
        round(
            total_time,
            3,
        ),
        "seconds",
    )

    print("=" * 70)

    return _build_response(
        decision=decision,

        risk_score=risk_score,

        emotion=emotion,

        emotion_confidence=emotion_confidence,

        emotion_confidence_level=(
            emotion_confidence_level
        ),

        pii_results=pii_results,

        response=ai_response_text,

        warning=warning_message,

        reason=reason,

        harm_score=harm_score,

        harmful_intent=harmful_intent,

        harmful_intent_type=(
            harmful_intent_type
        ),

        harmful_intent_score=(
            harmful_intent_score
        ),

        image_risk=image_risk,

        image_tags=image_tags,

        image_status=image_status,

        image_category=image_category,

        image_reason=image_reason,

        image_pii=image_pii,

        llm_called=llm_called,

        processing_time=total_time,

        log_id=log_id,
    )


# ============================================================
# MODULE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("AI CHILD SAFETY - CHAT ROUTE")
    print("=" * 70)

    print()
    print("Module loaded successfully.")
    print()
    print("Router prefix:")
    print(" - /api/v1")

    print()
    print("Endpoint:")
    print(" - POST /api/v1/chat")

    print()
    print("Supported input:")
    print(" - Text")
    print(" - Image")
    print(" - Text + Image")

    print()
    print("Safety stages:")
    print(" 1. Guardian rules")
    print(" 2. Image analysis")
    print(" 3. Harm detection")
    print(" 4. Emotion detection")
    print(" 5. PII detection")
    print(" 6. PII redaction")
    print(" 7. Risk calculation")
    print(" 8. ALLOW / WARN / BLOCK")
    print(" 9. Gemini")
    print("10. Provider response safety")
    print("11. Provider PII redaction")
    print("12. Privacy-safe logging")

    print()
    print("Privacy:")
    print(" - Raw text PII is never returned.")
    print(" - Raw image PII is never returned.")
    print(" - Raw OCR is never returned.")
    print(" - Raw user PII is not sent to Gemini.")
    print(" - Conversation context is sanitized.")
    print(" - Provider responses are rechecked.")

    print()
    print("Image-only emotion:")
    print(" - NOT_EVALUATED")

    print()
    print("Module test complete.")
    print("=" * 70)