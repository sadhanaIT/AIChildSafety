# ============================================================
# AI CHILD SAFETY - RISK CALCULATOR
# ============================================================

from typing import Any, Dict, List, Optional


# ============================================================
# CONSTANTS
# ============================================================

# ------------------------------------------------------------
# Risk weights
#
# IMPORTANT:
# image_risk_score already includes image NSFW + image PII.
# Therefore image PII must NOT be added again to pii_score.
# ------------------------------------------------------------

HARM_WEIGHT = 0.60
PII_WEIGHT = 0.20
IMAGE_WEIGHT = 0.20

# ------------------------------------------------------------
# Decision thresholds
# ------------------------------------------------------------

BLOCK_RISK_THRESHOLD = 0.70
WARN_RISK_THRESHOLD = 0.30

BLOCK_HARM_THRESHOLD = 0.85
WARN_HARM_THRESHOLD = 0.50

BLOCK_IMAGE_THRESHOLD = 0.85
WARN_IMAGE_THRESHOLD = 0.50

# ------------------------------------------------------------
# Age adjustment
# ------------------------------------------------------------

YOUNG_CHILD_AGE_ADJUSTMENT = 0.03
PRE_TEEN_AGE_ADJUSTMENT = 0.01
TEEN_AGE_ADJUSTMENT = 0.00


# ============================================================
# SAFE FLOAT
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0
) -> float:

    try:

        return float(value)

    except (
        TypeError,
        ValueError
    ):

        return default


# ============================================================
# CLAMP
# ============================================================

def _clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 1.0
) -> float:

    value = _safe_float(
        value
    )

    return max(
        minimum,
        min(
            maximum,
            value
        )
    )


# ============================================================
# NORMALIZE AGE CATEGORY
# ============================================================

def _normalize_age_category(
    age_category: Optional[str]
) -> str:

    value = str(
        age_category or "pre_teen"
    ).strip().lower()

    supported = {
        "young_child",
        "pre_teen",
        "teen"
    }

    if value not in supported:

        return "pre_teen"

    return value


# ============================================================
# PII CATEGORIES
# ============================================================

CRITICAL_PII_TYPES = {
    "PASSWORD",
    "PIN",
    "OTP",
    "AADHAAR",
    "PAN",
    "PASSPORT",

    # Financial/image-sensitive information
    "PAYMENT_CARD",
    "CARD_NUMBER",
    "CARD_EXPIRY",
    "CVV",
}

HIGH_PII_TYPES = {
    "PHONE_NUMBER",
    "EMAIL",
    "IP_ADDRESS",
    "SOCIAL_MEDIA",
    "ID_NUMBER",
}

MEDIUM_PII_TYPES = {
    "URL",
    "PERSON",
    "LOCATION",
}


# ============================================================
# PII SEVERITY CLASSIFICATION
# ============================================================

def _classify_pii(
    pii_details: List[Dict[str, Any]]
) -> Dict[str, Any]:

    critical_pii = False
    high_pii = False
    medium_pii = False

    detected_pii_types = []

    for item in pii_details:

        if not isinstance(
            item,
            dict
        ):

            continue

        pii_type = str(
            item.get(
                "type",
                ""
            )
        ).upper().strip()

        if not pii_type:

            continue

        detected_pii_types.append(
            pii_type
        )

        # ----------------------------------------------------
        # Category takes priority.
        # ----------------------------------------------------

        if pii_type in CRITICAL_PII_TYPES:

            critical_pii = True

        elif pii_type in HIGH_PII_TYPES:

            high_pii = True

        elif pii_type in MEDIUM_PII_TYPES:

            medium_pii = True

        # ----------------------------------------------------
        # Also understand explicit severity values.
        #
        # This makes the calculator compatible with both:
        #
        #   {"type": "EMAIL"}
        #
        # and:
        #
        #   {"type": "EMAIL", "severity": "HIGH"}
        # ----------------------------------------------------

        severity = str(
            item.get(
                "severity",
                ""
            )
        ).upper().strip()

        if severity == "CRITICAL":

            critical_pii = True

        elif severity == "HIGH":

            high_pii = True

        elif severity == "MEDIUM":

            medium_pii = True

    return {
        "critical_pii": critical_pii,
        "high_pii": high_pii,
        "medium_pii": medium_pii,
        "detected_pii_types": sorted(
            set(
                detected_pii_types
            )
        )
    }


# ============================================================
# PII SCORE
# ============================================================

def _calculate_pii_score(
    critical_pii: bool,
    high_pii: bool,
    medium_pii: bool
) -> float:

    if critical_pii:

        return 1.0

    if high_pii:

        return 0.75

    if medium_pii:

        return 0.35

    return 0.0


# ============================================================
# AGE ADJUSTMENT
# ============================================================

def _get_age_adjustment(
    age_category: str
) -> float:

    if age_category == "young_child":

        return YOUNG_CHILD_AGE_ADJUSTMENT

    if age_category == "pre_teen":

        return PRE_TEEN_AGE_ADJUSTMENT

    return TEEN_AGE_ADJUSTMENT


# ============================================================
# MAIN RISK CALCULATOR
# ============================================================

def calculate_risk_score(
    harm_score: float,
    pii_detected: bool,
    age_category: str = None,
    image_risk_score: float = 0.0,
    pii_details: list = None,
    harmful_intent: bool = False,
    image_pii_details: list = None
) -> dict:
    """
    Calculate the final safety risk.

    INPUT SIGNALS
    -------------

    harm_score:
        Text harm/toxicity score from 0.0 to 1.0.

    pii_detected:
        Whether text PII was detected.

    age_category:
        young_child / pre_teen / teen.

    image_risk_score:
        Combined image safety score.

        IMPORTANT:
        This already includes image NSFW + image PII.
        It must not be added again to text PII.

    pii_details:
        TEXT PII details only.

    harmful_intent:
        Direct harmful-intent detection.

    image_pii_details:
        Optional image PII details used for reporting/override.

        Image PII is NOT added to the normal PII score because
        image_risk_score already represents the image signal.

    DECISION PRIORITY
    -----------------

    1. Harmful intent
    2. Critical text PII
    3. Critical image PII
    4. High harm
    5. High image risk
    6. Overall risk
    7. Warning conditions
    8. Allow
    """

    # ========================================================
    # NORMALIZE INPUTS
    # ========================================================

    harm_score = _clamp(
        harm_score
    )

    image_risk_score = _clamp(
        image_risk_score
    )

    age_category = _normalize_age_category(
        age_category
    )

    if not isinstance(
        pii_details,
        list
    ):

        pii_details = []

    if not isinstance(
        image_pii_details,
        list
    ):

        image_pii_details = []

    harmful_intent = bool(
        harmful_intent
    )

    pii_detected = bool(
        pii_detected
    )


    # ========================================================
    # TEXT PII
    # ========================================================

    text_pii_result = _classify_pii(
        pii_details
    )

    critical_pii = text_pii_result[
        "critical_pii"
    ]

    high_pii = text_pii_result[
        "high_pii"
    ]

    medium_pii = text_pii_result[
        "medium_pii"
    ]

    detected_pii_types = (
        text_pii_result[
            "detected_pii_types"
        ]
    )


    # ========================================================
    # FALLBACK PII
    #
    # If the caller says PII exists but provides no details,
    # treat it conservatively as HIGH.
    # ========================================================

    if (
        pii_detected
        and not pii_details
    ):

        high_pii = True


    # ========================================================
    # IMAGE PII
    #
    # Image PII is intentionally kept separate.
    #
    # The image analyzer already converts critical image PII
    # into image_risk_score = 1.0.
    #
    # We additionally inspect image_pii_details so that a
    # caller cannot accidentally bypass a critical image PII
    # result.
    # ========================================================

    image_pii_result = _classify_pii(
        image_pii_details
    )

    critical_image_pii = image_pii_result[
        "critical_pii"
    ]

    high_image_pii = image_pii_result[
        "high_pii"
    ]

    medium_image_pii = image_pii_result[
        "medium_pii"
    ]

    detected_image_pii_types = (
        image_pii_result[
            "detected_pii_types"
        ]
    )


    # ========================================================
    # PII SCORE
    #
    # ONLY TEXT PII contributes here.
    #
    # Image PII is represented by image_risk_score.
    # ========================================================

    pii_score = _calculate_pii_score(
        critical_pii,
        high_pii,
        medium_pii
    )


    # ========================================================
    # WEIGHTED RISK
    # ========================================================

    weighted_score = (
        harm_score * HARM_WEIGHT
        +
        pii_score * PII_WEIGHT
        +
        image_risk_score * IMAGE_WEIGHT
    )


    # ========================================================
    # AGE VULNERABILITY
    # ========================================================

    age_adjustment = _get_age_adjustment(
        age_category
    )

    # --------------------------------------------------------
    # Age is only a contextual adjustment.
    #
    # Safe content should remain safe.
    # --------------------------------------------------------

    if (
        harm_score >= WARN_HARM_THRESHOLD
        or pii_score > 0.0
        or image_risk_score >= WARN_IMAGE_THRESHOLD
    ):

        weighted_score += age_adjustment


    # ========================================================
    # FINAL RISK SCORE
    # ========================================================

    risk_score = round(
        _clamp(
            weighted_score
        ),
        2
    )


    # ========================================================
    # DECISION ENGINE
    # ========================================================

    decision = "ALLOW"

    reason = (
        "No significant safety risk detected."
    )


    # ========================================================
    # BLOCK OVERRIDES
    # ========================================================

    if harmful_intent:

        decision = "BLOCK"

        reason = (
            "Direct harmful intent detected."
        )

    elif critical_pii:

        decision = "BLOCK"

        reason = (
            "Critical personal or financial "
            "information detected."
        )

    elif critical_image_pii:

        decision = "BLOCK"

        reason = (
            "Critical sensitive information "
            "detected in the image."
        )

    elif harm_score >= BLOCK_HARM_THRESHOLD:

        decision = "BLOCK"

        reason = (
            "High-risk harmful or toxic "
            "content detected."
        )

    elif image_risk_score >= BLOCK_IMAGE_THRESHOLD:

        decision = "BLOCK"

        reason = (
            "High-risk image content detected."
        )

    elif risk_score >= BLOCK_RISK_THRESHOLD:

        decision = "BLOCK"

        reason = (
            "Overall safety risk is high."
        )


    # ========================================================
    # WARN CONDITIONS
    # ========================================================

    elif harm_score >= WARN_HARM_THRESHOLD:

        decision = "WARN"

        reason = (
            "Potentially harmful content detected."
        )

    elif high_pii:

        decision = "WARN"

        reason = (
            "Sensitive personal information detected."
        )

    elif high_image_pii:

        decision = "WARN"

        reason = (
            "Sensitive information detected in the image."
        )

    elif image_risk_score >= WARN_IMAGE_THRESHOLD:

        decision = "WARN"

        reason = (
            "Potentially sensitive image "
            "content detected."
        )

    elif medium_pii:

        decision = "WARN"

        reason = (
            "Personal information detected."
        )

    elif medium_image_pii:

        decision = "WARN"

        reason = (
            "Potentially identifying information "
            "detected in the image."
        )

    elif risk_score >= WARN_RISK_THRESHOLD:

        decision = "WARN"

        reason = (
            "Moderate safety risk detected."
        )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        # ----------------------------------------------------
        # Final decision
        # ----------------------------------------------------

        "risk_score": risk_score,

        "decision": decision,

        "reason": reason,

        # ----------------------------------------------------
        # Individual signals
        # ----------------------------------------------------

        "harm_score": round(
            harm_score,
            2
        ),

        "pii_score": round(
            pii_score,
            2
        ),

        "image_risk_score": round(
            image_risk_score,
            2
        ),

        # ----------------------------------------------------
        # Text PII flags
        # ----------------------------------------------------

        "critical_pii": critical_pii,

        "high_pii": high_pii,

        "medium_pii": medium_pii,

        "detected_pii_types": (
            detected_pii_types
        ),

        # ----------------------------------------------------
        # Image PII flags
        #
        # These are informational/decision flags and are NOT
        # added again to pii_score.
        # ----------------------------------------------------

        "critical_image_pii": (
            critical_image_pii
        ),

        "high_image_pii": (
            high_image_pii
        ),

        "medium_image_pii": (
            medium_image_pii
        ),

        "detected_image_pii_types": (
            detected_image_pii_types
        ),

        # ----------------------------------------------------
        # Context
        # ----------------------------------------------------

        "age_category": age_category
    }


# ============================================================
# SIMPLE DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print(
        "\nRisk calculator module loaded successfully."
    )

    test_result = calculate_risk_score(
        harm_score=0.0,
        pii_detected=False,
        age_category="teen"
    )

    print(
        "\nExample result:"
    )

    print(
        test_result
    )