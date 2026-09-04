# ============================================================
# AI CHILD SAFETY - IMAGE ANALYZER
# ============================================================
#
# Responsibilities:
#   1. Validate uploaded images safely
#   2. Detect potentially explicit/NSFW visual content
#   3. Extract OCR internally
#   4. Detect sensitive PII from OCR
#   5. Calculate image-only risk
#   6. Decide ALLOW / WARN / BLOCK
#   7. Return only safe metadata
#
# SECURITY RULES:
#   - Raw OCR is NEVER returned.
#   - Raw PII values are NEVER returned.
#   - Image risk remains separate from text risk.
#   - Critical image PII causes BLOCK.
#   - Image-only requests do NOT run text emotion analysis.
#   - This module does not send anything to an external LLM.
#
# IMPORTANT CARD-DETECTION DESIGN:
#   - Luhn validation is used for standalone card-number detection.
#   - Images may contain synthetic/test card numbers that fail Luhn.
#   - When strong card context exists in OCR, a 13-19 digit
#     candidate is treated as PAYMENT_CARD even if Luhn fails.
#   - A second digit-focused OCR pass improves detection when
#     normal OCR confuses digits with letters.
# ============================================================

import io
import os
import re
from typing import List, Dict, Any

from PIL import (
    Image,
    ImageOps,
    ImageEnhance,
    UnidentifiedImageError,
)

from transformers import pipeline


# ============================================================
# CONFIGURATION
# ============================================================

IMAGE_MODEL_NAME = "Falconsai/nsfw_image_detection"


# ============================================================
# NSFW THRESHOLDS
# ============================================================

NSFW_BLOCK_THRESHOLD = 0.85
NSFW_WARN_THRESHOLD = 0.60


# ============================================================
# IMAGE SAFETY LIMITS
# ============================================================

MAX_IMAGE_BYTES = 15 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000


# ============================================================
# OCR CONFIGURATION
# ============================================================

OCR_AVAILABLE = False
pytesseract = None

DEFAULT_TESSERACT_PATH = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

OCR_TIMEOUT_SECONDS = 10

# Prevent OCR from producing an unnecessarily large
# internal string.
MAX_OCR_CHARS = 20_000


# ============================================================
# IMAGE MODEL
# ============================================================

image_classifier = None


# ============================================================
# OCR INITIALIZATION
# ============================================================

try:

    import pytesseract

    if os.path.exists(DEFAULT_TESSERACT_PATH):
        pytesseract.pytesseract.tesseract_cmd = (
            DEFAULT_TESSERACT_PATH
        )

    try:

        pytesseract.get_tesseract_version()
        OCR_AVAILABLE = True

    except Exception:

        OCR_AVAILABLE = False

except ImportError:

    pytesseract = None
    OCR_AVAILABLE = False


# ============================================================
# TEXT HELPERS
# ============================================================

def _clean_text(value: Any) -> str:
    """
    Normalize text without logging or exposing sensitive
    contents.
    """

    if value is None:
        return ""

    try:
        value = str(value)
    except Exception:
        return ""

    value = value.replace("\r\n", "\n")
    value = value.replace("\r", "\n")

    value = re.sub(
        r"[ \t]+",
        " ",
        value,
    )

    value = re.sub(
        r"\n{3,}",
        "\n\n",
        value,
    )

    value = value.strip()

    # Keep OCR bounded internally.
    if len(value) > MAX_OCR_CHARS:
        value = value[:MAX_OCR_CHARS]

    return value


def _digits_only(value: Any) -> str:
    """
    Return digits only.
    """

    try:
        text = str(value)
    except Exception:
        return ""

    return re.sub(
        r"\D",
        "",
        text,
    )


def _clamp(
    value: Any,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> float:

    try:
        number = float(value)

    except (TypeError, ValueError):

        number = 0.0

    return max(
        minimum,
        min(
            maximum,
            number,
        ),
    )


# ============================================================
# LUHN VALIDATION
# ============================================================

def _luhn_check(
    card_number: str,
) -> bool:
    """
    Validate a possible payment-card number.

    Luhn is useful for reducing false positives in ordinary
    text. However, image/card detection also supports
    contextual detection because synthetic/test card images
    can contain intentionally invalid numbers.
    """

    digits = _digits_only(card_number)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for index, digit in enumerate(
        reversed(digits)
    ):

        number = int(digit)

        if index % 2 == 1:

            number *= 2

            if number > 9:
                number -= 9

        total += number

    return total % 10 == 0


# ============================================================
# MASKING
# ============================================================

def _mask_card(
    value: str,
) -> str:

    digits = _digits_only(value)

    if len(digits) <= 4:
        return "****"

    return (
        "*" * (len(digits) - 4)
        + digits[-4:]
    )


def _mask_email(
    value: str,
) -> str:

    try:

        username, domain = value.split(
            "@",
            1,
        )

        if len(username) <= 1:

            masked_username = "*"

        else:

            masked_username = (
                username[0]
                + "*" * (len(username) - 1)
            )

        return (
            masked_username
            + "@"
            + domain
        )

    except Exception:

        return "[REDACTED]"


def _mask_generic(
    value: str,
) -> str:

    value = str(value)

    if len(value) <= 4:
        return "*" * len(value)

    return (
        value[:2]
        + "*" * (len(value) - 2)
    )


# ============================================================
# IMAGE PII RESULT
# ============================================================

def _add_pii(
    results: List[Dict[str, Any]],
    pii_type: str,
    value: str,
    severity: str,
) -> None:
    """
    Add masked PII metadata only.

    Raw value is never stored in the result.
    """

    if not value:
        return

    clean_value = str(
        value
    ).strip()

    if not clean_value:
        return

    pii_type = str(
        pii_type
    ).upper().strip()

    severity = str(
        severity
    ).upper().strip()

    normalized_value = clean_value.lower()

    # --------------------------------------------------------
    # Duplicate prevention
    # --------------------------------------------------------

    for existing in results:

        if (
            existing.get("_type") == pii_type
            and existing.get("_value_key")
            == normalized_value
        ):

            return

    # --------------------------------------------------------
    # Masking
    # --------------------------------------------------------

    if pii_type in {
        "PAYMENT_CARD",
        "CARD_NUMBER",
    }:

        masked = _mask_card(
            clean_value
        )

    elif pii_type == "EMAIL":

        masked = _mask_email(
            clean_value
        )

    else:

        masked = _mask_generic(
            clean_value
        )

    # --------------------------------------------------------
    # Internal metadata
    # --------------------------------------------------------

    results.append({

        "_type": pii_type,

        "_value_key": normalized_value,

        "type": pii_type,

        "severity": severity,

        "masked": masked,
    })


# ============================================================
# CARD OVERLAP DETECTION
# ============================================================

def _matches_overlap(
    start: int,
    end: int,
    spans: List[Any],
) -> bool:
    """
    Check whether a candidate OCR span overlaps an existing
    sensitive-number match.
    """

    for span in spans:

        try:

            other_start = span.start()
            other_end = span.end()

        except Exception:

            continue

        if (
            start < other_end
            and end > other_start
        ):

            return True

    return False


# ============================================================
# CARD CONTEXT
# ============================================================

def _has_card_context(
    text: str,
) -> bool:
    """
    Determine whether OCR contains strong payment-card
    context.

    This is intentionally conservative and looks for
    recognizable card-related words.
    """

    if not text:
        return False

    return bool(
        re.search(
            r"\b("
            r"card|"
            r"visa|"
            r"mastercard|"
            r"master\s*card|"
            r"amex|"
            r"american\s*express|"
            r"discover|"
            r"debit|"
            r"credit|"
            r"expiry|"
            r"expires|"
            r"expiration|"
            r"valid|"
            r"validity|"
            r"valid\s*thru|"
            r"security\s*code|"
            r"cvv|"
            r"cvc"
            r")\b",
            text,
            re.IGNORECASE,
        )
    )


# ============================================================
# CARD CANDIDATE DETECTION
# ============================================================

def _extract_card_candidates(
    text: str,
) -> List[Any]:
    """
    Find possible 13-19 digit card-number spans.

    This function intentionally allows spaces and hyphens.

    Examples:
        4111 1111 1111 1111
        4111-1111-1111-1111
        4111111111111111

    It does not decide whether the number is valid.
    """

    if not text:
        return []

    card_pattern = re.compile(
        r"(?<!\d)"
        r"(?:\d[\s-]?){13,19}"
        r"(?!\d)"
    )

    return list(
        card_pattern.finditer(text)
    )


# ============================================================
# PUBLIC IMAGE PII DETECTOR
# ============================================================

def detect_image_pii(
    ocr_text: str,
) -> List[Dict[str, Any]]:
    """
    Detect sensitive information from OCR text.

    Supported:
        PAYMENT_CARD
        CARD_NUMBER
        CARD_EXPIRY
        CVV
        OTP
        AADHAAR
        PAN
        EMAIL
        PHONE_NUMBER
        URL

    IMPORTANT:
        Raw OCR text is never returned.
        Raw PII values are never returned.
    """

    results: List[Dict[str, Any]] = []

    if not ocr_text:
        return results

    text = _clean_text(
        ocr_text
    )

    if not text:
        return results

    # ========================================================
    # CARD CONTEXT
    # ========================================================

    has_card_context = _has_card_context(
        text
    )

    # ========================================================
    # PAYMENT CARD
    # ========================================================

    card_matches = []

    for match in _extract_card_candidates(text):

        candidate = match.group(0)
        digits = _digits_only(candidate)

        if not 13 <= len(digits) <= 19:
            continue

        # ----------------------------------------------------
        # Detection rule:
        #
        # 1. Valid Luhn => card
        #
        # OR
        #
        # 2. Strong card context + 13-19 digit candidate
        #    => card
        #
        # The second rule is necessary for synthetic/test
        # card images and OCR imperfections.
        # ----------------------------------------------------

        if (
            _luhn_check(digits)
            or has_card_context
        ):

            card_matches.append(
                match
            )

            _add_pii(
                results,
                "PAYMENT_CARD",
                digits,
                "CRITICAL",
            )

    # ========================================================
    # CARD EXPIRY
    # ========================================================

    expiry_pattern = re.compile(
        r"\b(?:0[1-9]|1[0-2])"
        r"\s*[/\-]"
        r"\s*"
        r"(?:\d{2}|\d{4})\b"
    )

    if has_card_context:

        for match in expiry_pattern.finditer(
            text
        ):

            _add_pii(
                results,
                "CARD_EXPIRY",
                match.group(0),
                "CRITICAL",
            )

    # ========================================================
    # CVV / CVC
    # ========================================================

    cvv_pattern = re.compile(
        r"\b("
        r"CVV|"
        r"CVC|"
        r"SECURITY\s*CODE|"
        r"CARD\s*SECURITY\s*CODE"
        r")"
        r"\s*(?:IS|=|:|-)?"
        r"\s*(\d{3,4})\b",
        re.IGNORECASE,
    )

    for match in cvv_pattern.finditer(text):

        _add_pii(
            results,
            "CVV",
            match.group(2),
            "CRITICAL",
        )

    # ========================================================
    # OTP
    # ========================================================

    otp_pattern = re.compile(
        r"\b("
        r"OTP|"
        r"ONE[\s-]?TIME[\s-]?PASSWORD"
        r")"
        r"\s*(?:IS|=|:|-)?"
        r"\s*(\d{4,8})\b",
        re.IGNORECASE,
    )

    for match in otp_pattern.finditer(text):

        _add_pii(
            results,
            "OTP",
            match.group(2),
            "CRITICAL",
        )

    # ========================================================
    # AADHAAR
    # ========================================================

    # --------------------------------------------------------
    # Spaced / hyphenated Aadhaar
    #
    # 1234 5678 9012
    # 1234-5678-9012
    # --------------------------------------------------------

    aadhaar_pattern = re.compile(
        r"(?<!\d)"
        r"\d{4}"
        r"[\s-]"
        r"\d{4}"
        r"[\s-]"
        r"\d{4}"
        r"(?!\d)"
    )

    for match in aadhaar_pattern.finditer(text):

        # Do not duplicate a payment-card match.
        if _matches_overlap(
            match.start(),
            match.end(),
            card_matches,
        ):
            continue

        _add_pii(
            results,
            "AADHAAR",
            match.group(0),
            "CRITICAL",
        )

    # --------------------------------------------------------
    # Continuous Aadhaar with explicit context
    # --------------------------------------------------------

    aadhaar_context_pattern = re.compile(
        r"\b(?:aadhaar|aadhar)"
        r"\s*(?:number|no|id)?"
        r"\s*[:\-]?\s*"
        r"(\d{12})\b",
        re.IGNORECASE,
    )

    for match in aadhaar_context_pattern.finditer(text):

        _add_pii(
            results,
            "AADHAAR",
            match.group(1),
            "CRITICAL",
        )

    # ========================================================
    # PAN
    # ========================================================

    pan_pattern = re.compile(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        re.IGNORECASE,
    )

    for match in pan_pattern.finditer(text):

        _add_pii(
            results,
            "PAN",
            match.group(0),
            "CRITICAL",
        )

    # ========================================================
    # EMAIL
    # ========================================================

    email_pattern = re.compile(
        r"\b[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\."
        r"[A-Za-z]{2,}\b"
    )

    for match in email_pattern.finditer(text):

        _add_pii(
            results,
            "EMAIL",
            match.group(0),
            "HIGH",
        )

    # ========================================================
    # PHONE NUMBER
    # ========================================================

    phone_pattern = re.compile(
        r"(?<!\d)"
        r"(?:\+?91[\s-]?)?"
        r"[6-9]\d{9}"
        r"(?!\d)"
    )

    for match in phone_pattern.finditer(text):

        # A phone-number candidate must not be treated as
        # another PII item if it overlaps a payment card.
        if _matches_overlap(
            match.start(),
            match.end(),
            card_matches,
        ):
            continue

        _add_pii(
            results,
            "PHONE_NUMBER",
            match.group(0),
            "HIGH",
        )

    # ========================================================
    # URL
    # ========================================================

    url_pattern = re.compile(
        r"\b(?:https?://|www\.)"
        r"[^\s<>()]+",
        re.IGNORECASE,
    )

    for match in url_pattern.finditer(text):

        url_value = match.group(0)

        url_value = url_value.rstrip(
            ".,!?;:"
        )

        if url_value:

            _add_pii(
                results,
                "URL",
                url_value,
                "MEDIUM",
            )

    # ========================================================
    # FINAL SANITIZATION
    # ========================================================

    cleaned_results = []

    for item in results:

        cleaned_results.append({

            "type": item.get(
                "type",
                "UNKNOWN",
            ),

            "severity": item.get(
                "severity",
                "MEDIUM",
            ),

            "masked": item.get(
                "masked",
                "[REDACTED]",
            ),
        })

    return cleaned_results


# ============================================================
# IMAGE VALIDATION
# ============================================================

def _validate_image_bytes(
    file_bytes: bytes,
) -> None:

    if not isinstance(
        file_bytes,
        (bytes, bytearray),
    ):

        raise ValueError(
            "Image data must be bytes."
        )

    if not file_bytes:

        raise ValueError(
            "Image data is empty."
        )

    if len(file_bytes) > MAX_IMAGE_BYTES:

        raise ValueError(
            "Image file is too large."
        )


# ============================================================
# IMAGE OPENING
# ============================================================

def _open_image(
    file_bytes: bytes,
) -> Image.Image:
    """
    Safely open and fully load an image.

    Raw bytes are not returned.

    Pillow determines whether the actual image bytes can
    be decoded. This keeps image validation based on the
    actual file rather than trusting only a browser MIME type.
    """

    _validate_image_bytes(
        file_bytes
    )

    try:

        with Image.open(
            io.BytesIO(file_bytes)
        ) as image_check:

            width, height = image_check.size

            if (
                width <= 0
                or height <= 0
            ):

                raise ValueError(
                    "Image dimensions are invalid."
                )

            if width * height > MAX_IMAGE_PIXELS:

                raise ValueError(
                    "Image contains too many pixels."
                )

            # Apply EXIF orientation while still inside the
            # controlled image object.
            image = ImageOps.exif_transpose(
                image_check
            )

            # Convert to RGB because the image classifier
            # and OCR expect a normal image representation.
            image = image.convert(
                "RGB"
            )

            # Fully load pixels before leaving the context.
            image.load()

            return image.copy()

    except UnidentifiedImageError:

        raise ValueError(
            "Invalid or unsupported image file."
        )

    except ValueError:

        raise

    except Exception as error:

        raise ValueError(
            "Invalid image file: "
            + type(error).__name__
        )


# ============================================================
# OCR PREPROCESSING
# ============================================================

def _prepare_image_for_ocr(
    image: Image.Image,
) -> Image.Image:
    """
    Prepare image for general OCR.
    """

    image = ImageOps.exif_transpose(
        image
    )

    image = image.convert(
        "RGB"
    )

    width, height = image.size

    if width < 1400:

        scale = 1400 / max(
            width,
            1,
        )

        image = image.resize(
            (
                int(width * scale),
                int(height * scale),
            ),
            Image.Resampling.LANCZOS,
        )

    image = ImageEnhance.Contrast(
        image
    ).enhance(1.5)

    image = ImageEnhance.Sharpness(
        image
    ).enhance(1.2)

    return image


# ============================================================
# CARD-SPECIFIC OCR PREPROCESSING
# ============================================================

def _prepare_image_for_card_ocr(
    image: Image.Image,
) -> Image.Image:
    """
    Additional preprocessing for payment-card text.

    This does not return OCR data. It only creates an
    internally processed image for Tesseract.

    The goal is to improve recognition when characters such
    as:
        4 -> $
        5 -> S
        6 -> b
        7 -> ?
        8 -> B

    are confused by normal OCR.
    """

    image = ImageOps.exif_transpose(
        image
    ).convert(
        "RGB"
    )

    width, height = image.size

    # Card numbers are usually displayed across a horizontal
    # portion of the image. Upscaling improves digit recognition.
    target_width = 1800

    if width < target_width:

        scale = target_width / max(
            width,
            1,
        )

        image = image.resize(
            (
                int(width * scale),
                int(height * scale),
            ),
            Image.Resampling.LANCZOS,
        )

    image = ImageEnhance.Contrast(
        image
    ).enhance(1.8)

    image = ImageEnhance.Sharpness(
        image
    ).enhance(1.4)

    return image


# ============================================================
# OCR - GENERAL
# ============================================================

def _extract_ocr_text(
    image: Image.Image,
) -> str:
    """
    Extract OCR internally.

    IMPORTANT:
        OCR text must never be returned to React,
        external LLMs, logs, or API responses.
    """

    if not OCR_AVAILABLE:
        return ""

    if pytesseract is None:
        return ""

    try:

        prepared = _prepare_image_for_ocr(
            image
        )

        # ----------------------------------------------------
        # General OCR
        # ----------------------------------------------------

        general_text = pytesseract.image_to_string(
            prepared,
            config="--psm 6",
            timeout=OCR_TIMEOUT_SECONDS,
        )

        # ----------------------------------------------------
        # Card/digit-focused OCR
        #
        # This is deliberately internal.
        #
        # It improves detection when OCR confuses digits
        # with letters in card numbers.
        # ----------------------------------------------------

        card_prepared = _prepare_image_for_card_ocr(
            image
        )

        digit_text = pytesseract.image_to_string(
            card_prepared,
            config=(
                '--psm 6 '
                '-c tessedit_char_whitelist="'
                '0123456789- /"'
            ),
            timeout=OCR_TIMEOUT_SECONDS,
        )

        # ----------------------------------------------------
        # Combine both OCR passes internally.
        #
        # Raw OCR never leaves this function.
        # ----------------------------------------------------

        combined = (
            str(general_text or "")
            + "\n"
            + str(digit_text or "")
        )

        return _clean_text(
            combined
        )

    except Exception as error:

        # Never print OCR text.
        print(
            "OCR error:",
            type(error).__name__,
        )

        return ""


# ============================================================
# IMAGE CLASSIFICATION
# ============================================================

def _classify_image(
    image: Image.Image,
) -> List[Dict[str, Any]]:

    classifier = get_image_classifier()

    try:

        results = classifier(
            image,
            top_k=2,
        )

    except Exception as error:

        print(
            "Image classification error:",
            type(error).__name__,
        )

        raise RuntimeError(
            "Image safety model could not analyze the image."
        )

    if (
        isinstance(results, list)
        and results
        and isinstance(results[0], list)
    ):

        results = results[0]

    if not isinstance(
        results,
        list,
    ):

        return []

    normalized = []

    for item in results:

        if not isinstance(
            item,
            dict,
        ):

            continue

        label = str(
            item.get(
                "label",
                "",
            )
        ).lower().strip()

        score = _clamp(
            item.get(
                "score",
                0.0,
            )
        )

        if not label:
            continue

        normalized.append({

            "label": label,

            "score": score,
        })

    return normalized


# ============================================================
# PUBLIC MODEL LOADER
# ============================================================

def get_image_classifier():

    global image_classifier

    if image_classifier is None:

        print(
            "\n"
            + "=" * 70
        )

        print(
            "Loading image safety model"
        )

        print(
            "=" * 70
        )

        print(
            "Model:",
            IMAGE_MODEL_NAME,
        )

        try:

            image_classifier = pipeline(
                "image-classification",
                model=IMAGE_MODEL_NAME,
            )

        except Exception as error:

            print(
                "Image model loading error:",
                type(error).__name__,
            )

            raise RuntimeError(
                "Unable to load image safety model."
            )

        print(
            "Image safety model loaded."
        )

        if OCR_AVAILABLE:

            print(
                "OCR available."
            )

        else:

            print(
                "WARNING: OCR unavailable."
            )

        print(
            "=" * 70
        )

    return image_classifier


# ============================================================
# NSFW SCORE EXTRACTION
# ============================================================

def _extract_nsfw_score(
    classifier_results: List[Dict[str, Any]],
) -> Dict[str, float]:

    nsfw_score = 0.0
    normal_score = 0.0

    nsfw_labels = {
        "nsfw",
        "porn",
        "sexual",
        "explicit",
        "unsafe",
        "indecent",
    }

    normal_labels = {
        "normal",
        "safe",
        "sfw",
    }

    for item in classifier_results:

        label = str(
            item.get(
                "label",
                "",
            )
        ).lower().strip()

        score = _clamp(
            item.get(
                "score",
                0.0,
            )
        )

        if label in nsfw_labels:

            nsfw_score = max(
                nsfw_score,
                score,
            )

        elif label in normal_labels:

            normal_score = max(
                normal_score,
                score,
            )

    return {

        "nsfw_score": _clamp(
            nsfw_score
        ),

        "normal_score": _clamp(
            normal_score
        ),
    }


# ============================================================
# IMAGE STATUS
# ============================================================

def _determine_status(
    nsfw_score: float,
    image_pii: List[Dict[str, Any]],
) -> str:

    # --------------------------------------------------------
    # Critical PII always BLOCKS.
    # --------------------------------------------------------

    if any(
        item.get("severity") == "CRITICAL"
        for item in image_pii
    ):

        return "BLOCK"

    # --------------------------------------------------------
    # High-confidence unsafe visual content.
    # --------------------------------------------------------

    if nsfw_score >= NSFW_BLOCK_THRESHOLD:

        return "BLOCK"

    # --------------------------------------------------------
    # Moderate visual risk.
    # --------------------------------------------------------

    if nsfw_score >= NSFW_WARN_THRESHOLD:

        return "WARN"

    # --------------------------------------------------------
    # High PII.
    # --------------------------------------------------------

    if any(
        item.get("severity") == "HIGH"
        for item in image_pii
    ):

        return "WARN"

    return "ALLOW"


# ============================================================
# IMAGE CATEGORY
# ============================================================

def _determine_category(
    nsfw_score: float,
    image_pii: List[Dict[str, Any]],
) -> str:

    if any(
        item.get("severity") == "CRITICAL"
        for item in image_pii
    ):

        return "sensitive_personal_information"

    if nsfw_score >= NSFW_BLOCK_THRESHOLD:

        return "explicit_or_nsfw"

    if nsfw_score >= NSFW_WARN_THRESHOLD:

        return "potentially_sensitive"

    if any(
        item.get("severity") == "HIGH"
        for item in image_pii
    ):

        return "personal_information"

    if any(
        item.get("severity") == "MEDIUM"
        for item in image_pii
    ):

        return "low_sensitivity_information"

    return "normal"


# ============================================================
# IMAGE REASON
# ============================================================

def _determine_reason(
    nsfw_score: float,
    image_pii: List[Dict[str, Any]],
) -> str:

    critical = []
    high = []
    medium = []

    for item in image_pii:

        pii_type = item.get(
            "type"
        )

        severity = item.get(
            "severity"
        )

        if severity == "CRITICAL":

            if pii_type not in critical:

                critical.append(
                    pii_type
                )

        elif severity == "HIGH":

            if pii_type not in high:

                high.append(
                    pii_type
                )

        elif severity == "MEDIUM":

            if pii_type not in medium:

                medium.append(
                    pii_type
                )

    if critical:

        return (
            "Critical sensitive information detected: "
            + ", ".join(critical)
        )

    if nsfw_score >= NSFW_BLOCK_THRESHOLD:

        return (
            "High-confidence potentially unsafe "
            "or explicit visual content detected."
        )

    if nsfw_score >= NSFW_WARN_THRESHOLD:

        return (
            "Potentially sensitive visual content detected."
        )

    if high:

        return (
            "Personal information detected: "
            + ", ".join(high)
        )

    if medium:

        return (
            "Potentially identifying information detected: "
            + ", ".join(medium)
        )

    return (
        "No significant image safety risk detected."
    )


# ============================================================
# IMAGE RISK
# ============================================================

def _calculate_image_risk(
    nsfw_score: float,
    image_pii: List[Dict[str, Any]],
) -> float:

    nsfw_score = _clamp(
        nsfw_score
    )

    # --------------------------------------------------------
    # Critical PII = maximum image risk.
    # --------------------------------------------------------

    if any(
        item.get("severity") == "CRITICAL"
        for item in image_pii
    ):

        return 1.0

    # --------------------------------------------------------
    # High PII.
    # --------------------------------------------------------

    if any(
        item.get("severity") == "HIGH"
        for item in image_pii
    ):

        return max(
            nsfw_score,
            0.75,
        )

    # --------------------------------------------------------
    # Medium PII.
    # --------------------------------------------------------

    if any(
        item.get("severity") == "MEDIUM"
        for item in image_pii
    ):

        return max(
            nsfw_score,
            0.35,
        )

    return nsfw_score


# ============================================================
# IMAGE TAGS
# ============================================================

def _build_tags(
    nsfw_score: float,
    image_pii: List[Dict[str, Any]],
    status: str,
) -> List[str]:

    tags = []

    if nsfw_score >= NSFW_BLOCK_THRESHOLD:

        tags.append(
            "explicit_or_nsfw_content"
        )

    elif nsfw_score >= NSFW_WARN_THRESHOLD:

        tags.append(
            "potentially_sensitive_content"
        )

    else:

        tags.append(
            "normal_visual_content"
        )

    pii_types = {
        item.get("type")
        for item in image_pii
        if item.get("type")
    }

    if (
        "PAYMENT_CARD" in pii_types
        or "CARD_NUMBER" in pii_types
    ):

        tags.append(
            "payment_card"
        )

    if any(
        pii_type in pii_types
        for pii_type in {
            "CARD_EXPIRY",
            "CVV",
            "OTP",
            "AADHAAR",
            "PAN",
        }
    ):

        tags.append(
            "critical_personal_information"
        )

    if any(
        pii_type in pii_types
        for pii_type in {
            "EMAIL",
            "PHONE_NUMBER",
        }
    ):

        tags.append(
            "personal_contact_information"
        )

    if "URL" in pii_types:

        tags.append(
            "url_detected"
        )

    if status == "BLOCK":

        tags.append(
            "high_risk"
        )

    elif status == "WARN":

        tags.append(
            "review_required"
        )

    return sorted(
        set(tags)
    )


# ============================================================
# SAFE RESULT BUILDER
# ============================================================

def _build_safe_result(
    image_risk_score: float,
    image_tags: List[str],
    image_status: str,
    image_category: str,
    image_reason: str,
    nsfw_score: float,
    normal_score: float,
    image_pii: List[Dict[str, Any]],
    ocr_available: bool,
    ocr_detected: bool,
) -> Dict[str, Any]:
    """
    Construct the final public-safe result.

    RAW OCR IS NOT INCLUDED.
    """

    safe_pii = []

    for item in image_pii:

        safe_pii.append({

            "type": str(
                item.get(
                    "type",
                    "UNKNOWN",
                )
            ),

            "severity": str(
                item.get(
                    "severity",
                    "MEDIUM",
                )
            ),

            "masked": str(
                item.get(
                    "masked",
                    "[REDACTED]",
                )
            ),
        })

    return {

        "image_risk_score": round(
            _clamp(
                image_risk_score
            ),
            4,
        ),

        "image_tags": list(
            image_tags
        ),

        "image_status": str(
            image_status
        ),

        "image_category": str(
            image_category
        ),

        "image_reason": str(
            image_reason
        ),

        "nsfw_score": round(
            _clamp(
                nsfw_score
            ),
            4,
        ),

        "normal_score": round(
            _clamp(
                normal_score
            ),
            4,
        ),

        "image_pii_detected": bool(
            safe_pii
        ),

        "image_pii": safe_pii,

        # Status metadata only.
        "ocr_available": bool(
            ocr_available
        ),

        "ocr_detected": bool(
            ocr_detected
        ),
    }


# ============================================================
# MAIN IMAGE ANALYZER
# ============================================================

def analyze_image_risk(
    file_bytes: bytes,
) -> Dict[str, Any]:
    """
    Complete image safety analysis.

    Pipeline:

        bytes
          ↓
        validation
          ↓
        safe image loading
          ↓
        NSFW classification
          ↓
        internal OCR
          ↓
        image PII detection
          ↓
        image risk
          ↓
        ALLOW / WARN / BLOCK
          ↓
        safe metadata only

    IMPORTANT:
        Raw OCR never leaves this function.
    """

    # ========================================================
    # OPEN / VALIDATE IMAGE
    # ========================================================

    image = _open_image(
        file_bytes
    )

    try:

        # ====================================================
        # VISUAL CLASSIFICATION
        # ====================================================

        classifier_results = _classify_image(
            image
        )

        scores = _extract_nsfw_score(
            classifier_results
        )

        nsfw_score = scores[
            "nsfw_score"
        ]

        normal_score = scores[
            "normal_score"
        ]

        # ====================================================
        # OCR
        # ====================================================

        # Raw OCR exists only inside this function.
        ocr_text = _extract_ocr_text(
            image
        )

        # ====================================================
        # IMAGE PII
        # ====================================================

        image_pii = detect_image_pii(
            ocr_text
        )

        # ====================================================
        # IMAGE RISK
        # ====================================================

        image_risk_score = _calculate_image_risk(
            nsfw_score,
            image_pii,
        )

        # ====================================================
        # IMAGE STATUS
        # ====================================================

        image_status = _determine_status(
            nsfw_score,
            image_pii,
        )

        # ====================================================
        # IMAGE CATEGORY
        # ====================================================

        image_category = _determine_category(
            nsfw_score,
            image_pii,
        )

        # ====================================================
        # IMAGE REASON
        # ====================================================

        image_reason = _determine_reason(
            nsfw_score,
            image_pii,
        )

        # ====================================================
        # IMAGE TAGS
        # ====================================================

        image_tags = _build_tags(
            nsfw_score,
            image_pii,
            image_status,
        )

        # ====================================================
        # SAFE RESULT
        # ====================================================

        return _build_safe_result(

            image_risk_score=image_risk_score,

            image_tags=image_tags,

            image_status=image_status,

            image_category=image_category,

            image_reason=image_reason,

            nsfw_score=nsfw_score,

            normal_score=normal_score,

            image_pii=image_pii,

            ocr_available=OCR_AVAILABLE,

            ocr_detected=bool(
                ocr_text
            ),
        )

    finally:

        # Release image resources explicitly.
        try:

            image.close()

        except Exception:

            pass


# ============================================================
# COMPATIBILITY PUBLIC FUNCTION
# ============================================================

def analyze_image(
    file_bytes: bytes,
) -> Dict[str, Any]:
    """
    Public compatibility wrapper.

    chat.py and tests can import:

        from app.pipeline.image_analyzer import analyze_image

    without depending on the internal function name.
    """

    return analyze_image_risk(
        file_bytes
    )


# ============================================================
# OPTIONAL PII SUMMARY
# ============================================================

def get_image_pii_types(
    image_pii: List[Dict[str, Any]],
) -> List[str]:

    if not isinstance(
        image_pii,
        list,
    ):

        return []

    types = []

    for item in image_pii:

        if not isinstance(
            item,
            dict,
        ):

            continue

        pii_type = item.get(
            "type"
        )

        if pii_type and pii_type not in types:

            types.append(
                str(pii_type)
            )

    return types


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print(
        "\n"
        + "=" * 70
    )

    print(
        "AI CHILD SAFETY - IMAGE ANALYZER"
    )

    print(
        "=" * 70
    )

    print(
        "\nModule loaded successfully."
    )

    print(
        "\nPublic functions:"
    )

    print(
        " - get_image_classifier()"
    )

    print(
        " - detect_image_pii()"
    )

    print(
        " - get_image_pii_types()"
    )

    print(
        " - analyze_image_risk()"
    )

    print(
        " - analyze_image()"
    )

    print(
        "\nConfiguration:"
    )

    print(
        " - Image model:",
        IMAGE_MODEL_NAME,
    )

    print(
        " - OCR available:",
        OCR_AVAILABLE,
    )

    print(
        " - Max image size:",
        f"{MAX_IMAGE_BYTES / (1024 * 1024):.0f} MB",
    )

    print(
        " - Max image pixels:",
        f"{MAX_IMAGE_PIXELS:,}",
    )

    # --------------------------------------------------------
    # Direct PII detector tests.
    #
    # These do NOT require the image model and therefore
    # provide a quick sanity check for OCR-PII processing.
    # --------------------------------------------------------

    print(
        "\n"
        + "-" * 70
    )

    print(
        "IMAGE PII DIRECT TESTS"
    )

    print(
        "-" * 70
    )

    pii_tests = [

        (
            "Aadhaar",
            "My Aadhaar is 1234 5678 9012",
        ),

        (
            "PAN",
            "My PAN is ABCDE1234F",
        ),

        (
            "Email",
            "Email me at example@gmail.com",
        ),

        (
            "Phone",
            "Call me at 9876543210",
        ),

        (
            "OTP",
            "My OTP is 123456",
        ),

        (
            "CVV",
            "CVV is 123",
        ),

        (
            "Card - Luhn valid",
            "My card number is 4111 1111 1111 1111",
        ),

        (
            "Card - contextual synthetic/test number",
            "Visa Classic 4000 1234 5678 9010",
        ),

        (
            "Expiry",
            "My credit card expiry is 12/29",
        ),

        (
            "URL",
            "Visit https://example.com",
        ),
    ]

    for name, text in pii_tests:

        result = detect_image_pii(
            text
        )

        print(
            f"\n{name}:"
        )

        print(
            result
        )

    # --------------------------------------------------------
    # Verify the exact synthetic/test card number used in
    # the user's image.
    # --------------------------------------------------------

    test_card = (
        "Visa Classic "
        "4000 1234 5678 9010 "
        "12/20"
    )

    print(
        "\n"
        + "-" * 70
    )

    print(
        "SYNTHETIC VISA IMAGE-TEXT TEST"
    )

    print(
        "-" * 70
    )

    print(
        "Card detection:"
    )

    print(
        detect_image_pii(
            test_card
        )
    )

    # --------------------------------------------------------
    # Optional full-image test.
    #
    # Set:
    #
    # IMAGE_ANALYZER_TEST_IMAGE=C:\\path\\to\\image.png
    #
    # before running this module if you want to test a real
    # image through the complete analyzer.
    #
    # Raw OCR is NEVER printed.
    # --------------------------------------------------------

    test_image_path = os.getenv(
        "IMAGE_ANALYZER_TEST_IMAGE",
        "",
    ).strip()

    if test_image_path:

        print(
            "\n"
            + "-" * 70
        )

        print(
            "FULL IMAGE TEST"
        )

        print(
            "-" * 70
        )

        try:

            with open(
                test_image_path,
                "rb",
            ) as image_file:

                image_bytes = image_file.read()

            result = analyze_image_risk(
                image_bytes
            )

            print(
                "Full image result:"
            )

            print(
                result
            )

        except Exception as error:

            print(
                "Full image test error:",
                type(error).__name__,
            )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "DIRECT TEST COMPLETE"
    )

    print(
        "=" * 70
    )