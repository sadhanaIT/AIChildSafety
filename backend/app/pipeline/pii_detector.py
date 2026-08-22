import spacy
import re

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    nlp = None

def detect_pii(text: str) -> list:
    """
    Scans text for PII using spaCy NER and advanced Regex patterns
    (Emails, Phone Numbers, URLs, Passwords, IDs).
    """
    detected_entities = []
    if not nlp:
        return []

    # 1. spaCy NER (Names, Locations, Organizations)
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "ORG", "GPE", "LOC"]:
            detected_entities.append({
                "text": ent.text,
                "type": ent.label_,
                "source": "spaCy NER"
            })

    # 2. Comprehensive Regex Patterns
    patterns = {
        "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "PHONE_NUMBER": r'\b\+?\d{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "URL": r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
        "IP_ADDRESS": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        # Simple heuristic pattern for ID numbers (e.g., 10-12 digit numbers)
        "ID_NUMBER": r'\b\d{10,12}\b',
        # Password pattern keywords
        "PASSWORD_LEAK": r'(?:password|passwd|pwd)[\s:=]+([^\s]+)'
    }

    for pii_type, pattern in patterns.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched_value = match.group(1) if pii_type == "PASSWORD_LEAK" else match.group()
            detected_entities.append({
                "text": matched_value,
                "type": pii_type,
                "source": "Regex"
            })

    return detected_entities