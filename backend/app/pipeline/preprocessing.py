import re
import spacy

# Load spaCy English model for Named Entity Recognition (NER)
nlp = spacy.load("en_core_web_sm")

# Regular Expressions for sensitive PII detection
REGEX_PATTERNS = {
    "phone": r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "password": r"(?i)\b(password|passwd|pin)\b\s*[:=]?\s*\S+"
}

def preprocess_and_detect_pii(text: str) -> dict:
    cleaned_text = text.strip()
    detected_pii = []

    # 1. Regex Match for Phones, Emails, Passwords
    for pii_type, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, cleaned_text):
            detected_pii.append(pii_type)

    # 2. spaCy NER Match for Names and Locations
    doc = nlp(cleaned_text)
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "GPE", "LOC"]:
            detected_pii.append(f"{ent.label_}:{ent.text}")

    # 3. NLP Preprocessing Pipeline: Lemmatization & Stopword Removal
    lemmas = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct]

    return {
        "cleaned_text": cleaned_text,
        "lemmas": lemmas,
        "pii_detected": list(set(detected_pii))
    }