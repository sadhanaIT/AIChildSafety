"""
Text Preprocessing and PII Detection Module
-------------------------------------------
Implements:
1. Regex Pattern Detection (Phone numbers, Emails, Passwords, URLs, IDs)
2. spaCy Named Entity Recognition (NER) for PII (Names, Locations)
3. NLP Text Cleaning (Tokenization, Stop Word Removal, Lemmatization)
"""

import re
import spacy
from typing import Dict, List, Any

# Load spaCy English language model for NER and Lemmatization
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    raise RuntimeError("spaCy model 'en_core_web_sm' is missing. Run: python -m spacy download en_core_web_sm")

# Regex compilation for sensitive information detection
REGEX_PATTERNS = {
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "url": re.compile(
        r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"),
    "password_keyword": re.compile(r"(?i)\b(password|passwd|pin|secret|passcode)\b\s*[:=]?\s*\S+"),
    "id_number": re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9,12}\b")  # SSN format or generic IDs
}


def detect_pii_regex(text: str) -> List[str]:
    """Detects PII matches using pre-compiled regular expressions."""
    detected = []
    for pii_type, pattern in REGEX_PATTERNS.items():
        if pattern.search(text):
            detected.append(f"REGEX_{pii_type.upper()}")
    return detected


def detect_pii_ner(doc: spacy.tokens.Doc) -> List[str]:
    """Detects Named Entities (Names, Locations, Organizations) via spaCy NER."""
    detected = []
    sensitive_labels = {"PERSON": "NAME", "GPE": "LOCATION", "LOC": "LOCATION", "ORG": "ORGANIZATION"}

    for ent in doc.ents:
        if ent.label_ in sensitive_labels:
            detected.append(f"NER_{sensitive_labels[ent.label_]}:{ent.text}")

    return list(set(detected))


def preprocess_text(text: str) -> Dict[str, Any]:
    """
    Main NLP pipeline function.
    Cleans input, extracts PII via Regex + spaCy NER, and outputs lemmatized tokens.
    """
    cleaned_input = text.strip()
    doc = nlp(cleaned_input)

    # 1. PII Detection (Regex + NER)
    regex_pii = detect_pii_regex(cleaned_input)
    ner_pii = detect_pii_ner(doc)
    all_pii = regex_pii + ner_pii

    # 2. Tokenization, Stop Word Removal, and Lemmatization
    lemmas = [
        token.lemma_.lower()
        for token in doc
        if not token.is_stop and not token.is_punct and not token.is_space
    ]

    return {
        "original_text": text,
        "cleaned_text": cleaned_input,
        "lemmas": lemmas,
        "pii_detected": all_pii,
        "has_pii": len(all_pii) > 0
    }


# Quick verification block
if __name__ == "__main__":
    sample_text = "Hi! My name is Alice, my email is alice@example.com and my phone is 123-456-7890. I live in New York."
    result = preprocess_text(sample_text)

    print("Cleaned Lemmas:", result["lemmas"])
    print("PII Found:", result["pii_detected"])
    print("Has PII:", result["has_pii"])