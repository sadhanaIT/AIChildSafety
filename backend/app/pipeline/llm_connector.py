import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


# ============================================================
# ENVIRONMENT CONFIGURATION
# ============================================================

# llm_connector.py
#     ↓ parent = pipeline
#     ↓ parent = app
#     ↓ parent = backend
BASE_DIR = Path(__file__).resolve().parents[2]

ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE)

api_key = os.getenv("GEMINI_API_KEY")

print("LLM Connector .env path:", ENV_FILE)
print("LLM Connector API key loaded:", bool(api_key))


# ============================================================
# GEMINI CLIENT
# ============================================================

client = genai.Client(api_key=api_key) if api_key else None


# ============================================================
# LLM QUERY
# ============================================================

def query_external_llm(prompt: str, provider: str = "gemini") -> str:
    """
    Sends a sanitized child prompt to Google Gemini.
    """

    if client is None:
        print("⚠️ Gemini client unavailable. Using mock response.")

        return (
            "[Mock AI Response] "
            "I'm here to help you learn and explore safely!"
        )

    try:
        response = client.models.generate_content(
            model="gemini-3.7-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=(
                    "You are KiddieSafe AI, a warm, educational and "
                    "completely safe AI companion designed for children. "
                    "Keep answers brief, encouraging, wholesome and "
                    "age-appropriate. Never provide sexual, violent, "
                    "dangerous or inappropriate content."
                ),
                temperature=0.7,
                max_output_tokens=300,
            ),
        )

        if response.text:
            return response.text.strip()

        return "I'm having trouble generating a response right now."

    except Exception as e:
        print(f"⚠️ Gemini API Connection Error: {e}")

        return (
            "I'm having a little trouble connecting right now, "
            "but I'm still here with you!"
        )