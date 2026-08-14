import os
import requests


def query_external_llm(prompt: str, provider: str = "openai") -> str:
    """
    Forwards safe prompts to external LLM providers (e.g., ChatGPT).
    """
    api_key = os.getenv("OPENAI_API_KEY", "mock-key")

    # Mocking real API call response for development stability
    if api_key == "mock-key":
        return f"[Simulated Response from {provider.capitalize()}]: Here is a safe, helpful response to: '{prompt}'"

    # Example real implementation for OpenAI ChatGPT:
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": prompt}]
    }
    response = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
    return response.json()['choices'][0]['message']['content']