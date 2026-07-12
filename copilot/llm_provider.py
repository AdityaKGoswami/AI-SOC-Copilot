"""
Thin adapter so the triage pipeline isn't locked to one LLM provider.
Set LLM_PROVIDER=anthropic (default) or LLM_PROVIDER=openai in your .env.
"""

import os
import json


class LLMProvider:
    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    def __init__(self, model: str = "claude-haiku-4-5-20251001"):
        import anthropic
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model = model

    def complete(self, system: str, user: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=800,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text


class OpenAIProvider(LLMProvider):
    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model

    def complete(self, system: str, user: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=800,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content


class MockProvider(LLMProvider):
    """No API key required — returns a deterministic, clearly-labeled mock
    response so the full pipeline (sanitizer -> prompt -> parse -> validate)
    can be exercised and demoed without any cost or credentials. This is NOT
    real analysis; it exists purely so evaluators can run the pipeline
    end-to-end without needing an API key."""

    def complete(self, system: str, user: str) -> str:
        injected = "injection_attempt_detected\": true" if "sanitization flagged" in user else "injection_attempt_detected\": false"
        return json.dumps({
            "attack_technique": "T1204.002",
            "severity": "Medium",
            "confidence": 55,
            "recommended_action": "[MOCK MODE — no LLM called] Manually review this alert; set an API key for real analysis.",
            "explanation": "This is a mock response for demonstration purposes only — no LLM was actually called.",
            "injection_attempt_detected": "injection_attempt_detected" in injected and "true" in injected,
        })


def get_provider() -> LLMProvider:
    provider_name = os.getenv("LLM_PROVIDER", "anthropic").lower()
    if provider_name == "anthropic":
        return AnthropicProvider()
    elif provider_name == "openai":
        return OpenAIProvider()
    elif provider_name == "mock":
        return MockProvider()
    raise ValueError(f"Unknown LLM_PROVIDER: {provider_name}")
