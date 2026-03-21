"""
LLM abstraction layer.

Supports two providers, configured via LLM_PROVIDER environment variable:

  LLM_PROVIDER=openai   – Call OpenAI API directly.
                          Requires OPENAI_API_KEY.
                          No GPU needed; anyone can run the backend locally.

  LLM_PROVIDER=local    – Call the llm-service microservice.
                          Requires LLM_SERVICE_URL pointing to a running
                          instance of ../llm-service (FastAPI server that
                          hosts the fine-tuned Gemma 2 2B model).
                          The microservice exposes an OpenAI-compatible
                          /v1/chat/completions endpoint.
"""

import requests
try:
    from ..config import settings
except ImportError:
    from config import settings


class LLMClient:
    """Unified LLM client that delegates to either OpenAI or the local model."""

    def chat_completion(self, messages: list, response_format: dict = None) -> dict:
        """
        Send a chat-completion request.

        Args:
            messages: List of {"role": ..., "content": ...} dicts.
            response_format: Optional structured-output schema (OpenAI json_schema format).

        Returns:
            The raw API response dict (OpenAI-compatible shape).
        """
        if settings.LLM_PROVIDER == "local":
            return self._call_local(messages, response_format)
        return self._call_openai(messages, response_format)

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _call_openai(self, messages: list, response_format: dict = None) -> dict:
        """Call the real OpenAI API."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
        }
        body = {
            "model": settings.OPENAI_MODEL,
            "messages": messages,
        }
        if response_format:
            body["response_format"] = response_format

        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=body,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()

    def _call_local(self, messages: list, response_format: dict = None) -> dict:
        """
        Call the local LLM microservice.

        The microservice exposes the same /v1/chat/completions interface so the
        rest of the backend code is identical regardless of provider.
        """
        body = {"messages": messages}
        if response_format:
            body["response_format"] = response_format

        resp = requests.post(
            f"{settings.LLM_SERVICE_URL}/v1/chat/completions",
            json=body,
            timeout=300,  # local inference can be slow
        )
        resp.raise_for_status()
        return resp.json()


# Module-level singleton so services don't need to instantiate it each time
llm_client = LLMClient()
