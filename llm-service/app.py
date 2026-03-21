"""
LLM microservice – FastAPI server that hosts the fine-tuned Gemma 2 2B model
and exposes an OpenAI-compatible /v1/chat/completions endpoint.

Run on the GPU machine:
    uvicorn app:app --host 0.0.0.0 --port 8001

The backend's llm_client.py will call this when LLM_PROVIDER=local.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import model as llm_model

app = FastAPI(title="LLMShield – Local LLM Service")


# ──────────────────────────────────────────────────────────────────────────────
# Request / Response schemas  (OpenAI-compatible)
# ──────────────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    response_format: Optional[dict] = None


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "model": llm_model.BASE_MODEL_NAME}


@app.post("/v1/chat/completions")
def chat_completions(req: ChatRequest):
    """
    OpenAI-compatible chat completion endpoint.
    The backend calls this exactly the same way it would call api.openai.com.
    """
    try:
        messages = [{"role": m.role, "content": m.content} for m in req.messages]
        content = llm_model.generate(messages, req.response_format)

        # Return an OpenAI-compatible response envelope
        return {
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "model": llm_model.BASE_MODEL_NAME,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
