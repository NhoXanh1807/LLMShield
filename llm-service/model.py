"""
Model loader and inference engine for the fine-tuned Gemma 2 2B model.

Loaded once at startup; reused for every request.
"""

import json
import os
import re
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel

BASE_MODEL_NAME = os.getenv("BASE_MODEL", "google/gemma-2-2b-it")
ADAPTER_PATH = os.getenv("ADAPTER_PATH", "./adapter")
MAX_NEW_TOKENS = int(os.getenv("MAX_NEW_TOKENS", "1024"))

# Load once at module import time
print(f"[llm-service] Loading base model: {BASE_MODEL_NAME}")
print(f"[llm-service] Loading LoRA adapter from: {ADAPTER_PATH}")

_bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)

_tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)

_base = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_NAME,
    quantization_config=_bnb_config,
    device_map="auto",
)

_model = PeftModel.from_pretrained(_base, ADAPTER_PATH)
_model.eval()

print("[llm-service] Model loaded successfully.")


def generate(messages: list, response_format: dict = None) -> str:
    """
    Run inference for a list of chat messages.

    Args:
        messages: [{"role": "system"|"user"|"assistant", "content": "..."}]
        response_format: Ignored by the local model; kept for API compatibility.
                         The prompt already instructs the model to return JSON.

    Returns:
        The model's response as a plain string (should be valid JSON when
        the caller passes a json_schema response_format).
    """
    # Build prompt using the model's chat template
    prompt = _tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )

    # If structured JSON output is expected, append a reminder
    if response_format and response_format.get("type") == "json_schema":
        schema_name = response_format.get("json_schema", {}).get("name", "")
        prompt += f"\n\nRespond ONLY with valid JSON matching the {schema_name} schema. Do not include markdown or extra text."

    inputs = _tokenizer(prompt, return_tensors="pt").to(_model.device)

    with torch.no_grad():
        output_ids = _model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=_tokenizer.eos_token_id,
        )

    # Decode only the newly generated tokens (skip the prompt)
    generated = _tokenizer.decode(
        output_ids[0][inputs["input_ids"].shape[1]:],
        skip_special_tokens=True,
    ).strip()

    # If response_format requires JSON, try to extract a JSON block
    if response_format and response_format.get("type") == "json_schema":
        generated = _extract_json(generated)

    return generated


def _extract_json(text: str) -> str:
    """
    Extract the first JSON object from text.
    Falls back to returning the raw text if no JSON block is found.
    """
    # Try ```json ... ``` fenced block first
    match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if match:
        return match.group(1)

    # Try bare {...}
    match = re.search(r"(\{[\s\S]*\})", text)
    if match:
        candidate = match.group(1)
        try:
            json.loads(candidate)  # validate
            return candidate
        except json.JSONDecodeError:
            pass

    return text
