"""
Application settings loaded from environment variables.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ─── LLM Provider ─────────────────────────────────────────────────────────────
# Set LLM_PROVIDER=openai  → calls OpenAI API directly (no GPU required)
# Set LLM_PROVIDER=local   → calls the llm-service microservice (GPU required)
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")

# OpenAI settings (used when LLM_PROVIDER=openai)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

# Local LLM service settings (used when LLM_PROVIDER=local)
LLM_SERVICE_URL = os.getenv("LLM_SERVICE_URL", "http://localhost:8001")

# ─── DVWA Target ──────────────────────────────────────────────────────────────
DVWA_BASE_URL = os.getenv("DVWA_BASE_URL", "http://modsec.llmshield.click")
DVWA_USERNAME = os.getenv("DVWA_USERNAME", "admin")
DVWA_PASSWORD = os.getenv("DVWA_PASSWORD", "password")
DVWA_SECURITY_LEVEL = os.getenv("DVWA_SECURITY_LEVEL", "low")

# ─── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_NUM_PAYLOADS = int(os.getenv("DEFAULT_NUM_PAYLOADS", "5"))
DEFAULT_NUM_DEFENSE_RULES = int(os.getenv("DEFAULT_NUM_DEFENSE_RULES", "3"))
