
from llm.interfaces import AttackLLMInterface

from llm.model_versions.simulator.model import SimulateModel
from llm.model_versions.gemma2_2b.model import Gemma2_2B
from llm.model_versions.qwen35_4b.model import Qwen35_4B


class Config:
    MODEL_NAME = "FAKE" # ["FAKE", "GEMMA_2B", "QWEN_3B"]
    HF_TOKEN = ""
    MODEL : AttackLLMInterface|None = None
    NGROK_AUTHTOKEN = "3BsAFITReQh3QiJIsB40v8gPy7p_4mDoBhSHJuTopT1KysYgT"
    NGROK_DOMAIN = "overrigged-savingly-nelle.ngrok-free.dev"
    HOST_NAME = "127.0.0.1"
    PORT = 89
    MODEL_LOADERS = {
        "FAKE": SimulateModel,
        "GEMMA_2B": Gemma2_2B,
        "QWEN_4B": Qwen35_4B
    }