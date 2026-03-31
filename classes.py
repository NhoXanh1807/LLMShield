
from dataclasses import dataclass

class AttackLLMInterface:
    def __init__(self, hf_token, load_immediately=False):
        raise NotImplementedError("This method should be implemented by subclasses")
    
    def load_model(self):
        raise NotImplementedError("This method should be implemented by subclasses")
    
    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "") -> str:
        raise NotImplementedError("This method should be implemented by subclasses")


@dataclass
class PromptRequest:
    id: str
    prompt: str
    max_new_tokens: int = 128
    temperature: float = 0.7
    adapter_name: str = ""
    answer: str = None