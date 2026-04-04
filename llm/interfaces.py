
from dataclasses import dataclass

class AttackLLMInterface:
    def __init__(self, hf_token, load_immediately=False):
        raise NotImplementedError("This method should be implemented by subclasses")
    
    def load_model(self):
        raise NotImplementedError("This method should be implemented by subclasses")
    
    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "") -> str:
        raise NotImplementedError("This method should be implemented by subclasses")
    
    def build_prompt(self, args : dict) -> tuple[bool, str]:
        raise NotImplementedError("This method should be implemented by subclasses")
    
    def generate_payload(self, args : dict) -> str:
        raise NotImplementedError("This method should be implemented by subclasses")

@dataclass
class Request:
    id: str
    action: str
    data: dict