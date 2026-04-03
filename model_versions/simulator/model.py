import json

from interfaces import AttackLLMInterface

class SimulateModel(AttackLLMInterface):
    def __init__(self, hf_token, load_immediately=False):
        self.hf_token = hf_token
        self.loaded = False
        if load_immediately:
            self.load_model()

    def load_model(self):
        print("SimulateModel: Simulating model loading...")
        self.loaded = True

    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "") -> str:
        if not self.loaded:
            self.load_model()
        return "Simulated response to: " + prompt
    
    def build_prompt(self, data) -> tuple[bool, str]:
        return True, f"SimulatedPrompt({json.dumps(data)})"
    
    def generate_payload(self, data) -> str:
        success, prompt = self.build_prompt(data)
        data["prompt"] = prompt
        return f"SimulatedPayload({json.dumps(data)})"