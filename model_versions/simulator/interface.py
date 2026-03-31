from classes import AttackLLMInterface

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