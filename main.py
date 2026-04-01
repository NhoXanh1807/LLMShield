
import time
import sys
import json
sys.stdout.reconfigure(encoding='utf-8')
print("importing libraries...")

from config import Config
from interfaces import AttackLLMInterface, PromptRequest
from services import fetchPromptQueue, updateAnswer


def load_model(model_name, hf_token) -> AttackLLMInterface:
    if model_name == "FAKE":
        from model_versions.simulator.interface import SimulateModel
        model = SimulateModel(hf_token, load_immediately=True)
    elif model_name == "GEMMA_2B":
        from model_versions.gemma2_2b.interface import Gemma2_2B
        model = Gemma2_2B(hf_token, load_immediately=True)
    elif model_name == "QWEN_3B":
        from model_versions.qwen25_3b.interface import Qwen25_3B
        model = Qwen25_3B(hf_token, load_immediately=True)
    else:
        print(f"Model {model_name} not found.")
        exit(1)
    return model


def generate_response(model: AttackLLMInterface, prompt_request: PromptRequest) -> str:
    response = model.generate(
        prompt=prompt_request.prompt,
        max_new_tokens=prompt_request.max_new_tokens, 
        temperature=prompt_request.temperature, 
        adapter_name=prompt_request.adapter_name
    )
    print(f"generate_response() -> {response}")
    return response


if __name__ == "__main__":
    print("Config model name :", Config.MODEL_NAME)
    # Load HF token from command line argument or file
    if len(sys.argv) >= 2:
        Config.HF_TOKEN = sys.argv[1]
    else:
        with open("hf_token.txt", "r") as f:
            Config.HF_TOKEN = f.read().strip()
    
    # Validate HF token
    if not Config.HF_TOKEN:
        print("HF_TOKEN not provided.")
        exit(1)
    
    model = load_model(Config.MODEL_NAME, Config.HF_TOKEN)
    
    while True:
        print("Fetching prompt from queue...")
        prompt_request = None
        while prompt_request is None:
            prompt_request = fetchPromptQueue()
            time.sleep(3)
        
        print("Received prompt:")
        print("\t" + prompt_request.prompt.replace("\n", "\n\t"))
        
        print("Generating response...")
        response = generate_response(model, prompt_request)
        print("\t" + response.replace("\n", "\n\t"))
        
        print("Updating answer...")
        updateAnswer(prompt_request.id, response)
