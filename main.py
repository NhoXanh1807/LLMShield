
import time
import sys
import json
sys.stdout.reconfigure(encoding='utf-8')
print("importing libraries...")

from config import Config
from interfaces import AttackLLMInterface, Request
from services import fetchRequest, updateResponse


def load_model(model_name, hf_token) -> AttackLLMInterface:
    if model_name == "FAKE":
        from model_versions.simulator.interface import SimulateModel
        model = SimulateModel(hf_token, load_immediately=True)
    elif model_name == "GEMMA_2B":
        from model_versions.gemma2_2b.interface import Gemma2_2B
        model = Gemma2_2B(hf_token, load_immediately=True)
    else:
        print(f"Model {model_name} not found.")
        exit(1)
    return model


def generate_response(model: AttackLLMInterface, data: dict) -> str:
    prompt = data.get("prompt", None)
    if prompt is None:
        return "Error: No prompt provided."
    response = model.generate(
        prompt=prompt,
        max_new_tokens=data.get("max_new_tokens", 128), 
        temperature=data.get("temperature", 0.7), 
        adapter_name=data.get("adapter_name", "")
    )
    return response


def build_prompt(model: AttackLLMInterface, data: dict) -> str:
    success, prompt = model.build_prompt(data)
    return prompt


def generate_payload(model: AttackLLMInterface, data: dict) -> str:
    return model.generate_payload(data)



if __name__ == "__main__":
    print("Config model name :", Config.MODEL_NAME)
    # Load HF token from command line argument or file
    if len(sys.argv) >= 2:
        Config.HF_TOKEN = sys.argv[1]
        with open("hf_token.txt", "w") as f:
            f.write(Config.HF_TOKEN)
    else:
        with open("hf_token.txt", "r") as f:
            Config.HF_TOKEN = f.read().strip()
    
    # Validate HF token
    if not Config.HF_TOKEN:
        print("HF_TOKEN not provided.")
        exit(1)
    
    model = load_model(Config.MODEL_NAME, Config.HF_TOKEN)
    
    while True:
        print("Fetching request from queue...")
        request = None
        while request is None:
            request = fetchRequest()
            time.sleep(1)
        
        print("Request: ", request.action)
        response = None
        if request.action == "generate":
            response = generate_response(model, request.data)
        elif request.action == "build_prompt":
            response = build_prompt(model, request.data)
        elif request.action == "generate_payload":
            response = generate_payload(model, request.data)
        else:
            response = f"Error: Unknown action '{request.action}'"
        print("Response: ")
        print("\t" + response.replace("\n", "\n\t"))
        
        print("Updating answer...")
        updateResponse(request.id, response)
