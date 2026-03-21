print("importing libraries...")

import requests
from dataclasses import dataclass
from llm4waf import Gemma2B, Qwen25_3B, _WafAttackModel
import time
import sys
sys.stdout.reconfigure(encoding='utf-8')


MODELS = {
    "GEMMA_2B": {
        "model" : None, 
        "default_adapter": "phase3_rl"
    },
    "QWEN25_3B": {
        "model" : None,
        "default_adapter": "phase3_rl"
    }
}

@dataclass
class PromptRequest:
    id: str
    prompt: str
    model_name: str = "GEMMA_2B"
    adapter_name: str = "phase1"
    max_new_tokens: int = 128
    temperature: float = 0.7
    answer: str = None

def load_model(hf_token):
    return
    print("Loading models...")
    global MODELS
    MODELS["GEMMA_2B"]["model"] = Gemma2B(hf_token, True)
    # MODELS["QWEN25_3B"]["model"] = Qwen25_3B(hf_token)
    print("Models loaded.")

def fetchPromptQueue():
    try:
        res = requests.get("http://api.akng.io.vn:89/generation")
        if (res.status_code == 200 
            and "data" in res.json() 
            and res.json()["data"] is not None 
            and "id" in res.json()["data"] 
            and "prompt" in res.json()["data"]
        ):
            return PromptRequest(**res.json()["data"])
        else:
            return None
    except Exception as e:
        print(f"Error fetching prompt: {e}")
        time.sleep(5)
        print("Retrying fetch...")
        return None

def generate_response(prompt_request: PromptRequest) -> str:
    return "This is a placeholder response. The model is not loaded in this demo."
    model_name = prompt_request.model_name
    adapter_name = prompt_request.adapter_name
    prompt = prompt_request.prompt
    max_new_tokens = prompt_request.max_new_tokens
    temperature = prompt_request.temperature


    if model_name not in MODELS:
        raise ValueError(f"Model {model_name} not found")
    
    model = MODELS[model_name]["model"] # type: _WafAttackModel
    if model is None:
        raise ValueError(f"Model {model_name} not loaded")
    
    if adapter_name is None:
        adapter_name = MODELS[model_name]["default_adapter"]
    
    response = model.generate_response(
        prompt=prompt,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        adapter_name=adapter_name
    )
    return response

def updateAnswer(id, answer):
    try:
        res = requests.put("http://api.akng.io.vn:89/generation", json={
            "id": id,
            "answer": answer
        })
        if res.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error updating answer: {e}")
        time.sleep(5)
        print("Retrying update...")
        return False


if __name__ == "__main__":
    hf_token = None
    if len(sys.argv) >= 2:
        hf_token = sys.argv[1]
        with open("hf_token.txt", "w") as f:
            f.write(hf_token)
    else:
        with open("hf_token.txt", "r") as f:
            hf_token = f.read().strip()
    
    if not hf_token:
        print("Hugging Face token is required. Please provide it as a command line argument or store it in hf_token.txt")
        exit(1)
    
    load_model(hf_token)
    
    while True:
        print("Fetching prompt from queue...")
        prompt_request = None
        while prompt_request is None:
            prompt_request = fetchPromptQueue()
            time.sleep(3)
        
        print("Received prompt:")
        print("\t" + prompt_request.prompt.replace("\n", "\n\t"))
        
        print("Generating response...")
        response = generate_response(prompt_request)
        
        print("Updating answer...")
        updateAnswer(prompt_request.id, response)
