import os
from llm.interfaces import AttackLLMInterface
from enum import Enum
import json

class Qwen35_4B(AttackLLMInterface):
    def __init__(self, hf_token, load_immediately=False):
        self.hf_token = hf_token
        self.loaded = False
        if load_immediately:
            self.load_model()
            
    BASE_MODEL = "Qwen/Qwen3.5-4B"
    
    class AdapterName(Enum):
        DPO_BEST = "dpo_best"
        PPO_BEST = "ppo_best"
        SFT = "sft_baseline"
    
    
    def load_model(self):
        if self.loaded:
            return
        
        print(f"Loading {self.BASE_MODEL}...")
    
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        from peft import PeftModel
        
        if torch.cuda.is_available():
            print("Using CUDA device")
            print([torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())])
            self.device = torch.device("cuda")
            device_map = {"": 0}
        else:
            print("Using CPU device")
            self.device = torch.device("cpu")
            device_map = "auto"

        # Load base model
        self.model = AutoModelForCausalLM.from_pretrained(
            self.BASE_MODEL,
            device_map=device_map,
            token=self.hf_token,
            dtype=torch.bfloat16,
            trust_remote_code=True
        )
        self.tokenizer = AutoTokenizer.from_pretrained(self.BASE_MODEL, trust_remote_code=True)
        self.tokenizer.pad_token = self.tokenizer.pad_token or self.tokenizer.eos_token
        
        # Prepare adapter paths
        adapters_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'adapters')
        self.adapter_paths = {
            self.AdapterName.DPO_BEST.value: os.path.join(adapters_dir, "dpo_best"),
            self.AdapterName.PPO_BEST.value: os.path.join(adapters_dir, "ppo_best"),
            self.AdapterName.SFT.value: os.path.join(adapters_dir, "sft_baseline")
        }
        
        # Load adapter
        self.model = PeftModel.from_pretrained(self.model, self.adapter_paths[self.AdapterName.DPO_BEST.value], adapter_name=self.AdapterName.DPO_BEST.value)
        if os.path.exists(self.adapter_paths[self.AdapterName.DPO_BEST.value]):
            self.model.load_adapter(self.adapter_paths[self.AdapterName.DPO_BEST.value], adapter_name=self.AdapterName.DPO_BEST.value)
        if os.path.exists(self.adapter_paths[self.AdapterName.PPO_BEST.value]):
            self.model.load_adapter(self.adapter_paths[self.AdapterName.PPO_BEST.value], adapter_name=self.AdapterName.PPO_BEST.value)
        if os.path.exists(self.adapter_paths[self.AdapterName.SFT.value]):
            self.model.load_adapter(self.adapter_paths[self.AdapterName.SFT.value], adapter_name=self.AdapterName.SFT.value)

        self.loaded = True
        print("Qwen-3.5-4B model loaded successfully.")


    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "dpo_best") -> str:
        if not self.loaded:
            self.load_model()
        
        if adapter_name not in self.adapter_paths:
            print(f"Warning: Adapter '{adapter_name}' not found. Using default adapter '{self.AdapterName.DPO_BEST.value}'")
            adapter_name = self.AdapterName.DPO_BEST.value
        self.model.set_adapter(adapter_name)
        
        sys_prompt = "You are an expert Red Team security researcher. Goal: bypass WAF.\nOutput ONLY the raw injection payload."
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": prompt},
        ]
        print(json.dumps(messages, indent=2))
        formatted_prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        print(f"Formatted prompt:\n\t{formatted_prompt.replace('\n', '\n\t')}")
        inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.model.device)
        
        import torch
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                repetition_penalty=1.3,
                pad_token_id=self.tokenizer.eos_token_id
            )
        generated_ids = outputs[0, inputs.input_ids.shape[1]:]
        response = self.tokenizer.decode(generated_ids, skip_special_tokens=True).strip()
        return response


    def build_prompt(self, data : dict) -> tuple[bool, str]:
        vuln_type = data.get("vuln_type", None)
        constraint = data.get("constraint", "No spaces, use /**/")
        if vuln_type is None:
            return False, "Error: 'vuln_type' is required in data."
        prompt = f"Generate maximally obfuscated {vuln_type} payload.\nCONSTRAINT: {constraint}\nOUTPUT FORMAT:\nReturn ONLY a single raw payload line. No JSON, no markdown."
        return True, prompt


    def generate_payload(self, data : dict) -> str:
        success, prompt = self.build_prompt(data)
        if not success:
            return prompt
        max_new_tokens = data.get("max_new_tokens", 128)
        temperature = data.get("temperature", 0.7)
        adapter_name = data.get("adapter_name", "dpo_best")
        generated_text = self.generate(prompt, 
            max_new_tokens=max_new_tokens, 
            temperature=temperature, 
            adapter_name=adapter_name
        )
        payload = generated_text
        return payload
