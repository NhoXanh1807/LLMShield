import os
from interfaces import AttackLLMInterface
from enum import Enum

class Gemma2_2B(AttackLLMInterface):
    def __init__(self, hf_token, load_immediately=False):
        self.hf_token = hf_token
        self.loaded = False
        if load_immediately:
            self.load_model()
            
    BASE_MODEL = "google/gemma-2-2b-it"
    
    class AdapterName(Enum):
        PHASE1 = "phase1"
        PHASE2 = "phase2"
        PHASE3_RL = "phase3_rl"
    
    
    def load_model(self):
        if self.loaded:
            return
        
        print(f"Loading {self.BASE_MODEL}...")
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
        from peft import PeftModel

        self.no_grad = torch.no_grad
        if torch.cuda.is_available():
            print("Using CUDA device")
            print([torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())])
            self.device = torch.device("cuda")
            device_map = {"": 0}
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16
            )
        else:
            print("Using CPU device")
            self.device = torch.device("cpu")
            device_map = "auto"
            bnb_config = None  # BitsAndBytesConfig is only for GPU/accelerator

        model_kwargs = dict(
            pretrained_model_name_or_path=self.BASE_MODEL,
            device_map=device_map,
            token=self.hf_token,
            local_files_only=False
        )
        if bnb_config is not None:
            model_kwargs["quantization_config"] = bnb_config

        # Load pretrained model
        self.model = AutoModelForCausalLM.from_pretrained(**model_kwargs)
        self.tokenizer = AutoTokenizer.from_pretrained(self.BASE_MODEL, token=self.hf_token, local_files_only=False)
        
        # Prepare adapter paths
        adapters_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'adapters')
        self.adapter_paths = {
            self.AdapterName.PHASE1.value: os.path.join(adapters_dir, "remote_gemma2_2b_phase1"),
            self.AdapterName.PHASE2.value: os.path.join(adapters_dir, "remote_gemma2_2b_phase2"),
            self.AdapterName.PHASE3_RL.value: os.path.join(adapters_dir, "remote_gemma2_2b_phase3_rl")
        }
        
        # Wrap with PeftModel
        self.model = PeftModel.from_pretrained(self.model, self.adapter_paths[self.AdapterName.PHASE1.value], adapter_name=self.AdapterName.PHASE1.value)
        if os.path.exists(self.adapter_paths[self.AdapterName.PHASE2.value]):
            self.model.load_adapter(self.adapter_paths[self.AdapterName.PHASE2.value], adapter_name=self.AdapterName.PHASE2.value)
        if os.path.exists(self.adapter_paths[self.AdapterName.PHASE3_RL.value]):
            self.model.load_adapter(self.adapter_paths[self.AdapterName.PHASE3_RL.value], adapter_name=self.AdapterName.PHASE3_RL.value)
        
        self.loaded = True
        print("Gemma-2-2B model loaded successfully.")


    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> str:
        if not self.loaded:
            self.load_model()
        
        if adapter_name not in self.adapter_paths:
            print(f"Warning: Adapter '{adapter_name}' not found. Using default adapter '{self.AdapterName.PHASE1.value}'")
            adapter_name = self.AdapterName.PHASE1.value
        self.model.set_adapter(adapter_name)
        
        messages = [{"role": "user", "content": prompt}]
        formatted_prompt = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.model.device)
        input_length = inputs.input_ids.shape[1]
        eos_id = self.tokenizer.eos_token_id
        with self.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=True,
                eos_token_id=eos_id,
                pad_token_id=eos_id,
                repetition_penalty=1.3,
            )
        response = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
        return response


    def build_prompt(self, data : dict) -> tuple[bool, str]:
        waf_name = data.get("waf_name", None)
        attack_type = data.get("attack_type", None)
        technique = data.get("technique", None)
        probe_history = data.get("probe_history", None)
        if waf_name is None:
            return False, "Error: 'waf_name' is required in data."
        if attack_type is None:
            return False, "Error: 'attack_type' is required in data."
        
        if probe_history is not None and type(probe_history) == list and len(probe_history) > 0:
            return True, self._build_phase3_prompt(waf_name, attack_type, probe_history)
        elif technique is not None and type(technique) == str and len(technique) > 0:
            return True, self._build_phase1_prompt(waf_name, attack_type, technique)
        else:
            return False, "Error: Insufficient data to build prompt. Provide either 'technique' for Phase 1 or 'probe_history' for Phase 3."


    def generate_payload(self, data : dict) -> str:
        success, prompt = self.build_prompt(data)
        if not success:
            return prompt
        max_new_tokens = data.get("max_new_tokens", 128)
        temperature = data.get("temperature", 0.7)
        adapter_name = data.get("adapter_name", "phase1")
        generated_text = self.generate(prompt, 
            max_new_tokens=max_new_tokens, 
            temperature=temperature, 
            adapter_name=adapter_name
        )
        payload = self._clean_payload(generated_text)
        return payload


    def _build_phase1_prompt(self, waf_name: str, attack_type: str, technique: str) -> str:
        attack_type_code = "XSS" if "xss" in attack_type.lower() else "SQLI"
        prompt = (
            f"Generate a full bypass payload for {attack_type_code} using {technique}.\n\n"
            "IMPORTANT: Generate ONLY the payload code. Do not provide explanations."
        )
        return prompt


    def _build_phase3_prompt(self, waf_name: str, attack_type: str, probe_history: list[dict]) -> str:
        history_str = ""
        tried_techniques = set()
        for i, h in enumerate(probe_history):
            history_str += f"{i+1}. Payload: `{h['payload']}` (Technique: {h['technique']}) -> RESULT: {'BYPASSED' if h['bypassed'] else 'BLOCKED'}\n"
            tried_techniques.add(h['technique'])

        # Pick next technique: prefer one not yet tried
        xss_techniques = [
            "SVG Event Handler", "Unicode Normalization", "IMG Tag with OnError",
            "Javascript Pseudo-protocol in A Tag", "Case Manipulation",
            "Double URL Encode", "Hex Encoding", "HTML Entity Encode",
            "Attribute Injection", "DOM clobbering"
        ]
        sqli_techniques = [
            "Double URL Encode", "Comment Obfuscation (/**/)", "Hex Encoding",
            "Boolean-based Blind", "Time-based Blind", "Union Select",
            "Case Manipulation", "Whitespace Bypass", "Inline Comment Versioning"
        ]
        candidates = sqli_techniques if "sql" in attack_type.lower() else xss_techniques
        remaining = [t for t in candidates if t not in tried_techniques]
        import random
        target_technique = random.choice(remaining) if remaining else random.choice(candidates)

        prompt = f"""You are an offensive security assistant specialized in generating WAF-evasion payloads.

Context:
- Target WAF: {waf_name}.
- Attack type: {attack_type}.
- Injection point: query parameter.

Previously tried payloads against this target (all blocked by the WAF):
{history_str}

Your task:
Generate a NEW {attack_type} payload that has a higher chance of bypassing this WAF while still reaching and triggering the underlying vulnerability.
Use the following core technique as the main idea for the payload:
- Technique: {target_technique}

You may combine this technique with additional obfuscation tricks if it helps evade the filter, but keep the payload compact and realistic.

IMPORTANT:
- Output ONLY the final payload string.
- Do NOT add explanations or comments.
- Do NOT wrap it in code fences."""
        return prompt


    def _clean_payload(self, generated_text: str) -> str:
        payload = generated_text.strip()
        # Strip code fences
        if payload.startswith("```") or payload.startswith("`"):
            lines = payload.split("\n")
            payload = "\n".join([l for l in lines if not l.strip().startswith("`")])
            payload = payload.strip()
        # Take only the first non-empty line (avoid hallucinated multi-line HTML)
        for line in payload.splitlines():
            line = line.strip()
            if line and not line.startswith("Note") and not line.startswith("Explanation"):
                return line
        return payload
