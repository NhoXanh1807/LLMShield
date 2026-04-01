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
        try:
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
            print(f"Generated response: {response}")
            return response
        except Exception as e:
            print(f"Error during generation: {e}")
            return "Error generating response."
