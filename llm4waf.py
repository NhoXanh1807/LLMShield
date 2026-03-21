

import os
from dataclasses import dataclass
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
import re
from urllib.parse import unquote
import random

@dataclass
class PayloadResult:
    payload: str
    technique: str
    attack_type: str
    bypassed: bool
    status_code: int = None


class _WafAttackModel:
    """Shared helpers for all WAF attack payload generation models."""

    def generate_response(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase3_rl") -> str:
        """Generate a payload response from the model, given the prompt.
        This is the main method to call for generating attack payloads."""
        raise NotImplementedError("Subclasses must implement generate_response()")


# ---------------------------------------------------------------------------
# Concrete model classes
# ---------------------------------------------------------------------------

class Gemma2B(_WafAttackModel):
    def __init__(self, hf_token, load_immediately=False):
        self.hf_token = hf_token
        self.loaded = False
        if load_immediately:
            self.load_model()

    def load_model(self):
        if self.loaded:
            return
        print("Lazy loading Gemma-2-2B model...")

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

        self.base_model = "google/gemma-2-2b-it"
        model_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'model')
        self.phase1_adapter_path = os.path.join(model_dir, "remote_gemma2_2b_phase1")
        self.phase3_adapter_path = os.path.join(model_dir, "remote_gemma2_2b_phase3_rl")

        model_kwargs = dict(
            pretrained_model_name_or_path=self.base_model,
            device_map=device_map,
            token=self.hf_token,
            local_files_only=False
        )
        if bnb_config is not None:
            model_kwargs["quantization_config"] = bnb_config

        self.model = AutoModelForCausalLM.from_pretrained(**model_kwargs)
        self.model = PeftModel.from_pretrained(self.model, self.phase3_adapter_path, adapter_name="phase3_rl")
        self.model.load_adapter(self.phase1_adapter_path, adapter_name="phase1")
        self.tokenizer = AutoTokenizer.from_pretrained(self.base_model, token=self.hf_token, local_files_only=False)
        self.loaded = True
        print("Gemma-2-2B model loaded successfully (phase1 + phase3_rl adapters).")

    def generate_response(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase3_rl") -> str:
        if not self.loaded:
            self.load_model()
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


class Qwen25_3B(_WafAttackModel):
    """Qwen2.5-3B-Instruct with LoRA adapters (phase1 + phase3_rl)."""

    def __init__(self, hf_token, load_immediately=False):
        self.hf_token = hf_token
        self.loaded = False
        if load_immediately:
            self.load_model()

    def load_model(self):
        if self.loaded:
            return
        print("Lazy loading Qwen2.5-3B-Instruct model...")

        self.no_grad = torch.no_grad
        if torch.cuda.is_available():
            print("Using CUDA device")
            print([torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())])
            self.device = torch.device("cuda")
        else:
            print("Using CPU device")
            self.device = torch.device("cpu")

        self.base_model = "Qwen/Qwen2.5-3B-Instruct"
        model_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'model')
        self.phase1_adapter_path = os.path.join(model_dir, "remote_qwen_3b_phase1")
        self.phase3_adapter_path = os.path.join(model_dir, "remote_qwen_3b_phase3_rl")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.base_model, quantization_config=bnb_config, device_map={"": 0}
        )
        self.model = PeftModel.from_pretrained(self.model, self.phase3_adapter_path, adapter_name="phase3_rl")
        self.model.load_adapter(self.phase1_adapter_path, adapter_name="phase1")
        self.tokenizer = AutoTokenizer.from_pretrained(self.base_model)
        self.loaded = True
        print("Qwen2.5-3B model loaded successfully (phase1 + phase3_rl adapters).")

    def generate_response(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase3_rl") -> str:
        if not self.loaded:
            self.load_model()
        self.model.set_adapter(adapter_name)
        # Qwen2.5-Instruct uses ChatML — apply_chat_template handles it correctly
        messages = [{"role": "user", "content": prompt}]
        formatted_prompt = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.model.device)
        input_length = inputs.input_ids.shape[1]
        # Qwen2.5 EOS: <|im_end|>=151645, <|endoftext|>=151643
        from typing import List
        eos_ids = list({self.tokenizer.eos_token_id, 151645, 151643})
        with self.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=True,
                eos_token_id=eos_ids,
                pad_token_id=self.tokenizer.eos_token_id,
                repetition_penalty=1.3,
            )
        response = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
        return response

