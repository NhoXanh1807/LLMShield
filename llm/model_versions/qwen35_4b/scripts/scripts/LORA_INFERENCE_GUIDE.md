# LLM4WAF: LoRA Adapter Inference Guide

## ⚠️ CRITICAL WARNING: Unsloth vs HuggingFace PEFT
When loading the **DPO** or **PPO** adapters trained via TRL (Transformers Reinforcement Learning), **DO NOT USE** `FastLanguageModel.from_pretrained` from Unsloth. 

TRL saves PEFT adapters using the standard HuggingFace format, while Unsloth expects its own custom key prefixes (`default`).
Loading a standard TRL-saved adapter via Unsloth will silently drop the weights with the warning:
> `UserWarning: Found missing adapter keys while loading the checkpoint: [...]`

This results in the **Vanilla Base Model (Qwen3.5-4B)** being loaded instead of the finely-tuned security model. The Base model will throw **Safety Refusal Policies** and output unwanted `<think>` tags.

## ✅ Correct Python Loading Code (Production & Audit)
To properly load the SFT/DPO/PPO models and retain their WAF-bypassing behaviors, use the native `PeftModel` from HuggingFace `transformers`:

```python
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

ADAPTER_PATH = "./output_phase6_dpo_retrain_20260404T043633Z/final_adapter"

# 1. Load Base Model natively
base_model = AutoModelForCausalLM.from_pretrained(
    "Qwen/Qwen3.5-4B",
    device_map="auto",
    dtype=torch.bfloat16,
)

# 2. Attach PEFT Adapter
model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)

# 3. Load Tokenizer & Apply Chat Template
tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen3.5-4B", trust_remote_code=True)

# Format standard Qwen Chat Template
from unsloth.chat_templates import get_chat_template
tokenizer = get_chat_template(
    tokenizer, 
    chat_template="qwen-2.5", 
    mapping={"role": "role", "content": "content", "user": "user", "assistant": "assistant"}
)

# 4. Generate Payload
msgs = [
    {"role": "system", "content": "You are an expert Red Team security researcher. Goal: bypass WAF.\nOutput ONLY the raw injection payload."},
    {"role": "user", "content": "Generate maximally obfuscated sqli_blind payload.\nCONSTRAINT: Do not use ANY spaces. Use /**/."}
]

# CRITICAL: use 'text=text' explicitly to avoid Qwen3.5 Positional Argument ValueError
text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
inputs = tokenizer(text=text, return_tensors="pt").to(model.device)

with torch.no_grad():
    out = model.generate(**inputs, max_new_tokens=256, temperature=0.3, pad_token_id=tokenizer.eos_token_id)
    
out_tokens = out[0, inputs["input_ids"].shape[1]:]
print(tokenizer.decode(out_tokens, skip_special_tokens=True).strip())
```

## Hybrid Fuzzing Strategy
In your vulnerability scanners or production inference scripts, you can keep swapping `ADAPTER_PATH`:
1. Use **SFT/DPO Adapter** when the target WAF requires heavy Hex/URL Encoding purely to bypass strict characters.
2. Use **PPO Adapter** when dealing with Semantic Next-Gen WAFs that decode and normalize string semantics, requiring structural obfuscation over purely encoded obfuscation.
