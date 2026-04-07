import torch
import argparse
import sys
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

def generate_payload(adapter_path, vuln_type, constraint, model_id="Qwen/Qwen3.5-4B"):
    print(f"[*] Loading model and adapter: {adapter_path}...", file=sys.stderr)
    
    # Load base model
    base_model = AutoModelForCausalLM.from_pretrained(
        model_id,
        device_map="auto",
        torch_dtype=torch.bfloat16,
        trust_remote_code=True
    )
    
    # Load adapter
    model = PeftModel.from_pretrained(base_model, adapter_path)
    
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.pad_token or tokenizer.eos_token
    
    # Prepare prompt
    sys_prompt = "You are an expert Red Team security researcher. Goal: bypass WAF.\nOutput ONLY the raw injection payload."
    user_prompt = f"Generate maximally obfuscated {vuln_type} payload.\nCONSTRAINT: {constraint}\nOUTPUT FORMAT:\nReturn ONLY a single raw payload line. No JSON, no markdown."
    
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": user_prompt}
    ]
    
    # Apply template (Qwen style)
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text=text, return_tensors="pt").to(model.device)
    
    # Generate
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            temperature=0.3,
            repetition_penalty=1.3,
            pad_token_id=tokenizer.eos_token_id
        )
    
    # Decode
    generated_ids = outputs[0, inputs.input_ids.shape[1]:]
    response = tokenizer.decode(generated_ids, skip_special_tokens=True).strip()
    return response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM4WAF CLI Inference Tool")
    parser.add_argument("--adapter", type=str, required=True, help="Path to the LoRA adapter")
    parser.add_argument("--vuln", type=str, default="sqli_blind", help="Type of vulnerability (e.g. xss_dom, sqli_classic)")
    parser.add_argument("--constraint", type=str, default="No spaces, use /**/", help="WAF bypass constraint")
    
    args = parser.parse_args()
    
    payload = generate_payload(args.adapter, args.vuln, args.constraint)
    print("\n--- GENERATED PAYLOAD ---")
    print(payload)
    print("-------------------------\n")
