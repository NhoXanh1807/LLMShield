import torch
import argparse
import sys
import unsloth
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from unsloth.chat_templates import get_chat_template

def extract_payload(text):
    import json
    try:
        data = json.loads(text)
        if "payload" in data:
            return data["payload"]
    except:
        pass
        
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
    
    code_blocks = re.findall(r"```(?:sql|html|xml|javascript|js)?\n(.*?)```", text, flags=re.DOTALL)
    if code_blocks:
        return code_blocks[-1].strip()
        
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    
    lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
    for line in reversed(lines):
        lower_line = line.lower()
        if any(lower_line.startswith(prefix) for prefix in ["1.", "2.", "3.", "thought:", "thinking:", "analyze:", "here is"]):
            continue
        return line
        
    return text.strip()

def main():
    parser = argparse.ArgumentParser(description="LLM4WAF Interactive Multi-Turn CLI")
    parser.add_argument("--adapter", type=str, default="public/adapters/dpo_best", help="Path to the LoRA adapter")
    parser.add_argument("--model", type=str, default="Qwen/Qwen3.5-4B", help="Base model ID")
    args = parser.parse_args()

    print(f"[*] Loading base model and adapter from '{args.adapter}'...")
    base_model = AutoModelForCausalLM.from_pretrained(
        args.model,
        device_map="auto",
        torch_dtype=torch.bfloat16,
        trust_remote_code=True
    )
    
    # Fix Unsloth monkey-patching bug with accelerate's get_balanced_memory
    if hasattr(base_model, "_no_split_modules"):
        fixed_modules = []
        for x in base_model._no_split_modules:
            if isinstance(x, set):
                fixed_modules.extend(list(x))
            else:
                fixed_modules.append(x)
        base_model._no_split_modules = fixed_modules

    model = PeftModel.from_pretrained(base_model, args.adapter)
    
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True) 
    tokenizer = get_chat_template(
        tokenizer, 
        chat_template="qwen-2.5", 
        mapping={"role": "role", "content": "content", "user": "user", "assistant": "assistant"}
    )
    
    sys_prompt = "You are an expert Red Team security researcher. Output ONLY the raw injection payload line. Absolutely no markdown, no JSON, no thinking process, and no introduction. Just the payload string."
    
    messages = [{"role": "system", "content": sys_prompt}]
    
    print("\n" + "="*50)
    print("🛡️  LLM4WAF MULTI-TURN INTERACTIVE CLI 🛡️")
    print("="*50)
    
    vuln_type = input("\n[1] Enter Vulnerability Type (sqli_classic, sqli_blind, xss_reflected, xss_stored, xss_dom) [default: sqli_blind]: ").strip() or "sqli_blind"
    
    print("\n--- Common Evasion Constraints ---")
    print("  1. Avoid all quotes — use hex literals or CONCAT()")
    print("  2. Use deeply nested SQL/JS comments to split keywords (e.g. SE/**/LECT)")
    print("  3. Use math expressions and bitwise ops instead of 1=1 (e.g. 3&1=1)")
    print("  4. No spaces, use /**/ or weird whitespace (%09, %0a)")
    print("  5. Use CASE WHEN THEN ELSE for conditional execution")
    print("  6. Use HTML entity encoding or URL Double-Encoding")
    print("  7. Use obscure HTML5 event handlers (ontoggle, onpointerover)")
    print("  8. Use charcode reconstruction (String.fromCharCode)")
    
    constraint_input = input("\n[2] Select a number (1-8) OR type your custom Constraint [default: 4]: ").strip()
    
    constraint_map = {
        "1": "Avoid all quotes — use hex literals or CONCAT().",
        "2": "Use deeply nested SQL/JS comments to split every keyword.",
        "3": "Use math expressions and bitwise ops to hide booleans (e.g. 3&1=1).",
        "4": "Do not use ANY spaces. Use /**/ or weird whitespace like %09.",
        "5": "Use CASE WHEN THEN ELSE for conditional payload execution.",
        "6": "Use HTML entity encoding and URL Double-Encoding.",
        "7": "Use obscure HTML5 event handlers like ontoggle or onpointerover.",
        "8": "Use charcode reconstruction (String.fromCharCode) for script body."
    }
    
    constraint = constraint_map.get(constraint_input, constraint_input)
    if not constraint:
        constraint = constraint_map["4"]
        
    print(f"\n[*] Using Constraint: {constraint}")
    
    first_prompt = f"Turn 1: Generate a raw {vuln_type} payload.\nCONSTRAINT: {constraint}"
    messages.append({"role": "user", "content": first_prompt})
    
    turn = 1
    
    while True:
        print(f"\n⏳ Generating payload for Turn {turn}...")
        
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(text=text, return_tensors="pt").to(model.device)
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=300,
                temperature=0.4,
                repetition_penalty=1.3,
                pad_token_id=tokenizer.eos_token_id
            )
        
        generated_ids = outputs[0, inputs.input_ids.shape[1]:]
        raw_response = tokenizer.decode(generated_ids, skip_special_tokens=True).strip()
        payload = extract_payload(raw_response)
        
        print("\n" + "-"*40)
        print(f"🔥 GENERATED PAYLOAD (Turn {turn}):")
        print(f"\033[92m{payload}\033[0m") # In màu xanh lá
        print("-"*40)
        
        # Lưu vào history
        messages.append({"role": "assistant", "content": payload})
        
        # Lấy feedback
        print("\nTest payload này với WAF của bạn.")
        feedback = input(f"[?] Nhập WAF Feedback cho Turn {turn+1} (hoặc gõ 'exit' để thoát): ").strip()
        
        if feedback.lower() in ['exit', 'quit', 'q']:
            print("Đã thoát phiên làm việc.")
            break
            
        if not feedback:
            print("Feedback trống, tự động yêu cầu tạo payload khác...")
            feedback = "WAF BLOCKED. Generate an alternative, stronger obfuscation."
            
        turn += 1
        next_prompt = f"Turn {turn} Feedback: {feedback}"
        messages.append({"role": "user", "content": next_prompt})

if __name__ == "__main__":
    main()