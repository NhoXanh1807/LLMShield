import gradio as gr
import torch
import gc
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# Global model placeholders
global_model = None
global_tokenizer = None
current_loaded_model = None

AVAILABLE_MODELS = [
    "./adapters/ppo_best",
    "./adapters/dpo_best"
]

def load_selected_model(model_path, model_id="Qwen/Qwen3.5-4B"):
    global global_model, global_tokenizer, current_loaded_model
    if model_path == current_loaded_model:
        return f"Mô hình {model_path} đã đang được chạy!"
        
    print(f"Loading {model_path}...")
    try:
        # Clear old model if any to avoid OOM
        if global_model is not None:
            del global_model
            del global_tokenizer
            gc.collect()
            torch.cuda.empty_cache()
            
        base_model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            dtype=torch.bfloat16,
            trust_remote_code=True
        )
        
        global_model = PeftModel.from_pretrained(base_model, model_path)
        global_tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        global_tokenizer.pad_token = global_tokenizer.pad_token or global_tokenizer.eos_token
        
        current_loaded_model = model_path
        return f"✅ Tải thành công: {model_path}"
    except Exception as e:
        return f"❌ Lỗi tải mô hình: {e}"

def generate_payload(vuln_type, constraint, temperature=0.3):
    global global_model, global_tokenizer
    if global_model is None or global_tokenizer is None:
        return "Model not loaded! Please select a model and click 'Load Model' first."
        
    sys_prompt = "You are an expert Red Team security researcher. Goal: bypass WAF.\nOutput ONLY the raw injection payload."
    user_prompt = f"Generate maximally obfuscated {vuln_type} payload.\nCONSTRAINT: {constraint}\nOUTPUT FORMAT:\nReturn ONLY a single raw payload line. No JSON, no markdown."
    
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": user_prompt}
    ]
    
    text = global_tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = global_tokenizer(text=text, return_tensors="pt").to(global_model.device)
    
    with torch.no_grad():
        outputs = global_model.generate(
            **inputs,
            max_new_tokens=256,
            temperature=temperature,
            repetition_penalty=1.3,
            pad_token_id=global_tokenizer.eos_token_id
        )
    
    generated_ids = outputs[0, inputs.input_ids.shape[1]:]
    response = global_tokenizer.decode(generated_ids, skip_special_tokens=True).strip()
    return response

# Setup UI
with gr.Blocks(title="LLM4WAF Security Fuzzer Demo", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ LLM4WAF - Hybrid AI Fuzzer (Phase 6)")
    gr.Markdown("Interactive demo for generating WAF bypass payloads using SFT, DPO, and PPO models.")
    
    with gr.Row():
        model_dropdown = gr.Dropdown(choices=AVAILABLE_MODELS, label="Select Model Adapter", value=AVAILABLE_MODELS[0])
        btn_load = gr.Button("🔄 Load Model", variant="secondary")
        load_status = gr.Textbox(label="Status", value="Model not loaded", interactive=False)
        
    btn_load.click(fn=load_selected_model, inputs=[model_dropdown], outputs=[load_status])

    with gr.Row():
        with gr.Column():
            vuln_type = gr.Dropdown(
                choices=["sqli_classic", "sqli_blind", "xss_reflected", "xss_stored", "xss_dom", "cmd_injection"],
                label="Vulnerability Type",
                value="sqli_blind"
            )
            constraint = gr.Textbox(
                label="Bypass Constraint",
                placeholder="e.g., No spaces, use /**/, hex encoding...",
                value="Do not use ANY spaces. Use /**/ or other block comments to separate keywords.",
                lines=2
            )
            temp_slider = gr.Slider(minimum=0.1, maximum=1.0, value=0.3, step=0.1, label="Temperature")
            btn_generate = gr.Button("🔥 Generate Payload", variant="primary")
            
        with gr.Column():
            payload_output = gr.Textbox(label="💥 Generated Payload", interactive=False, lines=10)
            
    btn_generate.click(
        fn=generate_payload,
        inputs=[vuln_type, constraint, temp_slider],
        outputs=[payload_output]
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
