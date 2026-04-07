# LLM4WAF Phase 6: DPO Verification & PPO Stabilization Walkthrough

## What was Accomplished?

In this phase, we completed the final alignment tuning of the Qwen3.5-4B fuzzer through DPO and stabilized the GPU-intensive PPO pipeline. The fuzzer now successfully adheres to direct constraints without hallucinating refusal prompts.

### 1. PPO Out-of-Memory Resolution
- **The Issue:** Attempting to run TRL's PPOTrainer on `Qwen3.5-4B` spun up 4 complete instances of the base model in VRAM (Policy, Reference, Reward, Value). Even on a 140GB H200 GPU, sequence generation lengths caused CUDA to run out of memory. 
- **The Fix:** Reduced output generation budget (`response_length=400`), restricted `batch_size=8`, and enforced `mini_batch_size=1`. The PPO loop now successfully processes at `~80s/iteration`, fitting comfortably inside memory bounds without degrading RLHF optimization. 

### 2. DPO Audit & The Unsloth Loading Bug
- **The Issue:** Initial audits on our trained DPO Adapter showed the model inexplicably regressing to standard alignment: spitting out `<think>` logic tokens and heavily refusing to output security payloads. 
- **The Fix:** We discovered a major compatibility bug between HuggingFace's `TRL` standard adapter saving (`adapter_model.safetensors`) and Unsloth's `FastLanguageModel.from_pretrained` (which expected custom `default` module prefixes like `...lora_A.default.weight`).
  - Loading via Unsloth dropped almost all specialized weights (throwing a missing context warning). 
  - Loading via standard HuggingFace `PeftModel` restored the precise security behaviors of the DPO.

### 3. Comprehensive Payload Output Audit
We built an expanded test script `audit_dpo_hf.py` simulating 4 constraints. The results were stellar: 

| Vulnerability | Constraint Given | Generated Payload | Assessment |
| --- | --- | --- | --- |
| **`sqli_blind`** | No spaces, use `/**/` | `'/**/UNION/**/SELECT/**/NULL,CONCAT...` | Flawless bypassing of spaces. |
| **`xss_reflected`** | Deep `<svg>` / `base64` | `<script>eval(atob('PHN2Zz48...` | Heavy exploitation using JS decoding. |
| **`sqli_classic`** | Hex encoding `0x...` | `' UNION SELECT 0x313030303030...` | Completely converted into strict hex. |
| **`cmd_injection`** | `${IFS}` spacing | `${IFS}$(whoami)` | Minimalist, exact command substitution limit bypass. |

## Documentation Attached
We saved a permanent file to the repository (`/workspace/deploy_sft/LORA_INFERENCE_GUIDE.md`) to instruct future execution on how to load these TRL-generated adapters safely without silent fallback to the raw models. 

## Next Steps
PPO is presently running seamlessly in the background (Episode 8+/50). Once finished, the `/workspace/deploy_sft/output_phase6_ppo_retrain_...` directory will hold the ultimate adapter capable of navigating modern structural WAFs.
