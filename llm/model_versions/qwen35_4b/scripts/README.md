# 📦 LLM4WAF Phase 6 — Public Release Package

> Generated: 2026-04-04  
> Project: AI-driven Security Fuzzer (WAF Bypass Research)  
> Base Model: `Qwen/Qwen3.5-4B`

---

## 📁 Folder Structure

```
public/
├── README.md                    ← This file
├── reports/
│   ├── sft_dpo_ppo_comparison_*.md    ← 3-way SFT vs DPO vs PPO audit report
│   ├── sft_dpo_ppo_comparison_*.json  ← Raw JSON scores & payloads
│   ├── dpo_vs_ppo_comparison_*.md     ← DPO vs PPO audit report (v1)
│   └── dpo_vs_ppo_comparison_*.json   ← Raw JSON (v1)
├── adapters/
│   ├── sft_baseline/ ← 🟢 Baseline (SFT model)
│   ├── ppo_best/    ← 🏆 Best Overall (PPO, 130/150 score)
│   └── dpo_best/    ← 🎯 Best Constraint Adherence (DPO)
├── data/            ← 📊 Datasets for training
│   ├── sft_train.jsonl
│   ├── dpo_train.jsonl
│   └── README_data.md
├── scripts/         ← 🛠️ Reproduction scripts
│   ├── train_phase6.py
│   ├── train_phase6_dpo_compare.py
│   ├── audit_dpo_vs_ppo_compare.py
│   ├── gradio_app.py
│   ├── inference.py
│   └── run_dpo_ppo_sequential.sh
├── chat_history/    ← 📜 Full session walkthroughs (Phase 1-6)
│   ├── phase1_sft_dataset_walkthrough.md
│   ├── phase2_multiturn_sft_walkthrough.md
│   └── ... 
└── requirements.txt ← ⚙️ Environment dependencies
```

## 📊 Reproducibility & Training

To reproduce our results or fine-tune further:

1.  **Environment**: 
    Ensure you have `torch`, `transformers`, `peft` and optionally `unsloth` for 2x faster training. 
    `pip install -r requirements_final.txt`

2.  **SFT Fine-tuning (Baseline)**:
    Run the command: `python scripts/train_phase6.py` using `data/sft_train.jsonl`.

3.  **DPO / PPO Preference Optimization**:
    Use the provided preference dataset: `data/dpo_train.jsonl`.
    Execute: `bash scripts/run_dpo_ppo_sequential.sh`.

4.  **CLI Inference (Fast Generation)**:
    Use the `inference.py` script to generate payloads via command line:
    ```bash
    python scripts/inference.py --adapter ./adapters/ppo_best --vuln sqli_blind --constraint "No spaces, use /**/"
    ```

5.  **Interactive Demo (Gradio)**:
    Launch the web interface for real-time testing:
    ```bash
    python scripts/gradio_app.py
    ```
    Then open `http://localhost:7860` in your browser.

6.  **Audit & Evaluation**:
    Run the 3-way evaluation: `python scripts/audit_dpo_vs_ppo_compare.py`.

| Model | Total Score | Avg/Case | Wins |
|---|---|---|---|
| **PPO** 🥇 | **130/150** | **8.7/10** | **3** |
| SFT (Baseline) | 111/150 | 7.4/10 | 1 |
| DPO | 110/150 | 7.3/10 | 0 |

### Per-Vector Winner
| Vector | Winner |
|---|---|
| XSS DOM-Based | PPO |
| XSS Reflected | PPO |
| XSS Stored | PPO |
| SQLi Classic | SFT |
| SQLi Blind | DPO & PPO (Tie) |

---

## 🚀 How to Load Adapters

**CRITICAL:** Always use HuggingFace `PeftModel`, NOT Unsloth's `FastLanguageModel`.
Unsloth drops adapter weights silently — see `LORA_INFERENCE_GUIDE.md`.

```python
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

base = AutoModelForCausalLM.from_pretrained(
    "Qwen/Qwen3.5-4B",
    device_map="auto",
    dtype=torch.bfloat16,
)

# Load PPO (best overall)
model = PeftModel.from_pretrained(base, "./adapters/ppo_best")

# Or DPO (best constraint adherence)
# model = PeftModel.from_pretrained(base, "./adapters/dpo_best")

tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen3.5-4B")
```

### Recommended Inference Parameters
```python
model.generate(
    **inputs,
    max_new_tokens=300,
    temperature=0.4,
    do_sample=True,
    repetition_penalty=1.3,   # prevents loop bug
    pad_token_id=tokenizer.eos_token_id,
)
```

---

## 📋 Use Case Recommendations

| Use Case | Recommended Adapter |
|---|---|
| High-diversity creative payloads | `ppo_best` |
| Constraint-specific WAF bypass | `dpo_best` |
| Production fuzzer (recommended) | `ppo_best` for gen + `dpo_best` for validation |

---

*LLM4WAF Security Research — For authorized penetration testing only.*
