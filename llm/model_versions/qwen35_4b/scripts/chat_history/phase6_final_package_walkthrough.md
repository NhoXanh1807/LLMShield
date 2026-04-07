# 🚀 LLM4WAF Public Release — Complete Package

We have finalized the public version of the **AI-driven Security Fuzzer** research. The package is now a comprehensive toolkit for both using the pre-trained models and reproducing the entire training pipeline.

## 📦 What's in the Box?

The release is located at `/workspace/deploy_sft/public_llm4waf_release.zip` and contains:

### 1. 🤖 Pre-trained Adapters
- **`ppo_best`**: 🏆 Winner of the 15-case benchmark. Best for creative and complex bypasses.
- **`dpo_best`**: 🎯 Best at following strict constraints (e.g., specific encoding rules).

### 2. 📊 Full Datasets
- **`sft_train.jsonl`**: The baseline SFT dataset.
- **`dpo_train.jsonl`**: The preference dataset used for DPO and PPO.
- **`phase6_multiturn_sft.jsonl`**: Multi-turn attack trajectories.

### 3. 🛠️ Reproduction Scripts
- **Training**: Core logic for SFT, DPO, and PPO training.
- **Automation**: `run_dpo_ppo_sequential.sh` for one-click pipeline execution.
- **Evaluation**: The 3-way side-by-side audit script used for our final report.

### 4. 🎮 Inference & Demo
- **`inference.py`**: ⌨️ A clean CLI tool to generate a payload in seconds.
- **`gradio_app.py`**: 🌐 An interactive web UI for real-time testing and visualization.

---

## 🚀 Quick Usage

### Start the Interactive Demo
```bash
python public/scripts/gradio_app.py
```

### Generate a Payload (CLI)
```bash
python public/scripts/inference.py --adapter ./public/adapters/ppo_best --vuln sqli_blind --constraint "No spaces"
```

## 📈 Final Benchmark Summary
| Model | Score | Avg/Case |
|---|---|---|
| **PPO** | **130/150** | **8.7/10** |
| SFT | 111/150 | 7.4/10 |
| DPO | 110/150 | 7.3/10 |

> [!TIP]
> Use **PPO** for high-diversity fuzzing and **DPO** when you need strict adherence to specific WAF bypass rules.

---
*LLM4WAF Security Research Project | 2026*
