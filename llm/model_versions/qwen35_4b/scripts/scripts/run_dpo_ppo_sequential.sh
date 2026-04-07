#!/usr/bin/env bash
# ============================================================
# run_dpo_ppo_sequential.sh
# Chạy DPO → PPO tuần tự (cùng 1 H200).
# Log ra logs/dpo_train.log và logs/ppo_train.log.
# Dùng tee để quan sát live trên terminal.
# ============================================================
set -euo pipefail

# Activate virtualenv (packages: datasets, trl, peft, transformers, torch)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
    echo "✅ venv activated: $(which python3)"
else
    echo "⚠️  .venv not found, using system python3 — packages may be missing!"
fi

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

DPO_LOG="$LOG_DIR/dpo_train_${TIMESTAMP}.log"
PPO_LOG="$LOG_DIR/ppo_train_${TIMESTAMP}.log"

DPO_OUT="output_phase6_dpo_retrain_${TIMESTAMP}"
PPO_OUT="output_phase6_ppo_retrain_${TIMESTAMP}"

REWARD_MODEL="output_phase6_reward_model_compare_v3_20260403T1352Z/final"
SFT_ADAPTER="output_phase6_sft/final_adapter"

DPO_DATASET="data/processed/dpo_live_modsec_v4_full_21_payload_only_prioritized.jsonl"
PPO_PROMPTS="data/processed/ppo_prompts_phase6.jsonl"

echo "================================================================"
echo "  DPO + PPO Sequential Training — $TIMESTAMP"
echo "  DPO log : $DPO_LOG"
echo "  PPO log : $PPO_LOG"
echo "================================================================"
echo ""

# ── Helper: tail-and-grep payload lines for live monitoring ──
monitor_payloads() {
    local logfile="$1"
    local label="$2"
    echo ""
    echo ">>> [$label] Live payload monitor (Ctrl+C to stop tailing, training continues)"
    tail -f "$logfile" | grep --line-buffered -E \
        "(chosen|rejected|payload|BYPASS|BLOCK|loss|reward|step|Step)" 2>/dev/null || true
}

# ════════════════════════════════════════════════════════════
# PHASE A: DPO
# ════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [1/2] DPO TRAINING"
echo "  Dataset   : $DPO_DATASET  ($(wc -l < "$DPO_DATASET") rows)"
echo "  Adapter   : $SFT_ADAPTER"
echo "  Output    : $DPO_OUT"
echo "  Log       : $DPO_LOG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

DPO_START=$(date +%s)

python3 -u scripts/train_phase6_dpo_compare.py \
    --base_model   "Qwen/Qwen3.5-4B" \
    --adapter_path "$SFT_ADAPTER" \
    --dataset      "$DPO_DATASET" \
    --output_dir   "$DPO_OUT" \
    --max_steps    60 \
    --val_ratio    0.05 \
    --seed         3407 \
    2>&1 | tee "$DPO_LOG"

DPO_END=$(date +%s)
DPO_ELAPSED=$(( DPO_END - DPO_START ))
echo ""
echo "✅ DPO done in ${DPO_ELAPSED}s → $DPO_OUT/final_adapter"
echo ""

# Quick sanity: sample 3 generated payloads from DPO adapter
echo "──── DPO quick-sample payloads ────────────────────────────"
python3 -u - <<PYEOF
import torch, os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

base_model   = "Qwen/Qwen3.5-4B"
adapter_path = "$DPO_OUT/final_adapter"

tok = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
tok.pad_token = tok.pad_token or tok.eos_token

import torch
dtype = torch.bfloat16
base  = AutoModelForCausalLM.from_pretrained(base_model, torch_dtype=dtype, device_map="auto", trust_remote_code=True)
model = PeftModel.from_pretrained(base, adapter_path, is_trainable=False)
model.eval()

PROMPTS = [
    ("sqli_classic",   "Avoid all quotes — use hex literals, backtick strings."),
    ("xss_reflected",  "Use Unicode escape sequences for hex literals."),
    ("sqli_blind",     "Use time-based blind: IF(1=1, SLEEP(1), 0)."),
]

SYSTEM = "You are an expert Red Team security researcher. Output ONLY the raw injection payload."

for vector, constraint in PROMPTS:
    msgs = [
        {"role": "system",    "content": SYSTEM},
        {"role": "user",      "content": f"Generate maximally obfuscated {vector} payload.\nCONSTRAINT: {constraint}\nOUTPUT FORMAT:\nReturn ONLY a single raw payload line. No JSON, no markdown."},
    ]
    try:
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True, enable_thinking=False)
    except TypeError:
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=200, temperature=0.75, top_p=0.9,
                             do_sample=True, pad_token_id=tok.eos_token_id)
    gen = tok.decode(out[0, inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
    # Strip think blocks
    import re
    gen = re.sub(r"<think>.*?</think>", "", gen, flags=re.DOTALL)
    gen = re.sub(r"<think>.*$",         "", gen, flags=re.DOTALL)
    gen = gen.strip() or "(EMPTY — possible think-strip issue)"
    print(f"  [{vector}]")
    print(f"  Constraint : {constraint}")
    print(f"  Payload    : {gen[:200]}")
    print()
PYEOF

echo "──── End DPO sample ────────────────────────────────────────"
echo ""

# ════════════════════════════════════════════════════════════
# PHASE B: PPO
# ════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [2/2] PPO TRAINING"
echo "  Prompts       : $PPO_PROMPTS  ($(wc -l < "$PPO_PROMPTS") rows)"
echo "  Policy init   : $DPO_OUT/final_adapter  (DPO-warmed)"
echo "  Reward model  : $REWARD_MODEL"
echo "  Output        : $PPO_OUT"
echo "  Log           : $PPO_LOG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

PPO_START=$(date +%s)

python3 -u scripts/train_phase6_ppo_compare.py \
    --base_model      "Qwen/Qwen3.5-4B" \
    --policy_adapter  "$DPO_OUT/final_adapter" \
    --reward_model    "$REWARD_MODEL" \
    --prompts_dataset "$PPO_PROMPTS" \
    --output_dir      "$PPO_OUT" \
    --total_episodes  800 \
    --response_length 1024 \
    --batch_size      32 \
    --mini_batch_size 8 \
    --num_ppo_epochs  2 \
    --learning_rate   5e-7 \
    --save_steps      50 \
    --seed            3407 \
    2>&1 | tee "$PPO_LOG"

PPO_END=$(date +%s)
PPO_ELAPSED=$(( PPO_END - PPO_START ))
echo ""
echo "✅ PPO done in ${PPO_ELAPSED}s → $PPO_OUT/final_adapter"
echo ""

# ════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════
echo "================================================================"
echo "  ALL DONE"
echo "  DPO adapter : $DPO_OUT/final_adapter"
echo "  PPO adapter : $PPO_OUT/final_adapter"
echo "  DPO log     : $DPO_LOG"
echo "  PPO log     : $PPO_LOG"
echo "================================================================"

# Tail payload lines để review nhanh
echo ""
echo ">>> Last 20 meaningful lines từ DPO log:"
grep -E "(loss|reward|step|Step|chosen|payload)" "$DPO_LOG" | tail -20 || true

echo ""
echo ">>> Last 20 meaningful lines từ PPO log:"
grep -E "(loss|reward|step|Step|episode|kl)" "$PPO_LOG" | tail -20 || true
