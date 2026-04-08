#!/usr/bin/env python3
import argparse
import json
import os
import re
from datasets import load_dataset
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from trl import DPOTrainer, DPOConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, PeftModel

from rl_compare_common import resolve_best_sft_adapter


def _strip_thinking(text: str) -> str:
    """Strip Qwen3 <think>...</think> CoT blocks from training labels.

    If DPO chosen/rejected samples contain <think> blocks, the model learns
    to emit <think> as part of the payload — this is the root cause of the
    '<think> in payload' bug. Strip aggressively before feeding to DPOTrainer.
    """
    if not text:
        return text
    # Remove complete <think>...</think> blocks, keep content after </think>
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Remove incomplete/orphaned <think> (cut off at token budget)
    text = re.sub(r"<think>.*$", "", text, flags=re.DOTALL)
    return text.strip()


def _clean_row(row: dict) -> dict:
    """Strip thinking tokens from chosen/rejected fields in-place."""
    for field in ("chosen", "rejected"):
        if isinstance(row.get(field), str):
            row[field] = _strip_thinking(row[field])
        elif isinstance(row.get(field), list):
            # chat-format: list of {role, content} dicts
            cleaned = []
            for msg in row[field]:
                if isinstance(msg, dict) and msg.get("role") == "assistant":
                    msg = dict(msg)
                    msg["content"] = _strip_thinking(msg.get("content") or "")
                cleaned.append(msg)
            row[field] = cleaned
    return row


def split_dataset(ds, val_ratio: float, seed: int):
    if val_ratio <= 0 or len(ds) < 100:
        return ds, None
    split = ds.train_test_split(test_size=val_ratio, seed=seed, shuffle=True)
    return split["train"], split["test"]


def main():
    ap = argparse.ArgumentParser(description="Phase6 DPO training (payload-only) for comparison")
    ap.add_argument("--base_model", default="Qwen/Qwen3.5-4B")
    ap.add_argument("--adapter_path", default="auto")
    ap.add_argument("--dataset", default="data/processed/dpo_live_modsec_v4_full_21_payload_only_prioritized.jsonl")
    ap.add_argument("--output_dir", default="output_phase6_dpo_compare")
    ap.add_argument("--max_steps", type=int, default=800)
    ap.add_argument("--val_ratio", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--resume_from_checkpoint", type=str, default=None)
    ap.add_argument("--load_in_4bit", action="store_true")
    args = ap.parse_args()

    ds = load_dataset("json", data_files=args.dataset, split="train")
    ds = ds.filter(lambda x: bool(str(x.get("prompt", "")).strip()) and bool(str(x.get("chosen", "")).strip()) and bool(str(x.get("rejected", "")).strip()))
    # ── Strip <think> CoT blocks from chosen/rejected ──────────────────────────
    # Qwen3 thinking-mode outputs embed <think>...</think> blocks. If these end
    # up in training labels, DPO teaches the model to PREFIX payloads with <think>.
    ds = ds.map(_clean_row)
    ds = ds.filter(lambda x: bool(str(x.get("chosen", "")).strip()) and bool(str(x.get("rejected", "")).strip()))
    print(f"[DPO] Dataset after <think>-strip: {len(ds)} rows")
    train_ds, eval_ds = split_dataset(ds, args.val_ratio, args.seed)

    resolved_adapter_path = resolve_best_sft_adapter(args.adapter_path)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.pad_token or tokenizer.eos_token

    bnb_config = None
    dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
    if args.load_in_4bit:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=dtype,
            bnb_4bit_use_double_quant=True,
        )

    model_base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        dtype=None if args.load_in_4bit else dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    model_base.config.use_cache = False

    ref_base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        dtype=None if args.load_in_4bit else dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    ref_base.config.use_cache = False

    if resolved_adapter_path and os.path.exists(resolved_adapter_path):
        model = PeftModel.from_pretrained(model_base, resolved_adapter_path, is_trainable=True)
        ref_model = PeftModel.from_pretrained(ref_base, resolved_adapter_path, is_trainable=False)
    else:
        peft_config = LoraConfig(
            r=16,
            lora_alpha=32,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            lora_dropout=0.0,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(prepare_model_for_kbit_training(model_base), peft_config)
        ref_model = ref_base

    # TRL DPOTrainer expects this field for warning bookkeeping on some model wrappers.
    if not hasattr(model, "warnings_issued"):
        model.warnings_issued = {}
    if ref_model is not None and not hasattr(ref_model, "warnings_issued"):
        ref_model.warnings_issued = {}

    cfg = DPOConfig(
        output_dir=args.output_dir,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        per_device_eval_batch_size=4,
        learning_rate=2e-5,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        max_steps=args.max_steps,
        logging_steps=10,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=4,
        save_only_model=False,
        optim="paged_adamw_8bit" if args.load_in_4bit else "adamw_torch_fused",
        bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        fp16=not (torch.cuda.is_available() and torch.cuda.is_bf16_supported()),
        remove_unused_columns=False,
        report_to="none",
        beta=0.1,
        max_prompt_length=2048,
        max_length=3072,
        seed=args.seed,
        do_eval=eval_ds is not None,
        eval_strategy="steps" if eval_ds is not None else "no",
        eval_steps=100,
    )

    os.makedirs(args.output_dir, exist_ok=True)
    run_meta = {
        "base_model": args.base_model,
        "adapter_path": args.adapter_path,
        "resolved_adapter_path": resolved_adapter_path,
        "dataset": args.dataset,
        "train_rows": len(train_ds),
        "eval_rows": 0 if eval_ds is None else len(eval_ds),
        "max_steps": args.max_steps,
        "val_ratio": args.val_ratio,
        "seed": args.seed,
        "load_in_4bit": args.load_in_4bit,
        "resume_from_checkpoint": args.resume_from_checkpoint,
    }
    with open(os.path.join(args.output_dir, "run_meta.json"), "w", encoding="utf-8") as f:
        json.dump(run_meta, f, ensure_ascii=False, indent=2)

    trainer = DPOTrainer(
        model=model,
        ref_model=ref_model,
        args=cfg,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        processing_class=tokenizer,
    )

    trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)
    trainer.model.save_pretrained(f"{args.output_dir}/final_adapter")
    tokenizer.save_pretrained(f"{args.output_dir}/final_adapter")
    print(f"[OK] DPO done -> {args.output_dir}/final_adapter")


if __name__ == "__main__":
    main()
