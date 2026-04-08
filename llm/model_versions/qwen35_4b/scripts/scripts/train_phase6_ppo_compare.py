#!/usr/bin/env python3
import argparse
import json
import os
import re
from datasets import load_dataset
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, AutoModelForSequenceClassification, BitsAndBytesConfig
from trl import PPOTrainer, PPOConfig
from peft import PeftModel

from rl_compare_common import resolve_best_sft_adapter


def _strip_thinking(text: str) -> str:
    """Strip Qwen3 <think>...</think> CoT from generated responses.

    PPO generates responses and scores them with the reward model.
    If responses contain <think> blocks, the reward model sees the CoT text
    instead of the actual payload — corrupting rewards and causing the policy
    to learn that <think> is a valid payload prefix.
    """
    if not text:
        return text
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    pre, _, _ = text.partition("<think>")
    return (pre if "<think>" in text else text).strip()


def split_dataset(ds, val_ratio: float, seed: int):
    if val_ratio <= 0 or len(ds) < 100:
        return ds, None
    split = ds.train_test_split(test_size=val_ratio, seed=seed, shuffle=True)
    return split["train"], split["test"]


def ensure_scalar_reward_head(model):
    out_dim = int(model.score.weight.shape[0])
    if out_dim == 1:
        model.config.num_labels = 1
        model.num_labels = 1
        model.config.problem_type = "regression"
        return model
    in_dim = int(model.score.weight.shape[1])
    new_head = torch.nn.Linear(in_dim, 1, bias=False)
    new_head = new_head.to(device=model.score.weight.device, dtype=model.score.weight.dtype)
    if out_dim > 1:
        with torch.no_grad():
            new_head.weight.copy_(model.score.weight[:1])
    model.score = new_head
    model.config.num_labels = 1
    model.num_labels = 1
    model.config.problem_type = "regression"
    return model


def main():
    ap = argparse.ArgumentParser(description="Phase6 PPO training for comparison")
    ap.add_argument("--base_model", default="Qwen/Qwen3.5-4B")
    ap.add_argument("--policy_adapter", default="auto")
    ap.add_argument("--reward_model", default="output_phase6_reward_model/final")
    ap.add_argument("--prompts_dataset", default="data/processed/ppo_prompts_phase6.jsonl")
    ap.add_argument("--output_dir", default="output_phase6_ppo_compare")
    ap.add_argument("--val_ratio", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--total_episodes", type=int, default=1200)
    # 1024: enough headroom for Qwen3 <think>...</think> CoT (100-400 tok) + payload.
    # Old default 96 caused CoT to be cut mid-block, corrupting reward model inputs.
    ap.add_argument("--response_length", type=int, default=1024)
    ap.add_argument("--batch_size", type=int, default=64)
    ap.add_argument("--mini_batch_size", type=int, default=16)
    ap.add_argument("--num_ppo_epochs", type=int, default=2)
    ap.add_argument("--learning_rate", type=float, default=1e-6)
    ap.add_argument("--save_steps", type=int, default=50)
    ap.add_argument("--resume_from_checkpoint", type=str, default=None)
    ap.add_argument("--load_in_4bit", action="store_true")
    args = ap.parse_args()
    if args.batch_size % max(1, args.mini_batch_size) != 0:
        raise ValueError("--batch_size must be divisible by --mini_batch_size for PPO.")

    raw = load_dataset("json", data_files=args.prompts_dataset, split="train")
    raw = raw.filter(lambda x: bool(str(x.get("prompt", "")).strip()))

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.pad_token or tokenizer.eos_token
    tokenizer.padding_side = "left"
    resolved_policy_adapter = resolve_best_sft_adapter(args.policy_adapter)

    def tok(batch):
        return tokenizer(batch["prompt"], truncation=True, max_length=1536, padding=False)

    # Keep only tokenized fields for PPOTrainer to avoid collator nesting errors.
    ds = raw.map(tok, batched=True, remove_columns=raw.column_names)
    ds = ds.filter(lambda x: len(x["input_ids"]) > 0)
    train_ds, eval_ds = split_dataset(ds, args.val_ratio, args.seed)

    dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
    bnb_config = None
    if args.load_in_4bit:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=dtype,
            bnb_4bit_use_double_quant=True,
        )

    policy_base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        dtype=None if args.load_in_4bit else dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    if resolved_policy_adapter and os.path.exists(resolved_policy_adapter):
        policy = PeftModel.from_pretrained(policy_base, resolved_policy_adapter, is_trainable=True)
    else:
        policy = policy_base

    ref_base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        dtype=None if args.load_in_4bit else dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    if resolved_policy_adapter and os.path.exists(resolved_policy_adapter):
        ref_model = PeftModel.from_pretrained(ref_base, resolved_policy_adapter, is_trainable=False)
    else:
        ref_model = ref_base

    reward_model = AutoModelForSequenceClassification.from_pretrained(
        args.reward_model,
        dtype=dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    reward_model = ensure_scalar_reward_head(reward_model)
    value_model = AutoModelForSequenceClassification.from_pretrained(
        args.reward_model,
        dtype=dtype,
        device_map="auto",
        trust_remote_code=True,
    )
    value_model = ensure_scalar_reward_head(value_model)

    cfg = PPOConfig(
        output_dir=args.output_dir,
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=1,
        batch_size=args.batch_size,
        mini_batch_size=args.mini_batch_size,
        num_mini_batches=max(1, args.batch_size // max(1, args.mini_batch_size)),
        total_episodes=args.total_episodes,
        num_ppo_epochs=args.num_ppo_epochs,
        response_length=args.response_length,
        stop_token="eos",
        temperature=0.9,
        missing_eos_penalty=1.0,
        kl_coef=0.05,
        eval_strategy="steps" if eval_ds is not None else "no",
        eval_steps=args.save_steps,
        save_strategy="steps",
        save_steps=args.save_steps,
        save_total_limit=4,
        save_only_model=False,
        logging_steps=10,
        num_sample_generations=0,
        report_to="none",
        bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        fp16=not (torch.cuda.is_available() and torch.cuda.is_bf16_supported()),
        seed=args.seed,
        remove_unused_columns=False,
    )

    os.makedirs(args.output_dir, exist_ok=True)
    run_meta = {
        "base_model": args.base_model,
        "policy_adapter": args.policy_adapter,
        "resolved_policy_adapter": resolved_policy_adapter,
        "reward_model": args.reward_model,
        "prompts_dataset": args.prompts_dataset,
        "train_rows": len(train_ds),
        "eval_rows": 0 if eval_ds is None else len(eval_ds),
        "total_episodes": args.total_episodes,
        "batch_size": args.batch_size,
        "mini_batch_size": args.mini_batch_size,
        "num_ppo_epochs": args.num_ppo_epochs,
        "response_length": args.response_length,
        "learning_rate": args.learning_rate,
        "resume_from_checkpoint": args.resume_from_checkpoint,
    }
    with open(os.path.join(args.output_dir, "run_meta.json"), "w", encoding="utf-8") as f:
        json.dump(run_meta, f, ensure_ascii=False, indent=2)

    trainer = PPOTrainer(
        args=cfg,
        processing_class=tokenizer,
        model=policy,
        ref_model=ref_model,
        reward_model=reward_model,
        value_model=value_model,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
    )

    # PPOTrainer in TRL 0.24 does not accept resume_from_checkpoint in train().
    # Resume can be controlled via args.resume_from_checkpoint in PPOConfig if needed.
    trainer.train()
    trainer.policy_model.save_pretrained(f"{args.output_dir}/final_adapter")
    tokenizer.save_pretrained(f"{args.output_dir}/final_adapter")
    print(f"[OK] PPO done -> {args.output_dir}/final_adapter")


if __name__ == "__main__":
    main()
