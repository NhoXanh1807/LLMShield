import os
import json
import argparse
import torch
from unsloth import FastLanguageModel
from trl import SFTTrainer
from trl import SFTConfig
from datasets import load_dataset
from unsloth.chat_templates import get_chat_template

# Configuration
MODEL_NAME = "Qwen/Qwen3.5-4B"  # Updated to Qwen/Qwen3.5-4B as requested
DATASET_PATH = "data/phase6_merged_payload_only_strict.jsonl"
OUTPUT_DIR = "output_phase6_sft"
MAX_SEQ_LENGTH = 2048  # Reduced for higher throughput while preserving almost all samples
BATCH_SIZE = 8
GRAD_ACCUM = 8
EPOCHS = 3
LEARNING_RATE = 2e-5

def validate_payload_only_jsonl(path: str) -> dict:
    stats = {
        "total": 0,
        "bad_json": 0,
        "missing_messages": 0,
        "assistant_empty": 0,
        "assistant_json_like": 0,
        "valid": 0,
    }
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            stats["total"] += 1
            try:
                rec = json.loads(ln)
            except Exception:
                stats["bad_json"] += 1
                continue
            messages = rec.get("messages", [])
            if not isinstance(messages, list) or not messages:
                stats["missing_messages"] += 1
                continue
            assistant_msgs = [m.get("content", "") for m in messages if m.get("role") == "assistant"]
            if not assistant_msgs or any((not str(x).strip()) for x in assistant_msgs):
                stats["assistant_empty"] += 1
                continue
            # Payload-only schema should not be assistant JSON blocks.
            if any(str(x).strip().startswith("{") for x in assistant_msgs):
                stats["assistant_json_like"] += 1
                continue
            stats["valid"] += 1
    return stats

def format_dataset(examples, tokenizer):
    """
    Format standard HuggingFace messages array using Unsloth's chat template wrapper
    """
    texts = []
    for messages in examples["messages"]:
        # apply_chat_template handles the System/User/Assistant tags automatically
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        texts.append(text)
    return {"text": texts}


def build_prompt_completion_dataset(examples, tokenizer):
    """
    Convert multi-turn messages to prompt-completion where completion is only
    the final assistant turn. This enables completion-only loss and prevents
    learning to continue transcript role tags.
    """
    prompts, completions = [], []
    for messages in examples["messages"]:
        if not isinstance(messages, list) or len(messages) < 2:
            continue
        if messages[-1].get("role") != "assistant":
            continue
        completion = str(messages[-1].get("content", "")).strip()
        if not completion:
            continue
        prompt_messages = messages[:-1]
        if not prompt_messages or prompt_messages[-1].get("role") != "user":
            continue
        prompt = tokenizer.apply_chat_template(
            prompt_messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        prompts.append(prompt)
        completions.append(completion)
    return {"prompt": prompts, "completion": completions}

def get_optimized_gpu_config():
    """
    Heuristic config for better GPU utilization.
    - H100/A100 (>=70GB): BF16 + full precision weights (no 4bit), larger batch.
    - Mid GPUs: keep 4bit for stability.
    """
    cfg = {
        "dtype": None,
        "load_in_4bit": True,
        "batch_size": BATCH_SIZE,
        "grad_accum": GRAD_ACCUM,
        "optim": "adamw_8bit",
        "use_gradient_checkpointing": "unsloth",
        "dataset_num_proc": 2,
        "dataloader_num_workers": 4,
    }
    if not torch.cuda.is_available():
        return cfg

    props = torch.cuda.get_device_properties(0)
    total_gb = props.total_memory / (1024**3)
    name = props.name.lower()
    cpu_count = os.cpu_count() or 8

    # Fast math on modern NVIDIA GPUs.
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True

    if total_gb >= 120 or "h200" in name:
        cfg.update({
            "dtype": torch.bfloat16,
            "load_in_4bit": False,
            # 2048 seq length allows larger micro-batch on H200.
            "batch_size": 12,
            "grad_accum": 8,
            "optim": "adamw_torch_fused",
            # On 140GB VRAM we can usually disable checkpointing for higher tokens/sec.
            "use_gradient_checkpointing": False,
            "dataset_num_proc": min(8, max(2, cpu_count // 2)),
            "dataloader_num_workers": min(12, max(4, cpu_count // 2)),
        })
    elif total_gb >= 70 or "h100" in name or "a100" in name:
        cfg.update({
            "dtype": torch.bfloat16,
            "load_in_4bit": False,
            # OOM-safe default on long-context (3072) payload datasets.
            "batch_size": 4,
            "grad_accum": 16,
            "optim": "adamw_torch_fused",
            "use_gradient_checkpointing": "unsloth",
            "dataset_num_proc": min(6, max(2, cpu_count // 2)),
            "dataloader_num_workers": min(8, max(4, cpu_count // 2)),
        })
    elif total_gb >= 40:
        cfg.update({
            "dtype": torch.bfloat16 if torch.cuda.is_bf16_supported() else None,
            "load_in_4bit": True,
            "batch_size": 12,
            "grad_accum": 4,
            "optim": "adamw_8bit",
            "use_gradient_checkpointing": "unsloth",
            "dataset_num_proc": min(4, max(2, cpu_count // 2)),
            "dataloader_num_workers": min(6, max(2, cpu_count // 2)),
        })
    return cfg

def train(
    dataset_path: str,
    output_dir: str,
    epochs: int = EPOCHS,
    resume_from_checkpoint: str | None = None,
    save_strategy: str = "epoch",
    save_steps: int = 50,
    save_total_limit: int = 3,
    val_ratio: float = 0.05,
    test_ratio: float = 0.0,
    split_seed: int = 3407,
):
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    print(f"🔎 Validating payload-only dataset: {dataset_path}")
    vstats = validate_payload_only_jsonl(dataset_path)
    print(f"   - total={vstats['total']} valid={vstats['valid']} bad_json={vstats['bad_json']} "
          f"missing_messages={vstats['missing_messages']} assistant_empty={vstats['assistant_empty']} "
          f"assistant_json_like={vstats['assistant_json_like']}")
    if vstats["valid"] == 0:
        raise RuntimeError("No valid payload-only samples found. Abort training.")

    gpu_cfg = get_optimized_gpu_config()
    print(f"🚀 Loading {MODEL_NAME} with Unsloth...")
    print(f"⚙️ GPU config: load_in_4bit={gpu_cfg['load_in_4bit']} dtype={gpu_cfg['dtype']} "
          f"batch={gpu_cfg['batch_size']} grad_accum={gpu_cfg['grad_accum']} optim={gpu_cfg['optim']} "
          f"grad_ckpt={gpu_cfg['use_gradient_checkpointing']} data_proc={gpu_cfg['dataset_num_proc']} "
          f"loader_workers={gpu_cfg['dataloader_num_workers']}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_NAME,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=gpu_cfg["dtype"],  # Prefer bf16 on H100/A100
        load_in_4bit=gpu_cfg["load_in_4bit"],
    )

    print("🔧 Configuring LoRA Adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=32,
        lora_dropout=0, # optimized to 0 for Unsloth
        bias="none",
        use_gradient_checkpointing=gpu_cfg["use_gradient_checkpointing"],
        random_state=3407,
        use_rslora=False,
    )
    
    # Configure precise Chat Template for Qwen 2.5
    tokenizer = get_chat_template(
        tokenizer,
        chat_template="qwen-2.5",
        mapping={"role": "role", "content": "content", "user": "user", "assistant": "assistant"}
    )

    print(f"📂 Loading Golden Dataset from {dataset_path}...")
    dataset = load_dataset("json", data_files=dataset_path, split="train")
    
    print("🧹 Building prompt-completion dataset (assistant-last-only)...")
    dataset = dataset.map(
        lambda x: build_prompt_completion_dataset(x, tokenizer),
        batched=True,
        remove_columns=dataset.column_names,
        num_proc=gpu_cfg["dataset_num_proc"],
    )
    dataset = dataset.filter(
        lambda x: bool(str(x["prompt"]).strip()) and bool(str(x["completion"]).strip()),
        num_proc=gpu_cfg["dataset_num_proc"],
    )
    print(f"   - usable prompt-completion samples: {len(dataset)}")

    total_usable = len(dataset)
    train_dataset = dataset
    eval_dataset = None
    test_dataset = None

    if (val_ratio > 0 or test_ratio > 0) and total_usable >= 100:
        if val_ratio < 0 or test_ratio < 0 or (val_ratio + test_ratio) >= 0.5:
            raise ValueError("Invalid split ratios: require 0 <= val_ratio, test_ratio and val_ratio+test_ratio < 0.5")

        if test_ratio > 0:
            split_test = train_dataset.train_test_split(test_size=test_ratio, seed=split_seed, shuffle=True)
            train_dataset = split_test["train"]
            test_dataset = split_test["test"]

        if val_ratio > 0:
            remain = 1.0 - test_ratio
            val_from_train = val_ratio / remain if remain > 0 else val_ratio
            split_val = train_dataset.train_test_split(test_size=val_from_train, seed=split_seed + 1, shuffle=True)
            train_dataset = split_val["train"]
            eval_dataset = split_val["test"]

    print(
        f"🏋️ Starting SFT Training (total={total_usable}, train={len(train_dataset)}, "
        f"val={len(eval_dataset) if eval_dataset is not None else 0}, "
        f"test={len(test_dataset) if test_dataset is not None else 0})..."
    )
    text_tokenizer = tokenizer.tokenizer if hasattr(tokenizer, "tokenizer") else tokenizer
    trainer = SFTTrainer(
        model=model,
        processing_class=text_tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        args=SFTConfig(
            per_device_train_batch_size=gpu_cfg["batch_size"],
            gradient_accumulation_steps=gpu_cfg["grad_accum"],
            per_device_eval_batch_size=gpu_cfg["batch_size"],
            warmup_ratio=0.1,
            num_train_epochs=epochs,
            learning_rate=LEARNING_RATE,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=5,
            do_eval=eval_dataset is not None,
            eval_strategy="epoch" if eval_dataset is not None else "no",
            optim=gpu_cfg["optim"],
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=3407,
            output_dir=output_dir,
            save_strategy=save_strategy,
            save_steps=save_steps,
            save_total_limit=save_total_limit,
            save_only_model=False,  # keep optimizer/scheduler/rng state for resume
            dataloader_num_workers=gpu_cfg["dataloader_num_workers"],
            report_to="none",
            dataset_num_proc=gpu_cfg["dataset_num_proc"],
            max_length=MAX_SEQ_LENGTH,
            packing=False,
            completion_only_loss=True,
            assistant_only_loss=False,
        ),
    )

    os.makedirs(output_dir, exist_ok=True)
    run_meta = {
        "dataset": dataset_path,
        "epochs": epochs,
        "resume_from_checkpoint": resume_from_checkpoint,
        "save_strategy": save_strategy,
        "save_steps": save_steps,
        "save_total_limit": save_total_limit,
        "val_ratio": val_ratio,
        "test_ratio": test_ratio,
        "split_seed": split_seed,
        "max_seq_length": MAX_SEQ_LENGTH,
        "learning_rate": LEARNING_RATE,
        "usable_samples": total_usable,
        "train_samples": len(train_dataset),
        "val_samples": len(eval_dataset) if eval_dataset is not None else 0,
        "test_samples": len(test_dataset) if test_dataset is not None else 0,
        "batch_size": gpu_cfg["batch_size"],
        "grad_accum": gpu_cfg["grad_accum"],
        "load_in_4bit": gpu_cfg["load_in_4bit"],
        "dtype": str(gpu_cfg["dtype"]),
    }
    with open(os.path.join(output_dir, "run_meta.json"), "w", encoding="utf-8") as f:
        json.dump(run_meta, f, ensure_ascii=False, indent=2)

    if resume_from_checkpoint:
        print(f"♻️ Resuming from checkpoint: {resume_from_checkpoint}")
    trainer.train(resume_from_checkpoint=resume_from_checkpoint)

    if test_dataset is not None and len(test_dataset) > 0:
        print("🧪 Running final TEST evaluation...")
        test_metrics = trainer.evaluate(eval_dataset=test_dataset, metric_key_prefix="test")
        with open(os.path.join(output_dir, "test_metrics.json"), "w", encoding="utf-8") as f:
            json.dump(test_metrics, f, ensure_ascii=False, indent=2)
        print(f"   - test metrics: {test_metrics}")

    print("💾 Saving Model Adapter...")
    model.save_pretrained(f"{output_dir}/final_adapter")
    tokenizer.save_pretrained(f"{output_dir}/final_adapter")
    print("✅ Training Complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=str, default=DATASET_PATH)
    parser.add_argument("--output_dir", type=str, default=OUTPUT_DIR)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--resume_from_checkpoint", type=str, default=None)
    parser.add_argument("--save_strategy", type=str, choices=["epoch", "steps"], default="epoch")
    parser.add_argument("--save_steps", type=int, default=50)
    parser.add_argument("--save_total_limit", type=int, default=3)
    parser.add_argument("--val_ratio", type=float, default=0.05)
    parser.add_argument("--test_ratio", type=float, default=0.0)
    parser.add_argument("--split_seed", type=int, default=3407)
    args = parser.parse_args()
    train(
        args.dataset,
        args.output_dir,
        epochs=args.epochs,
        resume_from_checkpoint=args.resume_from_checkpoint,
        save_strategy=args.save_strategy,
        save_steps=args.save_steps,
        save_total_limit=args.save_total_limit,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
        split_seed=args.split_seed,
    )
