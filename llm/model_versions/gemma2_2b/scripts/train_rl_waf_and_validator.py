import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), 
    '..', #scripts
    '..', #gemma2_2b
    '..', #model_versions
    '..', #llm
    '..', #LLMShield
)))

from trl import PPOTrainer, PPOConfig
import json
from llm.model_versions.gemma2_2b.model import Gemma2_2B
from transformers import AutoTokenizer, AutoModelForCausalLM
from enum import Enum
import payload_harmness_validator as pval
import dvwa

class TrainableGemma2_2B(Gemma2_2B):
    def __init__(self, hf_token, load_immediately=False):
        super().__init__(hf_token, load_immediately)

    def reward_function(self, generated_payloads: list[str], rewards: list[float]):
        # Implement your reward function logic here
        # For example, you could return the rewards as-is or apply some transformation
        return rewards


def load_train_data(data_path):
    # Expecting a jsonl file with {"prompt": ..., "reward": ...}
    data = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            data.append(item)
    return data

def main():
    dvwa_url = "http://modsec.llmshield.click"
    session_id = dvwa.loginDVWA(dvwa_url)
    from dataclasses import asdict
    print(asdict(dvwa.attack_xss_reflected("<script>alert(1)</script>", session_id, dvwa_url)))
    exit()
    
    HF_TOKEN = input("HF_TOKEN=")
    model = TrainableGemma2_2B(hf_token=HF_TOKEN, load_immediately=True)

    # Load training data
    data_path = input("Path to train data (jsonl): ")
    train_data = load_train_data(data_path)

    # PPO config
    ppo_config = PPOConfig(
        model_name=model.BASE_MODEL,
        learning_rate=1e-5,
        batch_size=2,
        mini_batch_size=1,
        gradient_accumulation_steps=1,
        optimize_device_cache=True,
        log_with=None,
        total_ppo_epochs=3
    )

    # PPOTrainer expects HuggingFace model and tokenizer
    # Use model.model and model.tokenizer from your wrapper
    ppo_trainer = PPOTrainer(
        config=ppo_config,
        model=model.model,
        ref_model=None,
        tokenizer=model.tokenizer,
        dataset=None  # We'll feed data manually
    )

    for epoch in range(ppo_config.total_ppo_epochs):
        print(f"Epoch {epoch+1}/{ppo_config.total_ppo_epochs}")
        for item in train_data:
            prompt = item["prompt"]
            reward = item["reward"]
            # Generate response
            response = model.generate(prompt)
            # Compute reward (can be more complex)
            rewards = model.reward_function([response], [reward])
            # PPO step
            ppo_trainer.step([prompt], [response], rewards)
        
        # Save checkpoint after each epoch
        save_dir = f"ppo_checkpoint_epoch_{epoch+1}"
        os.makedirs(save_dir, exist_ok=True)
        model.model.save_pretrained(save_dir)
        model.tokenizer.save_pretrained(save_dir)
        print(f"Checkpoint saved to {save_dir}")

if __name__ == "__main__":
    main()

