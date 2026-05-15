# LLMShield

LLMShield is an external service dedicated to the heavy-compute tasks of the LLM4WAF system. This repository separates language model inference and knowledge retrieval from the main application so that LLM4WAF can focus on orchestrating the attack and defense pipelines. In the current architecture, LLMShield is responsible for loading models, managing adapters, initializing RAG, and exposing a unified HTTP API for external consumers.

## Introduction: LLMShield's Role in LLM4WAF

Within LLM4WAF, LLMShield acts as a foundational service layer for tasks that require significant compute resources and an independent runtime lifecycle. Specifically, LLMShield provides the model-serving environment used to generate prompts, produce attack payloads, and retrieve document context for defensive rule generation. This separation allows LLM4WAF to avoid handling model loading, GPU management, and vector store construction directly, while also making it easier to research, train, and integrate new model versions without large changes in the main repository.

## Project Source Code Structure

```text
LLMShield/
├── main.py
├── config.py
├── hf_token.txt
├── requirements.txt
├── llm/
│   ├── interfaces.py
│   └── model_versions/
│       ├── gemma2_2b/
│       │   ├── model.py
│       │   ├── adapters/
│       │   └── scripts/
│       ├── qwen35_4b/
│       │   ├── model.py
│       │   ├── adapters/
│       │   └── scripts/
│       ├── simulator/
│       │   └── model.py
│       └── ...(new model versions)...
├── rag/
│   ├── rag_service.py
│   ├── docs/
│   └── vector_store/
└── test/
```

- `main.py`: the service entry point. It initializes the model, initializes the RAG service, starts the HTTP server, and exposes the service through ngrok.
- `config.py`: holds runtime configuration and the `MODEL_LOADERS` registry that maps model names to their concrete implementations.
- `llm/interfaces.py`: defines the standard `AttackLLMInterface` that every new model implementation must follow.
- `llm/model_versions/`: stores each model version in an isolated structure. A model version can include inference code, adapters, training scripts, evaluation scripts, and research assets.
- `rag/rag_service.py`: implements all RAG-related logic, including document indexing, vector store management, retrieval, and reranking.
- `rag/docs/`: contains source materials for RAG, such as rule documentation, guidelines, and WAF-related knowledge.
- `rag/vector_store/`: stores the built FAISS index for reuse across service restarts.
- `test/`: contains quick test scripts or integration checks for individual service capabilities.

## Project Development Conventions

The purpose of the current layout is to keep the transport layer, model layer, and RAG layer separate. When adding new functionality, changes should be made in the appropriate layer instead of spreading logic across unrelated parts of the codebase.

### Research, Development, Training, and Integration of New Models

When adding a new model, create a dedicated directory under `llm/model_versions/` using the existing format so that all model-related assets remain colocated:

- `model.py`: model runtime implementation
- `adapters/`: adapters or checkpoints used for inference
- `scripts/`: scripts for training, data preparation, evaluation, or experimentation

Every new model must implement the standard interface defined in `llm/interfaces.py`:

```python
from llm.interfaces import AttackLLMInterface

class NewModel(AttackLLMInterface):
    def __init__(self, hf_token, load_immediately=False):
        self.hf_token = hf_token
        self.loaded = False
        if load_immediately:
            self.load_model()

    def load_model(self):
        ...

    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "") -> str:
        ...

    def build_prompt(self, args: dict) -> tuple[bool, str]:
        ...

    def generate_payload(self, args: dict) -> str:
        ...
```

Then import the new model and register its loader in `config.py`:

```python
from llm.model_versions.simulator.model import SimulateModel
from llm.model_versions.gemma2_2b.model import Gemma2_2B
from llm.model_versions.qwen35_4b.model import Qwen35_4B
# new model
from llm.model_versions.new_model.model import NewModel

class Config:
    MODEL_LOADERS = {
        "FAKE": SimulateModel,
        "GEMMA_2B": Gemma2_2B,
        "QWEN_4B": Qwen35_4B,
        # new model
        "NEW_MODEL": NewModel,
    }
```

The following conventions should be preserved:

- do not change the `AttackLLMInterface` contract unless it is absolutely necessary
- adapter names must remain stable so that external clients can call the correct `adapter_name`
- model-specific logic must stay inside that model's directory and should not be pushed into `main.py`
- training and research assets must stay in `scripts/`, and trained adapter versions must be stored in `adapters/`, not mixed into the repository root

### Updating or Modifying RAG

All RAG-related changes must be implemented inside the `rag` directory. This includes:

- updating source materials in `rag/docs/`
- modifying indexing, retrieval, and reranking logic in `rag/rag_service.py`
- updating or rebuilding the vector store in `rag/vector_store/`

When updating RAG, ensure that the output contract of the `rag_retrieve` action remains compatible with external repositories, especially the JSON response structure.

## Capabilities Provided by LLMShield

LLMShield currently provides a set of capabilities that support two main categories of work: LLM-based generation and RAG-based document context retrieval. These capabilities are exposed over HTTP so that LLM4WAF and other repositories can invoke them in a unified way.

The current service uses a shared HTTP endpoint and distinguishes capabilities through the `action` parameter.

- Method: `POST`
- Default local base endpoint: `http://127.0.0.1:89`
- Public endpoint: the ngrok URL printed when the service starts
- `action` can be passed in the query string or in the JSON body
- If the same key appears in both the query string and the JSON body, the value from the JSON body takes precedence

Common request format:

```text
POST /?action=<action_name>
```

### `generate` API

This capability accepts a fully prepared prompt and calls the currently loaded model directly to generate text output.

Request body:

```json
{
  "prompt": "Generate a payload...",
  "max_new_tokens": 128,
  "temperature": 0.7,
  "adapter_name": "phase1"
}
```

Main fields:

- `prompt`: required
- `max_new_tokens`: optional, default `128`
- `temperature`: optional, default `0.7`
- `adapter_name`: optional, used to select the appropriate adapter for the current model

Response:

- data type: plain text
- content: the string generated by the model

### `build_prompt` API

This capability uses the model's internal logic to build a prompt suitable for the task being processed. The request contract depends on the implementation of the currently loaded model.

Example request for `Gemma2_2B` in the payload-generation phase from a technique:

```json
{
  "waf_name": "ModSecurity",
  "attack_type": "sql_injection",
  "technique": "Comment Obfuscation (/**/)"
}
```

Example request with phase-3 data:

```json
{
  "waf_name": "ModSecurity",
  "attack_type": "sql_injection",
  "probe_history": [
    {
      "payload": "' or 1=1 --",
      "technique": "Boolean-based Blind",
      "is_bypassed": false
    }
  ]
}
```

Response:

- data type: plain text
- content: the constructed prompt

### `generate_payload` API

This capability is a higher-level utility that builds the prompt and generates a payload within the same request. It is the most suitable action when an external client wants the final payload directly.

Example request:

```json
{
  "waf_name": "ModSecurity",
  "attack_type": "sql_injection",
  "technique": "Comment Obfuscation (/**/)",
  "probe_history": null,
  "max_new_tokens": 128,
  "temperature": 0.7,
  "adapter_name": "phase1"
}
```

Response:

- data type: plain text
- content: the final payload after the model finishes processing

Notes:

- with `Gemma2_2B`, the output is cleaned to remove code fences and keep only the valid payload
- with other models, the `build_prompt()` contract may differ, so client request formats should be rechecked when switching models

### `rag_retrieve` API

This capability retrieves document context from the RAG system to support defensive rule generation in LLM4WAF or other systems.

Example request:

```json
{
  "attack_type": "sql_injection",
  "waf_name": "ModSecurity",
  "bypassed_payloads": [
    "'/**/OR/**/1=1--",
    "UNION/**/SELECT/**/1,2"
  ],
  "initial_k": 16,
  "final_k": 5,
  "filter_rules_only": true
}
```

Main fields:

- `attack_type`: required; must be one of the supported values such as `xss_dom`, `xss_reflected`, `xss_stored`, `sql_injection`, or `sql_injection_blind`
- `waf_name`: target WAF name
- `bypassed_payloads`: payload list used to enrich retrieval queries
- `initial_k`: number of candidates retrieved in the first retrieval stage
- `final_k`: number of final results after reranking
- `filter_rules_only`: when `true`, limits the results to sources suitable for rule generation

Response:

- data type: JSON
- main content: retrieval metadata, a `sources` list, the generated `queries`, and a `context` field intended for downstream rule generation

## Project Startup Guide

### Required Hardware

- Virtual machine (recommended: `Vast.ai`) or a personal machine with an NVIDIA CUDA-capable GPU.
- Minimum CUDA version: 12.8.
- Supported GPU compute architecture: sm_75 -> sm_90
- Suitable GPU families:
    - RTX 2000 series
    - RTX 3000 series
    - RTX 4000 series
    - NVIDIA A2000
    - NVIDIA A4000
    - NVIDIA A5000
    - NVIDIA A6000

## How to Run the Repository

```sh
# 1. Clone the repository
git clone https://github.com/NhoXanh1807/LLMShield


# 2. Enter the LLMShield repository directory
cd LLMShield
# Create a virtual environment
python -m venv .venv


# 3. Activate the virtual environment
# - Linux/MacOS
source .venv/bin/activate
# - Windows
.venv/Scripts/activate


# 4. Upgrade pip
python -m pip install --upgrade pip


# 5. Install dependencies
pip install -r requirements.txt


python main.py <HF_TOKEN> <MODEL_NAME> <ENABLE_RAG:y/n>
# 6. Prepare the HF_TOKEN from Hugging Face
# 7. Start the project


>importing libraries...
>Available models: ['FAKE', 'GEMMA_2B', 'QWEN_4B']
>Enter model name: 
# 8. Enter the LLM model name to run: GEMMA_2B is recommended


>NGROK: 127.0.0.1:89 -> https://overrigged-savingly-nelle.ngrok-free.dev
>Type 'exit' to stop server: 
# 9. At this point the service is running. Enter 'exit' to stop it.
```
