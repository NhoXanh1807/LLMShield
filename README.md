
# LLMShield - Hướng dẫn sử dụng & phát triển (2026)

## 1. Hướng dẫn chạy repo

1. **Tạo môi trường ảo (python-venv):**
```sh
python -m venv .venv
# Linux/MacOS
source .venv/bin/activate
# Windows
.venv/Scripts/activate
```

2. **Cài đặt thư viện:**
```sh
python -m pip install -r requirements.txt
```

3. **Chuẩn bị HuggingFace token:**
   - Cách 1: Tạo file `hf_token.txt` chứa HuggingFace access token.
   - Cách 2: Truyền hf_token qua arguments khi chạy:
```sh
python main.py {HF_TOKEN}
```

4. **Chạy hệ thống:**
```sh
python main.py
# hoặc
python main.py {HF_TOKEN}
```
Khi khởi động sẽ yêu cầu nhập tên model (FAKE, GEMMA_2B, QWEN_4B).

5. **API endpoint:**
   - Server HTTP chạy tại `http://127.0.0.1:89/` (hoặc domain ngrok nếu cấu hình).
   - Các action hỗ trợ: `generate`, `build_prompt`, `generate_payload`, `rag_retrieve`.

**Ví dụ CURL:**
```sh
curl -X POST "http://127.0.0.1:89/llm?action=generate&adapter_name=phase1&max_new_tokens=128&temperature=0.7" -d '{"prompt": "day la prompt ne"}'
```

**Ví dụ Python requests:**
```python
import requests
data = {"prompt": "day la prompt ne"}
res = requests.post("http://127.0.0.1:89/llm?action=generate&adapter_name=phase1&max_new_tokens=128&temperature=0.7", json=data)
print(res.text)
```

## 2. Cấu trúc thư mục dự án (chuẩn hóa)
```
LLMShield/
├── main.py                  # ENTRY POINT : file khởi chạy
├── config.py                # CẤU HÌNH KHỞI CHẠY
├── requirements.txt         # Danh sách thư viện
├── llm/
│   ├── interfaces.py        # Định nghĩa interface, dataclass chung
│   └── model_versions/
│       ├── gemma2_2b/
│       │   ├── model.py         # Implement AttackLLMInterface
│       │   ├── scripts/         # Tài liệu, dataset, script phát triển
│       │   └── adapters/        # Các adapter, checkpoint
│       ├── qwen35_4b/
│       │   ├── model.py
│       │   ├── scripts/
│       │   └── adapters/
│       ├── simulator/
│       │   └── model.py         # Model giả lập
│       └── ...(thêm model mới)...
├── rag/
│   ├── rag_service.py       # RAG service cho rule generation
│   └── docs/                # Tài liệu, rule, cheat sheet
└── ...
```

## 3. Interface chuẩn & phát triển model mới
- Interface chuẩn: `llm/interfaces.py` (class `AttackLLMInterface`)
- Mỗi model mới tạo class kế thừa interface này, ví dụ:
```python
from llm.interfaces import AttackLLMInterface
class NewModel(AttackLLMInterface):
    def __init__(self, hf_token, load_immediately=False): ...
    def load_model(self): ...
    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> str: ...
    def build_prompt(self, args: dict) -> tuple[bool, str]: ...
    def generate_payload(self, args: dict) -> str: ...
```

## 4. Thêm model mới vào hệ thống
- Đăng ký model mới trong `MODEL_LOADERS` ở `main.py`:
```python
MODEL_LOADERS = {
    "FAKE": SimulateModel,
    "GEMMA_2B": Gemma2_2B,
    "QWEN_4B": Qwen35_4B,
    "NEW_MODEL": NewModel
}
```

## 5. Tích hợp RAG (Retrieval-Augmented Generation)
- Module `rag/rag_service.py` hỗ trợ sinh rule/phản hồi nâng cao qua action `rag_retrieve`.
- Có thể mở rộng docs, vector store, embedding, reranker theo nhu cầu.

## 6. Forwarding qua ngrok
- Hệ thống tự động forwarding port qua ngrok nếu cấu hình `NGROK_AUTHTOKEN` và `NGROK_DOMAIN` trong `config.py`.

## 7. Lưu ý phát triển
- Không sửa đổi code lõi trừ khi thực sự cần thiết.
- Đảm bảo tuân thủ interface chuẩn.
- Tài liệu, dataset, script phát triển để trong `scripts/` của từng model.
- Adapter, checkpoint để trong `adapters/`.
