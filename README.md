
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
   - Server HTTP chạy tại `https://overrigged-savingly-nelle.ngrok-free.dev/` theo cấu hình NGROK.
   - Các action hỗ trợ: `generate`, `build_prompt`, `generate_payload`, `rag_retrieve`.
   - Server sẽ ưu tiên chấp nhận các params trong json body request trước, sau đó đến param trong query string

**Ví dụ CURL:**
```sh
curl -X POST "http://127.0.0.1:89/llm?action=generate&adapter_name=phase1&max_new_tokens=128&temperature=0.7&prompt=this_prompt_will_not_be_used" -d '{"prompt": "day moi la prompt ne"}'
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
- Đăng ký model mới trong `MODEL_LOADERS` ở `config.py`:
```python
from llm.model_versions.simulator.model import SimulateModel
from llm.model_versions.gemma2_2b.model import Gemma2_2B
from llm.model_versions.qwen35_4b.model import Qwen35_4B
from llm.model_versions.new_model.model import NewModel

class Config:
    ...
    MODEL_LOADERS = {
        "FAKE": SimulateModel,
        "GEMMA_2B": Gemma2_2B,
        "QWEN_4B": Qwen35_4B,
        "NEW_MODEL": NewModel
    }
    ...
```

## 5. Tích hợp RAG (Retrieval-Augmented Generation)
- Mọi cập nhật, nâng cấp mã nguồn của RAG chỉ được phép nằm gói gọn trong thư mục `/rag`, và phải đảm bảo hàm `rag_retrieve()` trong `main.py` sẽ xử lý và trả về dữ liệu như mong đợi dưới dạng JSON String (not multi-line JSON).

## 6. Lưu ý phát triển
- Không sửa đổi code lõi trừ khi thực sự cần thiết.
- Đảm bảo tuân thủ interface chuẩn.
- Tài liệu, dataset, script phát triển để trong `scripts/` của từng model.
- Adapter, checkpoint để trong `adapters/`.
