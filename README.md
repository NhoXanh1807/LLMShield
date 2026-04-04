https://github.com/NhoXanh1807/LLMShield
https://github.com/NhoXanh1807/LLM4WAF

## Hướng dẫn chạy repo

1. Khuyến nghị sử dụng python-venv
```sh
python3 -m venv .venv
# Linux/MacOS
source .venv/bin/activate
# Windows
.venv/Scripts/activate
```

2. Kiểm tra cài đặt đủ thư viện trong `requirements.txt`
```sh
python3 -m pip install -r requirements.txt
```

3. Kiểm tra cấu hình lựa chọn model để khởi chạy trong file `config.py`

4. Chuẩn bị HuggingFace token:
- Cách 1: Tạo file `hf_token.txt` chứa HuggingFace access token
- Cách 2: Truyền hf_token qua arguments khi chạy 
```sh
python3 main.py {HF_TOKEN}
```

5. Chạy hệ thống:
```sh
python3 main.py
# Hoặc
python3 main.py {HF_TOKEN}
```

6. Sử dụng hệ thống

***CURL***
```sh
curl -X POST "http://api.akng.io.vn:89/llm?adapter_name=phase1&max_new_tokens=128&temperature=0.7" -d "day la prompt ne"


{"success":true,"message":"success","data":"Simulated response to: day la prompt ne"}
```

***Python requests***
```python
import requests
adapter_name = "phase1"
max_new_tokens = "128"
temperature = "0.7"
res = requests.post(f"http://api.akng.io.vn:89/llm?adapter_name={adapter_name}&max_new_tokens={max_new_tokens}&temperature={temperature}", data="day la prompt ne")
print(res.text)
```

# LLMShield - Hướng dẫn phát triển và mở rộng dự án

## Mục tiêu thiết kế
Repo này được thiết kế để mọi phiên bản model đều có thể sử dụng chung một interface chuẩn là `AttackLLMInterface` (định nghĩa trong file `/interfaces.py`). Nhờ đó, hệ thống có thể dễ dàng tích hợp, thử nghiệm và sử dụng bất kỳ model mới nào chỉ bằng cách tuân thủ interface này, mà không cần sửa code lõi.


## Cấu trúc thư mục dự án
```
LLMShield/
├── main.py                  # ENTRY POINT : file khởi chạy
├── config.py                # CẤU HÌNH KHỞI CHẠY
├── interfaces.py            # Định nghĩa interface, dataclass chung
├── requirements.txt         # Danh sách thư viện
├── external_services.py     # API giao tiếp với Queue
└── model_versions/          # Các phiên bản nghiên cứu models
    ├── gemma2_2b/
    │   ├── model.py         # MODEL INTERFACE : implement AttackLLMInterface
    │   ├── scripts/         # Chứa documents, dataset, scripts preprocess, finetune, test, ... Mọi thứ liên quan đến quá trình phát triển model này.
    │   └── adapters/        # Chứa adapters để sử dụng. 
    ├── qwen25_3b/
    │   ├── model.py
    │   ├── scripts/
    │   └── adapters/
    └── ...(thêm model mới)...
        ├── model.py
        ├── scripts/
        └── adapters/
```

## Nguyên tắc phát triển
1. Với mỗi nguyên cứu model mới chúng ta sẽ tạo một thư mục mới trong `model_versions`
2. Các file làm việc trong lúc phát triển model, ví dụ như datasets, preprocessing scripts, finetuning scripts, test scripts, ... đều phải đặt gọn trong thư mục `scripts`. Thư mục `scripts` là nơi duy nhất được lộn xộn.
3. Các **adapters** kết quả sau khi finetuning, dùng để test này kia thì phải đặt trong thư mục `adapters`.
4. Mỗi model version mình phải thiết kế một file `model.py`, khai báo một class mới, implement interface `AttackLLMInterface` để entry point file `main.py` có thể sử dụng model mới này thông qua interface.

```python
# /model_versions/new_model/interface.py
from interfaces import AttackLLMInterface
class NewModelClass(AttackLLMInterface):
    def __init__(self, hf_token, load_immediately=False):
        # ...
    def load_model(self):
        # ...
    def generate(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> str:
        # ...
    def build_prompt(self, args : dict) -> tuple[bool, str]:
        # ...
    def generate_payload(self, args : dict) -> str:
        # ...
```

5. Khai báo tên model mới để load model trong hàm `load_model()` trong file `/main.py`
```python
# /main.py
def load_model(model_name, hf_token) -> AttackLLMInterface:
    #...
    elif model_name == "NEW_MODEL_NAME":
        from model_versions.new_model.interface import NewModelClass
        model = NewModelClass(hf_token, load_immediately=True)
    #...
    return model
```


## Lưu ý
- Không sửa đổi code lõi trừ khi thực sự cần thiết.
- Đảm bảo tuân thủ interface.
