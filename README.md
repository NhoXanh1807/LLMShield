# LLMShield

LLMShield là external service chuyên trách cho các tác vụ nặng của hệ thống LLM4WAF. Repo này tách riêng phần suy luận mô hình ngôn ngữ và truy hồi tri thức để LLM4WAF có thể tập trung vào orchestration của attack pipeline và defend pipeline. Trong kiến trúc hiện tại, LLMShield chịu trách nhiệm nạp model, quản lý adapter, khởi tạo RAG, và cung cấp HTTP API để các thành phần bên ngoài gọi đến một cách thống nhất.

## Mở đầu, nói về mục tiêu của LLMShield đối với LLM4WAF

Đối với LLM4WAF, LLMShield là lớp dịch vụ nền dùng để xử lý các tác vụ cần nhiều tài nguyên tính toán và có vòng đời vận hành độc lập. Cụ thể, LLMShield cung cấp môi trường phục vụ mô hình để sinh prompt, sinh payload tấn công, và truy hồi ngữ cảnh tài liệu phục vụ sinh rule phòng thủ. Cách tổ chức này giúp LLM4WAF không phải gánh phần load model, quản lý GPU, hay xây dựng vector store, đồng thời tạo điều kiện để nhóm phát triển nghiên cứu, huấn luyện, và tích hợp thêm model mới mà không phải thay đổi nhiều ở repo chính.

## Trình bày cấu trúc source code dự án

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
│       └── ...(thêm model mới)...
├── rag/
│   ├── rag_service.py
│   ├── docs/
│   └── vector_store/
└── test/
```

- `main.py`: entry point của service. File này khởi tạo model, khởi tạo RAG service, mở HTTP server và public service qua ngrok.
- `config.py`: nơi khai báo cấu hình runtime và bảng đăng ký `MODEL_LOADERS` để ánh xạ tên model sang implementation tương ứng.
- `llm/interfaces.py`: định nghĩa interface chuẩn `AttackLLMInterface` mà mọi model mới phải tuân theo.
- `llm/model_versions/`: nơi chứa từng phiên bản model theo dạng tách biệt. Mỗi model có thể đi kèm code inference, adapters, scripts huấn luyện, scripts đánh giá, và tài nguyên phục vụ nghiên cứu.
- `rag/rag_service.py`: nơi hiện thực toàn bộ logic RAG, bao gồm indexing tài liệu, vector store, retrieval và reranking.
- `rag/docs/`: tập tài liệu nguồn cho RAG như rule docs, guideline và tri thức liên quan đến các WAF.
- `rag/vector_store/`: nơi lưu FAISS index đã build để tái sử dụng khi khởi động lại service.
- `test/`: các script kiểm tra nhanh hoặc test integration cho từng chức năng của service.

## Quy chuẩn phát triển dự án

Mục tiêu của cách tổ chức hiện tại là giữ cho transport layer, model layer và RAG layer tách biệt. Khi phát triển thêm tính năng, cần ưu tiên mở rộng đúng lớp chức năng thay vì sửa lan sang nhiều nơi.

### Nghiên cứu, phát triển, huấn luyện, tích hợp thêm model mới

Khi thêm model mới, cần tạo thư mục riêng trong `llm/model_versions/` theo đúng format hiện tại để giữ mọi thứ liên quan đến model nằm cùng một chỗ:

- `model.py`: code implement model runtime
- `adapters/`: các adapter hoặc checkpoint phục vụ inference
- `scripts/`: script huấn luyện, chuẩn bị dữ liệu, đánh giá, hoặc thực nghiệm

Model mới phải implement interface chuẩn trong `llm/interfaces.py`:

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

Sau đó import model mới và khai báo loader trong `config.py`:

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

Quy chuẩn cần giữ:

- không sửa contract của `AttackLLMInterface` nếu chưa thật sự cần thiết
- tên adapter phải ổn định để client bên ngoài có thể gọi đúng `adapter_name`
- logic đặc thù của từng model phải nằm trong thư mục model đó, không đẩy sang `main.py`
- tài nguyên phục vụ huấn luyện và nghiên cứu để trong `scripts/`, từng versions adapters sau khi huấn luyện phải để trong `adapters/`, không đặt lẫn ở thư mục gốc

### Cập nhật, chỉnh sửa RAG

Mọi thay đổi liên quan đến RAG cần được thực hiện trong thư mục `rag`. Điều này bao gồm:

- cập nhật tài liệu nguồn trong `rag/docs/`
- chỉnh sửa logic indexing, retrieval, reranking trong `rag/rag_service.py`
- cập nhật hoặc rebuild vector store trong `rag/vector_store/`

Khi chỉnh sửa RAG, cần đảm bảo đầu ra của action `rag_retrieve` vẫn giữ được contract mà repo ngoài đang sử dụng, đặc biệt là cấu trúc JSON response.

## Chức năng mà LLMShield cung cấp

LLMShield hiện cung cấp một tập chức năng phục vụ hai nhóm nghiệp vụ chính: sinh nội dung bằng LLM và truy hồi ngữ cảnh tài liệu bằng RAG. Các chức năng này được expose qua HTTP API để LLM4WAF hoặc các repo khác có thể gọi đến theo cùng một cách thống nhất.

Service hiện tại dùng chung một endpoint HTTP và phân biệt chức năng bằng tham số `action`.

- Method: `POST`
- Base endpoint local mặc định: `http://127.0.0.1:89`
- Public endpoint: URL được ngrok in ra khi service khởi động
- `action` có thể được truyền trong query string hoặc JSON body
- Nếu cùng một key xuất hiện ở cả query string và JSON body thì giá trị trong JSON body sẽ được ưu tiên

Ví dụ format gọi chung:

```text
POST /?action=<ten_action>
```

### API `generate`

Chức năng này nhận một prompt hoàn chỉnh và gọi trực tiếp vào model đang được nạp để sinh text đầu ra.

Request body:

```json
{
  "prompt": "Generate a payload...",
  "max_new_tokens": 128,
  "temperature": 0.7,
  "adapter_name": "phase1"
}
```

Các trường chính:

- `prompt`: bắt buộc
- `max_new_tokens`: tùy chọn, mặc định `128`
- `temperature`: tùy chọn, mặc định `0.7`
- `adapter_name`: tùy chọn, dùng để chọn adapter tương ứng với model hiện tại

Response:

- kiểu dữ liệu: plain text
- nội dung: chuỗi do model sinh ra

### API `build_prompt`

Chức năng này dùng logic nội bộ của model để tạo prompt phù hợp với bài toán đang xử lý. Contract request phụ thuộc vào implementation của model đang được nạp.

Ví dụ request với `Gemma2_2B` ở phase sinh payload từ kỹ thuật:

```json
{
  "waf_name": "ModSecurity",
  "attack_type": "sql_injection",
  "technique": "Comment Obfuscation (/**/)"
}
```

Ví dụ request với dữ liệu phase 3:

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

- kiểu dữ liệu: plain text
- nội dung: prompt đã được build

### API `generate_payload`

Chức năng này là lớp tiện ích ở mức cao hơn, dùng để build prompt và sinh payload trong cùng một request. Đây là action phù hợp nhất khi client bên ngoài muốn nhận payload đầu ra trực tiếp.

Ví dụ request:

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

- kiểu dữ liệu: plain text
- nội dung: payload cuối cùng sau khi model xử lý xong

Lưu ý:

- với `Gemma2_2B`, đầu ra được làm sạch để bỏ code fence và chỉ giữ payload hợp lệ
- với model khác, contract của `build_prompt()` có thể khác, nên khi đổi model cần kiểm tra lại client request format

### API `rag_retrieve`

Chức năng này truy hồi ngữ cảnh tài liệu từ hệ RAG để phục vụ sinh rule phòng thủ ở LLM4WAF hoặc các hệ thống khác.

Ví dụ request:

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

Các trường chính:

- `attack_type`: bắt buộc, phải là một trong các giá trị mà service hỗ trợ như `xss_dom`, `xss_reflected`, `xss_stored`, `sql_injection`, `sql_injection_blind`
- `waf_name`: tên WAF đích
- `bypassed_payloads`: danh sách payload dùng để enrich truy vấn retrieval
- `initial_k`: số lượng candidate lấy ở bước retrieval đầu
- `final_k`: số lượng kết quả cuối cùng sau rerank
- `filter_rules_only`: chỉ lấy các nguồn phù hợp cho sinh rule nếu bật `true`

Response:

- kiểu dữ liệu: JSON
- nội dung chính gồm metadata truy hồi, danh sách `sources`, các `queries` đã sinh, và trường `context` dùng để feed tiếp cho tác vụ sinh rule

## Hướng dẫn khởi chạy dự án

### Phần cứng yêu cầu

- Máy ảo (khuyến nghị web `Vast.ai`) hoặc máy cá nhân có GPU nhân CUDA.
- Phiên bản cuda tối thiểu 12.8.
- Kiến trúc GPU compute phù hợp : sm_75 -> sm_90
- Các dòng phù hợp:
    - RTX 2000 series
    - RTX 3000 series
    - RTX 4000 series
    - NVIDIA A2000
    - NVIDIA A4000
    - NVIDIA A5000
    - NVIDIA A6000

## Hướng dẫn chạy repo

```sh
# 1. Tải repo về máy
git clone https://github.com/NhoXanh1807/LLMShield


# 2. Vào thư mục của repo LLMShield
cd LLMShield
# Tạo Virtual Enviroment
python -m venv .venv


# 3. Kích hoạt VENV
# - Linux/MacOS
source .venv/bin/activate
# - Windows
.venv/Scripts/activate


# 4. Cập nhật pip mới
python -m pip install --upgrade pip


# 5. Cài đặt thư viện
pip install -r requirements.txt


# 6. Chuẩn bị HF_TOKEN từ Huggingface
# 7. Chạy dự án
python main.py <HF_TOKEN>


>importing libraries...
>Available models: ['FAKE', 'GEMMA_2B', 'QWEN_4B']
>Enter model name: 
# 8. Nhập tên model LLM để chạy : khuyến nghị GEMMA_2B


>NGROK: 127.0.0.1:89 -> https://overrigged-savingly-nelle.ngrok-free.dev
>Type 'exit' to stop server: 
# 9. Hiện như vậy là service đã chạy rồi nhé, nếu muốn tắt có thể nhập 'exit'
```
