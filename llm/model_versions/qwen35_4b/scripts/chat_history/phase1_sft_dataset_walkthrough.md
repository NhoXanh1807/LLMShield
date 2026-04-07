# Kịch bản DPO Data Generation (21 Techniques V4)

Để khắc phục hiện tượng Mode Collapse của DPO vì dữ liệu cũ quá nghèo nàn, chúng tôi đã tạo một phễu sinh dữ liệu đa dạng hơn rất nhiều cho cụm Docker Live WAF. Dưới đây là các thay đổi cốt lõi:

## Script Mới: `scripts/generate_dpo_full_21_techs.py`

Thay vì sử dụng danh sách tĩnh 16 technique lỏng lẻo như bản V3, bản V4 này đã được nhúng **cứng** 21 techniques nguyên thủy đến từ pha SFT, chia vào 5 mảng:
- `sqli_classic`
- `sqli_blind`
- `xss_reflected`
- `xss_stored`
- `xss_dom`

**Điểm đặc biệt (Teacher Mode):** Script tự động load model `output_phase6_sft/final_adapter` làm Base Model thay vì chạy Qwen 3.5 4B thuần. Nhờ đó, model đã thông minh sẵn sẽ đóng vai Teacher (Người mài giũa) để sinh payload có tỷ lệ vượt ngục (CHOSEN) cao hơn hẳn.

## Tài Liệu Đã Cập Nhật

File `REMOTE_DPO_LIVE_INSTRUCTIONS.md` đã được thay thế toàn bộ lệnh bash ở Bước 2 & Bước 3:
- Lệnh tạo Data sẽ sử dụng `--attempts 1050` (Tương đương cho mỗi nhánh 50 lệnh sinh mồi).
- Đầu ra sẽ là `data/processed/dpo_live_modsec_v4_full_21.jsonl`
- Đầu ra của mô hình huấn luyện sau cùng sẽ là `output_phase6_dpo_true_v4`.

---

**Cách chạy ngay lập tức nếu Server có sẵn GPU & Docker WAF:**
```bash
python3 scripts/generate_dpo_full_21_techs.py --attempts 1050
```
