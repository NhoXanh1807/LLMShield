# Dataset Documentation

## Files

| File | Samples | Description |
|------|---------|-------------|
| `sft_train.jsonl` | 1,480 | SFT training mix — balanced across 21 techniques, payload-stripped to remove bias |
| `dpo_train.jsonl` | 2,550 | DPO training pairs — `chosen` (WAF bypass) vs `rejected` (blocked) per technique |
| `multiturn_train.jsonl` | 581 | Multi-turn conversation SFT data — full attack trajectories with WAF oracle feedback |

---

## Format

### `sft_train.jsonl` — Single/Multi-turn SFT
Each line is a JSON object:
```json
{
  "messages": [
    {"role": "system",    "content": "You are an expert Red Team security researcher..."},
    {"role": "user",      "content": "Generate maximally obfuscated sqli_classic payload...\nCONSTRAINT: Avoid all quotes — use hex literals..."},
    {"role": "assistant", "content": "1 AND 1=1 UNION SELECT 1,CONCAT(0x61,0x64,0x6d,0x69,0x6e)--"}
  ],
  "meta": {
    "vector": "sqli_classic",
    "constraint": "Avoid all quotes — use hex literals, backtick strings, or CONCAT(0x27,...).",
    "outcome": "bypass_success"
  }
}
```

### `dpo_train.jsonl` — DPO Pairs
```json
{
  "prompt": "<|im_start|>system\n...<|im_end|>\n<|im_start|>user\n...<|im_end|>\n<|im_start|>assistant\n",
  "chosen": "{\"thought\": \"Use hex encoding to avoid quote detection\", \"payload\": \"1 AND 1=CONCAT(0x31)\"}",
  "rejected": "{\"thought\": \"Standard union select\", \"payload\": \"' OR 1=1 UNION SELECT user,password FROM users--\"}",
  "meta": {
    "vector": "sqli_classic",
    "constraint": "Avoid all quotes — use hex literals...",
    "chosen_status": "BYPASS",
    "rejected_status": "BLOCKED"
  }
}
```

### `multiturn_train.jsonl` — Multi-Turn Trajectories
```json
{
  "messages": [
    {"role": "system",    "content": "..."},
    {"role": "user",      "content": "Turn 1: Generate payload. CONSTRAINT: ..."},
    {"role": "assistant", "content": "<payload_1>"},
    {"role": "user",      "content": "Turn 2 Feedback: WAF PL4 HTTP 403 BLOCKED. Switch family..."},
    {"role": "assistant", "content": "<payload_2_different_family>"},
    {"role": "user",      "content": "Turn 3 Feedback: WAF PL4 HTTP 200 BYPASS. Strengthen..."},
    {"role": "assistant", "content": "<payload_3_escalated>"}
  ],
  "meta": {
    "vector": "sqli_blind",
    "constraint": "Use CASE WHEN THEN ELSE for conditional execution.",
    "outcome": "bypass_success",
    "turns": 3
  }
}
```

---

## 21 Evasion Techniques

The dataset covers **21 WAF evasion techniques** distributed across 5 attack vectors:

### SQLi Classic (5 techniques)
1. Avoid all quotes — use hex literals, backtick strings, or CONCAT(0x27,...)
2. Randomly mix uppercase/lowercase on all keywords (e.g. sElEcT, UnIoN)
3. Split keywords with balanced comments and inline whitespace
4. Use MySQL `/*!50000SELECT*/` versioned comment syntax
5. Use deeply nested SQL comments to split every keyword (e.g. SE/**/LECT)

### SQLi Blind (7 techniques)
6. Use CASE WHEN THEN ELSE for conditional payload execution
7. Use GROUP_CONCAT and subqueries to exfiltrate data without UNION
8. Use LIKE with wildcards or REGEXP instead of = for comparisons
9. Use math expressions and bitwise ops to hide booleans (e.g. 3&1=1)
10. Use string concatenation: 'ad'||'min' or CONCAT('ad','min')
11. Use time-based blind: IF(1=1, SLEEP(1), 0) for oracle
12. Use weird whitespace: tabs (%09), newlines (%0a), form-feed (%0c)

### XSS Reflected (4 techniques)
13. Use HTML entity encoding or &#x notation for XSS tag attributes
14. Use Hex encoding or CHAR() to substitute all string literals
15. Use URL Double-Encoding on top of hex encoding
16. Use deeply nested SQL/JS comments to split every keyword

### XSS Stored (2 techniques)
17. Prepend null bytes (%00) or Unicode padding before keywords
18. Use data:text/html or javascript: URL schemes for XSS

### XSS DOM (3 techniques)
19. Use charcode reconstruction (String.fromCharCode) for script body
20. Use fragmented tag construction to evade naive filters
21. Use obscure HTML5 event handlers: ontoggle, onpointerover, onautocomplete

---

## Generation Pipeline

```
DVWA + ModSecurity PL1-4 (live WAF oracle)
         │
         ▼
generate_dpo_data.py          ← Qwen 4B SFT model generates payloads
         │                       WAF probes each payload across PL1-4
         ▼                       chosen=BYPASS / rejected=BLOCKED
dpo_train.jsonl
         │
         ▼
augment_multiturn_sft.py      ← DeepSeek API generates multi-turn trajectories
         │                       with WAF feedback loop
         ▼
multiturn_train.jsonl
         │
         ▼
prepare_datasets.py           ← Mix + balance + quality filter
         │
         ▼
sft_train.jsonl
```

---

## Statistics

| Metric | Value |
|--------|-------|
| Total SFT samples | 1,480 |
| Total DPO pairs | 2,550 |
| Total multi-turn trajectories | 581 |
| Attack vectors | 5 |
| Evasion techniques | 21 |
| WAF paranoia levels tested | 4 (PL1–PL4 ModSecurity) |
| Avg turns per multi-turn sample | ~3 |
