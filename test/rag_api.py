

import requests
domain = "https://overrigged-savingly-nelle.ngrok-free.dev"
res = requests.post(f"{domain}?action=rag_retrieve", json={
    "attack_type":"",
    "waf_name":"",
    "bypassed_payloads":[],
    "initial_k":10,
    "final_k":3,
    "filter_rules_only": True
})
print(res.json())

