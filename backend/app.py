"""
Flask API server for LLMShield backend.

Endpoints:
  POST /api/attack  – Full red+blue team workflow
  POST /api/retest  – Retest previously bypassed payloads
  POST /api/defend  – Generate defense rules only
  GET  /api/health  – Health check (reports active LLM provider)
"""

import json
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from wafw00f.main import WAFW00F

try:
    from config import settings
    from services.payload_service import generate_payloads_from_domain_waf_info
    from services.defense_service import generate_defend_rules_and_instructions
    from services.dvwa_service import (
        loginDVWA,
        attack_xss_dom,
        attack_xss_reflected,
        attack_xss_stored,
        attack_sql_injection,
        attack_sql_injection_blind,
    )
except ImportError:
    from backend.config import settings
    from backend.services.payload_service import generate_payloads_from_domain_waf_info
    from backend.services.defense_service import generate_defend_rules_and_instructions
    from backend.services.dvwa_service import (
        loginDVWA,
        attack_xss_dom,
        attack_xss_reflected,
        attack_xss_stored,
        attack_sql_injection,
        attack_sql_injection_blind,
    )

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

ATTACK_FUNCTIONS = {
    "xss_dom": attack_xss_dom,
    "xss_reflected": attack_xss_reflected,
    "xss_stored": attack_xss_stored,
    "sql_injection": attack_sql_injection,
    "sql_injection_blind": attack_sql_injection_blind,
}


# ──────────────────────────────────────────────────────────────────────────────
# Health check
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "ok",
        "llm_provider": settings.LLM_PROVIDER,
        "llm_service_url": settings.LLM_SERVICE_URL if settings.LLM_PROVIDER == "local" else None,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Main attack workflow
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/attack", methods=["POST"])
def api_attack():
    try:
        data = request.get_json()
        domain = data.get("domain")
        attack_type = data.get("attack_type")
        num_payloads = data.get("num_payloads", settings.DEFAULT_NUM_PAYLOADS)

        if not domain or not attack_type:
            return jsonify({"error": "Missing 'domain' or 'attack_type'"}), 400

        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain

        # 1. WAF fingerprinting
        w = WAFW00F(domain)
        waf_info = w.identwaf()

        # 2. Generate attack payloads via LLM
        llm_result = generate_payloads_from_domain_waf_info(waf_info, attack_type, num_payloads)
        content = llm_result.get("choices", [])[0].get("message", {}).get("content")
        instructions = json.loads(content).get("items", []) if content else []

        # 3. Execute payloads against DVWA
        session_id = loginDVWA()
        attack_func = ATTACK_FUNCTIONS.get(attack_type)

        for ins in instructions:
            payload = ins.get("payload")
            if attack_func and payload:
                result = attack_func(payload, session_id)
                ins["bypassed"] = not result["blocked"]
                ins["status_code"] = result["status_code"]
            else:
                ins["bypassed"] = False
                ins["status_code"] = None
            ins["attack_type"] = attack_type

        payloads = [
            {
                "attack_type": attack_type,
                "payload": ins.get("payload"),
                "bypassed": ins.get("bypassed", False),
                "status_code": ins.get("status_code"),
            }
            for ins in instructions
        ]

        # 4. Auto-generate defense rules for bypassed payloads
        bypassed_payloads = [ins["payload"] for ins in instructions if ins.get("bypassed")]
        bypassed_instructions = [ins["instruction"] for ins in instructions if ins.get("bypassed")]

        defense_rules = []
        if bypassed_payloads:
            defend_result = generate_defend_rules_and_instructions(
                waf_info, bypassed_payloads, bypassed_instructions
            )
            defend_content = defend_result.get("choices", [])[0].get("message", {}).get("content")
            defense_rules = json.loads(defend_content).get("items", []) if defend_content else []

        return jsonify({
            "domain": domain,
            "waf_info": waf_info,
            "payloads": payloads,
            "instructions": instructions,
            "defense_rules": defense_rules,
            "raw_llm_response": llm_result,
        }), 200

    except Exception:
        print("=" * 50)
        print("ERROR in /api/attack:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": traceback.format_exc()}), 500


# ──────────────────────────────────────────────────────────────────────────────
# Retest bypassed payloads
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/retest", methods=["POST"])
def api_retest():
    try:
        data = request.get_json()
        bypassed_payloads = data.get("bypassed_payloads", [])

        if not bypassed_payloads:
            return jsonify({"error": "No payloads provided for retest"}), 400

        session_id = loginDVWA()
        results = []

        for item in bypassed_payloads:
            payload = item.get("payload")
            attack_type = item.get("attack_type")
            attack_func = ATTACK_FUNCTIONS.get(attack_type)

            if attack_func and payload:
                result = attack_func(payload, session_id)
                results.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "bypassed": not result["blocked"],
                    "status_code": result["status_code"],
                })
            else:
                results.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "bypassed": False,
                    "status_code": None,
                    "error": "Invalid attack type or payload",
                })

        return jsonify({"results": results}), 200

    except Exception:
        print("=" * 50)
        print("ERROR in /api/retest:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": traceback.format_exc()}), 500


# ──────────────────────────────────────────────────────────────────────────────
# Standalone defense rule generation
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/defend", methods=["POST"])
def api_defend():
    try:
        data = request.get_json()
        waf_info = data.get("waf_info")
        bypassed_payloads = data.get("bypassed_payloads")
        bypassed_instructions = data.get("bypassed_instructions")

        if not waf_info or not bypassed_payloads or not bypassed_instructions:
            return jsonify({"error": "Missing 'waf_info', 'bypassed_payloads', or 'bypassed_instructions'"}), 400

        defend_result = generate_defend_rules_and_instructions(
            waf_info, bypassed_payloads, bypassed_instructions
        )
        content = defend_result.get("choices", [])[0].get("message", {}).get("content")
        rules = json.loads(content).get("items", []) if content else []

        return jsonify({"rules": rules, "raw_llm_response": defend_result}), 200

    except Exception:
        return jsonify({"error": traceback.format_exc()}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
