"""
Payload generation service using LLM.
"""

import json
try:
    from .llm_client import llm_client
    from ..config.settings import DEFAULT_NUM_PAYLOADS
    from ..config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt
except ImportError:
    from services.llm_client import llm_client
    from config.settings import DEFAULT_NUM_PAYLOADS
    from config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt


# JSON schema for structured output
_PAYLOAD_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "PayloadList",
        "schema": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "payload": {
                                "type": "string",
                                "description": "The attack payload",
                            },
                            "instruction": {
                                "type": "string",
                                "description": "Short instruction (3-5 sentences) on how to use the payload",
                            },
                        },
                        "required": ["payload", "instruction"],
                    },
                }
            },
            "required": ["items"],
        },
    },
}


def generate_payloads_from_domain_waf_info(waf_info, attack_type, num_of_payloads=None):
    """
    Generate attack payloads using the configured LLM.

    Args:
        waf_info: WAF detection information.
        attack_type: Type of attack (xss_dom, sql_injection, etc.).
        num_of_payloads: Number of payloads to generate.

    Returns:
        dict: LLM response (OpenAI-compatible shape) with generated payloads.
    """
    if num_of_payloads is None:
        num_of_payloads = DEFAULT_NUM_PAYLOADS

    messages = [
        {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": get_red_team_user_prompt(
                json.dumps(waf_info), attack_type, num_of_payloads
            ),
        },
    ]

    result = llm_client.chat_completion(messages, response_format=_PAYLOAD_RESPONSE_FORMAT)
    result["messages"] = messages
    return result
