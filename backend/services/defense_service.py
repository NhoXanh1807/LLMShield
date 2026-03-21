"""
Defense rule generation service using LLM.
"""

import json
try:
    from .llm_client import llm_client
    from ..config.settings import DEFAULT_NUM_DEFENSE_RULES
    from ..config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt
except ImportError:
    from services.llm_client import llm_client
    from config.settings import DEFAULT_NUM_DEFENSE_RULES
    from config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt


# JSON schema for structured output
_DEFENSE_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "DefenseRuleList",
        "schema": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule": {
                                "type": "string",
                                "description": "The WAF rule or configuration to implement",
                            },
                            "instructions": {
                                "type": "string",
                                "description": "Short instructions on how to implement the rule",
                            },
                        },
                        "required": ["rule", "instructions"],
                    },
                }
            },
            "required": ["items"],
        },
    },
}


def generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions):
    """
    Generate ModSecurity defense rules using the configured LLM.

    Args:
        waf_info: WAF detection information.
        bypassed_payloads: List of payloads that bypassed the WAF.
        bypassed_instructions: Instructions for each bypassed payload.

    Returns:
        dict: LLM response (OpenAI-compatible shape) with generated defense rules.
    """
    messages = [
        {"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": get_blue_team_user_prompt(
                json.dumps(waf_info),
                json.dumps(bypassed_payloads),
                json.dumps(bypassed_instructions),
                DEFAULT_NUM_DEFENSE_RULES,
            ),
        },
    ]

    result = llm_client.chat_completion(messages, response_format=_DEFENSE_RESPONSE_FORMAT)
    result["messages"] = messages
    return result
