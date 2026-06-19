"""Build garak's REST generator config from a recon Target (TOOL_API.md §2).

The request body + response extractor are derived from the endpoint's API family
(inferred from path, falling back to ai_interface_type) — the §2.3 payoff: the
attack tool is pre-configured from the graph.
"""
from __future__ import annotations


def _family_from_target(target) -> str:
    """Infer the API family from the endpoint path (most reliable signal)."""
    path = (getattr(target, "path", "") or "").lower()
    if "/v1/chat/completions" in path:
        return "openai-chat"
    if "/v1/completions" in path:
        return "openai-completion"
    if "/v1/messages" in path:
        return "anthropic"
    if "/api/chat" in path:
        return "ollama-chat"
    if "/api/generate" in path:
        return "ollama-generate"
    # Fall back to the recon interface type.
    iface = (getattr(target, "ai_interface_type", "") or "").lower()
    if iface == "llm-completion":
        return "openai-completion"
    return "openai-chat"  # the common default


def _body_and_field(family: str, model: str):
    """Return (req_template_json_object, response_json_field) for a family."""
    if family == "openai-chat":
        return ({"model": model, "messages": [{"role": "user", "content": "$INPUT"}]},
                "$.choices[0].message.content")
    if family == "openai-completion":
        return ({"model": model, "prompt": "$INPUT"},
                "$.choices[0].text")
    if family == "anthropic":
        return ({"model": model, "max_tokens": 512,
                 "messages": [{"role": "user", "content": "$INPUT"}]},
                "$.content[0].text")
    if family == "ollama-chat":
        return ({"model": model, "messages": [{"role": "user", "content": "$INPUT"}],
                 "stream": False},
                "$.message.content")
    if family == "ollama-generate":
        return ({"model": model, "prompt": "$INPUT", "stream": False},
                "$.response")
    # default openai-chat
    return ({"model": model, "messages": [{"role": "user", "content": "$INPUT"}]},
            "$.choices[0].message.content")


def build_rest_config(target, model: str | None = None,
                      api_key_header: str | None = None) -> dict:
    """Build the {"rest": {"RestGenerator": {...}}} option-file dict.

    `model`: the target model id to send. Defaults to recon's guess; some
    servers ignore it, but OpenAI/Ollama-compat require a value.
    `api_key_header`: if set (e.g. "Authorization"), adds `<header>: Bearer $KEY`
    so garak injects REST_API_KEY; omit for unauthenticated targets.
    """
    family = _family_from_target(target)
    if not model:
        ids = getattr(target, "ai_model_ids", None) or []
        model = (ids[0] if ids else None) or getattr(target, "ai_model_family_guess", None) or "default"

    body, field = _body_and_field(family, model)

    headers = {"Content-Type": "application/json"}
    if api_key_header:
        headers[api_key_header] = "Bearer $KEY"

    return {
        "rest": {
            "RestGenerator": {
                "name": f"redamon:{getattr(target, 'baseurl', '')}{getattr(target, 'path', '')}",
                "uri": target.url,
                "method": (getattr(target, "method", "POST") or "POST").lower(),
                "headers": headers,
                "req_template_json_object": body,
                "response_json": True,
                "response_json_field": field,
                "request_timeout": 60,
            }
        }
    }
