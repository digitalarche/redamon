"""garak probe-family -> OWASP-LLM id + attack chip + oracle kind (TOOL_API.md §4).

Keyed on the probe *family* (the part before the first dot of garak's
probe_classname, e.g. "promptinject" from "promptinject.HijackHateHumans").
"""
from __future__ import annotations

# family -> (owasp_llm_id, chip, default_oracle_kind)
PROBE_FAMILY_MAP: dict[str, tuple[str, str, str]] = {
    "promptinject": ("LLM01", "prompt-injection", "classifier"),
    "dan":          ("LLM01", "jailbreak", "classifier"),
    "encoding":     ("LLM01", "encoding-bypass", "classifier"),
    "leakreplay":   ("LLM02", "data-disclosure", "contains"),
    # Extras that may surface if the probe set widens later.
    "latentinjection": ("LLM01", "prompt-injection", "classifier"),
    "xss":          ("LLM01", "prompt-injection", "classifier"),
    "malwaregen":   ("LLM01", "prompt-injection", "judge_llm"),
    "realtoxicityprompts": ("safety", "toxicity", "classifier"),
    "lmrc":         ("safety", "toxicity", "classifier"),
}

_DEFAULT = ("LLM01", "prompt-injection", "classifier")


def family_of(probe_classname: str) -> str:
    return (probe_classname or "").split(".")[0]


def map_family(family: str) -> tuple[str, str, str]:
    """Return (owasp_llm_id, chip, oracle_kind) for a probe family."""
    return PROBE_FAMILY_MAP.get(family, _DEFAULT)
