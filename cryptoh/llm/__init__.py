"""LLM layer: live Gemma client, offline fallback, response parser, prompt."""
from cryptoh.llm.fallback import diagnose as fallback_diagnose
from cryptoh.llm.gemma import MODEL_ID, diagnose_live
from cryptoh.llm.ollama_local import diagnose_local
from cryptoh.llm.parser import parse_json_response
from cryptoh.llm.prompts.diagnose import DIAGNOSE_PROMPT
from cryptoh.llm.scrub import scrub_pii

__all__ = [
    "DIAGNOSE_PROMPT",
    "MODEL_ID",
    "diagnose_live",
    "diagnose_local",
    "fallback_diagnose",
    "parse_json_response",
    "scrub_pii",
]
