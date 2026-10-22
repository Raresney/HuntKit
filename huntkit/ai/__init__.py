"""AI layer — optional, multi-provider advisor over the intel report.

A feature layer (like intel/knowledge/report) that builds on ``core`` and
``intel``. Local providers (Ollama) run fully offline; cloud providers are
gated behind explicit approval so engagement data is never sent silently.
"""

from __future__ import annotations

from .advisor import (
    SYSTEM_PROMPT,
    Advice,
    Advisor,
    ApprovalDenied,
    build_context,
    make_advisor,
)
from .providers import (
    AnthropicProvider,
    OllamaProvider,
    OpenAIProvider,
    Provider,
    ProviderError,
    get_provider,
    provider_names,
)

__all__ = [
    "SYSTEM_PROMPT",
    "Advice",
    "Advisor",
    "ApprovalDenied",
    "AnthropicProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "Provider",
    "ProviderError",
    "build_context",
    "get_provider",
    "make_advisor",
    "provider_names",
]
