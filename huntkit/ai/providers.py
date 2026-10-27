"""AI providers — a thin, dependency-free abstraction over one HTTP call.

Each provider turns a (system, prompt) pair into completion text. They talk raw
JSON over stdlib ``urllib`` so the AI layer stays optional and adds no
dependencies (HuntKit is lean-dep on purpose; Ollama has no SDK anyway).

The security-relevant property is :attr:`Provider.is_local`. Local providers
(Ollama on 127.0.0.1) never send engagement data off the machine; cloud
providers do, and the advisor gates them behind explicit approval.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ..core.config import Config


class ProviderError(RuntimeError):
    """A provider could not produce a completion (network, auth, empty reply)."""


def _post_json(url: str, headers: dict[str, str], payload: dict, timeout: int) -> dict:
    """POST JSON and parse the JSON reply. Raises ProviderError on any failure.

    Kept module-level so tests can stub the whole network round-trip.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise ProviderError(f"{url}: HTTP {e.code} — {detail}") from None
    except urllib.error.URLError as e:
        raise ProviderError(f"cannot reach {url}: {e.reason}") from None
    except (TimeoutError, OSError, ValueError) as e:
        raise ProviderError(f"request to {url} failed: {e}") from None


def _api_key(config: Config, name: str, *env_names: str) -> str:
    """Resolve an API key: config.api_keys first, then well-known env vars."""
    key = config.api_keys.get(name)
    if key:
        return key
    for env in env_names:
        val = os.environ.get(env)
        if val:
            return val
    return ""


class Provider:
    """Base provider. Subclasses set the class attrs and implement ``complete``."""

    name: str = ""
    default_model: str = ""
    is_local: bool = False

    def available(self, config: Config) -> bool:
        """Whether this provider can be used right now (key present, etc.)."""
        return True

    def endpoint_host(self, config: Config) -> str:
        """Human-readable destination, shown at the approval gate."""
        return ""

    def complete(self, system: str, prompt: str, *, model: str, config: Config) -> str:
        raise NotImplementedError


class OllamaProvider(Provider):
    """Local Ollama (offline). Data never leaves the machine — no approval gate."""

    name = "ollama"
    default_model = "llama3.2"
    is_local = True

    def endpoint_host(self, config: Config) -> str:
        return config.ai.endpoint

    def complete(self, system: str, prompt: str, *, model: str, config: Config) -> str:
        url = config.ai.endpoint.rstrip("/") + "/api/chat"
        data = _post_json(
            url,
            {},
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
            timeout=config.general.timeout,
        )
        text = (data.get("message") or {}).get("content", "").strip()
        if not text:
            raise ProviderError("Ollama returned no content (is the model pulled?)")
        return text


class AnthropicProvider(Provider):
    """Anthropic Claude via the Messages API (cloud → gated)."""

    name = "claude"
    default_model = "claude-opus-4-8"
    is_local = False

    def _key(self, config: Config) -> str:
        return _api_key(config, "anthropic", "ANTHROPIC_API_KEY")

    def available(self, config: Config) -> bool:
        return bool(self._key(config))

    def endpoint_host(self, config: Config) -> str:
        return "api.anthropic.com"

    def complete(self, system: str, prompt: str, *, model: str, config: Config) -> str:
        key = self._key(config)
        if not key:
            raise ProviderError("no Anthropic API key (set HUNTKIT_APIKEY_ANTHROPIC)")
        data = _post_json(
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": key, "anthropic-version": "2023-06-01"},
            {
                "model": model,
                "max_tokens": 1024,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=config.general.timeout,
        )
        text = "".join(
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        ).strip()
        if not text:
            raise ProviderError("Anthropic returned no text content")
        return text


class OpenAIProvider(Provider):
    """OpenAI chat completions (cloud → gated)."""

    name = "openai"
    default_model = "gpt-4o-mini"
    is_local = False

    def _key(self, config: Config) -> str:
        return _api_key(config, "openai", "OPENAI_API_KEY")

    def available(self, config: Config) -> bool:
        return bool(self._key(config))

    def endpoint_host(self, config: Config) -> str:
        return "api.openai.com"

    def complete(self, system: str, prompt: str, *, model: str, config: Config) -> str:
        key = self._key(config)
        if not key:
            raise ProviderError("no OpenAI API key (set HUNTKIT_APIKEY_OPENAI)")
        data = _post_json(
            "https://api.openai.com/v1/chat/completions",
            {"authorization": f"Bearer {key}"},
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=config.general.timeout,
        )
        choices = data.get("choices") or []
        text = (choices[0].get("message", {}).get("content", "") if choices else "").strip()
        if not text:
            raise ProviderError("OpenAI returned no content")
        return text


_PROVIDERS: dict[str, Provider] = {
    p.name: p for p in (OllamaProvider(), AnthropicProvider(), OpenAIProvider())
}


def get_provider(name: str) -> Provider | None:
    return _PROVIDERS.get(name.strip().lower())


def provider_names() -> list[str]:
    return list(_PROVIDERS)
