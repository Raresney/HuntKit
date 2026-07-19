"""Layered YAML configuration.

Resolution order (later wins):
  1. built-in defaults (this module)
  2. user config      ~/.config/huntkit/huntkit.yaml   (or $HUNTKIT_CONFIG_HOME)
  3. project config    ./huntkit.yaml                   (cwd, walked upward)
  4. explicit --config path
  5. environment       HUNTKIT_<SECTION>_<KEY>

Everything is typed via dataclasses so the rest of the codebase gets
autocomplete and mypy checking instead of dictionary spelunking.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

CONFIG_FILENAME = "huntkit.yaml"


# --------------------------------------------------------------------------
# Typed sections
# --------------------------------------------------------------------------
@dataclass
class GeneralConfig:
    workspace_path: str = "~/.huntkit"
    threads: int = 20
    rate: int = 150          # requests/sec hint passed to rate-aware tools
    timeout: int = 300       # per-command seconds
    retry: int = 1           # retries on transient failure
    default_report_format: str = "markdown"
    color: bool = True


@dataclass
class HttpConfig:
    proxy: Optional[str] = None            # e.g. http://127.0.0.1:8080 (Burp)
    user_agent: str = "HuntKit/0.2 (+https://github.com/Raresney/HuntKit)"
    headers: dict[str, str] = field(default_factory=dict)
    rate_limit: int = 150
    follow_redirects: bool = True


@dataclass
class ToolConfig:
    """Per-tool overrides. `path` pins a binary; `extra_args` is appended."""

    enabled: bool = True
    path: Optional[str] = None
    extra_args: list[str] = field(default_factory=list)
    timeout: Optional[int] = None


@dataclass
class WordlistConfig:
    dir_fuzz: Optional[str] = None
    dns: Optional[str] = None
    params: Optional[str] = None


@dataclass
class NucleiConfig:
    templates: Optional[str] = None        # custom template dir
    severity: str = "low,medium,high,critical"
    extra_args: list[str] = field(default_factory=list)


@dataclass
class AIConfig:
    provider: str = "ollama"               # ollama|openai|claude|gemini
    model: str = "llama3.2"
    endpoint: str = "http://127.0.0.1:11434"
    require_approval: bool = True          # never send engagement data silently
    max_context_items: int = 40


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    wordlists: WordlistConfig = field(default_factory=WordlistConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    tools: dict[str, ToolConfig] = field(default_factory=dict)
    api_keys: dict[str, str] = field(default_factory=dict)

    # provenance (not serialised into user config)
    _sources: list[str] = field(default_factory=list, repr=False)

    # ---- construction ----------------------------------------------------
    @classmethod
    def load(cls, explicit_path: Optional[Path] = None) -> "Config":
        cfg = cls()
        for path in _candidate_paths(explicit_path):
            data = _read_yaml(path)
            if data:
                cfg._merge(data)
                cfg._sources.append(str(path))
        cfg._apply_env()
        return cfg

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        cfg = cls()
        cfg._merge(data or {})
        return cfg

    # ---- access ----------------------------------------------------------
    def tool(self, name: str) -> ToolConfig:
        """Return the (possibly default) config for a named tool."""
        return self.tools.get(name, ToolConfig())

    @property
    def workspace_root(self) -> Path:
        return Path(self.general.workspace_path).expanduser()

    def to_dict(self) -> dict[str, Any]:
        data = _dataclass_to_dict(self)
        data.pop("_sources", None)
        return data

    # ---- internal merge --------------------------------------------------
    def _merge(self, data: dict[str, Any]) -> None:
        for key in ("general", "http", "wordlists", "nuclei", "ai"):
            if key in data and isinstance(data[key], dict):
                _merge_into(getattr(self, key), data[key])
        if "tools" in data and isinstance(data["tools"], dict):
            for name, tdata in data["tools"].items():
                base = self.tools.get(name, ToolConfig())
                _merge_into(base, tdata or {})
                self.tools[name] = base
        if "api_keys" in data and isinstance(data["api_keys"], dict):
            self.api_keys.update({k: str(v) for k, v in data["api_keys"].items()})

    def _apply_env(self) -> None:
        """Override scalars from HUNTKIT_<SECTION>_<KEY> environment vars."""
        for section_name in ("general", "http", "ai", "nuclei"):
            section = getattr(self, section_name)
            for f in fields(section):
                env_key = f"HUNTKIT_{section_name.upper()}_{f.name.upper()}"
                if env_key in os.environ:
                    setattr(section, f.name, _coerce(os.environ[env_key], f.type))
        # API keys: HUNTKIT_APIKEY_<NAME>
        for env_key, val in os.environ.items():
            if env_key.startswith("HUNTKIT_APIKEY_"):
                self.api_keys[env_key[len("HUNTKIT_APIKEY_"):].lower()] = val


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _candidate_paths(explicit: Optional[Path]) -> list[Path]:
    paths: list[Path] = []
    # user-level
    home = os.environ.get("HUNTKIT_CONFIG_HOME")
    user_dir = Path(home).expanduser() if home else Path.home() / ".config" / "huntkit"
    paths.append(user_dir / CONFIG_FILENAME)
    # project-level: nearest huntkit.yaml walking up from cwd
    project = _find_upwards(Path.cwd(), CONFIG_FILENAME)
    if project:
        paths.append(project)
    if explicit:
        paths.append(Path(explicit).expanduser())
    return paths


def _find_upwards(start: Path, filename: str) -> Optional[Path]:
    for parent in [start, *start.parents]:
        candidate = parent / filename
        if candidate.is_file():
            return candidate
    return None


def _read_yaml(path: Path) -> Optional[dict[str, Any]]:
    try:
        if not path.is_file():
            return None
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else None
    except (OSError, yaml.YAMLError):
        return None


def _merge_into(obj: Any, data: dict[str, Any]) -> None:
    """Shallow-merge dict values onto a dataclass instance, by field name."""
    valid = {f.name for f in fields(obj)}
    for key, value in data.items():
        if key in valid and value is not None:
            setattr(obj, key, value)


def _coerce(raw: str, target_type: Any) -> Any:
    type_str = str(target_type)
    if "int" in type_str:
        try:
            return int(raw)
        except ValueError:
            return raw
    if "bool" in type_str:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return raw


def _dataclass_to_dict(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in asdict(obj).items()}
    return obj


def sample_yaml() -> str:
    """Render a documented default config for `huntkit config init`."""
    return _SAMPLE_YAML


_SAMPLE_YAML = """\
# HuntKit configuration — https://github.com/Raresney/HuntKit
# Place at ~/.config/huntkit/huntkit.yaml (global) or ./huntkit.yaml (project).
# Every value below is a default; delete what you don't need to override.

general:
  workspace_path: ~/.huntkit
  threads: 20
  rate: 150
  timeout: 300
  retry: 1
  default_report_format: markdown   # markdown | html | json
  color: true

http:
  proxy: null                       # e.g. http://127.0.0.1:8080 for Burp
  user_agent: "HuntKit/0.2 (+https://github.com/Raresney/HuntKit)"
  headers: {}                       # e.g. { X-Bug-Bounty: my-handle }
  rate_limit: 150
  follow_redirects: true

wordlists:
  dir_fuzz: null                    # e.g. /usr/share/seclists/.../common.txt
  dns: null
  params: null

nuclei:
  templates: null                   # custom template directory
  severity: low,medium,high,critical
  extra_args: []

ai:
  provider: ollama                  # ollama | openai | claude | gemini
  model: llama3.2
  endpoint: http://127.0.0.1:11434
  require_approval: true            # never send recon data without a prompt
  max_context_items: 40

# Per-tool overrides. Pin a binary path, disable a tool, or append args.
tools:
  amass:
    enabled: true
    # path: /opt/amass/amass
    # extra_args: ["-active"]

# Secrets pulled by data-source tools. Prefer env vars: HUNTKIT_APIKEY_<NAME>.
api_keys: {}
  # chaos: "..."
  # github: "..."
  # shodan: "..."
"""
