import pytest
from typer.testing import CliRunner

from huntkit.ai import (
    Advisor,
    ApprovalDenied,
    build_context,
    make_advisor,
    provider_names,
    providers,
)
from huntkit.ai.providers import (
    AnthropicProvider,
    OllamaProvider,
    OpenAIProvider,
    Provider,
    ProviderError,
    _api_key,
)
from huntkit.app import app
from huntkit.core.config import Config
from huntkit.core.workspace import Workspace
from huntkit.intel import analyze

runner = CliRunner()


def _seed(tmp_path) -> Workspace:
    ws = Workspace.open("acme", base=tmp_path)
    ws.append_unique("recon/subdomains.txt", ["api.dev.example.com", "admin.example.com"])
    ws.append_unique("recon/ports.txt", ["admin.example.com:6379"])
    ws.append_unique("urls/urls.txt", ["https://api.dev.example.com/admin?id=5&redirect=http://x"])
    ws.set_scope(["*.example.com"], [])
    return ws


# ---------------------------------------------------------------------------
# providers
# ---------------------------------------------------------------------------
class TestKeys:
    def test_config_key_beats_env(self, monkeypatch):
        cfg = Config()
        assert _api_key(cfg, "anthropic", "ANTHROPIC_API_KEY") == ""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "envk")
        assert _api_key(cfg, "anthropic", "ANTHROPIC_API_KEY") == "envk"
        cfg.api_keys["anthropic"] = "cfgk"
        assert _api_key(cfg, "anthropic", "ANTHROPIC_API_KEY") == "cfgk"

    def test_availability(self, monkeypatch):
        cfg = Config()
        assert OllamaProvider().available(cfg) is True  # local always attemptable
        assert AnthropicProvider().available(cfg) is False  # no key
        monkeypatch.setenv("OPENAI_API_KEY", "k")
        assert OpenAIProvider().available(cfg) is True


class TestRequestShapes:
    def test_ollama_hits_chat_endpoint(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            providers,
            "_post_json",
            lambda url, h, p, timeout: seen.update(url=url, p=p) or {"message": {"content": "x"}},
        )
        out = OllamaProvider().complete("s", "u", model="llama3.2", config=Config())
        assert out == "x"
        assert seen["url"].endswith("/api/chat") and seen["p"]["stream"] is False

    def test_anthropic_messages_contract(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            providers,
            "_post_json",
            lambda url, h, p, timeout: (
                seen.update(url=url, h=h, p=p) or {"content": [{"type": "text", "text": "hi"}]}
            ),
        )
        cfg = Config()
        cfg.api_keys["anthropic"] = "k"
        out = AnthropicProvider().complete("sys", "usr", model="claude-opus-4-8", config=cfg)
        assert out == "hi"
        assert seen["url"].endswith("/v1/messages")
        assert seen["h"]["x-api-key"] == "k"
        assert seen["h"]["anthropic-version"] == "2023-06-01"
        assert seen["p"]["model"] == "claude-opus-4-8" and seen["p"]["system"] == "sys"
        assert seen["p"]["messages"][0]["content"] == "usr"

    def test_openai_bearer_auth(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            providers,
            "_post_json",
            lambda url, h, p, timeout: (
                seen.update(h=h) or {"choices": [{"message": {"content": "ok"}}]}
            ),
        )
        cfg = Config()
        cfg.api_keys["openai"] = "k"
        out = OpenAIProvider().complete("s", "u", model="gpt-4o-mini", config=cfg)
        assert out == "ok" and seen["h"]["authorization"] == "Bearer k"

    def test_empty_reply_raises(self, monkeypatch):
        monkeypatch.setattr(providers, "_post_json", lambda *a, **k: {"message": {"content": ""}})
        with pytest.raises(ProviderError):
            OllamaProvider().complete("s", "u", model="m", config=Config())

    def test_missing_cloud_key_raises(self):
        with pytest.raises(ProviderError):
            AnthropicProvider().complete("s", "u", model="m", config=Config())


# ---------------------------------------------------------------------------
# advisor — context + the approval gate
# ---------------------------------------------------------------------------
class _Stub(Provider):
    name = "stub"
    default_model = "m"
    is_local = False

    def __init__(self):
        self.calls = 0

    def available(self, config):
        return True

    def endpoint_host(self, config):
        return "stub.example"

    def complete(self, system, prompt, *, model, config):
        self.calls += 1
        return "PLAN"


class TestContext:
    def test_context_is_recon_only(self, tmp_path):
        report = analyze(_seed(tmp_path))
        ctx = build_context(report)
        assert ctx.startswith("Program: acme")
        assert "Prioritised hosts:" in ctx and "admin.example.com" in ctx
        assert "Attack paths:" in ctx


class TestGate:
    def test_cloud_denied_sends_nothing(self, tmp_path):
        report = analyze(_seed(tmp_path))
        prov = _Stub()
        with pytest.raises(ApprovalDenied):
            Advisor(prov, Config()).advise(report, approve=lambda _t: False)
        assert prov.calls == 0  # never reached the network

    def test_cloud_missing_callback_denies(self, tmp_path):
        report = analyze(_seed(tmp_path))
        prov = _Stub()
        with pytest.raises(ApprovalDenied):
            Advisor(prov, Config()).advise(report, approve=None)
        assert prov.calls == 0

    def test_cloud_approved_sends(self, tmp_path):
        report = analyze(_seed(tmp_path))
        prov = _Stub()
        advice = Advisor(prov, Config()).advise(report, approve=lambda _t: True)
        assert prov.calls == 1 and advice.answer == "PLAN" and advice.is_local is False

    def test_local_skips_gate(self, tmp_path):
        report = analyze(_seed(tmp_path))
        prov = _Stub()
        prov.is_local = True
        advice = Advisor(prov, Config()).advise(report, approve=None)  # no callback needed
        assert prov.calls == 1 and advice.is_local is True

    def test_resolve_model_prefers_provider_default(self):
        assert Advisor(AnthropicProvider(), Config()).resolve_model() == "claude-opus-4-8"
        assert Advisor(AnthropicProvider(), Config()).resolve_model("x") == "x"

    def test_make_advisor_unknown_is_none(self):
        assert make_advisor(Config(), "gemini") is None
        assert make_advisor(Config(), "ollama") is not None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTKIT_HOME", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("HUNTKIT_APIKEY_ANTHROPIC", raising=False)
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestCli:
    def test_local_runs_and_stays_local(self, home, monkeypatch):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        monkeypatch.setattr(
            providers, "_post_json", lambda *a, **k: {"message": {"content": "PLAN: redis first"}}
        )
        result = runner.invoke(app, ["advise", "-p", "acme"])  # default provider = ollama
        assert result.exit_code == 0
        assert "PLAN: redis first" in result.stdout and "data stayed on" in result.stdout

    def test_cloud_declined_sends_nothing(self, home, monkeypatch):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        monkeypatch.setenv("HUNTKIT_APIKEY_ANTHROPIC", "k")
        calls = {"n": 0}

        def _fake(*a, **k):
            calls["n"] += 1
            return {"content": [{"type": "text", "text": "x"}]}

        monkeypatch.setattr(providers, "_post_json", _fake)
        result = runner.invoke(app, ["advise", "-p", "acme", "--provider", "claude"], input="n\n")
        assert result.exit_code == 0
        assert "nothing was sent" in result.stdout and calls["n"] == 0

    def test_cloud_yes_sends(self, home, monkeypatch):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        monkeypatch.setenv("HUNTKIT_APIKEY_ANTHROPIC", "k")
        monkeypatch.setattr(
            providers,
            "_post_json",
            lambda *a, **k: {"content": [{"type": "text", "text": "CLOUD PLAN"}]},
        )
        result = runner.invoke(app, ["advise", "-p", "acme", "--provider", "claude", "--yes"])
        assert result.exit_code == 0 and "CLOUD PLAN" in result.stdout

    def test_cloud_without_key_exits_1(self, home):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        result = runner.invoke(app, ["advise", "-p", "acme", "--provider", "claude"])
        assert result.exit_code == 1

    def test_unknown_provider_exits_2(self, home):
        runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
        _seed(home)
        result = runner.invoke(app, ["advise", "-p", "acme", "--provider", "gemini"])
        assert result.exit_code == 2

    def test_no_findings_warns(self, home):
        runner.invoke(app, ["init", "empty", "-s", "example.com"])
        result = runner.invoke(app, ["advise", "-p", "empty"])
        assert result.exit_code == 0 and "no findings" in result.stdout

    def test_provider_names_registered(self):
        assert set(provider_names()) == {"ollama", "claude", "openai"}
