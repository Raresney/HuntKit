from huntkit.core.config import Config, ToolConfig


def test_defaults():
    c = Config()
    assert c.general.threads == 20
    assert c.general.timeout == 300
    assert c.ai.provider == "ollama"
    assert c.ai.require_approval is True


def test_from_dict_merges_partial():
    c = Config.from_dict({"general": {"threads": 50}, "http": {"proxy": "http://127.0.0.1:8080"}})
    assert c.general.threads == 50
    assert c.general.timeout == 300  # untouched default preserved
    assert c.http.proxy == "http://127.0.0.1:8080"


def test_tool_override_and_default():
    c = Config.from_dict({"tools": {"amass": {"enabled": False, "extra_args": ["-active"]}}})
    assert c.tool("amass").enabled is False
    assert c.tool("amass").extra_args == ["-active"]
    # unknown tool yields defaults
    assert isinstance(c.tool("subfinder"), ToolConfig)
    assert c.tool("subfinder").enabled is True


def test_api_keys_and_workspace_root():
    c = Config.from_dict({"api_keys": {"chaos": "abc"}, "general": {"workspace_path": "~/x"}})
    assert c.api_keys["chaos"] == "abc"
    assert c.workspace_root.name == "x"


def test_env_override(monkeypatch):
    monkeypatch.setenv("HUNTKIT_GENERAL_THREADS", "99")
    monkeypatch.setenv("HUNTKIT_HTTP_PROXY", "http://p:1")
    monkeypatch.setenv("HUNTKIT_APIKEY_SHODAN", "sk")
    c = Config.load()
    assert c.general.threads == 99
    assert c.http.proxy == "http://p:1"
    assert c.api_keys["shodan"] == "sk"


def test_load_reads_project_yaml(tmp_path, monkeypatch):
    (tmp_path / "huntkit.yaml").write_text("general:\n  threads: 7\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "noexist"))
    c = Config.load()
    assert c.general.threads == 7


def test_to_dict_excludes_sources():
    c = Config.load()
    d = c.to_dict()
    assert "_sources" not in d
    assert d["general"]["threads"] == c.general.threads
