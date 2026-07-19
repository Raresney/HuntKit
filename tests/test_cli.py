import pytest
from typer.testing import CliRunner

from huntkit import __version__
from huntkit.app import app

runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolate workspace root and config away from the real home."""
    monkeypatch.setenv("HUNTKIT_GENERAL_WORKSPACE_PATH", str(tmp_path))
    monkeypatch.setenv("HUNTKIT_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "HuntKit" in result.stdout


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    # no_args_is_help exits 0 or 2 depending on typer version; help text present
    assert "recon" in result.stdout and "doctor" in result.stdout


def test_doctor_runs(home):
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "toolchain" in result.stdout
    assert "subfinder" in result.stdout


def test_plugins_list(home):
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "subfinder" in result.stdout and "nuclei" in result.stdout


def test_plugins_list_filter_category(home):
    result = runner.invoke(app, ["plugins", "list", "--category", "scan"])
    assert result.exit_code == 0
    assert "nuclei" in result.stdout
    assert "subfinder" not in result.stdout


def test_plugins_show(home):
    result = runner.invoke(app, ["plugins", "show", "subfinder"])
    assert result.exit_code == 0
    assert "projectdiscovery" in result.stdout.lower()


def test_plugins_show_unknown(home):
    result = runner.invoke(app, ["plugins", "show", "nope"])
    assert result.exit_code == 2


def test_config_path(home):
    result = runner.invoke(app, ["config", "path"])
    assert result.exit_code == 0
    assert "user" in result.stdout


def test_config_init_and_no_overwrite(home, tmp_path):
    target = tmp_path / "huntkit.yaml"
    result = runner.invoke(app, ["config", "init", "-o", str(target)])
    assert result.exit_code == 0
    assert target.exists()
    # second time without --force refuses
    result2 = runner.invoke(app, ["config", "init", "-o", str(target)])
    assert result2.exit_code == 1


def test_init_creates_workspace(home):
    result = runner.invoke(app, ["init", "acme", "-s", "example.com"])
    assert result.exit_code == 0
    assert (home / "acme" / "scope" / "in_scope.txt").exists()


def test_init_rejects_bad_scope(home):
    result = runner.invoke(app, ["init", "acme", "-s", "not a domain"])
    assert result.exit_code == 2  # error text goes to stderr


def test_recon_rejects_bad_domain(home):
    result = runner.invoke(app, ["recon", "not_a_domain"])
    assert result.exit_code == 2


def test_recon_runs_and_writes_seed(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    result = runner.invoke(app, ["recon", "example.com", "-p", "acme", "-s", "subs"])
    assert result.exit_code == 0
    assert (home / "acme" / "recon" / "subdomains.txt").read_text().strip() == "example.com"


def test_recon_normalises_url(home):
    result = runner.invoke(app, ["recon", "https://example.com/path", "-p", "acme", "-s", "subs"])
    assert result.exit_code == 0
    # url got normalised to the bare domain in the banner/summary
    assert "example.com" in result.stdout


def test_workspace_list_and_show(home):
    runner.invoke(app, ["init", "acme", "-s", "example.com"])
    listed = runner.invoke(app, ["workspace", "list"])
    assert listed.exit_code == 0
    assert "acme" in listed.stdout
    shown = runner.invoke(app, ["workspace", "show", "acme"])
    assert shown.exit_code == 0
    assert "example.com" in shown.stdout


def test_clean_resets_state(home):
    runner.invoke(app, ["init", "acme", "-s", "*.example.com"])
    runner.invoke(app, ["recon", "example.com", "-p", "acme", "-s", "subs"])
    result = runner.invoke(app, ["clean", "-p", "acme", "--state"])
    assert result.exit_code == 0
    assert "reset" in result.stdout
