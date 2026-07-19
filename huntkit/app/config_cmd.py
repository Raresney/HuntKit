"""`huntkit config` — inspect and scaffold configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
import yaml

from ..core.config import CONFIG_FILENAME, Config, sample_yaml
from ..utils import filesystem as fs
from ..utils import terminal as term

config_app = typer.Typer(no_args_is_help=True, help="Inspect and scaffold configuration.")


def _user_config_path() -> Path:
    home = os.environ.get("HUNTKIT_CONFIG_HOME")
    base = Path(home).expanduser() if home else Path.home() / ".config" / "huntkit"
    return base / CONFIG_FILENAME


@config_app.command("init")
def config_init(
    path: Optional[Path] = typer.Option(
        None, "--path", "-o", help="Where to write (default: user config dir)."
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite if it exists."),
) -> None:
    """Write a documented default huntkit.yaml."""
    target = path or _user_config_path()
    if target.exists() and not force:
        term.warn(f"{target} already exists — use --force to overwrite.")
        raise typer.Exit(1)
    fs.write_text(target, sample_yaml())
    term.ok(f"wrote config: {target}")
    term.info("edit it, or override any value with HUNTKIT_<SECTION>_<KEY> env vars.")


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Print the resolved, merged configuration (secrets redacted)."""
    config: Config = ctx.obj.config
    data = config.to_dict()
    if data.get("api_keys"):
        data["api_keys"] = {k: "***" for k in data["api_keys"]}
    term.console.print(yaml.safe_dump(data, sort_keys=False, default_flow_style=False).rstrip())
    if config._sources:
        term.info("merged from: " + ", ".join(config._sources))
    else:
        term.info("using built-in defaults (no config file found).")


@config_app.command("path")
def config_path() -> None:
    """Show where HuntKit looks for configuration."""
    user = _user_config_path()
    project = Path.cwd() / CONFIG_FILENAME
    rows = [
        ("user", str(user), "yes" if user.exists() else "no"),
        ("project", str(project), "yes" if project.exists() else "no"),
    ]
    term.print_table("Config search path", ["scope", "path", "exists"], rows)
