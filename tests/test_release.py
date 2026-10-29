"""Guard the release contract.

The classic release footgun is a version that disagrees across pyproject, the
package, and the changelog — so a tag ships the wrong number, or PyPI rejects a
re-used version. These lock the invariants without needing to build or publish.
"""

from __future__ import annotations

import re
from pathlib import Path

import huntkit

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
RELEASE_WF = ROOT / ".github" / "workflows" / "release.yml"


def _pyproject_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, "no version in pyproject.toml"
    return m.group(1)


def test_version_agrees_across_sources() -> None:
    assert huntkit.__version__ == _pyproject_version()


def test_changelog_documents_current_version() -> None:
    assert f"## [{huntkit.__version__}]" in CHANGELOG.read_text(encoding="utf-8")


class TestReleaseWorkflow:
    def _wf(self) -> str:
        return RELEASE_WF.read_text(encoding="utf-8")

    def test_exists(self) -> None:
        assert RELEASE_WF.is_file()

    def test_triggers_on_version_tags(self) -> None:
        text = self._wf()
        assert "tags:" in text
        assert '"v*"' in text or "v*" in text

    def test_builds_and_checks(self) -> None:
        text = self._wf()
        assert "python -m build" in text
        assert "twine check" in text

    def test_publishes_to_pypi(self) -> None:
        assert "pypa/gh-action-pypi-publish" in self._wf()

    def test_uses_oidc_not_a_stored_token(self) -> None:
        # trusted publishing: id-token permission, and no PYPI token secret.
        text = self._wf()
        assert "id-token: write" in text
        assert "PYPI_API_TOKEN" not in text and "password:" not in text

    def test_cuts_a_github_release(self) -> None:
        assert "action-gh-release" in self._wf()
