"""Tests for persisting and reloading verification results."""

from __future__ import annotations

from huntkit.core.workspace import Workspace
from huntkit.intel.signals import VerifyState
from huntkit.verify.engine import VerifyResult
from huntkit.verify.store import load_results, save_results


def test_store_round_trips_results(tmp_path):
    ws = Workspace.open("p", base=tmp_path)
    res = {("h", "git-exposed"): VerifyResult(VerifyState.CONFIRMED, "200 ref")}
    save_results(ws, res)
    assert load_results(ws) == res


def test_load_results_tolerates_missing_file(tmp_path):
    assert load_results(Workspace.open("p", base=tmp_path)) == {}


def test_load_results_tolerates_malformed_file(tmp_path):
    ws = Workspace.open("p", base=tmp_path)
    ws.path("scans", "verify.json").write_text("{not json", encoding="utf-8")
    assert load_results(ws) == {}
