"""Politeness policy — Pace normalisation and per-tool flag rendering."""

from __future__ import annotations

from huntkit.core.config import Config
from huntkit.core.pacing import Pace, delay_arg, duration, rate_arg


class TestPaceFromConfig:
    def test_reads_the_right_knobs(self):
        cfg = Config()
        cfg.http.rate_limit = 40
        cfg.http.delay = 0.5
        cfg.general.rate = 500
        cfg.general.threads = 8
        pace = Pace.from_config(cfg)
        assert pace.rate == 40
        assert pace.port_rate == 500
        assert pace.delay == 0.5
        assert pace.concurrency == 8

    def test_floors_negatives_and_zero_threads(self):
        cfg = Config()
        cfg.http.rate_limit = -5
        cfg.http.delay = -1.0
        cfg.general.threads = 0
        pace = Pace.from_config(cfg)
        assert pace.rate == 0
        assert pace.delay == 0.0
        assert pace.concurrency == 1  # never zero workers


class TestDuration:
    def test_sub_second_is_millis(self):
        assert duration(0.5) == "500ms"
        assert duration(0.2) == "200ms"

    def test_whole_seconds(self):
        assert duration(2) == "2s"

    def test_fractional_seconds_keep_decimal(self):
        assert duration(1.5) == "1.5s"


class TestRateArg:
    def test_emits_when_positive(self):
        assert rate_arg("-rate-limit", 40) == ["-rate-limit", "40"]

    def test_empty_when_zero_or_negative(self):
        assert rate_arg("-rate-limit", 0) == []
        assert rate_arg("-rate", -1) == []


class TestDelayArg:
    def test_nothing_when_not_positive(self):
        assert delay_arg("-delay", 0) == []
        assert delay_arg("-delay", -2) == []

    def test_pd_duration_default(self):
        assert delay_arg("-delay", 0.25) == ["-delay", "250ms"]
        assert delay_arg("-delay", 2) == ["-delay", "2s"]

    def test_seconds_unit_for_ffuf(self):
        assert delay_arg("-p", 1.5, unit="sec") == ["-p", "1.5"]

    def test_millis_unit_for_dalfox(self):
        assert delay_arg("--delay", 0.3, unit="ms") == ["--delay", "300"]
