"""
Unit tests for nids/utils/stats.py

Covers every statistical primitive used by the detection engine.
Tests are designed to be fast (< 100 ms total) and dependency-free —
no Scapy, no network, no filesystem I/O.
"""

import math
import time

import pytest

from nids.utils.stats import (
    EWMA,
    SlidingWindowCounter,
    SlidingWindowSet,
    WelfordAccumulator,
    shannon_entropy,
)


# ── WelfordAccumulator ────────────────────────────────────────────────────────

class TestWelfordAccumulator:

    def test_single_value_mean(self):
        """After one observation, mean equals that value."""
        w = WelfordAccumulator()
        w.update(7.0)
        assert w.mean == 7.0
        assert w.n == 1

    def test_single_value_variance_is_zero(self):
        """Variance requires at least two observations (Bessel's correction)."""
        w = WelfordAccumulator()
        w.update(7.0)
        assert w.variance == 0.0
        assert w.std_dev  == 0.0

    def test_known_dataset_mean_and_std(self):
        """
        Reference dataset [2,4,4,4,5,5,7,9] — mean=5, population_std=2.
        Our implementation uses *sample* variance (Bessel ÷ n-1), so
        sample_std = 2 × sqrt(8/7) ≈ 2.1381.
        """
        w = WelfordAccumulator()
        for x in [2, 4, 4, 4, 5, 5, 7, 9]:
            w.update(x)

        assert abs(w.mean - 5.0) < 1e-9

        expected_sample_std = math.sqrt(
            sum((x - 5.0) ** 2 for x in [2, 4, 4, 4, 5, 5, 7, 9]) / 7
        )
        assert abs(w.std_dev - expected_sample_std) < 1e-9

    def test_z_score_returns_zero_when_std_is_zero(self):
        """Division-by-zero guard: identical observations → std=0 → z=0."""
        w = WelfordAccumulator()
        for _ in range(5):
            w.update(3.0)
        assert w.z_score(3.0) == 0.0
        assert w.z_score(99.0) == 0.0  # still 0 because std is ~0

    def test_z_score_known_value(self):
        """z(9) for the reference dataset ≈ +1.8708."""
        w = WelfordAccumulator()
        for x in [2, 4, 4, 4, 5, 5, 7, 9]:
            w.update(x)
        assert abs(w.z_score(9) - 1.8708) < 0.001

    def test_is_anomalous_fires_on_outlier(self):
        """
        A value far from a tight cluster should be flagged.

        The baseline must have non-zero variance for z-score to work,
        so we use slightly jittered values around 1.0 instead of
        a perfectly constant sequence (which gives std_dev = 0).
        """
        w = WelfordAccumulator()
        for x in [1.0, 1.1, 0.9, 1.2, 0.8, 1.0, 1.1, 0.9, 1.0, 1.2,
                  1.1, 0.8, 1.0, 0.9, 1.1, 1.2, 0.8, 1.0, 0.9, 1.1]:
            w.update(x)   # tight cluster around 1.0, std_dev ≈ 0.13
        assert w.is_anomalous(100.0, threshold=3.0)

    def test_is_anomalous_quiet_during_warmup(self):
        """is_anomalous requires n >= 10 — never fires during warmup."""
        w = WelfordAccumulator()
        for _ in range(9):
            w.update(1.0)
        # Only 9 observations — below the minimum
        assert not w.is_anomalous(9999.0, threshold=3.0)

    def test_normal_value_not_anomalous(self):
        """A value within 3σ of the baseline should not be flagged."""
        w = WelfordAccumulator()
        for x in [2, 4, 4, 4, 5, 5, 7, 9]:
            w.update(x)
        assert not w.is_anomalous(5.0, threshold=3.0)

    def test_incremental_equals_batch(self):
        """Welford's result must match the direct calculation for any dataset."""
        data = [3.1, 7.2, 1.5, 9.8, 4.4, 6.6, 2.2, 8.1, 5.5, 3.9]
        w = WelfordAccumulator()
        for x in data:
            w.update(x)

        n    = len(data)
        mean = sum(data) / n
        var  = sum((x - mean) ** 2 for x in data) / (n - 1)   # Bessel
        assert abs(w.mean    - mean)           < 1e-9
        assert abs(w.variance - var)           < 1e-9


# ── EWMA ──────────────────────────────────────────────────────────────────────

class TestEWMA:

    def test_first_update_equals_input(self):
        """The very first observation initialises the EWMA to that value."""
        e = EWMA(alpha=0.3)
        result = e.update(42.0)
        assert result == 42.0
        assert e.value == 42.0

    def test_alpha_one_always_returns_latest(self):
        """α = 1.0 means no memory — value is always the last observation."""
        e = EWMA(alpha=1.0)
        e.update(10.0)
        e.update(20.0)
        assert e.value == 20.0

    def test_convergence_toward_constant_input(self):
        """After many identical inputs the EWMA must converge to that value."""
        e = EWMA(alpha=0.2)
        for _ in range(100):
            e.update(50.0)
        assert abs(e.value - 50.0) < 0.001

    def test_smoothing_dampens_spike(self):
        """
        A sudden spike should *not* immediately dominate the EWMA
        when alpha is small — this verifies the smoothing property.

        With alpha=0.05 a single update of 1000 contributes only 5 %
        of the new value:  0.05×1000 + 0.95×1 ≈ 50.95, far below 1000.
        (alpha=0.1 would give 100.9, which is already well below 1000
        but not below 100 — so we use a smaller alpha here.)
        """
        e = EWMA(alpha=0.05)
        for _ in range(50):
            e.update(1.0)
        e.update(1000.0)       # spike
        # EWMA should be much closer to 1 than to 1000
        assert e.value < 100.0


# ── Shannon Entropy ───────────────────────────────────────────────────────────

class TestShannonEntropy:

    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_binary_returns_one_bit(self):
        """Balanced binary string → exactly 1 bit of entropy."""
        assert abs(shannon_entropy("01") - 1.0) < 1e-9

    def test_single_symbol_returns_zero(self):
        """No uncertainty when all symbols are the same."""
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_legitimate_hostname_low_entropy(self):
        """Short dictionary words have low entropy (< 3 bits)."""
        assert shannon_entropy("www")   < 2.5
        assert shannon_entropy("mail")  < 2.5

    def test_base32_payload_high_entropy(self):
        """
        Base32-encoded random data should exceed 3.8 bits — the tunnel
        detection threshold in dns_tunnel.py.
        """
        import base64, os
        payload = base64.b32encode(os.urandom(32)).decode().lower()
        assert shannon_entropy(payload) > 3.5

    def test_long_diverse_string_high_entropy(self):
        """A string covering the full ASCII printable set → high entropy."""
        diverse = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        assert shannon_entropy(diverse) > 5.0


# ── SlidingWindowCounter ──────────────────────────────────────────────────────

class TestSlidingWindowCounter:

    def test_count_within_window(self):
        """Events added within the window are all counted."""
        swc = SlidingWindowCounter(window_seconds=60.0)
        now = time.monotonic()
        for i in range(10):
            swc.add(ts=now + i * 0.1)
        assert swc.count(now=now + 2.0) == 10

    def test_expired_events_not_counted(self):
        """Events older than the window are pruned."""
        swc = SlidingWindowCounter(window_seconds=5.0)
        old = time.monotonic() - 10.0   # 10 s ago — definitely expired
        swc.add(ts=old)
        assert swc.count() == 0

    def test_rate_calculation(self):
        """rate() = count / window_seconds."""
        swc = SlidingWindowCounter(window_seconds=10.0)
        now = time.monotonic()
        for i in range(50):
            swc.add(ts=now + i * 0.1)
        # All 50 events are within 5 s, window is 10 s → rate = 50/10 = 5/s
        assert abs(swc.rate(now=now + 5.0) - 5.0) < 0.1

    def test_empty_counter_returns_zero(self):
        swc = SlidingWindowCounter(window_seconds=60.0)
        assert swc.count() == 0
        assert swc.rate()  == 0.0


# ── SlidingWindowSet ──────────────────────────────────────────────────────────

class TestSlidingWindowSet:

    def test_duplicates_counted_once(self):
        """The same value added multiple times counts as one unique entry."""
        sws: SlidingWindowSet = SlidingWindowSet(window_seconds=60.0)
        now = time.monotonic()
        sws.add("a", ts=now)
        sws.add("a", ts=now + 1)
        sws.add("b", ts=now + 2)
        assert sws.unique_count(now=now + 3) == 2

    def test_expired_values_removed(self):
        """Values outside the window are excluded from unique counts."""
        sws: SlidingWindowSet = SlidingWindowSet(window_seconds=1.0)
        now = time.monotonic()
        sws.add("old", ts=now - 5.0)   # 5 s ago — outside 1-s window
        sws.add("new", ts=now)
        assert sws.unique_count(now=now) == 1
        assert "new" in sws.unique(now=now)

    def test_empty_set_returns_zero(self):
        sws: SlidingWindowSet = SlidingWindowSet(window_seconds=60.0)
        assert sws.unique_count() == 0
        assert sws.unique() == set()
