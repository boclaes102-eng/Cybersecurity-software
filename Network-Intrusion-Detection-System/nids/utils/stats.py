"""
Statistical primitives for anomaly detection.

Core algorithms:
  - WelfordAccumulator : numerically stable online mean/variance (O(1) space)
  - EWMA               : exponential weighted moving average for rate smoothing
  - SlidingWindowCounter: event rate over a rolling time window
  - SlidingWindowSet   : unique-value counting over a rolling time window
  - shannon_entropy    : information-theoretic entropy for DNS analysis
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Welford's Online Algorithm
# ---------------------------------------------------------------------------

@dataclass
class WelfordAccumulator:
    """
    Welford's one-pass algorithm for numerically stable running statistics.

    The naive variance formula Σ(x²)/n - (Σx/n)² suffers catastrophic
    cancellation for large values. Welford's method avoids this by updating
    the sum of squared deviations incrementally.

    Reference: Welford, B.P. (1962). "Note on a method for calculating
    corrected sums of squares and products." Technometrics, 4(3), 419–420.

    Complexity: O(1) time and space per update.
    """

    _n: int = 0
    _mean: float = 0.0
    _M2: float = 0.0  # aggregate squared distance from current mean

    def update(self, x: float) -> None:
        """Incorporate one new observation."""
        self._n += 1

        # First delta: distance from the *old* mean (before update)
        delta = x - self._mean

        # Update mean incrementally — no need to store all values
        self._mean += delta / self._n

        # Second delta: distance from the *new* mean (after update)
        # Using two different deltas is the core of Welford's trick:
        # their product equals the exact contribution to the sum of
        # squared deviations without ever computing a large intermediate sum.
        delta2 = x - self._mean
        self._M2 += delta * delta2

    @property
    def n(self) -> int:
        return self._n

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        """Sample variance with Bessel's correction (unbiased estimator)."""
        return self._M2 / (self._n - 1) if self._n >= 2 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        """
        Standard score of x against the current distribution.

        z = (x - μ) / σ

        A z-score of +3 means x is 3 standard deviations above the mean —
        statistically, only ~0.13 % of observations from a normal distribution
        would be that extreme.  We use this to fire anomaly alerts.

        Returns 0 when std_dev ≈ 0 to avoid division-by-zero;
        callers should gate on `n >= WARMUP` before trusting this value.
        """
        sd = self.std_dev
        return 0.0 if sd < 1e-9 else (x - self._mean) / sd

    def is_anomalous(self, x: float, threshold: float = 3.0) -> bool:
        """True if x is more than `threshold` σ from the mean."""
        return self._n >= 10 and abs(self.z_score(x)) > threshold


# ---------------------------------------------------------------------------
# Exponential Weighted Moving Average
# ---------------------------------------------------------------------------

@dataclass
class EWMA:
    """
    Single-pass exponential smoothing for rate and level estimation.

    α controls the decay rate of past observations:
      α = 0.05  →  slow, stable (long memory)
      α = 0.30  →  fast, reactive (short memory)

    The half-life of a past observation is: -ln(2) / ln(1 - α) steps.
    """

    alpha: float = 0.1
    _value: float = 0.0
    _initialized: bool = False

    def update(self, x: float) -> float:
        if not self._initialized:
            self._value = x
            self._initialized = True
        else:
            self._value = self.alpha * x + (1.0 - self.alpha) * self._value
        return self._value

    @property
    def value(self) -> float:
        return self._value

    @property
    def initialized(self) -> bool:
        return self._initialized


# ---------------------------------------------------------------------------
# Shannon Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """
    Shannon information entropy of a string, measured in bits per symbol.

    H(X) = -Σ p(x) · log₂ p(x)

    Empirical calibration for DNS subdomain labels:
      Legitimate hostnames   : ~1.5 – 3.0 bits
      Hex-encoded data       : ~3.5 – 4.0 bits
      Base32-encoded data    : ~4.0 – 4.5 bits   (DNS tunnel tools default)
      Base64-encoded data    : ~4.5 – 5.0 bits
      Uniformly random bytes : ~5.5 – 6.0 bits
    """
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ---------------------------------------------------------------------------
# Sliding-window primitives
# ---------------------------------------------------------------------------

class SlidingWindowCounter:
    """
    Count events that occurred within the most recent `window` seconds.

    Internally stores event timestamps in a deque; expired entries are
    lazily pruned on each access, giving amortised O(1) per operation.
    """

    __slots__ = ("_window", "_events")

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._events: deque[float] = deque()

    def add(self, ts: Optional[float] = None) -> None:
        now = ts if ts is not None else time.monotonic()
        self._events.append(now)
        self._expire(now)

    def _expire(self, now: float) -> None:
        # Pop from the left (oldest) until all remaining events are within window.
        # deque.popleft() is O(1), making the amortised cost O(1) per add().
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()

    def count(self, now: Optional[float] = None) -> int:
        self._expire(now if now is not None else time.monotonic())
        return len(self._events)

    def rate(self, now: Optional[float] = None) -> float:
        """
        Mean events per second over the configured window.

        Dividing by the full window length (not just the elapsed time)
        gives a conservative rate that naturally ramps up from zero as
        the window fills — no spike on cold start.
        """
        return self.count(now) / self._window


class SlidingWindowSet(Generic[T]):
    """
    Track unique values seen within a rolling time window.

    Useful for counting distinct destination IPs or ports contacted by
    a source in the last N seconds — the key primitive for scan detection.
    """

    __slots__ = ("_window", "_events")

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._events: deque[tuple[float, T]] = deque()

    def add(self, value: T, ts: Optional[float] = None) -> None:
        now = ts if ts is not None else time.monotonic()
        self._events.append((now, value))
        self._expire(now)

    def _expire(self, now: float) -> None:
        cutoff = now - self._window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def unique(self, now: Optional[float] = None) -> set[T]:
        self._expire(now if now is not None else time.monotonic())
        return {v for _, v in self._events}

    def unique_count(self, now: Optional[float] = None) -> int:
        return len(self.unique(now))
