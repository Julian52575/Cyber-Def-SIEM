"""Alert detection shared by the commands: per-IP rate thresholds and raising alerts."""

import time
from collections import defaultdict, deque
from collections.abc import Mapping
from typing import Protocol

from opentelemetry.util.types import AnyValue

from my_siem.telemetry import ERROR, EventLogger


class RateDetector:
    """Flag a key (e.g. a source IP) that hits `threshold` times within `window` seconds."""

    def __init__(self, threshold: int, window: float) -> None:
        self.threshold = threshold
        self.window = window
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, now: float) -> bool:
        hits = self._hits[key]
        hits.append(now)
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.threshold:
            # Start counting afresh so an ongoing attack alerts once per burst.
            hits.clear()
            return True
        return False


class AlertState(Protocol):
    def alert(self, name: str, ip: str, message: str, at: float) -> None: ...


def raise_alert(
    out: EventLogger,
    state: AlertState,
    name: str,
    ip: str,
    message: str,
    attributes: Mapping[str, AnyValue] | None = None,
    at: float | None = None,
) -> None:
    """Record alert `name` against `ip` and log it as `siem.alert.<name>`.

    `at` is when the triggering event happened (default now), so an alert raised while
    reading old logs lands at its time, not at the time it was read.
    """
    at = time.time() if at is None else at
    state.alert(name, ip, message, at)
    out.emit(
        ERROR,
        f"siem.alert.{name}",
        message,
        {"client.address": ip, **(attributes or {})},
        at,
    )


def rate_alert(
    out: EventLogger,
    state: AlertState,
    name: str,
    ip: str,
    detector: RateDetector,
    what: str,
    at: float | None = None,
) -> None:
    raise_alert(
        out,
        state,
        name,
        ip,
        f"{ip} made {detector.threshold} {what} within {detector.window:.0f}s",
        {
            "siem.alert.threshold": detector.threshold,
            "siem.alert.window": detector.window,
        },
        at,
    )
