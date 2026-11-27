"""Event counts per minute, hour and day, kept as long as the time filters reach back.

Raw logs grow with traffic; these stay a few KB, so a 100-day view costs the same as a
1-minute one, and they outlive the raw logs' retention.
"""

import json
import os
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult

from my_siem.clock import HOUR, MINUTE, add_days, day_start, hour_start, minute_start

FORMAT = 1


@dataclass(frozen=True)
class Tier:
    """Buckets on whole Paris minutes, hours or days, so they line up across restarts."""

    name: str
    keep: int  # complete buckets kept, besides the current one
    start: Callable[[float], int]  # start of the bucket holding an epoch
    shift: Callable[[int, int], int]  # a bucket start moved by n buckets

    def oldest(self, now: float) -> int:
        return self.shift(self.start(now), -self.keep)


TIERS = (
    Tier("minute", 60, minute_start, lambda s, n: s + n * MINUTE),
    Tier("hour", 24, hour_start, lambda s, n: s + n * HOUR),
    # Not a fixed width: DST days last 23 or 25 hours.
    Tier("day", 100, day_start, add_days),
)


@dataclass(frozen=True)
class Bucket:
    start: int
    counts: dict[str, int]


class Rollup:
    """Thread-safe: the command's threads count while the API thread reads."""

    def __init__(
        self, path: Path | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        """`path` is where the counts survive restarts; None keeps them in memory."""
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._tiers: dict[str, dict[int, Counter[str]]] = {t.name: {} for t in TIERS}
        self._saved_minute = TIERS[0].start(clock())

    def add(self, event_name: str, at: float) -> None:
        with self._lock:
            now = self._clock()
            for tier in TIERS:
                start = tier.start(at)
                if start >= tier.oldest(now):
                    self._tiers[tier.name].setdefault(start, Counter())[event_name] += 1
            minute = TIERS[0].start(now)
            if minute != self._saved_minute:
                self._saved_minute = minute
                self._prune(now)
                self._save()

    def series(self, since: float) -> tuple[Tier, list[Bucket]]:
        """Buckets from `since` to now, in the finest tier that reaches back that far.

        Every bucket in the range is listed, empty ones included, so a chart can plot
        them as they are.
        """
        with self._lock:
            now = self._clock()
            tier = next((t for t in TIERS if since >= t.oldest(now)), TIERS[-1])
            buckets = self._tiers[tier.name]
            start = max(tier.start(since), tier.oldest(now))
            series = []
            while start <= now:
                series.append(Bucket(start, dict(buckets.get(start, {}))))
                start = tier.shift(start, 1)
            return tier, series

    def _prune(self, now: float) -> None:
        for tier in TIERS:
            oldest = tier.oldest(now)
            buckets = self._tiers[tier.name]
            for start in [s for s in buckets if s < oldest]:
                del buckets[start]

    def load(self) -> None:
        """Read the counts saved by an earlier run, if any.

        Raises OSError or ValueError on a file that cannot be read or makes no sense.
        """
        if self.path is None:
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise ValueError(f"{self.path}: not a rollup of format {FORMAT}")
        with self._lock:
            for tier in TIERS:
                saved = data.get(tier.name, {})
                self._tiers[tier.name] = {
                    int(start): Counter({str(k): int(v) for k, v in counts.items()})
                    for start, counts in saved.items()
                }
            self._prune(self._clock())

    def save(self) -> None:
        with self._lock:
            self._prune(self._clock())
            self._save()

    def _save(self) -> None:
        """Call with `_lock` held. Written aside then renamed: a crash keeps the old file."""
        if self.path is None:
            return
        data: dict[str, Any] = {"format": FORMAT}
        for tier in TIERS:
            data[tier.name] = {
                str(s): dict(c) for s, c in sorted(self._tiers[tier.name].items())
            }
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(data, out, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as e:
            # Counts stay in memory and the next minute retries; events must not stop.
            print(f"my_siem: warning: cannot save {self.path}: {e}", file=sys.stderr)


class RollupExporter(LogRecordExporter):
    """Counts each record by event name, at the time the event happened."""

    def __init__(self, rollup: Rollup) -> None:
        self.rollup = rollup

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        for record in batch:
            r = record.log_record
            name = r.event_name or "unnamed"
            at = (r.timestamp or time.time_ns()) / 1e9
            self.rollup.add(name, at)
        return LogRecordExportResult.SUCCESS

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def shutdown(self) -> None:
        self.rollup.save()
