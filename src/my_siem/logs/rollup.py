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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from my_siem.logs.window import TIERS, Tier

FORMAT = 1


@dataclass(frozen=True)
class Bucket:
    start: int
    counts: dict[str, int]


class Rollup:
    """Thread-safe: the command's threads count while the API thread reads.

    Also keeps marks: how far a source was read (e.g. the time of the last sshd line).
    They are saved with the counts, so after a crash both go back to the same point and
    re-reading from the mark never counts an event twice.
    """

    def __init__(
        self, path: Path | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        """`path` is where the counts survive restarts; None keeps them in memory."""
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._tiers: dict[str, dict[int, Counter[str]]] = {name: {} for name in TIERS}
        self._marks: dict[str, float] = {}
        self.saved_at: float | None = None
        self._saved_minute = TIERS["minute"].start(clock())

    def add(self, keys: Mapping[str, int], at: float) -> None:
        """Add each key's amount to the buckets holding `at`."""
        with self._lock:
            now = self._clock()
            for tier in TIERS.values():
                start = tier.start(at)
                if start >= tier.oldest(now):
                    self._tiers[tier.name].setdefault(start, Counter()).update(keys)
            # TODO(logs): saved on the minute's first event, not on the minute: a quiet
            # command saves late (nothing is lost, exit saves too). Ends with a timer.
            minute = TIERS["minute"].start(now)
            if minute != self._saved_minute:
                self._saved_minute = minute
                self._prune(now)
                self._save()

    def buckets(self, tier: Tier, since: float) -> list[Bucket]:
        """Every bucket of `tier` from the one holding `since` to now, empty ones too."""
        with self._lock:
            now = self._clock()
            saved = self._tiers[tier.name]
            start = max(tier.start(since), tier.oldest(now))
            out = []
            while start <= now:
                out.append(Bucket(start, dict(saved.get(start, {}))))
                start = tier.shift(start, 1)
            return out

    def mark(self, name: str) -> float | None:
        with self._lock:
            return self._marks.get(name)

    def set_mark(self, name: str, at: float) -> None:
        with self._lock:
            self._marks[name] = at

    def _prune(self, now: float) -> None:
        for tier in TIERS.values():
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
            for name in TIERS:
                saved = data.get(name, {})
                self._tiers[name] = {
                    int(start): Counter({str(k): int(v) for k, v in counts.items()})
                    for start, counts in saved.items()
                }
            self._marks = {str(k): float(v) for k, v in data.get("marks", {}).items()}
            self._prune(self._clock())

    def save(self) -> None:
        with self._lock:
            self._prune(self._clock())
            self._save()

    def _save(self) -> None:
        """Call with `_lock` held. Written aside then renamed: a crash keeps the old file."""
        if self.path is None:
            return
        data: dict[str, Any] = {"format": FORMAT, "marks": self._marks}
        for name in TIERS:
            data[name] = {str(s): dict(c) for s, c in sorted(self._tiers[name].items())}
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(data, out, separators=(",", ":"))
            os.replace(tmp, self.path)
            self.saved_at = self._clock()
        except OSError as e:
            # Counts stay in memory and the next minute retries; events must not stop.
            print(f"my_siem: warning: cannot save {self.path}: {e}", file=sys.stderr)
