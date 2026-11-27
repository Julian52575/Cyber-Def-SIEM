"""Read recent records back, newest first, for the time filters.

A dashboard polls every few seconds, so files are not re-read each time: a gzipped hour
never changes and is parsed once, and the hour being written is read from where the last
read stopped. Only the newest `LIMIT` records of each kind are kept per file.
"""

import gzip
import heapq
import json
import re
import threading
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult

from my_siem.clock import HOUR
from my_siem.logs.files import list_logs
from my_siem.telemetry import record_dict

type Record = dict[str, Any]
# Event name prefixes, e.g. ("siem.alert.",): which records a table shows.
type Kinds = tuple[str, ...]

LIMIT = 100
# Parsed files kept; a 100-day view of a quiet host is 2400 hourly files.
CACHED_FILES = 4096
# Lets a line be skipped on its name alone, without parsing its JSON.
_NAME = re.compile(rb'"event_name":"([^"]*)"')


def at_of(record: Record) -> float:
    return datetime.fromisoformat(record["timestamp"]).timestamp()


def newest(
    found: list[tuple[float, Record]], since: float, limit: int
) -> list[tuple[float, Record]]:
    return sorted((f for f in found if f[0] >= since), key=lambda f: -f[0])[:limit]


@dataclass
class _Parsed:
    """What one file holds of one kind: its newest records, and how far it was read."""

    records: deque[tuple[float, Record]] = field(
        default_factory=lambda: deque(maxlen=LIMIT)
    )
    offset: int = 0
    complete: bool = False  # a gzipped hour, read to its end
    size: int = -1  # of the gzipped file when read: an import may add a member to it


class FileReader:
    def __init__(self, folder: Path, command: str) -> None:
        self._folder = folder
        self._command = command
        self._lock = threading.Lock()
        self._cache: OrderedDict[tuple[Path, Kinds], _Parsed] = OrderedDict()

    def recent(self, kinds: Kinds, since: float, limit: int = LIMIT) -> list[Record]:
        """The newest `limit` records of `kinds` that happened at or after `since`."""
        found: list[tuple[float, Record]] = []
        with self._lock:
            for f in reversed(list_logs(self._folder, self._command)):
                # A file only holds events from before its hour ended.
                end = f.hour + HOUR
                if end < since:
                    break
                top = newest(found, since, limit)
                if len(top) >= limit and top[-1][0] >= end:
                    break
                found.extend(self._read(f.path, f.compressed, kinds))
        return [r for _, r in newest(found, since, limit)]

    def _read(
        self, path: Path, compressed: bool, kinds: Kinds
    ) -> deque[tuple[float, Record]]:
        key = (path, kinds)
        parsed = self._cache.pop(key, None) or _Parsed()
        try:
            size = path.stat().st_size if compressed else -1
            if parsed.complete and parsed.size != size:
                parsed = _Parsed()
            self._cache[key] = parsed
            while len(self._cache) > CACHED_FILES:
                self._cache.popitem(last=False)
            if parsed.complete:
                return parsed.records
            if compressed:
                with gzip.open(path, "rb") as f:
                    data = f.read()
            else:
                with path.open("rb") as plain:
                    plain.seek(parsed.offset)
                    data = plain.read()
        except FileNotFoundError:
            # Gzipped or deleted since listed; the next listing finds the new name.
            self._cache.pop(key, None)
            return deque()
        # Leave a line still being written for the next read.
        end = len(data) if compressed else data.rfind(b"\n") + 1
        found = list(parsed.records)
        for line in data[:end].splitlines():
            m = _NAME.search(line)
            if m is not None and m[1].decode().startswith(kinds):
                try:
                    record = json.loads(line)
                    found.append((at_of(record), record))
                except ValueError:
                    continue  # a record cut short by a crash
        # By time, not file order: an imported member may follow newer records.
        parsed.records = deque(
            heapq.nlargest(LIMIT, found, key=lambda f: f[0]), maxlen=LIMIT
        )
        parsed.offset += end
        parsed.complete = compressed
        parsed.size = size
        return parsed.records


class MemoryReader(LogRecordExporter):
    """With no log files: the last records, kept in memory as they are logged."""

    def __init__(self, size: int = 5000) -> None:
        self._lock = threading.Lock()
        self._records: deque[tuple[float, Record]] = deque(maxlen=size)

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        with self._lock:
            for r in batch:
                record = record_dict(r)
                self._records.append((at_of(record), record))
        return LogRecordExportResult.SUCCESS

    def recent(self, kinds: Kinds, since: float, limit: int = LIMIT) -> list[Record]:
        with self._lock:
            found = [f for f in self._records if f[1]["event_name"].startswith(kinds)]
        return [r for _, r in newest(found, since, limit)]

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def shutdown(self) -> None:
        pass
