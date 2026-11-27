"""One command's logs: every event written goes through here, and every read comes from here."""

import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult

from my_siem.logs.files import HourlyLogExporter, Retention
from my_siem.logs.reader import LIMIT, FileReader, Kinds, MemoryReader, Record
from my_siem.logs.rollup import Bucket, Rollup
from my_siem.logs.window import Window
from my_siem.telemetry import event_logger, make_provider

# What one event adds to the counts: its name, plus whatever the command breaks it down by.
type CountKeys = Callable[[str, Mapping[str, Any]], Mapping[str, int]]

ROLLUP_FILE = "rollup.json"


def event_keys(name: str, attributes: Mapping[str, Any]) -> dict[str, int]:
    """Counted for every command: the event name, and `alerts` for any alert."""
    keys = {name: 1}
    if name.startswith("siem.alert."):
        keys["alerts"] = 1
    return keys


class _Counter(LogRecordExporter):
    """Feeds each record to the rollup, at the time its event happened."""

    def __init__(self, rollup: Rollup, keys: CountKeys) -> None:
        self._rollup = rollup
        self._keys = keys

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        for record in batch:
            r = record.log_record
            name = r.event_name or "unnamed"
            at = (r.timestamp or time.time_ns()) / 1e9
            self._rollup.add(self._keys(name, dict(r.attributes or {})), at)
        return LogRecordExportResult.SUCCESS

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def shutdown(self) -> None:
        self._rollup.save()


class LogManager:
    """Writes a command's events to its hourly files, counts and optional stdout copy,
    and reads them back for a time window.

    With `folder` None (`--no-log`), nothing is written to disk: counts and the last
    records stay in memory for this run.
    """

    def __init__(
        self,
        command: str,
        folder: Path | None,
        retention: Retention | None = None,
        keys: CountKeys = event_keys,
        stdout: LogRecordExporter | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """`retention` is required with a `folder`. Raises OSError when the log folder or
        file cannot be opened."""
        self.command = command
        self.folder = folder
        self.keys = keys
        self._clock = clock
        exporters: list[LogRecordExporter] = []
        self.reader: FileReader | MemoryReader
        self.writer: HourlyLogExporter | None = None
        if folder is None:
            self.reader = MemoryReader()
            exporters.append(self.reader)
            self.rollup = Rollup(None, clock)
        else:
            if retention is None:
                raise ValueError("log files need a retention")
            self.writer = HourlyLogExporter(folder, command, retention, clock)
            exporters.append(self.writer)
            self.reader = FileReader(folder, command)
            self.rollup = Rollup(folder / ROLLUP_FILE, clock)
            try:
                self.rollup.load()
            except (OSError, ValueError) as e:
                # Only past counts are lost; better than not monitoring.
                print(f"my_siem: warning: starting counts afresh: {e}", file=sys.stderr)
        if stdout is not None:
            exporters.append(stdout)
        exporters.append(_Counter(self.rollup, keys))
        self._provider = make_provider(exporters)
        self.out = event_logger(self._provider, f"my_siem.{command}")

    @property
    def log_file(self) -> Path | None:
        return None if self.writer is None else self.writer.path

    @property
    def retention(self) -> Retention | None:
        return None if self.writer is None else self.writer.retention

    def count(self, record: Mapping[str, Any], at: float) -> None:
        """Count a record written to the files without going through `out` (an import)."""
        name = record["event_name"]
        self.rollup.add(self.keys(name, record.get("attributes") or {}), at)

    @property
    def resumed(self) -> bool:
        return self.writer is not None and self.writer.resumed

    def counts(self, window: Window) -> list[Bucket]:
        """The window's buckets, oldest first, empty ones included."""
        return self.rollup.buckets(window.tier, window.since(self._clock()))

    def recent(self, kinds: Kinds, window: Window, limit: int = LIMIT) -> list[Record]:
        """The newest records of `kinds` within the window, newest first."""
        return self.reader.recent(kinds, window.since(self._clock()), limit)

    def mark(self, source: str) -> float | None:
        """When the last event read from `source` happened, saved with the counts."""
        return self.rollup.mark(source)

    def set_mark(self, source: str, at: float) -> None:
        self.rollup.set_mark(source, at)

    def close(self) -> None:
        self._provider.shutdown()
