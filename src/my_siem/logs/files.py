"""Raw event logs cut into one file per Paris hour, gzipped once closed, aged and capped.

Each file opens with a resource line (who wrote the records: host, version, instance),
written again whenever a later run appends; it applies to the records below it.
"""

import gzip
import os
import re
import shutil
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import IO

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult

from my_siem.clock import HOUR, hour_start, local
from my_siem.telemetry import record_json, resource_json

DAY = 86400
MB = 1024 * 1024
# With the UTC offset: when DST ends, 02:00 comes twice, as +0200 then +0100.
_STAMP = "%Y-%m-%dT%H%z"


def log_name(command: str, hour: int) -> str:
    return f"{command}.{local(hour).strftime(_STAMP)}.jsonl"


@dataclass(frozen=True)
class LogFile:
    path: Path
    hour: int

    @property
    def compressed(self) -> bool:
        return self.path.suffix == ".gz"


def list_logs(folder: Path, command: str) -> list[LogFile]:
    """The command's hourly files in `folder`, oldest first."""
    pattern = re.compile(
        rf"^{re.escape(command)}\.(\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}[+-]\d{{4}})\.jsonl(\.gz)?$"
    )
    found = []
    try:
        entries = list(folder.iterdir())
    except FileNotFoundError:
        return []
    for p in entries:
        m = pattern.match(p.name)
        if m is not None:
            at = datetime.strptime(m[1], _STAMP).timestamp()
            found.append(LogFile(p, int(at)))
    # Plain before .gz within an hour, so a half-done compression is redone, not lost.
    return sorted(found, key=lambda f: (f.hour, f.compressed))


@dataclass(frozen=True)
class Retention:
    max_age_days: int
    max_size_mb: int

    def sweep(self, folder: Path, command: str, current: int, now: float) -> None:
        """Gzip closed hours, then drop files past the age, then the oldest past the size.

        Files of hour `current` (being written) or later are never touched.
        """
        for f in list_logs(folder, command):
            if not f.compressed and f.hour < current:
                _try(partial(_compress, f.path))
        oldest = now - self.max_age_days * DAY
        kept = []
        for f in list_logs(folder, command):
            if f.hour < current and f.hour + HOUR <= oldest:
                _try(f.path.unlink)
            else:
                kept.append(f)
        total = sum(_size(f.path) for f in kept)
        for f in kept:
            if total <= self.max_size_mb * MB or f.hour >= current:
                break
            total -= _size(f.path)
            _try(f.path.unlink)


def _compress(path: Path) -> None:
    gz = path.with_name(path.name + ".gz")
    tmp = gz.with_name(gz.name + ".tmp")
    with path.open("rb") as src, gzip.open(tmp, "wb") as dst:
        shutil.copyfileobj(src, dst)
    os.chmod(tmp, 0o640)
    os.replace(tmp, gz)
    path.unlink()


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _try(action: Callable[[], object]) -> None:
    # A sweep runs off the event path, with no logger to report to.
    try:
        action()
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"my_siem: warning: log retention: {e}", file=sys.stderr)


def _open_append(path: Path) -> tuple[IO[str], bool]:
    """Open `path` for appending; also tell if it already held records."""
    resumed = path.exists() and path.stat().st_size > 0
    # Logs reveal users and addresses, so keep them away from other users.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    out = os.fdopen(fd, "a", encoding="utf-8")
    if resumed and not _ends_with_newline(path):
        out.write("\n")  # a crash cut the last record short; don't glue onto it
    return out, resumed


def add_to_closed_hour(folder: Path, command: str, hour: int, lines: bytes) -> Path:
    """Add JSON lines to a closed hour: to its plain file while it is not gzipped yet,
    else as one more gzip member. Call with the writer's `maintenance` lock held."""
    plain = folder / log_name(command, hour)
    if plain.exists():
        out, _ = _open_append(plain)
        with out:
            out.write(lines.decode())
        return plain
    gz = plain.with_name(plain.name + ".gz")
    tmp = gz.with_name(gz.name + ".tmp")
    # Rewritten aside then renamed: a crash mid-write must not leave a truncated member.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "wb") as dst:
        try:
            with gz.open("rb") as src:
                shutil.copyfileobj(src, dst)
        except FileNotFoundError:
            pass
        dst.write(gzip.compress(lines, mtime=0))
    os.replace(tmp, gz)
    return gz


def _ends_with_newline(path: Path) -> bool:
    with path.open("rb") as f:
        f.seek(-1, os.SEEK_END)
        return f.read(1) == b"\n"


class HourlyLogExporter(LogRecordExporter):
    """Write records as JSON lines into the file of the hour they are written in.

    Safe to share between the command's threads. Each change of hour starts a sweep
    in the background, so gzipping a large file never holds up an event.
    """

    def __init__(
        self,
        folder: Path,
        command: str,
        retention: Retention,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.folder = folder
        self._command = command
        self.retention = retention
        self._clock = clock
        self._lock = threading.Lock()
        # Held by a sweep, and by anything else rewriting closed hours (the log import).
        self.maintenance = threading.Lock()
        self.last_sweep: float | None = None
        folder.mkdir(parents=True, exist_ok=True)
        self._hour = hour_start(clock())
        self.path = folder / log_name(command, self._hour)
        self._out, self.resumed = _open_append(self.path)
        self._header_due = True
        self._sweep()

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        with self._lock:
            hour = hour_start(self._clock())
            if hour != self._hour:
                self._out.close()
                self._hour = hour
                self.path = self.folder / log_name(self._command, hour)
                self._out, _ = _open_append(self.path)
                self._header_due = True
                self._sweep()
            if self._header_due and batch:
                self._out.write(resource_json(batch[0].resource) + "\n")
                self._header_due = False
            for record in batch:
                self._out.write(record_json(record) + "\n")
            self._out.flush()
        return LogRecordExportResult.SUCCESS

    def _sweep(self) -> None:
        threading.Thread(
            target=self._sweep_once,
            args=(self._hour, self._clock()),
            name=f"my_siem.{self._command}.retention",
            daemon=True,
        ).start()

    def _sweep_once(self, current: int, now: float) -> None:
        # Hours rarely change faster than a sweep ends; if they do, the next one catches up.
        if not self.maintenance.acquire(blocking=False):
            return
        try:
            self.retention.sweep(self.folder, self._command, current, now)
            self.last_sweep = self._clock()
        finally:
            self.maintenance.release()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        with self._lock:
            self._out.flush()
        return True

    def shutdown(self) -> None:
        with self._lock:
            self._out.close()
