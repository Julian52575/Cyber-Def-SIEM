"""Read a command's past events again from the host's own logs, into its hourly files.

The command's own code replays them (`Source.replay`), so imported records, counts and
alerts look like live ones. Only closed hours are written: the current one belongs to the
running writer. Records already in the files are not written twice.
"""

import gzip
import json
import re
import secrets
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult

from my_siem.clock import HOUR, add_days, day_start, hour_start
from my_siem.logs.files import LogFile, add_to_closed_hour, list_logs
from my_siem.logs.manager import LogManager
from my_siem.logs.reader import Kinds, Record, at_of
from my_siem.logs.window import LONGEST
from my_siem.telemetry import (
    EventLogger,
    dumps,
    event_logger,
    make_provider,
    record_dict,
    resource_json,
)

# Set on every imported record, so it can be told from a live one.
IMPORTED = "siem.import.source"
UNITS = {"hour": 24, "day": LONGEST.count}
_NAME = re.compile(rb'"event_name":"([^"]*)"')


@dataclass(frozen=True)
class Source:
    """Where a command's past events can be read again, and how."""

    where: str
    # Emits the events of [since, until), oldest first, as the command does live.
    replay: Callable[[EventLogger, float, float], None]
    # Event name prefixes `replay` emits, alerts included.
    kinds: Kinds
    # An imported alert this close to a logged one of the same name and address is it.
    alert_window: float
    # For a source that sees the traffic differently from the live command (an access
    # log vs. the sniffer): an hour already watched live is skipped, not merged.
    skip_watched_hours: bool = False


@dataclass(frozen=True)
class Span:
    since: int
    until: int


def import_span(unit: str, count: int, now: float) -> Span:
    """The last `count` hours or days, up to the start of the current hour."""
    until = hour_start(now)
    if unit == "hour":
        return Span(until - count * HOUR, until)
    return Span(add_days(day_start(now), -count), until)


@dataclass
class Report:
    """One command's import, updated as it goes."""

    command: str
    where: str
    events: int = 0  # read from the source within the span
    new: int = 0  # not already logged: what is (or would be) written
    raw_bytes: int = 0
    gz_bytes: int = 0  # what the new records take on disk, gzipped
    hours: int = 0  # hourly files added to
    skipped_hours: int = 0  # already watched live, for a `skip_watched_hours` source
    folder_bytes: int = 0  # the command's log files before the import
    cap_bytes: int = 0
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _lines(f: LogFile) -> Iterator[bytes]:
    try:
        with gzip.open(f.path, "rb") if f.compressed else f.path.open("rb") as lines:
            yield from lines
    except FileNotFoundError:
        pass  # gzipped or swept since listed


class _Logged:
    """What the command's files already hold of a span, to tell new records from old."""

    def __init__(self, folder: Path, command: str, source: Source, span: Span) -> None:
        self._window = source.alert_window
        self.events: Counter[int] = Counter()
        self.alerts: defaultdict[tuple[str, Any], list[float]] = defaultdict(list)
        self.watched: set[int] = set()
        for f in list_logs(folder, command):
            # Old events read late (e.g. at startup) land in later files, never earlier.
            if f.hour + HOUR <= span.since:
                continue
            for line in _lines(f):
                m = _NAME.search(line)
                if m is None or not m[1].decode().startswith(source.kinds):
                    continue
                try:
                    record = json.loads(line)
                    at = at_of(record)
                except (ValueError, KeyError):
                    continue
                if span.since <= at < span.until:
                    self._add(record, at, source.skip_watched_hours)

    def _add(self, record: Record, at: float, track_hours: bool) -> None:
        attrs = record.get("attributes") or {}
        if track_hours and IMPORTED not in attrs:
            self.watched.add(hour_start(at))
        name = record["event_name"]
        if name.startswith("siem.alert."):
            self.alerts[(name, attrs.get("client.address"))].append(at)
        else:
            self.events[_key(record)] += 1

    def claim(self, record: Record, at: float) -> bool:
        """True if `record` is already logged; each logged record matches only once."""
        name = record["event_name"]
        if name.startswith("siem.alert."):
            # Detection restarts at the span's start, so an alert may land a bit off.
            ip = (record.get("attributes") or {}).get("client.address")
            times = self.alerts.get((name, ip), [])
            near = [t for t in times if abs(t - at) <= self._window]
            if not near:
                return False
            times.remove(min(near, key=lambda t: abs(t - at)))
            return True
        key = _key(record)
        if self.events[key] <= 0:
            return False
        self.events[key] -= 1
        return True


def _key(record: Record) -> int:
    return hash((record["timestamp"], record["event_name"], record["body"]))


class _Collector(LogRecordExporter):
    def __init__(self, take: Callable[[Record, str], None]) -> None:
        self._take = take

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        for r in batch:
            self._take(record_dict(r), resource_json(r.resource))
        return LogRecordExportResult.SUCCESS

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def shutdown(self) -> None:
        pass


def import_logs(
    logs: LogManager,
    source: Source,
    span: Span,
    write: bool,
    report: Report | None = None,
) -> Report:
    """Replay `source` over `span` into the command's files, or with `write` False only
    measure what would be written. Errors end up in `report.error`."""
    folder = logs.folder
    if folder is None:
        raise ValueError(f"{logs.command} writes no log files")
    report = report or Report(logs.command, source.where)
    lock = logs.writer.maintenance if logs.writer is not None else threading.Lock()
    logged = _Logged(folder, logs.command, source, span)
    pending: defaultdict[int, list[tuple[float, Record]]] = defaultdict(list)
    skipped: set[int] = set()
    resource = ""
    failure: list[Exception] = []

    def flush(before: int | None) -> None:
        for hour in sorted(h for h in pending if before is None or h < before):
            records = pending.pop(hour)
            text = resource + "\n" + "".join(dumps(r) + "\n" for _, r in records)
            data = text.encode()
            report.raw_bytes += len(data)
            report.gz_bytes += len(gzip.compress(data, mtime=0))
            report.hours += 1
            if write:
                with lock:
                    add_to_closed_hour(folder, logs.command, hour, data)
                for at, r in records:
                    logs.count(r, at)

    def take(record: Record, resource_line: str) -> None:
        nonlocal resource
        at = at_of(record)
        if failure or not span.since <= at < span.until:
            return
        report.events += 1
        hour = hour_start(at)
        if hour in logged.watched:
            skipped.add(hour)
            report.skipped_hours = len(skipped)
            return
        if logged.claim(record, at):
            return
        resource = resource_line
        record["attributes"] = {**(record["attributes"] or {}), IMPORTED: source.where}
        report.new += 1
        newer = all(hour > h for h in pending)
        pending[hour].append((at, record))
        if newer:
            # Raised in here, an error would be swallowed by the OTel processor.
            try:
                flush(hour)
            except OSError as e:
                failure.append(e)

    provider = make_provider([_Collector(take)])
    try:
        out = event_logger(provider, f"my_siem.{logs.command}")
        source.replay(out, span.since, span.until)
        if failure:
            raise failure[0]
        flush(None)
    except OSError as e:
        report.error = str(e)
    finally:
        provider.shutdown()
        if write:
            logs.rollup.save()
    return report


def folder_bytes(folder: Path, command: str) -> int:
    total = 0
    for f in list_logs(folder, command):
        try:
            total += f.path.stat().st_size
        except FileNotFoundError:
            pass
    return total


@dataclass
class ImportJob:
    span: Span
    reports: list[Report]
    started_at: float
    finished_at: float | None = None
    state: str = "running"  # then "done", or "failed" if a command could not be read

    def to_json(self) -> dict[str, Any]:
        return {
            "state": self.state,
            **asdict(self.span),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "reports": [r.to_json() for r in self.reports],
        }


class ImportBusy(Exception):
    pass


@dataclass
class Importer:
    """The admin panel's log import: estimated first, then run in the background, one
    at a time. Only running commands that write log files and have a source can import."""

    logs: Mapping[str, LogManager]
    sources: Mapping[str, Source]
    clock: Callable[[], float] = time.time
    job: ImportJob | None = None
    # HACK(import): only for the GET fallback (see /admin/import/start in api.py).
    # Only the admin page holds it, and another site cannot read that page.
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check_token(self, token: str | None) -> bool:
        return token is not None and secrets.compare_digest(token, self.token)

    def __post_init__(self) -> None:
        self.sources = {
            name: s
            for name, s in self.sources.items()
            if name in self.logs and self.logs[name].folder is not None
        }

    def max_count(self, unit: str) -> int:
        """Days stop at the retention age: older files would be deleted on the next sweep."""
        ages = [r.max_age_days for m in self.logs.values() if (r := m.retention)]
        if unit == "day" and ages:
            return max(1, min(UNITS["day"], *ages))
        return UNITS[unit]

    def span(self, unit: str, count: int) -> Span:
        if unit not in UNITS:
            raise ValueError(f"unit must be one of {', '.join(UNITS)}, got {unit!r}")
        if not 1 <= count <= self.max_count(unit):
            raise ValueError(f"count must be 1 to {self.max_count(unit)} {unit}s")
        return import_span(unit, count, self.clock())

    def _reports(self, commands: Sequence[str]) -> list[Report]:
        if not commands:
            raise ValueError("pick at least one command")
        unknown = [c for c in commands if c not in self.sources]
        if unknown:
            raise ValueError(f"cannot import into {', '.join(unknown)}")
        reports = []
        for name in dict.fromkeys(commands):
            logs = self.logs[name]
            assert logs.folder is not None
            retention = logs.retention
            reports.append(
                Report(
                    name,
                    self.sources[name].where,
                    folder_bytes=folder_bytes(logs.folder, name),
                    cap_bytes=retention.max_size_mb * 1024 * 1024 if retention else 0,
                )
            )
        return reports

    def estimate(self, commands: Sequence[str], unit: str, count: int) -> ImportJob:
        """Reads the sources and the logs like the import, but writes nothing."""
        span = self.span(unit, count)
        job = ImportJob(span, self._reports(commands), self.clock())
        self._run(job, write=False)
        return job

    def start(self, commands: Sequence[str], unit: str, count: int) -> ImportJob:
        """Raises ImportBusy while another import runs, ValueError on a bad request."""
        span = self.span(unit, count)
        reports = self._reports(commands)
        with self._lock:
            if self.job is not None and self.job.state == "running":
                raise ImportBusy("an import is already running")
            job = self.job = ImportJob(span, reports, self.clock())
        threading.Thread(
            target=self._run, args=(job, True), name="my_siem.import", daemon=True
        ).start()
        return job

    def _run(self, job: ImportJob, write: bool) -> None:
        for r in job.reports:
            logs, source = self.logs[r.command], self.sources[r.command]
            try:
                import_logs(logs, source, job.span, write, r)
            except Exception as e:  # noqa: BLE001 -- shown on the admin panel
                r.error = f"{type(e).__name__}: {e}"
        job.finished_at = self.clock()
        job.state = "failed" if any(r.error for r in job.reports) else "done"
