"""Emit every SIEM event as an OpenTelemetry log record, written as one JSON line."""

import os
import socket
import threading
import time
from collections.abc import Mapping, Sequence
from importlib.metadata import version
from pathlib import Path
from typing import IO

from opentelemetry._logs import Logger, SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider, ReadableLogRecord
from opentelemetry.sdk._logs.export import (
    LogRecordExporter,
    LogRecordExportResult,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.util.types import AnyValue

SERVICE_NAME = "my_siem"
INFO = SeverityNumber.INFO
WARN = SeverityNumber.WARN
ERROR = SeverityNumber.ERROR


class JsonLinesExporter(LogRecordExporter):
    """Write records as JSON lines; safe to share between the monitor's threads."""

    def __init__(self, out: IO[str], owned: bool = False) -> None:
        self._out = out
        self._owned = owned
        self._lock = threading.Lock()

    @classmethod
    def append_to(cls, path: Path) -> tuple["JsonLinesExporter", bool]:
        """Open `path` for appending, creating its folders; also tell if it held records."""
        path.parent.mkdir(parents=True, exist_ok=True)
        resumed = path.exists() and path.stat().st_size > 0
        # Logs reveal users and addresses, so keep them away from other users.
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        out = os.fdopen(fd, "a", encoding="utf-8")
        if resumed and not _ends_with_newline(path):
            out.write("\n")  # a crash cut the last record short; don't glue onto it
        return cls(out, owned=True), resumed

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        with self._lock:
            for record in batch:
                self._out.write(record.to_json(indent=None) + "\n")
            self._out.flush()
        return LogRecordExportResult.SUCCESS

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        with self._lock:
            self._out.flush()
        return True

    def shutdown(self) -> None:
        with self._lock:
            self._out.flush()
            if self._owned:
                self._out.close()


def _ends_with_newline(path: Path) -> bool:
    with path.open("rb") as f:
        f.seek(-1, os.SEEK_END)
        return f.read(1) == b"\n"


def make_provider(exporters: Sequence[LogRecordExporter]) -> LoggerProvider:
    resource = Resource.create(
        {
            "service.name": SERVICE_NAME,
            "service.version": version(SERVICE_NAME),
            "host.name": socket.gethostname(),
        }
    )
    provider = LoggerProvider(resource=resource)
    for exporter in exporters:
        provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    return provider


class EventLogger:
    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    def emit(
        self,
        severity: SeverityNumber,
        event_name: str,
        body: str,
        attributes: Mapping[str, AnyValue] | None = None,
        at: float | None = None,
    ) -> None:
        """`at` is when the event happened (epoch seconds), defaulting to now."""
        self._logger.emit(
            timestamp=time.time_ns() if at is None else int(at * 1e9),
            severity_number=severity,
            severity_text=severity.name,
            event_name=event_name,
            body=body,
            attributes={k: v for k, v in (attributes or {}).items() if v is not None},
        )


def event_logger(provider: LoggerProvider, scope: str) -> EventLogger:
    return EventLogger(provider.get_logger(scope, version(SERVICE_NAME)))
