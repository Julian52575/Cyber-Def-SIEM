"""Emit every SIEM event as an OpenTelemetry log record, written as one JSON line."""

import json
import socket
import threading
import time
from collections.abc import Mapping, Sequence
from typing import IO, Any

from opentelemetry._logs import Logger, SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider, ReadableLogRecord
from opentelemetry.sdk._logs.export import (
    LogRecordExporter,
    LogRecordExportResult,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.util import ns_to_iso_str
from opentelemetry.util.types import AnyValue

from my_siem.version import VERSION

SERVICE_NAME = "my_siem"
INFO = SeverityNumber.INFO
WARN = SeverityNumber.WARN
ERROR = SeverityNumber.ERROR


def _dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, separators=(",", ":"), default=repr)


def record_json(record: ReadableLogRecord, with_resource: bool = False) -> str:
    """OTel's JSON shape without what is always empty here or repeated on every line.

    Trace fields only appear when a record carries a trace; the observed time, a few
    microseconds after the event time, is left out.
    """
    r = record.log_record
    data: dict[str, Any] = {
        "timestamp": ns_to_iso_str(r.timestamp or r.observed_timestamp or 0),
        "severity_number": r.severity_number.value if r.severity_number else None,
        "severity_text": r.severity_text,
        "event_name": r.event_name or "",
        "body": r.body,
        "attributes": dict(r.attributes) if r.attributes else None,
    }
    if r.trace_id:
        data["trace_id"] = f"0x{r.trace_id:032x}"
        data["span_id"] = f"0x{r.span_id or 0:016x}"
        data["trace_flags"] = r.trace_flags
    if record.dropped_attributes:
        data["dropped_attributes"] = record.dropped_attributes
    if with_resource:
        data["resource"] = json.loads(record.resource.to_json())
    return _dumps(data)


def resource_json(resource: Resource) -> str:
    """The line naming who wrote the records below it."""
    return _dumps({"resource": json.loads(resource.to_json())})


class JsonLinesExporter(LogRecordExporter):
    """Write records as JSON lines to a stream; safe to share between threads.

    Each line carries its resource: several commands may share the stream.
    """

    def __init__(self, out: IO[str]) -> None:
        self._out = out
        self._lock = threading.Lock()

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        with self._lock:
            for record in batch:
                self._out.write(record_json(record, with_resource=True) + "\n")
            self._out.flush()
        return LogRecordExportResult.SUCCESS

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        with self._lock:
            self._out.flush()
        return True

    def shutdown(self) -> None:
        with self._lock:
            self._out.flush()


def make_provider(exporters: Sequence[LogRecordExporter]) -> LoggerProvider:
    resource = Resource.create(
        {
            "service.name": SERVICE_NAME,
            "service.version": VERSION,
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
    return EventLogger(provider.get_logger(scope, VERSION))
