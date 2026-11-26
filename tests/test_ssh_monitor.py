import io
import json

import pytest
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter

from my_siem.detect import RateDetector
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.monitor import report_auth, report_conn
from my_siem.ssh.net import Connection, ConnEvent, ConnKind
from my_siem.telemetry import JsonLinesExporter, event_logger, make_provider


@pytest.fixture
def exporter() -> InMemoryLogRecordExporter:
    return InMemoryLogRecordExporter()


def records(exporter: InMemoryLogRecordExporter) -> list[ReadableLogRecord]:
    return list(exporter.get_finished_logs())


def test_failed_login_is_a_warn_record_with_semconv_attributes(
    exporter: InMemoryLogRecordExporter,
) -> None:
    out = event_logger(make_provider([exporter]), "test")
    event = AuthEvent(
        AuthKind.LOGIN_FAILURE, "root", "203.0.113.9", 4242, 90, "password"
    )

    report_auth(out, event, RateDetector(5, 60), now=0)

    [rec] = records(exporter)
    assert rec.log_record.event_name == "siem.ssh.login_failure"
    assert rec.log_record.severity_number is SeverityNumber.WARN
    assert dict(rec.log_record.attributes or {}) == {
        "user.name": "root",
        "client.address": "203.0.113.9",
        "client.port": 4242,
        "process.pid": 90,
        "siem.ssh.auth.method": "password",
    }
    assert rec.resource.attributes["service.name"] == "my_siem"


def test_repeated_failures_raise_an_error_alert(
    exporter: InMemoryLogRecordExporter,
) -> None:
    out = event_logger(make_provider([exporter]), "test")
    failures = RateDetector(2, 60)
    event = AuthEvent(AuthKind.INVALID_USER, "admin", "203.0.113.9", 1, 7)

    for t in (0, 1):
        report_auth(out, event, failures, now=t)

    alert = records(exporter)[-1].log_record
    assert alert.event_name == "siem.alert.ssh_bruteforce"
    assert alert.severity_number is SeverityNumber.ERROR
    assert (alert.attributes or {})["client.address"] == "203.0.113.9"


def test_closed_connection_carries_its_stats_and_packet_time(
    exporter: InMemoryLogRecordExporter,
) -> None:
    out = event_logger(make_provider([exporter]), "test")
    conn = Connection(
        "10.0.0.5", 50122, "10.0.0.1", 22, started=100.0, packets=4, bytes=300
    )

    report_conn(out, ConnEvent(ConnKind.CLOSED, conn, at=130.0), RateDetector(5, 60))

    rec = records(exporter)[0].log_record
    assert rec.event_name == "siem.ssh.connection.closed"
    assert rec.timestamp == 130 * 10**9
    attrs = rec.attributes or {}
    assert attrs["server.port"] == 22
    assert attrs["network.transport"] == "tcp"
    assert attrs["siem.ssh.connection.duration"] == 30.0


def test_console_output_is_one_json_record_per_line() -> None:
    buf = io.StringIO()
    out = event_logger(make_provider([JsonLinesExporter(buf)]), "test")
    event = AuthEvent(
        AuthKind.LOGIN_SUCCESS, "alice", "10.0.0.5", 5000, 50, "publickey"
    )

    report_auth(out, event, RateDetector(5, 60), now=0)
    report_auth(out, event, RateDetector(5, 60), now=0)

    lines = buf.getvalue().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["event_name"] == "siem.ssh.login_success"
    assert rec["severity_text"] == "INFO"
    assert rec["attributes"]["user.name"] == "alice"
