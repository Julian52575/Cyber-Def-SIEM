import io
import json
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter

from my_siem.detect import RateDetector
from my_siem.logs import LogManager
from my_siem.net import Connection, ConnEvent, ConnKind
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.monitor import (
    SSHD_LOG,
    SshMonitorConfig,
    _auth_events,
    report_auth,
    report_conn,
)
from my_siem.ssh.state import SshState
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

    report_auth(out, SshState({}), event, RateDetector(5, 60))

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
        report_auth(out, SshState({}), replace(event, at=t), failures)

    alert = records(exporter)[-1].log_record
    assert alert.event_name == "siem.alert.ssh_bruteforce"
    assert alert.timestamp == 1 * 10**9  # at the failure that tipped it, not when read
    assert alert.severity_number is SeverityNumber.ERROR
    assert (alert.attributes or {})["client.address"] == "203.0.113.9"


def test_closed_connection_carries_its_stats_and_packet_time(
    exporter: InMemoryLogRecordExporter,
) -> None:
    out = event_logger(make_provider([exporter]), "test")
    conn = Connection(
        "10.0.0.5", 50122, "10.0.0.1", 22, started=100.0, packets=4, bytes=300
    )

    report_conn(
        out,
        SshState({}),
        ConnEvent(ConnKind.CLOSED, conn, at=130.0),
        RateDetector(5, 60),
    )

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

    report_auth(out, SshState({}), event, RateDetector(5, 60))
    report_auth(out, SshState({}), event, RateDetector(5, 60))

    lines = buf.getvalue().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["event_name"] == "siem.ssh.login_success"
    assert rec["severity_text"] == "INFO"
    assert rec["attributes"]["user.name"] == "alice"


def stamped(at: float, user: str) -> str:
    stamp = datetime.fromtimestamp(at).astimezone().isoformat()
    return f"{stamp} host sshd[1]: Invalid user {user} from 1.2.3.4 port 5\n"


def test_sshd_history_is_read_from_the_saved_mark(tmp_path: Path) -> None:
    now = time.time()
    log = tmp_path / "auth.log"
    log.write_text(stamped(now - 7200, "before") + stamped(now - 3600, "after"))
    cfg = SshMonitorConfig(auth_log=str(log), sniff_traffic=False)

    fresh = LogManager("ssh", None)
    assert next(_auth_events(fresh, SshState({}), cfg)).user == "before"

    resumed = LogManager("ssh", None)
    resumed.set_mark(SSHD_LOG, now - 7200)
    assert next(_auth_events(resumed, SshState({}), cfg)).user == "after"
