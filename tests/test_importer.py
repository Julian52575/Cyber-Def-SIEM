import gzip
import json
import time
from pathlib import Path

import pytest

from my_siem.clock import HOUR, hour_start, local
from my_siem.detect import RateDetector
from my_siem.http.command import HttpConfig, HttpWatcher
from my_siem.http.command import count_keys as http_keys
from my_siem.http.command import import_source as http_source
from my_siem.http.command import new_state as http_state
from my_siem.http.wire import parse_request
from my_siem.logs import LogManager, Retention, Window
from my_siem.logs.files import add_to_closed_hour, list_logs, log_name
from my_siem.logs.importer import IMPORTED, ImportBusy, Importer, ImportJob, import_span
from my_siem.logs.reader import FileReader
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.monitor import SshMonitorConfig, new_state, report_auth
from my_siem.ssh.monitor import import_source as ssh_source

KEEP = Retention(max_age_days=100, max_size_mb=100)
# Fixed for the whole test, so the current hour cannot change halfway through.
NOW = time.time()
HOUR_NOW = hour_start(NOW)
T1 = HOUR_NOW - 2 * HOUR + 60  # two closed hours back
T2 = HOUR_NOW - HOUR + 120  # the last closed hour


def clock() -> float:
    return NOW


def sshd(at: float, msg: str, pid: int = 100) -> str:
    return f"{local(at).isoformat()} host sshd[{pid}]: {msg}\n"


def access(at: float, ip: str, request: str, status: int) -> str:
    stamp = local(at).strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{stamp}] "{request}" {status} 12 "-" "curl/8.5"\n'


def records(logs: LogManager) -> list[dict[str, object]]:
    assert logs.folder is not None
    out = []
    for f in list_logs(logs.folder, logs.command):
        opener = gzip.open if f.compressed else open
        with opener(f.path, "rt") as lines:
            out += [r for r in map(json.loads, lines) if "event_name" in r]
    return out


def wait(job: ImportJob) -> ImportJob:
    deadline = time.monotonic() + 5
    while job.state == "running":
        assert time.monotonic() < deadline, "import still running"
        time.sleep(0.01)
    return job


@pytest.fixture
def ssh(tmp_path: Path) -> tuple[LogManager, Importer, Path]:
    auth = tmp_path / "auth.log"
    auth.write_text(
        sshd(T1, "Failed password for root from 203.0.113.9 port 4242 ssh2")
        + sshd(T1 + 1, "Failed password for root from 203.0.113.9 port 4243 ssh2")
        + sshd(T2, "Accepted publickey for alice from 10.0.0.5 port 50122 ssh2")
        # The current hour belongs to the running command: never imported.
        + sshd(HOUR_NOW, "Accepted publickey for bob from 10.0.0.6 port 50123 ssh2")
    )
    logs = LogManager("ssh", tmp_path / "logs" / "ssh", KEEP, clock=clock)
    cfg = SshMonitorConfig(auth_log=str(auth), fail_threshold=2)
    return logs, Importer({"ssh": logs}, {"ssh": ssh_source(cfg)}, clock), auth


def test_ssh_import_writes_closed_hours_with_alerts_and_counts(
    ssh: tuple[LogManager, Importer, Path],
) -> None:
    logs, importer, _ = ssh

    [report] = wait(importer.start(["ssh"], "hour", 3)).reports

    assert report.error is None
    assert (report.events, report.new, report.hours) == (4, 4, 2)
    names = sorted(str(r["event_name"]) for r in records(logs))
    assert names == [
        "siem.alert.ssh_bruteforce",
        "siem.ssh.login_failure",
        "siem.ssh.login_failure",
        "siem.ssh.login_success",
    ]
    assert all(r["attributes"][IMPORTED] for r in records(logs))  # type: ignore[index]
    assert logs.folder is not None
    closed = [f for f in list_logs(logs.folder, "ssh") if f.hour < HOUR_NOW]
    assert [f.hour for f in closed] == [hour_start(T1), hour_start(T2)]
    assert all(f.compressed for f in closed)
    totals = logs.counts(Window("hour", 3))
    assert sum(b.counts.get("siem.ssh.login_failure", 0) for b in totals) == 2
    assert sum(b.counts.get("alerts", 0) for b in totals) == 1
    [login] = logs.recent(("siem.ssh.login_success",), Window("hour", 3))
    assert login["attributes"]["user.name"] == "alice"


def test_importing_twice_writes_nothing_more(
    ssh: tuple[LogManager, Importer, Path],
) -> None:
    logs, importer, _ = ssh
    wait(importer.start(["ssh"], "hour", 3))
    before = len(records(logs))

    [again] = wait(importer.start(["ssh"], "hour", 3)).reports

    assert (again.events, again.new, again.hours) == (4, 0, 0)
    assert len(records(logs)) == before


def test_events_the_command_already_logged_are_skipped(
    ssh: tuple[LogManager, Importer, Path],
) -> None:
    logs, importer, _ = ssh
    # As ssh's startup catch-up does: an old event, into the current hour's file.
    state = new_state(SshMonitorConfig())
    failure = AuthEvent(
        AuthKind.LOGIN_FAILURE, "root", "203.0.113.9", 4242, 100, "password", T1
    )
    report_auth(logs.out, state, failure, RateDetector(99, 60))

    [report] = importer.estimate(["ssh"], "hour", 3).reports

    assert (report.events, report.new) == (4, 3)


def test_estimate_measures_without_writing(
    ssh: tuple[LogManager, Importer, Path],
) -> None:
    logs, importer, _ = ssh

    job = importer.estimate(["ssh"], "hour", 3)

    [report] = job.reports
    assert job.state == "done"
    assert report.new == 4
    assert 0 < report.gz_bytes < report.raw_bytes
    assert records(logs) == []
    assert importer.job is None


def test_a_span_shorter_than_the_events_leaves_the_older_ones(
    ssh: tuple[LogManager, Importer, Path],
) -> None:
    _, importer, _ = ssh

    [report] = importer.estimate(["ssh"], "hour", 1).reports

    assert (report.events, report.new) == (1, 1)  # alice's login only


def test_an_unreadable_source_is_reported_not_raised(
    ssh: tuple[LogManager, Importer, Path],
) -> None:
    _, importer, auth = ssh
    auth.unlink()

    job = wait(importer.start(["ssh"], "hour", 3))

    assert job.state == "failed"
    assert "auth.log" in str(job.reports[0].error)


def test_one_import_at_a_time(ssh: tuple[LogManager, Importer, Path]) -> None:
    _, importer, _ = ssh
    importer.job = ImportJob(import_span("hour", 1, NOW), [], NOW)

    with pytest.raises(ImportBusy):
        importer.start(["ssh"], "hour", 1)


def test_bad_requests_are_refused(ssh: tuple[LogManager, Importer, Path]) -> None:
    _, importer, _ = ssh

    for commands, unit, count in [
        ([], "hour", 1),
        (["dummy"], "hour", 1),
        (["ssh"], "minute", 1),
        (["ssh"], "hour", 25),
        (["ssh"], "day", 101),
    ]:
        with pytest.raises(ValueError):
            importer.estimate(commands, unit, count)


def test_days_stop_at_the_retention_age(tmp_path: Path) -> None:
    logs = LogManager("ssh", tmp_path, Retention(max_age_days=7, max_size_mb=1))

    assert Importer({"ssh": logs}, {}).max_count("day") == 7
    assert Importer({"ssh": logs}, {}).max_count("hour") == 24


def test_commands_without_log_files_cannot_import(tmp_path: Path) -> None:
    logs = LogManager("ssh", None)
    source = ssh_source(SshMonitorConfig(auth_log=str(tmp_path / "auth.log")))

    assert Importer({"ssh": logs}, {"ssh": source}).sources == {}


def test_http_import_skips_hours_the_sniffer_watched(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        access(T1, "203.0.113.9", "GET /a HTTP/1.1", 200)
        + access(T2, "203.0.113.9", "GET /.env HTTP/1.1", 404)
    )
    logs = LogManager("http", tmp_path / "logs", KEEP, http_keys, clock=clock)
    cfg = HttpConfig(access_log=str(log))
    req = parse_request(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
    assert req is not None
    HttpWatcher(logs.out, http_state(cfg), cfg).report_request(
        req, ("203.0.113.9", 5555), ("10.0.0.1", 80), T1
    )
    importer = Importer({"http": logs}, {"http": http_source(cfg)}, clock)

    [report] = wait(importer.start(["http"], "hour", 3)).reports

    assert report.skipped_hours == 1
    # The request, its response, and the alert for the .env probe.
    assert report.new == 3
    imported = [r for r in records(logs) if IMPORTED in r["attributes"]]  # type: ignore[operator]
    assert {r["event_name"] for r in imported} == {
        "siem.http.request",
        "siem.http.response",
        "siem.alert.http_suspicious_request",
    }
    request = next(r for r in imported if r["event_name"] == "siem.http.request")
    assert request["body"] == "GET /.env from 203.0.113.9"
    assert "client.port" not in request["attributes"]  # type: ignore[operator]
    totals = logs.counts(Window("hour", 3))
    assert sum(b.counts.get("status:4xx", 0) for b in totals) == 1


def test_records_added_to_a_gzipped_hour_are_read(tmp_path: Path) -> None:
    hour = HOUR_NOW - HOUR

    def line(user: str, at: float) -> bytes:
        stamp = local(at).isoformat()
        r = {"timestamp": stamp, "event_name": "siem.ssh.login_success", "body": user}
        return (json.dumps(r, separators=(",", ":")) + "\n").encode()

    add_to_closed_hour(
        tmp_path, "ssh", hour, b'{"resource":{}}\n' + line("a", hour + 1)
    )
    reader = FileReader(tmp_path, "ssh")
    assert [r["body"] for r in reader.recent(("siem.ssh.",), hour)] == ["a"]

    add_to_closed_hour(tmp_path, "ssh", hour, line("b", hour + 2))

    assert [r["body"] for r in reader.recent(("siem.ssh.",), hour)] == ["b", "a"]
    assert [f.name for f in tmp_path.iterdir()] == [log_name("ssh", hour) + ".gz"]


def test_a_closed_hour_not_gzipped_yet_is_appended_to(tmp_path: Path) -> None:
    hour = HOUR_NOW - HOUR
    plain = tmp_path / log_name("ssh", hour)
    plain.write_text('{"cut short')

    add_to_closed_hour(tmp_path, "ssh", hour, b'{"event_name":"x"}\n')

    assert plain.read_text() == '{"cut short\n{"event_name":"x"}\n'
