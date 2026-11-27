import json
import socket
import threading
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter

from my_siem import main as cli
from my_siem.api import ApiServer, create_app
from my_siem.detect import RateDetector
from my_siem.net import Connection, ConnEvent, ConnKind
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.monitor import SshMonitorConfig, new_state, report_auth, report_conn
from my_siem.ssh.state import SshState
from my_siem.telemetry import EventLogger, event_logger, make_provider

HOSTS = ["testserver"]


def test_ssh_endpoint_reports_logins_connections_and_alerts() -> None:
    state = new_state(SshMonitorConfig(ports=frozenset({22, 2222})))
    out = event_logger(make_provider([InMemoryLogRecordExporter()]), "test")
    failures = RateDetector(2, 60)
    bad = AuthEvent(AuthKind.LOGIN_FAILURE, "root", "203.0.113.9", 4242, 90, "password")
    for t in (0, 1):
        report_auth(out, state, bad, failures, now=t)
    kept = Connection("10.0.0.5", 50122, "10.0.0.1", 22, started=100.0)
    gone = Connection("10.0.0.6", 50123, "10.0.0.1", 22, started=100.0)
    openings = RateDetector(99, 60)
    for event in (
        ConnEvent(ConnKind.OPENED, kept, 100.0),
        ConnEvent(ConnKind.OPENED, gone, 100.0),
        ConnEvent(ConnKind.CLOSED, gone, 110.0),
    ):
        report_conn(out, state, event, openings)

    client = TestClient(create_app({"ssh": state.snapshot}, HOSTS))
    body = client.get("/ssh").json()

    assert body["config"]["ports"] == [22, 2222]
    assert body["counts"] == {
        "login_failure": 2,
        "alerts": 1,
        "conn_opened": 2,
        "conn_closed": 1,
    }
    [active] = body["active_connections"]
    assert active["client_ip"] == "10.0.0.5"
    assert active["started"].startswith("1970-01-01T00:01:40")
    assert body["recent_logins"][0]["user"] == "root"
    assert body["recent_alerts"][0]["name"] == "ssh_bruteforce"


def test_healthz_only_answers_allowed_hosts() -> None:
    client = TestClient(
        create_app({"ssh": SshState({}).snapshot}, ["localhost", "::1"])
    )

    ok = client.get("http://localhost:8080/healthz")
    v6 = client.get("http://[::1]:8080/healthz")
    rebound = client.get("http://evil.example/healthz")

    assert ok.json() == {"status": "ok", "commands": ["ssh"]}
    assert v6.status_code == 200
    assert rebound.status_code == 400


def test_every_route_is_read_only() -> None:
    app = create_app({"ssh": SshState({}).snapshot}, HOSTS)

    for route in app.routes:
        assert getattr(route, "methods", set()) <= {"GET", "HEAD"}, route


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "path", ["/ssh", "/healthz", "/docs", "/ui/ssh", "/ui/ssh/stream", "/nowhere"]
)
def test_writes_are_refused_everywhere(method: str, path: str) -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    res = client.request(method, path)

    assert res.status_code == 405
    assert res.json() == {"detail": "read-only API"}


def test_api_flag_serves_the_running_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bodies: list[dict[str, object]] = []
    stop = threading.Event()

    def fake_run(out: EventLogger, cfg: SshMonitorConfig, state: SshState) -> None:
        log = tmp_path / "logs" / "ssh" / "ssh.jsonl"
        started = [json.loads(line) for line in log.read_text().splitlines()][-1]
        url = started["attributes"]["url.full"]
        with urllib.request.urlopen(f"{url}ssh", timeout=5) as res:
            bodies.append(json.load(res))
        stop.set()

    monkeypatch.setitem(cli.COMMANDS, "ssh", replace(cli.COMMANDS["ssh"], run=fake_run))
    cli.main(["--path", str(tmp_path), "--api", "--api-port", "0", "ssh"])

    assert stop.is_set()
    assert bodies[0]["config"]["window"] == 60.0  # type: ignore[index]


def test_busy_api_port_stops_with_an_error(tmp_path: Path) -> None:
    with socket.create_server(("127.0.0.1", 0)) as busy:
        port = busy.getsockname()[1]
        with pytest.raises(SystemExit, match="cannot serve the API"):
            cli.main(["--path", str(tmp_path), "--api-port", str(port), "--api", "ssh"])


def test_bad_api_port_flag_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--path", str(tmp_path), "--api", "--api-port", "70000", "ssh"])
    assert exc.value.code == 2


def test_unwritable_log_with_api_fails_with_a_plain_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A directory where the log file should be: opening it fails like a permission error.
    (tmp_path / "logs" / "ssh" / "ssh.jsonl").mkdir(parents=True)

    with pytest.raises(SystemExit, match="cannot open log file") as exc:
        cli.main(["--path", str(tmp_path), "--api", "--api-port", "0", "ssh"])

    assert exc.value.__context__ is not None  # the OSError, not a cleanup failure
    assert isinstance(exc.value.__context__, OSError)


def test_api_server_stops_even_if_never_started() -> None:
    server = ApiServer(
        create_app({"ssh": SshState({}).snapshot}, HOSTS), "127.0.0.1", 0
    )

    server.stop()

    assert server.socket.fileno() == -1
