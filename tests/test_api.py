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
from my_siem.api import create_app
from my_siem.detect import RateDetector
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.monitor import SshMonitorConfig, new_state, report_auth, report_conn
from my_siem.ssh.net import Connection, ConnEvent, ConnKind
from my_siem.ssh.state import SshState
from my_siem.telemetry import EventLogger, event_logger, make_provider


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

    client = TestClient(create_app("ssh", state.snapshot, []))
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


def test_healthz_and_cors_only_for_listed_origins() -> None:
    app = create_app("ssh", SshState({}).snapshot, ["http://localhost:3000"])
    client = TestClient(app)

    ok = client.get("/healthz", headers={"Origin": "http://localhost:3000"})
    other = client.get("/healthz", headers={"Origin": "http://evil.example"})

    assert ok.json() == {"status": "ok", "command": "ssh"}
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in other.headers


def test_every_route_is_read_only() -> None:
    app = create_app("ssh", SshState({}).snapshot, [])

    for route in app.routes:
        assert getattr(route, "methods", set()) <= {"GET", "HEAD"}, route


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", ["/ssh", "/healthz", "/docs", "/nowhere"])
def test_writes_are_refused_everywhere(method: str, path: str) -> None:
    client = TestClient(create_app("ssh", SshState({}).snapshot, []))

    res = client.request(method, path)

    assert res.status_code == 405
    assert res.json() == {"detail": "read-only API"}


def test_cors_preflight_still_works() -> None:
    app = create_app("ssh", SshState({}).snapshot, ["http://localhost:3000"])
    res = TestClient(app).options(
        "/ssh",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert res.status_code == 200
    assert res.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_api_flag_serves_the_running_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bodies: list[dict[str, object]] = []
    stop = threading.Event()

    def fake_run(out: EventLogger, cfg: SshMonitorConfig, state: SshState) -> None:
        log = tmp_path / "logs" / "ssh" / "ssh.jsonl"
        started = [json.loads(line) for line in log.read_text().splitlines()][-1]
        url = started["attributes"]["url.full"]
        with urllib.request.urlopen(url, timeout=5) as res:
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
