import http.client
import time
from typing import Any

from fastapi.testclient import TestClient

from my_siem.api import ApiServer, create_app
from my_siem.dummy.command import DummyConfig, DummyState
from my_siem.http.command import HttpState
from my_siem.http.wire import parse_request
from my_siem.https.command import HttpsState
from my_siem.https.tls import ClientHello, Opening
from my_siem.main import COMMANDS
from my_siem.net import Connection, ConnEvent, ConnKind
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.state import SshState
from my_siem.web import History, sse
from my_siem.web.charts import Series, line_chart, nice_ticks
from my_siem.web.sections import (
    SECTIONS,
    http_metrics,
    per_sample,
    ssh_metrics,
    top_counts,
    top_failed_ips,
)

HOSTS = ["testserver"]
XSS = "<script>alert(1)</script>"


def busy_state() -> SshState:
    state = SshState({"ports": [22]})
    state.source("sshd_log", "running", "/var/log/auth.log")
    state.source("network", "failed", "no CAP_NET_RAW")
    state.auth(
        AuthEvent(AuthKind.INVALID_USER, XSS, "203.0.113.9", 4242, 90, None), 1.0
    )
    state.auth(
        AuthEvent(AuthKind.LOGIN_FAILURE, "root", "203.0.113.9", 4243, 91, "password"),
        2.0,
    )
    conn = Connection("10.0.0.5", 50122, "10.0.0.1", 22, started=100.0)
    state.conn(ConnEvent(ConnKind.OPENED, conn, 100.0))
    return state


def test_root_redirects_to_the_running_command() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    res = client.get("/", follow_redirects=False)

    assert res.status_code == 307
    assert res.headers["location"] == "/ui/ssh"


def test_ssh_page_shows_the_live_state() -> None:
    client = TestClient(create_app({"ssh": busy_state().snapshot}, HOSTS))

    res = client.get("/ui/ssh")

    assert res.status_code == 200
    assert 'data-stream="/ui/ssh/stream"' in res.text
    for shown in (
        "sshd logs",
        "Network sniffer",
        "no CAP_NET_RAW",
        "10.0.0.5",
        "10.0.0.1:22",
    ):
        assert shown in res.text


def test_attacker_controlled_usernames_are_escaped() -> None:
    client = TestClient(create_app({"ssh": busy_state().snapshot}, HOSTS))

    res = client.get("/ui/ssh")

    assert XSS not in res.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in res.text
    assert "script-src 'self'" in res.headers["content-security-policy"]


def test_one_tab_per_running_command_in_the_given_order() -> None:
    snapshots = {
        "dummy": DummyState(DummyConfig()).snapshot,
        "ssh": SshState({}).snapshot,
    }
    client = TestClient(create_app(snapshots, HOSTS))

    page = client.get("/ui/dummy").text

    assert client.get("/", follow_redirects=False).headers["location"] == "/ui/dummy"
    assert page.index('href="/ui/dummy"') < page.index('href="/ui/ssh"')
    assert 'data-stream="/ui/dummy/stream"' in page
    assert "Port scan" in page


def test_only_running_commands_have_a_tab() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    assert 'href="/ui/dummy"' not in client.get("/ui/ssh").text
    assert client.get("/ui/dummy").status_code == 404
    assert client.get("/dummy").status_code == 404
    assert client.get("/ui/nowhere").status_code == 404


def test_every_command_has_a_section() -> None:
    assert SECTIONS.keys() == COMMANDS.keys()


def test_static_assets_are_served() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    assert "EventSource" in client.get("/static/live.js").text
    assert client.get("/static/style.css").status_code == 200


def test_history_keeps_the_last_samples_of_each_section() -> None:
    state = busy_state()
    client = TestClient(create_app({"ssh": state.snapshot}, HOSTS, every=0.01))

    # The context manager runs the lifespan, which starts the sampler.
    with client:
        time.sleep(0.1)
        page = client.get("/ui/ssh").text

    assert "No data yet." not in page.split("Authentication outcomes")[0]


def test_history_records_metrics_not_whole_snapshots() -> None:
    history = History(busy_state().snapshot, ssh_metrics)

    history.record()

    [(_, metrics)] = history.samples
    assert metrics == {"active": 1, "conn_opened": 1, "failed": 2, "alerts": 0}


def test_per_sample_marks_restarts_as_unknown() -> None:
    assert per_sample([3, 5, 5, 1, 4]) == [None, 2, 0, None, 3]


def test_top_failed_ips_ranks_addresses() -> None:
    logins: list[dict[str, Any]] = [
        {"kind": "login_failure", "ip": "a"},
        {"kind": "invalid_user", "ip": "b"},
        {"kind": "login_failure", "ip": "b"},
        {"kind": "login_success", "ip": "a"},
    ]
    assert top_failed_ips(logins) == [("b", 2), ("a", 1)]


def test_nice_ticks_use_round_steps() -> None:
    assert nice_ticks(0) == [0, 0.5, 1]
    assert nice_ticks(37) == [0, 10, 20, 30, 40]


def test_line_chart_breaks_the_line_on_unknown_points() -> None:
    chart = line_chart(
        "t", "", ["a", "b", "c"], [Series("s", "red", [None, 1, 2])], str
    )

    [series] = chart["series"]
    assert series["d"].count("M") == 1
    assert chart["table"]["rows"][0] == ["a", "–"]


def test_sse_frames_every_line() -> None:
    assert sse("update", "<p>\n</p>") == "event: update\ndata: <p>\ndata: </p>\n\n"


def test_stream_pushes_rendered_sections() -> None:
    app = create_app({"ssh": busy_state().snapshot}, ["127.0.0.1"], every=0.05)
    server = ApiServer(app, "127.0.0.1", 0)
    server.start()
    try:
        host, port = server.socket.getsockname()[:2]
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/ui/ssh/stream")
        res = conn.getresponse()
        assert res.status == 200
        assert res.getheader("content-type", "").startswith("text/event-stream")

        lines = [res.readline().decode() for _ in range(4)]
        conn.close()
    finally:
        server.stop()

    assert lines[0].startswith("retry: ")
    assert lines[2] == "event: update\n"
    assert lines[3].startswith("data: ")


def busy_http_state() -> HttpState:
    state = HttpState({"ports": [3000]})
    state.source("network", "running", "ports 3000")
    req = parse_request(
        f"GET /q?{XSS} HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: {XSS}\r\n\r\n".encode()
    )
    assert req is not None
    state.request(req, ("203.0.113.9", 4242), ("10.0.0.1", 3000), ["xss"], 1.0)
    state.response(404)
    conn = Connection("203.0.113.9", 4242, "10.0.0.1", 3000, started=100.0)
    state.conn(ConnEvent(ConnKind.OPENED, conn, 100.0))
    return state


def busy_https_state() -> HttpsState:
    state = HttpsState({"ports": [443]})
    conn = Connection("203.0.113.9", 4242, "10.0.0.1", 443, started=100.0)
    state.conn(ConnEvent(ConnKind.OPENED, conn, 100.0))
    state.handshake(Opening.HELLO, ClientHello(0x0304, XSS, ("h2",)), conn, 100.1)
    state.handshake(Opening.PLAINTEXT_HTTP, None, conn, 100.2)
    return state


def test_http_page_shows_requests_with_attacker_data_escaped() -> None:
    client = TestClient(create_app({"http": busy_http_state().snapshot}, HOSTS))

    res = client.get("/ui/http")

    assert res.status_code == 200
    for shown in ("Recent requests", "shop.test", "203.0.113.9:4242", "4xx", "xss"):
        assert shown in res.text
    assert "Active HTTP connections" in res.text
    assert XSS not in res.text
    assert client.get("/http").json()["status_classes"] == {"4xx": 1}


def test_https_page_shows_handshakes_with_server_names_escaped() -> None:
    client = TestClient(create_app({"https": busy_https_state().snapshot}, HOSTS))

    res = client.get("/ui/https")

    assert res.status_code == 200
    for shown in ("TLS 1.3", "Plaintext HTTP", "h2", "Active HTTPS connections"):
        assert shown in res.text
    assert XSS not in res.text
    assert "&lt;script&gt;" in res.text


def test_http_metrics_count_error_responses() -> None:
    metrics = http_metrics(busy_http_state().snapshot())
    assert metrics == {"active": 1, "requests": 1, "errors": 1, "suspicious": 1}


def test_top_counts_skips_empty_values() -> None:
    rows: list[dict[str, Any]] = [{"h": "a"}, {"h": None}, {"h": "b"}, {"h": "a"}]
    assert top_counts(rows, "h") == [("a", 2), ("b", 1)]
