import asyncio
import http.client
import time
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from my_siem.api import ApiServer, create_app
from my_siem.detect import RateDetector
from my_siem.dummy.command import DummyConfig, DummyState
from my_siem.http import command as http_command
from my_siem.http.command import HttpConfig, HttpState, HttpWatcher
from my_siem.http.wire import parse_request
from my_siem.https import command as https_command
from my_siem.https.command import HttpsConfig, HttpsState, HttpsWatcher
from my_siem.https.tls import ClientHello, Opening
from my_siem.logs import LogManager
from my_siem.main import COMMANDS
from my_siem.net import Connection, ConnEvent, ConnKind
from my_siem.ssh.log import AuthEvent, AuthKind
from my_siem.ssh.monitor import report_auth
from my_siem.ssh.state import SshState
from my_siem.web import History, ui_window
from my_siem.web.charts import Series, line_chart, nice_ticks
from my_siem.web.help import command_help, render
from my_siem.web.sections import (
    SECTIONS,
    active_metrics,
    top_counts,
    top_failed_ips,
)

HOSTS = ["testserver"]
XSS = "<script>alert(1)</script>"


def busy_ssh() -> tuple[SshState, LogManager]:
    """Logged through the monitor's own code, into an in-memory LogManager."""
    state = SshState({"ports": [22]})
    logs = LogManager("ssh", None)
    state.source("sshd_log", "running", "/var/log/auth.log")
    state.source("network", "failed", "no CAP_NET_RAW")
    failures = RateDetector(5, 60)
    now = time.time()
    for event in (
        AuthEvent(AuthKind.INVALID_USER, XSS, "203.0.113.9", 4242, 90, None, now - 2),
        AuthEvent(
            AuthKind.LOGIN_FAILURE, "root", "203.0.113.9", 4243, 91, "password", now - 1
        ),
    ):
        report_auth(logs.out, state, event, failures)
    conn = Connection("10.0.0.5", 50122, "10.0.0.1", 22, started=100.0)
    state.conn(ConnEvent(ConnKind.OPENED, conn, 100.0))
    return state, logs


def busy_state() -> SshState:
    return busy_ssh()[0]


def app_of(name: str, state: Any, logs: LogManager, **kw: Any) -> FastAPI:
    return create_app({name: state.snapshot}, HOSTS, logs={name: logs}, **kw)


def ssh_app(**kw: Any) -> FastAPI:
    return app_of("ssh", *busy_ssh(), **kw)


def test_root_serves_the_first_command_without_redirect() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    res = client.get("/", follow_redirects=False)

    assert res.status_code == 200
    assert 'data-fragment="./ui/ssh/fragment"' in res.text


@pytest.mark.parametrize(
    ("page", "root"),
    [("/", "./"), ("/ui/ssh", "../"), ("/ui/ssh?root=https://evil/", "../")],
)
def test_links_are_relative_so_a_proxy_prefix_works(page: str, root: str) -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    html = client.get(page).text

    assert f'href="{root}static/style.css?v=' in html
    assert f'src="{root}static/live.js?v=' in html
    assert f'href="{root}ui/ssh?unit=minute&amp;count=60"' in html
    assert "evil" not in html


def test_ssh_page_shows_the_live_state_and_the_logged_logins() -> None:
    client = TestClient(ssh_app())

    res = client.get("/ui/ssh")

    assert res.status_code == 200
    assert 'data-fragment="../ui/ssh/fragment"' in res.text
    for shown in (
        "sshd logs",
        "Network sniffer",
        "no CAP_NET_RAW",
        "10.0.0.5",
        "10.0.0.1:22",
        "203.0.113.9:4243",
        "Failed login",
    ):
        assert shown in res.text


def test_attacker_controlled_usernames_are_escaped() -> None:
    client = TestClient(ssh_app())

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

    assert 'data-fragment="./ui/dummy/fragment"' in client.get("/").text
    assert page.index('href="../ui/dummy?') < page.index('href="../ui/ssh?')
    assert 'data-fragment="../ui/dummy/fragment"' in page
    assert "Detections by rule" in page


def test_only_running_commands_have_a_tab() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    assert 'href="../ui/dummy' not in client.get("/ui/ssh").text
    assert client.get("/ui/dummy").status_code == 404
    assert client.get("/dummy").status_code == 404
    assert client.get("/ui/nowhere").status_code == 404


def test_every_command_has_a_section() -> None:
    assert SECTIONS.keys() == COMMANDS.keys()


def test_static_assets_are_served() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    assert "data-fragment" in client.get("/static/live.js").text
    assert client.get("/static/style.css").status_code == 200


def test_history_keeps_the_last_samples_of_each_section() -> None:
    client = TestClient(ssh_app(every=0.01))

    # The context manager runs the lifespan, which starts the sampler.
    with client:
        time.sleep(0.1)
        page = client.get("/ui/ssh").text

    assert "No data yet." not in page.split("Authentication outcomes")[0]


def test_history_records_metrics_not_whole_snapshots() -> None:
    history = History(busy_state().snapshot, active_metrics)

    history.record()

    [(_, metrics)] = history.samples
    assert metrics == {"active": 1}


def test_history_samples_on_wall_clock_boundaries() -> None:
    history = History(busy_state().snapshot, active_metrics)

    async def sample_twice() -> None:
        task = asyncio.create_task(history.run(0.05))
        while len(history.samples) < 2:
            await asyncio.sleep(0.01)
        task.cancel()

    asyncio.run(sample_twice())

    for at, _ in history.samples:
        assert round(at / 0.05, 6).is_integer()


def test_top_failed_ips_ranks_addresses() -> None:
    logins: list[dict[str, Any]] = [
        {"failed": True, "ip": "a"},
        {"failed": True, "ip": "b"},
        {"failed": True, "ip": "b"},
        {"failed": False, "ip": "a"},
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


def test_fragment_is_a_complete_response_a_proxy_can_forward() -> None:
    state, logs = busy_ssh()
    app = create_app(
        {"ssh": state.snapshot}, ["127.0.0.1"], every=0.05, logs={"ssh": logs}
    )
    server = ApiServer(app, "127.0.0.1", 0)
    server.start()
    try:
        host, port = server.socket.getsockname()[:2]
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/ui/ssh/fragment")
        res = conn.getresponse()
        body = res.read().decode()
        conn.close()
    finally:
        server.stop()

    assert res.status == 200
    assert res.getheader("content-length") == str(len(body.encode()))
    assert res.getheader("cache-control") == "no-store"
    assert "10.0.0.5" in body
    assert "<html" not in body


def test_page_offers_refresh_rates_and_preselects_the_sampling_one() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    html = client.get("/ui/ssh").text

    for s in (1, 2, 5, 10, 15, 30, 60):
        assert f'<option value="{s}"' in html
    assert '<option value="5" selected>' in html
    assert html.count(" selected>") == 1


def test_fragment_of_an_unknown_section_is_404() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    assert client.get("/ui/nope/fragment").status_code == 404


def busy_http() -> tuple[HttpState, LogManager]:
    state = HttpState({"ports": [80]})
    logs = LogManager("http", None, keys=http_command.count_keys)
    watcher = HttpWatcher(logs.out, state, HttpConfig())
    state.source("network", "running", "ports 80")
    req = parse_request(
        f"GET /q?{XSS} HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: {XSS}\r\n\r\n".encode()
    )
    assert req is not None
    now = time.time()
    watcher.report_request(req, ("203.0.113.9", 4242), ("10.0.0.1", 80), now)
    watcher.report_response(404, ("203.0.113.9", 4242), ("10.0.0.1", 80), now)
    conn = Connection("203.0.113.9", 4242, "10.0.0.1", 80, started=100.0)
    state.conn(ConnEvent(ConnKind.OPENED, conn, 100.0))
    return state, logs


def busy_https() -> tuple[HttpsState, LogManager]:
    state = HttpsState({"ports": [443]})
    logs = LogManager("https", None, keys=https_command.count_keys)
    watcher = HttpsWatcher(logs.out, state, HttpsConfig())
    conn = Connection("203.0.113.9", 4242, "10.0.0.1", 443, started=100.0)
    state.conn(ConnEvent(ConnKind.OPENED, conn, 100.0))
    now = time.time()
    watcher.report(Opening.HELLO, ClientHello(0x0304, XSS, ("h2",)), conn, now)
    watcher.report(Opening.PLAINTEXT_HTTP, None, conn, now)
    return state, logs


def test_http_page_shows_requests_with_attacker_data_escaped() -> None:
    client = TestClient(app_of("http", *busy_http()))

    res = client.get("/ui/http")

    assert res.status_code == 200
    for shown in ("Recent requests", "shop.test", "203.0.113.9:4242", "4xx", "xss"):
        assert shown in res.text
    assert "Active HTTP connections" in res.text
    assert XSS not in res.text
    body = client.get("/http").json()
    assert body["status_classes"] == {"4xx": 1}
    assert body["window"]["totals"]["status:4xx"] == 1
    assert body["window"]["totals"]["rule:xss"] == 1


def test_https_page_shows_handshakes_with_server_names_escaped() -> None:
    client = TestClient(app_of("https", *busy_https()))

    res = client.get("/ui/https")

    assert res.status_code == 200
    for shown in ("TLS 1.3", "Plaintext HTTP", "h2", "Active HTTPS connections"):
        assert shown in res.text
    assert XSS not in res.text
    assert "&lt;script&gt;" in res.text


def test_top_counts_skips_empty_values() -> None:
    rows: list[dict[str, Any]] = [{"h": "a"}, {"h": None}, {"h": "b"}, {"h": "a"}]
    assert top_counts(rows, "h") == [("a", 2), ("b", 1)]


@pytest.mark.parametrize("command", list(COMMANDS))
def test_every_command_has_a_readme(command: str) -> None:
    assert command_help(command) is not None


def test_page_opens_the_command_readme_from_a_help_button() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    page = client.get("/ui/ssh").text

    assert 'popovertarget="help"' in page
    assert 'id="help"' in page and "popover" in page
    assert "what it reads and how</h1>" in page
    assert "<table>" in page


def test_help_keeps_external_links_and_unlinks_repo_paths() -> None:
    html = render("[main](../../README.md) [up](#top) [ext](https://example.com)")

    assert "../../README.md" not in html and "main" in html
    assert 'href="#top"' in html
    assert 'href="https://example.com"' in html


def test_help_escapes_raw_html() -> None:
    assert XSS not in render(XSS)


def test_asset_urls_change_with_their_content() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    page = client.get("/ui/ssh").text
    version = page.split("static/style.css?v=", 1)[1].split('"', 1)[0]

    assert f"static/live.js?v={version}" in page
    assert client.get(f"/static/style.css?v={version}").status_code == 200


def test_page_is_dark_by_default_and_follows_the_theme_cookie() -> None:
    client = TestClient(create_app({"ssh": SshState({}).snapshot}, HOSTS))

    assert '<html lang="en" data-theme="dark">' in client.get("/ui/ssh").text
    assert 'id="theme-toggle"' in client.get("/").text

    client.cookies.set("my_siem_theme", "light")
    assert 'data-theme="light"' in client.get("/ui/ssh").text
    assert 'data-theme="light"' in client.get("/").text

    client.cookies.set("my_siem_theme", '"><script>')
    assert 'data-theme="dark"' in client.get("/ui/ssh").text


def test_page_offers_the_three_window_units_and_keeps_the_window_in_tab_links() -> None:
    client = TestClient(ssh_app())

    page = client.get("/ui/ssh?unit=hour&count=3").text

    for unit, max_ in (("minute", 60), ("hour", 24), ("day", 100)):
        assert f'value="{unit}" data-max="{max_}"' in page
    assert 'value="hour" data-max="24" checked' in page
    assert 'id="window-slider" min="1" max="24" value="3"' in page
    # The number field is what the form sends, so typing works without JavaScript.
    assert 'id="window-count" name="count" min="1" max="24" value="3"' in page
    assert 'href="../ui/ssh?unit=hour&amp;count=3"' in page
    assert "Last 3 hours, since" in page


@pytest.mark.parametrize(
    ("unit", "count", "expected"),
    [
        (None, None, ("minute", 60)),
        ("day", 500, ("day", 100)),
        ("day", 0, ("day", 1)),
        ("week", 2, ("minute", 2)),
    ],
)
def test_pages_forgive_a_bad_window(
    unit: str | None, count: int | None, expected: tuple[str, int]
) -> None:
    w = ui_window(unit, count)
    assert (w.unit, w.count) == expected


def test_fragment_shows_only_what_happened_in_its_window() -> None:
    state, logs = busy_ssh()
    old = time.time() - 3 * 3600
    report_auth(
        logs.out,
        state,
        AuthEvent(AuthKind.LOGIN_SUCCESS, "olduser", "198.51.100.7", 1, 1, "key", old),
        RateDetector(5, 60),
    )
    client = TestClient(app_of("ssh", state, logs))

    assert "olduser" not in client.get("/ui/ssh/fragment?unit=hour&count=1").text
    assert "olduser" in client.get("/ui/ssh/fragment?unit=hour&count=4").text


def test_json_api_serves_the_window_strictly() -> None:
    client = TestClient(ssh_app())

    body = client.get("/ssh?unit=hour&count=2").json()

    assert body["window"]["unit"] == "hour"
    assert len(body["window"]["buckets"]) == 2
    assert body["window"]["totals"]["siem.ssh.login_failure"] == 1
    [newest, older] = body["window"]["events"]["logins"]
    assert newest["event_name"] == "siem.ssh.login_failure"
    assert older["attributes"]["user.name"] == XSS
    assert client.get("/ssh").json()["window"]["unit"] == "minute"
    assert client.get("/ssh?unit=hour&count=25").status_code == 422
    assert client.get("/ssh?unit=week").status_code == 422
