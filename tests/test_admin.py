import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from my_siem.api import create_app
from my_siem.clock import HOUR, hour_start, local
from my_siem.logs import LogManager, Retention
from my_siem.ssh.monitor import SshMonitorConfig, import_source
from my_siem.ssh.state import SshState
from my_siem.telemetry import INFO

HOSTS = ["testserver", "localhost"]
KEEP = Retention(max_age_days=30, max_size_mb=1)
# Attacker-free, but a path is still shown as text: it must come out escaped.
ODD = "<img src=x onerror=alert(1)>"
JSON = {"content-type": "application/json"}


def admin_app(tmp_path: Path, log: bool = True) -> tuple[FastAPI, LogManager]:
    auth = tmp_path / f"auth{ODD}.log"
    at = hour_start(time.time()) - HOUR + 30
    auth.write_text(
        f"{local(at).isoformat()} host sshd[1]: "
        "Failed password for root from 203.0.113.9 port 4242 ssh2\n"
    )
    root = tmp_path / "logs"
    logs = LogManager("ssh", root / "ssh" if log else None, KEEP)
    app = create_app(
        {"ssh": SshState({}).snapshot},
        HOSTS,
        logs={"ssh": logs},
        sources={"ssh": import_source(SshMonitorConfig(auth_log=str(auth)))},
        log_root=root if log else None,
        retention=KEEP,
    )
    return app, logs


def test_admin_tab_shows_jobs_sizes_and_the_import_form(tmp_path: Path) -> None:
    app, logs = admin_app(tmp_path)
    logs.out.emit(INFO, "siem.ssh.login_success", "in")
    (tmp_path / "logs" / "old").mkdir()

    html = TestClient(app).get("/ui/admin").text

    assert '<a class="tab-admin" href="../ui/admin?' in html
    assert 'aria-current="page">Admin</a>' in html
    assert "Log manager (ssh)" in html
    assert "Dashboard (ssh)" in html  # the active connections sampler
    assert "<code>ssh</code></td>" in html and "<code>old</code></td>" in html
    assert 'name="command" value="ssh" checked' in html
    assert 'data-max="24"' in html and 'data-max="30"' in html  # days: retention age
    assert ODD not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_section_tabs_link_to_the_admin_tab_with_the_window(tmp_path: Path) -> None:
    app, _ = admin_app(tmp_path)

    html = TestClient(app).get("/ui/ssh?unit=hour&count=3").text

    assert 'href="../ui/admin?unit=hour&amp;count=3"' in html


def test_admin_tab_without_log_files_says_so(tmp_path: Path) -> None:
    app, _ = admin_app(tmp_path, log=False)

    html = TestClient(app).get("/ui/admin").text

    assert "--no-log" in html
    assert 'id="import-form"' not in html


def test_admin_tab_is_not_polled(tmp_path: Path) -> None:
    client = TestClient(admin_app(tmp_path)[0])

    html = client.get("/ui/admin").text

    # live.js polls the element with data-fragment: the admin tab must have none.
    assert "data-fragment" not in html
    assert "Every 5 s" in html and "Every hour, on its first event" in html
    assert client.get("/ui/admin/fragment").status_code == 404
    usage = client.get("/ui/admin/usage")
    assert usage.text.lstrip().startswith('<div class="card" id="usage">')


def test_jobs_and_log_sizes_as_json(tmp_path: Path) -> None:
    app, logs = admin_app(tmp_path)
    logs.out.emit(INFO, "siem.ssh.login_success", "in")
    client = TestClient(app)

    jobs = client.get("/admin/jobs").json()
    [folder] = client.get("/admin/logs").json()

    assert {j["service"] for j in jobs} == {"Log manager (ssh)", "Dashboard (ssh)"}
    assert all("next" not in j and j["frequency"] for j in jobs)
    assert folder["name"] == "ssh"
    assert folder["log_files"] == 1
    assert folder["plain_bytes"] > 0
    assert folder["cap_bytes"] == 1024 * 1024


def test_import_is_estimated_then_run(tmp_path: Path) -> None:
    client = TestClient(admin_app(tmp_path)[0])
    request = {"commands": ["ssh"], "unit": "hour", "count": 2}

    estimate = client.get("/admin/import/estimate?command=ssh&unit=hour&count=2")
    started = client.post("/admin/import", json=request)
    deadline = time.monotonic() + 5
    while (status := client.get("/admin/import").json())["state"] == "running":
        assert time.monotonic() < deadline
        time.sleep(0.01)

    assert estimate.json()["reports"][0]["new"] == 1
    assert started.status_code == 202
    assert status["state"] == "done"
    assert status["reports"][0]["new"] == 1
    assert status["since"].endswith("+01:00") or status["since"].endswith("+02:00")
    assert (
        client.get("/admin/import/estimate?command=ssh&unit=hour&count=2").json()[
            "reports"
        ][0]["new"]
        == 0
    )


def test_import_status_is_idle_before_any(tmp_path: Path) -> None:
    client = TestClient(admin_app(tmp_path)[0])

    assert client.get("/admin/import").json() == {"state": "idle"}


@pytest.mark.parametrize(
    "query",
    [
        "command=dummy&unit=hour&count=1",
        "command=ssh&unit=minute&count=1",
        "command=ssh&unit=hour&count=0",
        "unit=hour&count=1",
    ],
)
def test_bad_estimates_are_422(tmp_path: Path, query: str) -> None:
    client = TestClient(admin_app(tmp_path)[0])

    assert client.get(f"/admin/import/estimate?{query}").status_code == 422


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        # What a form on another site can send.
        ({"content-type": "application/x-www-form-urlencoded"}, 415),
        ({"content-type": "text/plain"}, 415),
        ({**JSON, "origin": "https://evil.example"}, 403),
        ({**JSON, "sec-fetch-site": "cross-site"}, 403),
        (
            {
                **JSON,
                "origin": "http://localhost:8080",
                "sec-fetch-site": "same-origin",
            },
            202,
        ),
        (JSON, 202),  # curl: no Origin
    ],
)
def test_import_refuses_cross_site_requests(
    tmp_path: Path, headers: dict[str, str], status: int
) -> None:
    client = TestClient(admin_app(tmp_path)[0])
    body = '{"commands": ["ssh"], "unit": "hour", "count": 1}'

    res = client.post("/admin/import", content=body, headers=headers)

    assert res.status_code == status, res.text


def test_other_writes_stay_refused(tmp_path: Path) -> None:
    client = TestClient(admin_app(tmp_path)[0])

    for method, path in [
        ("POST", "/admin/jobs"),
        ("PUT", "/admin/import"),
        ("DELETE", "/admin/import"),
        ("POST", "/admin/import/estimate"),
    ]:
        res = client.request(method, path, json={})
        assert res.status_code == 405, (method, path)


@pytest.mark.parametrize(
    ("host", "origin", "status"),
    [
        ("bastion.example:8080", "http://bastion.example:8080", 202),
        ("localhost:18081", "http://localhost:18081", 202),  # an SSH tunnel
        ("bastion.example:8080", "https://evil.example", 403),
        ("bastion.example:8080", "null", 403),
    ],
)
def test_with_any_host_allowed_only_the_same_origin_may_import(
    tmp_path: Path, host: str, origin: str, status: int
) -> None:
    auth = tmp_path / "auth.log"
    auth.write_text("")
    logs = LogManager("ssh", tmp_path / "logs" / "ssh", KEEP)
    app = create_app(
        {"ssh": SshState({}).snapshot},
        ["*"],
        logs={"ssh": logs},
        sources={"ssh": import_source(SshMonitorConfig(auth_log=str(auth)))},
        log_root=tmp_path / "logs",
        retention=KEEP,
    )
    body = '{"commands": ["ssh"], "unit": "hour", "count": 1}'

    res = TestClient(app).post(
        f"http://{host}/admin/import",
        content=body,
        headers={**JSON, "origin": origin, "sec-fetch-site": "same-origin"},
    )

    assert res.status_code == status, res.text


def test_a_get_with_the_page_token_starts_an_import(tmp_path: Path) -> None:
    app, _ = admin_app(tmp_path)
    client = TestClient(app)
    html = client.get("/ui/admin").text
    token = html.split('data-token="')[1].split('"')[0]
    query = "command=ssh&unit=hour&count=1"

    started = client.get(f"/admin/import/start?{query}&token={token}")

    assert started.status_code == 202, started.text
    assert started.headers["cache-control"] == "no-store"
    assert len(token) >= 32


@pytest.mark.parametrize(
    ("token", "headers"),
    [
        (None, {}),
        ("guess", {}),
        ("PAGE", {"sec-fetch-site": "cross-site"}),  # an <img> on another site
    ],
)
def test_a_get_without_the_page_token_is_refused(
    tmp_path: Path, token: str | None, headers: dict[str, str]
) -> None:
    app, _ = admin_app(tmp_path)
    client = TestClient(app)
    html = client.get("/ui/admin").text
    if token == "PAGE":
        token = html.split('data-token="')[1].split('"')[0]
    query = "command=ssh&unit=hour&count=1" + (f"&token={token}" if token else "")

    res = client.get(f"/admin/import/start?{query}", headers=headers)

    assert res.status_code == 403
    assert client.get("/admin/import").json() == {"state": "idle"}
