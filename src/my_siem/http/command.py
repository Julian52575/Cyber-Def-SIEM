"""The `http` command: sniff plaintext HTTP, log requests and responses, raise alerts."""

import argparse
from collections import Counter, deque
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from scapy.layers.inet import TCP
from scapy.packet import Packet

from my_siem.config import Fields
from my_siem.detect import RateDetector, raise_alert, rate_alert
from my_siem.http.access_log import AUTO, parse_access_line, resolve_access_log
from my_siem.http.wire import HttpRequest, match_rules, parse_request, parse_response
from my_siem.live import RECENT, ConnState, iso
from my_siem.logs import LogManager, event_keys
from my_siem.logs.importer import Source
from my_siem.net import ConnTracker, ip_of, parse_ports, ports_from_json, run_sniffer
from my_siem.system_logs import history
from my_siem.telemetry import INFO, WARN, EventLogger


@dataclass(frozen=True)
class HttpConfig:
    """Settings of the `http` command, read from config/http/config.json."""

    ports: frozenset[int] = frozenset({80})
    interface: str | None = None
    request_threshold: int = 100
    error_threshold: int = 20
    window: float = 60.0
    # Read only by the log import: "auto" (nginx's, else Apache's) or a file path.
    access_log: str = AUTO

    def __post_init__(self) -> None:
        for name in ("request_threshold", "error_threshold", "window"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name!r} must be positive")
        if not self.access_log:
            raise ValueError("'access_log' cannot be empty")

    @classmethod
    def from_json(cls, f: Fields) -> "HttpConfig":
        d = cls()
        return cls(
            ports=ports_from_json(f.raw("ports"), d.ports),
            interface=f.optional("interface", str),
            request_threshold=f.get("request_threshold", int, d.request_threshold),
            error_threshold=f.get("error_threshold", int, d.error_threshold),
            window=f.get("window", float, d.window),
            access_log=f.get("access_log", str, d.access_log),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "ports": sorted(self.ports),
            "interface": self.interface,
            "request_threshold": self.request_threshold,
            "error_threshold": self.error_threshold,
            "window": self.window,
            "access_log": self.access_log,
        }


# (address, port): an access log knows neither the client's port nor the server.
type Client = tuple[str, int | None]
type Endpoint = tuple[str | None, int | None]


def status_class(status: int) -> str:
    return f"{status // 100}xx"


class HttpState(ConnState):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._statuses: Counter[str] = Counter()
        self._rules: Counter[str] = Counter()
        self._requests: deque[dict[str, Any]] = deque(maxlen=RECENT)

    def request(
        self,
        req: HttpRequest,
        client: Client,
        server: Endpoint,
        rules: list[str],
        at: float,
    ) -> None:
        with self._lock:
            self._counts["requests"] += 1
            if rules:
                self._counts["suspicious"] += 1
                self._rules.update(rules)
            self._requests.append(
                {
                    "at": iso(at),
                    "client_ip": client[0],
                    "client_port": client[1],
                    "server_ip": server[0],
                    "server_port": server[1],
                    "method": req.method,
                    "host": req.host,
                    "target": req.target,
                    "user_agent": req.user_agent,
                    "rules": rules,
                }
            )

    def response(self, status: int) -> None:
        with self._lock:
            self._counts["responses"] += 1
            self._statuses[status_class(status)] += 1

    def _snapshot(self, now: float) -> dict[str, Any]:
        return {
            **super()._snapshot(now),
            "status_classes": dict(self._statuses),
            "rules": dict(self._rules),
            "recent_requests": list(self._requests),
        }


def new_state(cfg: HttpConfig) -> HttpState:
    return HttpState(cfg.to_json())


class HttpWatcher:
    """Turns sniffed packets into events, state updates and alerts."""

    def __init__(self, out: EventLogger, state: HttpState, cfg: HttpConfig) -> None:
        self.out = out
        self.state = state
        self.ports = cfg.ports
        self.tracker = ConnTracker(cfg.ports)
        self.requests = RateDetector(cfg.request_threshold, cfg.window)
        self.errors = RateDetector(cfg.error_threshold, cfg.window)

    def handle(self, pkt: Packet, now: float) -> None:
        ip = ip_of(pkt)
        if TCP in pkt and ip is not None:
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            # Before the tracker, which forgets the flow on a FIN that carries data.
            if payload and tcp.dport in self.ports:
                req = parse_request(payload)
                if req is not None:
                    self.report_request(
                        req, (ip.src, tcp.sport), (ip.dst, tcp.dport), now
                    )
            elif payload and tcp.sport in self.ports:
                status = parse_response(payload)
                if status is not None:
                    self.report_response(
                        status, (ip.dst, tcp.dport), (ip.src, tcp.sport), now
                    )
        event = self.tracker.handle(pkt, now)
        if event is not None:
            self.state.conn(event)

    def report_request(
        self,
        req: HttpRequest,
        client: Client,
        server: Endpoint,
        now: float,
    ) -> None:
        rules = match_rules(req)
        self.state.request(req, client, server, rules, now)
        self.out.emit(
            WARN if rules else INFO,
            "siem.http.request",
            f"{req.method} {req.target} from {_addr(client)}",
            {
                **_endpoints(client, server),
                "http.request.method": req.method,
                "url.path": req.path,
                "url.query": req.target.partition("?")[2] or None,
                "http.request.header.host": req.host,
                "user_agent.original": req.user_agent,
                "network.protocol.name": "http",
                "network.protocol.version": req.version,
                "siem.http.rules": rules or None,
            },
            now,
        )
        if rules:
            raise_alert(
                self.out,
                self.state,
                "http_suspicious_request",
                client[0],
                f"{client[0]} sent {req.method} {req.target} ({', '.join(rules)})",
                {"siem.http.rules": rules, "url.path": req.path},
                at=now,
            )
        if self.requests.hit(client[0], now):
            rate_alert(
                self.out,
                self.state,
                "http_request_flood",
                client[0],
                self.requests,
                "http requests",
                at=now,
            )

    def report_response(
        self,
        status: int,
        client: Client,
        server: Endpoint,
        now: float,
    ) -> None:
        self.state.response(status)
        self.out.emit(
            WARN if status >= 400 else INFO,
            "siem.http.response",
            f"{status} to {_addr(client)}",
            {**_endpoints(client, server), "http.response.status_code": status},
            now,
        )
        # Many 4xx to one client: it is guessing paths (directory brute force, scanner).
        if 400 <= status < 500 and self.errors.hit(client[0], now):
            rate_alert(
                self.out,
                self.state,
                "http_error_scan",
                client[0],
                self.errors,
                "requests answered with 4xx",
                at=now,
            )


def _addr(end: Client) -> str:
    return end[0] if end[1] is None else f"{end[0]}:{end[1]}"


def _endpoints(client: Client, server: Endpoint) -> dict[str, Any]:
    return {
        "client.address": client[0],
        "client.port": client[1],
        "server.address": server[0],
        "server.port": server[1],
    }


def _ports(spec: str) -> frozenset[int]:
    try:
        return parse_ports(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def add_arguments(parser: argparse.ArgumentParser) -> None:
    # None so that only flags actually given override the config.
    parser.add_argument("--ports", type=_ports, help='HTTP ports, e.g. "80,8080"')
    parser.add_argument("--interface", help="interface to sniff on (default: all)")
    parser.add_argument(
        "--request-threshold", type=int, help="requests from one IP that alert"
    )
    parser.add_argument(
        "--error-threshold", type=int, help="4xx responses to one IP that alert"
    )
    parser.add_argument("--window", type=float, help="alert window in seconds")
    parser.add_argument(
        "--access-log",
        metavar="PATH",
        help='web server access log the log import reads (default: "auto")',
    )


def apply_flags(cfg: HttpConfig, args: argparse.Namespace) -> HttpConfig:
    names = (
        "ports",
        "interface",
        "request_threshold",
        "error_threshold",
        "window",
        "access_log",
    )
    return replace(
        cfg, **{n: getattr(args, n) for n in names if getattr(args, n) is not None}
    )


def count_keys(name: str, attributes: Mapping[str, Any]) -> dict[str, int]:
    """Besides the event name: suspicious requests, each rule they match, status classes."""
    keys = event_keys(name, attributes)
    if name == "siem.http.request":
        rules = attributes.get("siem.http.rules") or ()
        if rules:
            keys["suspicious"] = 1
        for rule in rules:
            keys[f"rule:{rule}"] = 1
    elif name == "siem.http.response":
        status = attributes.get("http.response.status_code")
        if isinstance(status, int):
            keys[f"status:{status_class(status)}"] = 1
    return keys


def run(logs: LogManager, cfg: HttpConfig, state: HttpState) -> None:
    out = logs.out
    watcher = HttpWatcher(out, state, cfg)
    run_sniffer(
        out,
        state,
        "http",
        cfg.interface,
        cfg.ports,
        lambda pkt: watcher.handle(pkt, float(pkt.time)),
    )


def import_source(cfg: HttpConfig) -> Source:
    """Past requests read from the web server's access log, for the log import."""
    path = resolve_access_log(cfg.access_log)

    def replay(out: EventLogger, since: float, until: float) -> None:
        watcher = HttpWatcher(out, new_state(cfg), cfg)
        server: Endpoint = (None, None)
        for line in history(path, since):
            entry = parse_access_line(line)
            if entry is None or not since <= entry.at < until:
                continue
            client: Client = (entry.client_ip, None)
            watcher.report_request(entry.request, client, server, entry.at)
            watcher.report_response(entry.status, client, server, entry.at)

    return Source(
        where=str(path),
        replay=replay,
        kinds=("siem.http.request", "siem.http.response", "siem.alert.http_"),
        alert_window=cfg.window,
        # TODO(import): an hour the sniffer logged anything in is skipped whole, losing
        # its unsniffed requests. Ends when the two can be matched request by request.
        skip_watched_hours=True,
    )
