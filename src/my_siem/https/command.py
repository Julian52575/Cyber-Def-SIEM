"""The `https` command: sniff TLS handshakes, log who asks for which server, alert.

The traffic is encrypted, so only the ClientHello is read: the server name (SNI),
the highest TLS version and the protocols (ALPN) the client offers.
"""

import argparse
from collections import Counter, deque
from dataclasses import dataclass, replace
from typing import Any

from scapy.layers.inet import TCP
from scapy.packet import Packet

from my_siem.config import Fields
from my_siem.detect import RateDetector, raise_alert, rate_alert
from my_siem.https.tls import MAX_PENDING, ClientHello, HelloAssembler, Opening
from my_siem.live import RECENT, ConnState, iso
from my_siem.net import (
    Connection,
    ConnKind,
    ConnTracker,
    conn_attributes,
    parse_ports,
    ports_from_json,
    run_sniffer,
)
from my_siem.telemetry import INFO, WARN, EventLogger


@dataclass(frozen=True)
class HttpsConfig:
    """Settings of the `https` command, read from config/https/config.json."""

    ports: frozenset[int] = frozenset({443})
    iface: str | None = None
    conn_threshold: int = 100
    window: float = 60.0

    def __post_init__(self) -> None:
        for name in ("conn_threshold", "window"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name!r} must be positive")

    @classmethod
    def from_json(cls, f: Fields) -> "HttpsConfig":
        d = cls()
        return cls(
            ports=ports_from_json(f.raw("ports"), d.ports),
            iface=f.optional("iface", str),
            conn_threshold=f.get("conn_threshold", int, d.conn_threshold),
            window=f.get("window", float, d.window),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "ports": sorted(self.ports),
            "iface": self.iface,
            "conn_threshold": self.conn_threshold,
            "window": self.window,
        }


class HttpsState(ConnState):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._versions: Counter[str] = Counter()
        self._handshakes: deque[dict[str, Any]] = deque(maxlen=RECENT)

    def handshake(
        self, kind: Opening, hello: ClientHello | None, c: Connection, at: float
    ) -> None:
        with self._lock:
            self._counts[kind] += 1
            if hello is not None:
                self._versions[hello.version_name] += 1
                if hello.server_name is None:
                    self._counts["no_sni"] += 1
                if hello.legacy:
                    self._counts["legacy_tls"] += 1
            self._handshakes.append(
                {
                    "at": iso(at),
                    "kind": kind,
                    "client_ip": c.client_ip,
                    "client_port": c.client_port,
                    "server_ip": c.server_ip,
                    "server_port": c.server_port,
                    "server_name": None if hello is None else hello.server_name,
                    "version": None if hello is None else hello.version_name,
                    "alpn": list(hello.alpn) if hello else [],
                }
            )

    def _snapshot(self, now: float) -> dict[str, Any]:
        return {
            **super()._snapshot(now),
            "tls_versions": dict(self._versions),
            "recent_handshakes": list(self._handshakes),
        }


def new_state(cfg: HttpsConfig) -> HttpsState:
    return HttpsState(cfg.to_json())


class HttpsWatcher:
    """Turns sniffed packets into events, state updates and alerts."""

    def __init__(self, out: EventLogger, state: HttpsState, cfg: HttpsConfig) -> None:
        self.out = out
        self.state = state
        self.tracker = ConnTracker(cfg.ports)
        self.hellos = HelloAssembler()
        self.openings = RateDetector(cfg.conn_threshold, cfg.window)
        self.window = cfg.window
        # When each client last raised https_legacy_tls, to alert once per window.
        self.legacy_alerted: dict[str, float] = {}

    def handle(self, pkt: Packet, now: float) -> None:
        event = self.tracker.handle(pkt, now)
        if event is not None:
            self.state.conn(event)
            c = event.conn
            if event.kind is ConnKind.OPENED:
                if self.openings.hit(c.client_ip, now):
                    rate_alert(
                        self.out,
                        self.state,
                        "https_conn_flood",
                        c.client_ip,
                        self.openings,
                        "https connections",
                    )
            else:
                self.hellos.forget(c.key)
            return
        key = self.tracker.client_flow(pkt)
        if key is None:
            return
        payload = bytes(pkt[TCP].payload)
        if payload:
            seen = self.hellos.feed(key, payload)
            if seen is not None:
                self.report(seen.kind, seen.hello, self.tracker.flows[key], now)

    def report(
        self, kind: Opening, hello: ClientHello | None, c: Connection, now: float
    ) -> None:
        self.state.handshake(kind, hello, c, now)
        flow = f"{c.client_ip}:{c.client_port} -> {c.server_ip}:{c.server_port}"
        attributes: dict[str, Any] = conn_attributes(c)
        if hello is None:
            plaintext = kind is Opening.PLAINTEXT_HTTP
            self.out.emit(
                WARN,
                f"siem.https.{kind}",
                f"{'plaintext http' if plaintext else 'non-tls traffic'} on {flow}",
                attributes,
                now,
            )
            return
        self.out.emit(
            WARN if hello.legacy else INFO,
            "siem.https.client_hello",
            f"tls handshake for {hello.server_name or '(no server name)'} "
            f"offering {hello.version_name} on {flow}",
            attributes
            | {
                "server.address": hello.server_name or c.server_ip,
                "tls.server_name": hello.server_name,
                "tls.protocol.name": "ssl" if hello.version < 0x0301 else "tls",
                "tls.protocol.version": hello.version_name.split()[-1],
                "tls.client.supported_alpn": list(hello.alpn) or None,
                "siem.https.legacy_tls": hello.legacy,
            },
            now,
        )
        if hello.legacy and self._first_legacy(c.client_ip, now):
            raise_alert(
                self.out,
                self.state,
                "https_legacy_tls",
                c.client_ip,
                f"{c.client_ip} offered at most {hello.version_name}",
                {"tls.protocol.version": hello.version_name.split()[-1]},
            )

    def _first_legacy(self, ip: str, now: float) -> bool:
        last = self.legacy_alerted.get(ip)
        if last is not None and now - last < self.window:
            return False
        if len(self.legacy_alerted) >= MAX_PENDING:
            self.legacy_alerted.clear()
        self.legacy_alerted[ip] = now
        return True


def _ports(spec: str) -> frozenset[int]:
    try:
        return parse_ports(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def add_arguments(parser: argparse.ArgumentParser) -> None:
    # None so that only flags actually given override the config.
    parser.add_argument("--ports", type=_ports, help='HTTPS ports, e.g. "443,8443"')
    parser.add_argument("--iface", help="interface to sniff on (default: all)")
    parser.add_argument(
        "--conn-threshold", type=int, help="new connections from one IP that alert"
    )
    parser.add_argument("--window", type=float, help="alert window in seconds")


def apply_flags(cfg: HttpsConfig, args: argparse.Namespace) -> HttpsConfig:
    names = ("ports", "iface", "conn_threshold", "window")
    return replace(
        cfg, **{n: getattr(args, n) for n in names if getattr(args, n) is not None}
    )


def run(out: EventLogger, cfg: HttpsConfig, state: HttpsState) -> None:
    watcher = HttpsWatcher(out, state, cfg)
    run_sniffer(
        out,
        state,
        "https",
        cfg.iface,
        cfg.ports,
        lambda pkt: watcher.handle(pkt, float(pkt.time)),
    )
