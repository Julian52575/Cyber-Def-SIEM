"""Run the SSH log follower and the network sniffer side by side and report events."""

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from scapy.packet import Packet
from scapy.sendrecv import sniff

from my_siem.config import Fields
from my_siem.detect import RateDetector
from my_siem.ssh.log import (
    AuthEvent,
    AuthKind,
    follow_events,
    follow_file,
    follow_journal,
)
from my_siem.ssh.net import (
    ConnEvent,
    ConnKind,
    SshConnTracker,
    bpf_filter,
    parse_ports,
)
from my_siem.telemetry import ERROR, INFO, WARN, EventLogger

DEFAULT_AUTH_LOG = Path("/var/log/auth.log")

# Attributes follow OTel semantic conventions; the ones it has no name for live
# under our own "siem." namespace, as the spec asks for custom attributes.


AUTO = "auto"
JOURNALD = "journald"


@dataclass(frozen=True)
class SshMonitorConfig:
    """Settings of the `ssh` command, read from config/ssh/config.json."""

    ports: frozenset[int] = frozenset({22})
    iface: str | None = None
    # "auto" (auth.log if present, else journald), "journald", or a file path.
    auth_log: str = AUTO
    read_auth_log: bool = True
    sniff: bool = True
    fail_threshold: int = 5
    conn_threshold: int = 20
    window: float = 60.0

    def __post_init__(self) -> None:
        for name in ("fail_threshold", "conn_threshold", "window"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name!r} must be positive")
        if not self.auth_log:
            raise ValueError("'auth_log' cannot be empty")
        if not (self.read_auth_log or self.sniff):
            raise ValueError("sshd logs and sniffing are both disabled: nothing to do")

    @classmethod
    def from_json(cls, f: Fields) -> "SshMonitorConfig":
        d = cls()
        ports = f.raw("ports")
        if ports is None:
            ports = d.ports
        elif isinstance(ports, str):
            ports = parse_ports(ports)
        elif isinstance(ports, list) and all(type(p) is int for p in ports):
            ports = parse_ports(",".join(map(str, ports)))
        else:
            raise ValueError(
                f"'ports' must be a list of ints or a string like \"22,221-229\", got {ports!r}"
            )
        return cls(
            ports=ports,
            iface=f.optional("iface", str),
            auth_log=f.get("auth_log", str, d.auth_log),
            read_auth_log=f.get("read_auth_log", bool, d.read_auth_log),
            sniff=f.get("sniff", bool, d.sniff),
            fail_threshold=f.get("fail_threshold", int, d.fail_threshold),
            conn_threshold=f.get("conn_threshold", int, d.conn_threshold),
            window=f.get("window", float, d.window),
        )


def resolve_auth_log(setting: str) -> Path | None:
    """The file to follow, or None for journald."""
    if setting == JOURNALD:
        return None
    if setting == AUTO:
        return DEFAULT_AUTH_LOG if DEFAULT_AUTH_LOG.exists() else None
    return Path(setting)


def _alert(
    out: EventLogger, name: str, ip: str, detector: RateDetector, what: str
) -> None:
    out.emit(
        ERROR,
        f"siem.alert.{name}",
        f"{ip} made {detector.threshold} {what} within {detector.window:.0f}s",
        {
            "client.address": ip,
            "siem.alert.threshold": detector.threshold,
            "siem.alert.window": detector.window,
        },
    )


def report_auth(
    out: EventLogger, event: AuthEvent, failures: RateDetector, now: float
) -> None:
    failed = event.kind in (AuthKind.LOGIN_FAILURE, AuthKind.INVALID_USER)
    out.emit(
        WARN if failed else INFO,
        f"siem.ssh.{event.kind}",
        f"ssh {event.kind.replace('_', ' ')} for {event.user!r} "
        f"from {event.ip}:{event.port}",
        {
            "user.name": event.user,
            "client.address": event.ip,
            "client.port": event.port,
            "process.pid": event.pid,
            "siem.ssh.auth.method": event.method,
        },
    )
    if failed and failures.hit(event.ip, now):
        _alert(out, "ssh_bruteforce", event.ip, failures, "failed ssh logins")


def report_conn(out: EventLogger, event: ConnEvent, openings: RateDetector) -> None:
    c = event.conn
    attributes: dict[str, str | int | float | bool] = {
        "client.address": c.client_ip,
        "client.port": c.client_port,
        "server.address": c.server_ip,
        "server.port": c.server_port,
        "network.transport": "tcp",
        "network.type": "ipv6" if ":" in c.client_ip else "ipv4",
    }
    flow = f"{c.client_ip}:{c.client_port} -> {c.server_ip}:{c.server_port}"
    if event.kind is ConnKind.OPENED:
        out.emit(
            INFO,
            "siem.ssh.connection.opened",
            f"ssh connection {flow}",
            attributes,
            event.at,
        )
        if openings.hit(c.client_ip, event.at):
            _alert(out, "ssh_conn_flood", c.client_ip, openings, "ssh connections")
        return
    attributes |= {
        "siem.ssh.connection.duration": round(event.duration, 3),
        "siem.ssh.connection.packets": c.packets,
        "siem.ssh.connection.bytes": c.bytes,
        "siem.ssh.connection.reset": event.reset,
    }
    out.emit(
        INFO,
        "siem.ssh.connection.closed",
        f"ssh connection {flow} closed after {event.duration:.1f}s",
        attributes,
        event.at,
    )


def _auth_lines(out: EventLogger, cfg: SshMonitorConfig) -> Iterator[str]:
    path = resolve_auth_log(cfg.auth_log)
    out.emit(
        INFO,
        "siem.source.started",
        f"reading sshd logs from {path or JOURNALD}",
        {"siem.source": "sshd_log", "log.file.path": str(path) if path else None},
    )
    return follow_journal() if path is None else follow_file(path)


def _run_logs(out: EventLogger, cfg: SshMonitorConfig) -> None:
    failures = RateDetector(cfg.fail_threshold, cfg.window)
    try:
        for event in follow_events(_auth_lines(out, cfg)):
            report_auth(out, event, failures, time.monotonic())
    except OSError as e:
        out.emit(
            ERROR,
            "siem.source.failed",
            f"cannot read sshd logs: {e}",
            {"siem.source": "sshd_log", "error.type": type(e).__name__},
        )


def _run_sniffer(out: EventLogger, cfg: SshMonitorConfig) -> None:
    tracker = SshConnTracker(cfg.ports)
    openings = RateDetector(cfg.conn_threshold, cfg.window)

    def on_packet(pkt: Packet) -> None:
        event = tracker.handle(pkt, float(pkt.time))
        if event is not None:
            report_conn(out, event, openings)

    ports = sorted(cfg.ports)
    out.emit(
        INFO,
        "siem.source.started",
        f"sniffing ssh traffic on ports {','.join(map(str, ports))}",
        {
            "siem.source": "network",
            "network.interface.name": cfg.iface,
            "siem.ports": ports,
        },
    )
    try:
        sniff(iface=cfg.iface, filter=bpf_filter(cfg.ports), prn=on_packet, store=False)
    except (OSError, RuntimeError) as e:
        out.emit(
            ERROR,
            "siem.source.failed",
            f"cannot sniff (needs root or CAP_NET_RAW): {e}",
            {"siem.source": "network", "error.type": type(e).__name__},
        )


def run(out: EventLogger, cfg: SshMonitorConfig) -> None:
    workers = []
    if cfg.read_auth_log:
        workers.append(threading.Thread(target=_run_logs, args=(out, cfg), daemon=True))
    if cfg.sniff:
        workers.append(
            threading.Thread(target=_run_sniffer, args=(out, cfg), daemon=True)
        )
    for w in workers:
        w.start()
    try:
        for w in workers:
            w.join()
    except KeyboardInterrupt:
        pass
