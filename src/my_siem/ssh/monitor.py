"""Run the SSH log follower and the network sniffer side by side and report events."""

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.packet import Packet

from my_siem.clock import local
from my_siem.config import Fields
from my_siem.detect import RateDetector, rate_alert
from my_siem.logs import LONGEST, LogManager
from my_siem.net import (
    ConnEvent,
    ConnKind,
    ConnTracker,
    conn_attributes,
    ports_from_json,
    run_sniffer,
)
from my_siem.ssh.log import AuthEvent, AuthKind, file_events, journal_events
from my_siem.ssh.state import SshState
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
    interface: str | None = None
    # "auto" (auth.log if present, else journald), "journald", or a file path.
    auth_log: str = AUTO
    read_auth_log: bool = True
    sniff_traffic: bool = True
    fail_threshold: int = 5
    conn_threshold: int = 20
    window: float = 60.0

    def __post_init__(self) -> None:
        for name in ("fail_threshold", "conn_threshold", "window"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name!r} must be positive")
        if not self.auth_log:
            raise ValueError("'auth_log' cannot be empty")
        if not (self.read_auth_log or self.sniff_traffic):
            raise ValueError("sshd logs and sniffing are both disabled: nothing to do")

    @classmethod
    def from_json(cls, f: Fields) -> "SshMonitorConfig":
        d = cls()
        return cls(
            ports=ports_from_json(f.raw("ports"), d.ports),
            interface=f.optional("interface", str),
            auth_log=f.get("auth_log", str, d.auth_log),
            read_auth_log=f.get("read_auth_log", bool, d.read_auth_log),
            sniff_traffic=f.get("sniff_traffic", bool, d.sniff_traffic),
            fail_threshold=f.get("fail_threshold", int, d.fail_threshold),
            conn_threshold=f.get("conn_threshold", int, d.conn_threshold),
            window=f.get("window", float, d.window),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "ports": sorted(self.ports),
            "interface": self.interface,
            "auth_log": self.auth_log,
            "read_auth_log": self.read_auth_log,
            "sniff_traffic": self.sniff_traffic,
            "fail_threshold": self.fail_threshold,
            "conn_threshold": self.conn_threshold,
            "window": self.window,
        }


def new_state(cfg: SshMonitorConfig) -> SshState:
    return SshState(cfg.to_json())


def resolve_auth_log(setting: str) -> Path | None:
    """The file to follow, or None for journald."""
    if setting == JOURNALD:
        return None
    if setting == AUTO:
        return DEFAULT_AUTH_LOG if DEFAULT_AUTH_LOG.exists() else None
    return Path(setting)


# Where in the sshd log the last event came from, saved with the counts.
SSHD_LOG = "sshd_log"


def report_auth(
    out: EventLogger, state: SshState, event: AuthEvent, failures: RateDetector
) -> None:
    """Timed by the event: an old line read at startup lands, and alerts, at its time."""
    state.auth(event, event.at)
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
        event.at,
    )
    if failed and failures.hit(event.ip, event.at):
        rate_alert(
            out,
            state,
            "ssh_bruteforce",
            event.ip,
            failures,
            "failed ssh logins",
            at=event.at,
        )


def report_conn(
    out: EventLogger, state: SshState, event: ConnEvent, openings: RateDetector
) -> None:
    state.conn(event)
    c = event.conn
    attributes = conn_attributes(c)
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
            rate_alert(
                out,
                state,
                "ssh_conn_flood",
                c.client_ip,
                openings,
                "ssh connections",
                at=event.at,
            )
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


def _auth_events(
    logs: LogManager, state: SshState, cfg: SshMonitorConfig
) -> Iterator[AuthEvent]:
    """sshd's events from where the last run stopped, else as far back as the
    filters reach, then live."""
    path = resolve_auth_log(cfg.auth_log)
    since = logs.mark(SSHD_LOG)
    if since is None:
        since = float(LONGEST.since(time.time()))
    where = str(path or JOURNALD)
    state.source("sshd_log", "running", where)
    logs.out.emit(
        INFO,
        "siem.source.started",
        f"reading sshd logs from {where}, after {local(since).isoformat()}",
        {"siem.source": "sshd_log", "log.file.path": str(path) if path else None},
    )
    return journal_events(since) if path is None else file_events(path, since)


def _run_logs(logs: LogManager, state: SshState, cfg: SshMonitorConfig) -> None:
    failures = RateDetector(cfg.fail_threshold, cfg.window)
    try:
        for event in _auth_events(logs, state, cfg):
            report_auth(logs.out, state, event, failures)
            logs.set_mark(SSHD_LOG, event.at)
    except OSError as e:
        state.source("sshd_log", "failed", str(e))
        logs.out.emit(
            ERROR,
            "siem.source.failed",
            f"cannot read sshd logs: {e}",
            {"siem.source": "sshd_log", "error.type": type(e).__name__},
        )


def _run_sniffer(logs: LogManager, state: SshState, cfg: SshMonitorConfig) -> None:
    tracker = ConnTracker(cfg.ports)
    openings = RateDetector(cfg.conn_threshold, cfg.window)

    def on_packet(pkt: Packet) -> None:
        event = tracker.handle(pkt, float(pkt.time))
        if event is not None:
            report_conn(logs.out, state, event, openings)

    run_sniffer(logs.out, state, "ssh", cfg.interface, cfg.ports, on_packet)


def run(logs: LogManager, cfg: SshMonitorConfig, state: SshState) -> None:
    workers = []
    if cfg.read_auth_log:
        workers.append(
            threading.Thread(target=_run_logs, args=(logs, state, cfg), daemon=True)
        )
    if cfg.sniff_traffic:
        workers.append(
            threading.Thread(target=_run_sniffer, args=(logs, state, cfg), daemon=True)
        )
    for w in workers:
        w.start()
    try:
        for w in workers:
            w.join()
    except KeyboardInterrupt:
        pass
