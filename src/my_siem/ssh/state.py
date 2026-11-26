"""Live view of the `ssh` command, fed by the monitor and read by the API."""

import threading
import time
from collections import Counter, deque
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from my_siem.ssh.log import AuthEvent
from my_siem.ssh.net import Connection, ConnEvent, ConnKind, FlowKey

RECENT = 100


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _key(c: Connection) -> FlowKey:
    return (c.client_ip, c.client_port, c.server_ip, c.server_port)


class SshState:
    """Thread-safe: the log and sniffer threads write while the API thread reads."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._started = time.time()
        self._sources: dict[str, dict[str, str]] = {}
        self._counts: Counter[str] = Counter()
        self._active: dict[FlowKey, Connection] = {}
        self._logins: deque[dict[str, Any]] = deque(maxlen=RECENT)
        self._alerts: deque[dict[str, Any]] = deque(maxlen=RECENT)

    def source(self, name: str, status: str, detail: str) -> None:
        with self._lock:
            self._sources[name] = {"status": status, "detail": detail}

    def auth(self, event: AuthEvent, at: float) -> None:
        with self._lock:
            self._counts[event.kind] += 1
            self._logins.append({"at": _iso(at), **asdict(event)})

    def conn(self, event: ConnEvent) -> None:
        with self._lock:
            self._counts[event.kind] += 1
            if event.kind is ConnKind.OPENED:
                self._active[_key(event.conn)] = event.conn
            else:
                self._active.pop(_key(event.conn), None)

    def alert(self, name: str, ip: str, message: str, at: float) -> None:
        with self._lock:
            self._counts["alerts"] += 1
            self._alerts.append(
                {"at": _iso(at), "name": name, "ip": ip, "message": message}
            )

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            active = [
                {
                    **asdict(c),
                    "started": _iso(c.started),
                    "duration": round(now - c.started, 3),
                }
                for c in self._active.values()
            ]
            return {
                "started_at": _iso(self._started),
                "uptime": round(now - self._started, 3),
                "config": self._config,
                "sources": dict(self._sources),
                "counts": dict(self._counts),
                "active_connections": active,
                "recent_logins": list(self._logins),
                "recent_alerts": list(self._alerts),
            }
