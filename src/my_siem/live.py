"""Live state shared by the commands that track connections and raise alerts."""

import threading
import time
from collections import Counter, deque
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from my_siem.net import Connection, ConnEvent, ConnKind, FlowKey

RECENT = 100


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


class ConnState:
    """Thread-safe: the command's threads write while the API thread reads.

    Subclasses add their own fields under `_lock` and extend `snapshot()`.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._started = time.time()
        self._sources: dict[str, dict[str, str]] = {}
        self._counts: Counter[str] = Counter()
        self._active: dict[FlowKey, Connection] = {}
        self._alerts: deque[dict[str, Any]] = deque(maxlen=RECENT)

    def source(self, name: str, status: str, detail: str) -> None:
        with self._lock:
            self._sources[name] = {"status": status, "detail": detail}

    def conn(self, event: ConnEvent) -> None:
        with self._lock:
            self._counts[event.kind] += 1
            if event.kind is ConnKind.OPENED:
                self._active[event.conn.key] = event.conn
            else:
                self._active.pop(event.conn.key, None)

    def alert(self, name: str, ip: str, message: str, at: float) -> None:
        with self._lock:
            self._counts["alerts"] += 1
            self._alerts.append(
                {"at": iso(at), "name": name, "ip": ip, "message": message}
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot(time.time())

    def _snapshot(self, now: float) -> dict[str, Any]:
        """Call with `_lock` held."""
        active = [
            {
                **asdict(c),
                "started": iso(c.started),
                "duration": round(now - c.started, 3),
            }
            for c in self._active.values()
        ]
        return {
            "started_at": iso(self._started),
            "uptime": round(now - self._started, 3),
            "config": self._config,
            "sources": dict(self._sources),
            "counts": dict(self._counts),
            "active_connections": active,
            "recent_alerts": list(self._alerts),
        }
