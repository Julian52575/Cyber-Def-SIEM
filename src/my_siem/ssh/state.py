"""Live view of the `ssh` command, fed by the monitor and read by the API."""

from collections import deque
from dataclasses import asdict
from typing import Any

from my_siem.live import RECENT, ConnState, iso
from my_siem.ssh.log import AuthEvent


class SshState(ConnState):
    """Thread-safe: the log and sniffer threads write while the API thread reads."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._logins: deque[dict[str, Any]] = deque(maxlen=RECENT)

    def auth(self, event: AuthEvent, at: float) -> None:
        with self._lock:
            self._counts[event.kind] += 1
            self._logins.append({"at": iso(at), **asdict(event)})

    def _snapshot(self, now: float) -> dict[str, Any]:
        return {**super()._snapshot(now), "recent_logins": list(self._logins)}
