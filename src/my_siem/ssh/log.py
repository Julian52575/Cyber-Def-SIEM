"""SSH authentication events read from sshd's log (auth.log or journald), with their time."""

import json
import os
import re
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from my_siem.system_logs import history, read_lines, rotated


class AuthKind(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    INVALID_USER = "invalid_user"
    LOGOUT = "logout"


@dataclass(frozen=True)
class AuthEvent:
    kind: AuthKind
    user: str
    ip: str
    port: int
    pid: int
    method: str | None = None
    at: float = 0.0  # when sshd logged it (epoch seconds)


# OpenSSH >= 9.8 logs from "sshd-session" instead of "sshd".
_SYSLOG = re.compile(r"\bsshd(?:-session)?\[(?P<pid>\d+)\]: (?P<msg>.*)$")
# rsyslog's default since Debian 12 / Ubuntu 23.10, with the offset: unambiguous.
_ISO_TIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s"
)
# The traditional one: no year, no zone; the host's local time.
_BSD_TIME = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})\s")
_ADDR = r"(?P<ip>\S+) port (?P<port>\d+)"
_MESSAGES: list[tuple[AuthKind, re.Pattern[str]]] = [
    (
        AuthKind.LOGIN_SUCCESS,
        re.compile(rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {_ADDR}"),
    ),
    (
        AuthKind.LOGIN_FAILURE,
        re.compile(
            rf"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S*) from {_ADDR}"
        ),
    ),
    (AuthKind.INVALID_USER, re.compile(rf"^Invalid user (?P<user>\S*) from {_ADDR}")),
    (AuthKind.LOGOUT, re.compile(rf"^Disconnected from user (?P<user>\S+) {_ADDR}")),
]


def parse_message(msg: str, pid: int, at: float) -> AuthEvent | None:
    """Turn one sshd message into an event, or None if it is not one we track."""
    for kind, pattern in _MESSAGES:
        m = pattern.match(msg)
        if m is not None:
            groups = m.groupdict()
            return AuthEvent(
                kind=kind,
                user=groups["user"],
                ip=groups["ip"],
                port=int(groups["port"]),
                pid=pid,
                method=groups.get("method"),
                at=at,
            )
    return None


def line_time(line: str, now: float) -> float | None:
    """When a syslog line was written, or None if its stamp is not one we know."""
    m = _ISO_TIME.match(line)
    if m is not None:
        return datetime.fromisoformat(m[1]).timestamp()
    m = _BSD_TIME.match(line)
    if m is None:
        return None
    year = datetime.fromtimestamp(now).year
    at = datetime.strptime(f"{year} {m[1]}", "%Y %b %d %H:%M:%S").timestamp()
    # A December line read in January is from last year.
    if at > now + 86400:
        at = datetime.strptime(f"{year - 1} {m[1]}", "%Y %b %d %H:%M:%S").timestamp()
    return at


def parse_line(line: str, now: float | None = None) -> AuthEvent | None:
    """Turn one sshd syslog line into an event, timed by its stamp (else `now`)."""
    header = _SYSLOG.search(line.rstrip("\n"))
    if header is None:
        return None
    now = time.time() if now is None else now
    at = line_time(line, now)
    return parse_message(header["msg"], int(header["pid"]), now if at is None else at)


def follow_file(
    path: Path, from_start: bool = False, poll: float = 0.5
) -> Iterator[str]:
    """Yield lines appended to `path` (all of it first if `from_start`), surviving logrotate."""
    f = path.open(encoding="utf-8", errors="replace")
    if not from_start:
        f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    try:
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            time.sleep(poll)
            try:
                rotated_away = path.stat().st_ino != inode
            except FileNotFoundError:
                continue
            if rotated_away:
                f.close()
                f = path.open(encoding="utf-8", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
    finally:
        f.close()


def file_events(path: Path, since: float | None) -> Iterator[AuthEvent]:
    """Events from `path`, then as it grows: from `since` on, reading its rotated
    copies first, or only new lines when `since` is None."""
    if since is not None:
        for old in rotated(path):
            # A rotated file was last written when its newest line was.
            if old.stat().st_mtime > since:
                yield from _after(map(parse_line, read_lines(old)), since)
    lines = follow_file(path, from_start=since is not None)
    yield from _after(map(parse_line, lines), since)


def file_history(path: Path, since: float, until: float) -> Iterator[AuthEvent]:
    """Events of [since, until) from `path` and its rotated copies, not followed."""
    yield from _within(map(parse_line, history(path, since)), since, until)


def journal_history(since: float, until: float) -> Iterator[AuthEvent]:
    """Events of [since, until) from journald, not followed."""
    cmd = [
        "journalctl",
        f"--since=@{int(since)}",
        f"--until=@{int(until) + 1}",
        "--output=json",
        "_COMM=sshd",
        "_COMM=sshd-session",
    ]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        yield from _within(map(parse_journal, proc.stdout), since, until)


def journal_events(since: float | None) -> Iterator[AuthEvent]:
    """Events from journald, from `since` on (or only new ones), then as they come."""
    start = "--lines=0" if since is None else f"--since=@{int(since)}"
    cmd = [
        "journalctl",
        "--follow",
        start,
        "--output=json",
        "_COMM=sshd",
        "_COMM=sshd-session",
    ]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        yield from _after(map(parse_journal, proc.stdout), since)


def parse_journal(line: str) -> AuthEvent | None:
    """One `journalctl --output=json` entry, timed to the microsecond."""
    try:
        entry = json.loads(line)
        msg = entry["MESSAGE"]
        if isinstance(msg, list):  # journald's form for a message that is not UTF-8
            msg = bytes(msg).decode("utf-8", "replace")
        at = int(entry["__REALTIME_TIMESTAMP"]) / 1e6
        pid = int(entry.get("_PID", 0))
    except (ValueError, KeyError, TypeError):
        return None
    return parse_message(msg, pid, at)


def _after(
    events: Iterator[AuthEvent | None], since: float | None
) -> Iterator[AuthEvent]:
    for event in events:
        if event is not None and (since is None or event.at > since):
            yield event


def _within(
    events: Iterator[AuthEvent | None], since: float, until: float
) -> Iterator[AuthEvent]:
    for event in events:
        if event is not None and since <= event.at < until:
            yield event
