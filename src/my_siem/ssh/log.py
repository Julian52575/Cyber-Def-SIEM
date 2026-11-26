"""SSH authentication events read from sshd's log (auth.log or journald)."""

import os
import re
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


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


# OpenSSH >= 9.8 logs from "sshd-session" instead of "sshd".
_SYSLOG = re.compile(r"\bsshd(?:-session)?\[(?P<pid>\d+)\]: (?P<msg>.*)$")
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


def parse_line(line: str) -> AuthEvent | None:
    """Turn one sshd log line into an event, or None if it is not one we track."""
    header = _SYSLOG.search(line.rstrip("\n"))
    if header is None:
        return None
    msg = header["msg"]
    for kind, pattern in _MESSAGES:
        m = pattern.match(msg)
        if m is not None:
            groups = m.groupdict()
            return AuthEvent(
                kind=kind,
                user=groups["user"],
                ip=groups["ip"],
                port=int(groups["port"]),
                pid=int(header["pid"]),
                method=groups.get("method"),
            )
    return None


def follow_file(path: Path, poll: float = 0.5) -> Iterator[str]:
    """Yield lines appended to `path` from now on, surviving logrotate."""
    f = path.open(encoding="utf-8", errors="replace")
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
                rotated = path.stat().st_ino != inode
            except FileNotFoundError:
                continue
            if rotated:
                f.close()
                f = path.open(encoding="utf-8", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
    finally:
        f.close()


def follow_journal() -> Iterator[str]:
    """Yield new sshd lines from journald, in the same syslog shape as auth.log."""
    cmd = [
        "journalctl",
        "--follow",
        "--lines=0",
        "--output=short-iso",
        "_COMM=sshd",
        "_COMM=sshd-session",
    ]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as proc:
        assert proc.stdout is not None
        yield from proc.stdout


def follow_events(lines: Iterator[str]) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event
