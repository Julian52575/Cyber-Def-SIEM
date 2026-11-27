import gzip
import json
from dataclasses import replace
from datetime import datetime
from itertools import islice
from pathlib import Path

import pytest

from my_siem.ssh.log import (
    AuthEvent,
    AuthKind,
    file_events,
    line_time,
    parse_journal,
    parse_line,
    rotated,
)

ISO = "2026-11-26T14:50:00.123456+01:00 DefSec2026"
SYSLOG = "Nov 26 14:50:00 DefSec2026"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            f"{ISO} sshd[812]: Accepted publickey for alice from 10.0.0.5 port 50122 ssh2: ED25519 SHA256:abc",
            AuthEvent(
                AuthKind.LOGIN_SUCCESS, "alice", "10.0.0.5", 50122, 812, "publickey"
            ),
        ),
        (
            f"{SYSLOG} sshd[90]: Failed password for root from 203.0.113.9 port 4242 ssh2",
            AuthEvent(
                AuthKind.LOGIN_FAILURE, "root", "203.0.113.9", 4242, 90, "password"
            ),
        ),
        (
            f"{ISO} sshd-session[7]: Failed password for invalid user admin from 2001:db8::1 port 1 ssh2",
            AuthEvent(AuthKind.LOGIN_FAILURE, "admin", "2001:db8::1", 1, 7, "password"),
        ),
        (
            f"{ISO} sshd[7]: Invalid user oracle from 203.0.113.9 port 4243",
            AuthEvent(AuthKind.INVALID_USER, "oracle", "203.0.113.9", 4243, 7),
        ),
        (
            f"{ISO} sshd-session[812]: Disconnected from user alice 10.0.0.5 port 50122",
            AuthEvent(AuthKind.LOGOUT, "alice", "10.0.0.5", 50122, 812),
        ),
    ],
)
def test_parse_line_recognises_sshd_messages(line: str, expected: AuthEvent) -> None:
    event = parse_line(line + "\n")
    assert event is not None
    assert replace(event, at=0.0) == expected


@pytest.mark.parametrize(
    "line",
    [
        f"{ISO} sshd[812]: Received disconnect from 10.0.0.5 port 50122:11: bye",
        f"{ISO} sudo[3]: Failed password for root from 1.2.3.4 port 1 ssh2",
        "garbage",
    ],
)
def test_parse_line_ignores_other_lines(line: str) -> None:
    assert parse_line(line) is None


def test_events_are_timed_by_their_line() -> None:
    event = parse_line(f"{ISO} sshd[7]: Invalid user x from 1.2.3.4 port 5")
    assert event is not None
    assert (
        event.at
        == datetime.fromisoformat("2026-11-26T14:50:00.123456+01:00").timestamp()
    )
    undated = parse_line("sshd[7]: Invalid user x from 1.2.3.4 port 5", now=42.0)
    assert undated is not None and undated.at == 42.0


def test_a_syslog_stamp_without_year_is_never_in_the_future() -> None:
    january = datetime(2027, 1, 2, 10, 0).timestamp()
    assert line_time("Dec 31 23:00:00 host x", january) == (
        datetime(2026, 12, 31, 23, 0).timestamp()
    )
    assert line_time("Jan  2 09:00:00 host x", january) == (
        datetime(2027, 1, 2, 9, 0).timestamp()
    )


def test_rotated_copies_come_oldest_first(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    for name in (
        "auth.log",
        "auth.log.1",
        "auth.log.2.gz",
        "auth.log.10.gz",
        "auth.log.bak",
    ):
        (tmp_path / name).write_text("")
    assert [p.name for p in rotated(log)] == [
        "auth.log.10.gz",
        "auth.log.2.gz",
        "auth.log.1",
    ]


def stamped(hour: int, user: str) -> str:
    return f"2026-11-26T{hour:02d}:00:00+01:00 host sshd[1]: Invalid user {user} from 1.2.3.4 port 5\n"


def test_reading_from_a_time_takes_rotated_copies_then_the_live_file(
    tmp_path: Path,
) -> None:
    log = tmp_path / "auth.log"
    with gzip.open(tmp_path / "auth.log.2.gz", "wt") as f:
        f.write(stamped(8, "too_old") + stamped(10, "a"))
    (tmp_path / "auth.log.1").write_text(stamped(11, "b"))
    log.write_text(stamped(12, "c") + "2026-11-26T12:30:00+01:00 host CRON[2]: noise\n")
    since = datetime.fromisoformat("2026-11-26T09:00:00+01:00").timestamp()

    users = [e.user for e in islice(file_events(log, since), 3)]

    assert users == ["a", "b", "c"]


def test_journal_entries_are_timed_to_the_microsecond() -> None:
    entry = {
        "__REALTIME_TIMESTAMP": "1764166200123456",
        "_PID": "812",
        "MESSAGE": "Failed password for root from 203.0.113.9 port 4242 ssh2",
    }
    event = parse_journal(json.dumps(entry))
    assert event == AuthEvent(
        AuthKind.LOGIN_FAILURE,
        "root",
        "203.0.113.9",
        4242,
        812,
        "password",
        1764166200.123456,
    )
    # A message that is not UTF-8 comes as a list of bytes.
    entry["MESSAGE"] = list(b"Invalid user \xff from 1.2.3.4 port 5")  # type: ignore[assignment]
    event = parse_journal(json.dumps(entry))
    assert event is not None and event.kind is AuthKind.INVALID_USER
    assert parse_journal("not json") is None
