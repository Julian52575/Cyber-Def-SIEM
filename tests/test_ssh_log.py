import pytest

from my_siem.ssh.log import AuthEvent, AuthKind, follow_events, parse_line

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
    assert parse_line(line + "\n") == expected


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


def test_follow_events_skips_unrelated_lines() -> None:
    lines = iter(
        [
            f"{ISO} CRON[1]: session opened",
            f"{ISO} sshd[2]: Invalid user x from 1.2.3.4 port 5",
        ]
    )
    assert [e.kind for e in follow_events(lines)] == [AuthKind.INVALID_USER]
