from datetime import datetime
from pathlib import Path

import pytest

from my_siem.http.access_log import (
    ACCESS_LOGS,
    AUTO,
    parse_access_line,
    resolve_access_log,
)

AT = datetime.fromisoformat("2026-11-27T15:04:05+01:00").timestamp()


def test_reads_the_combined_format() -> None:
    entry = parse_access_line(
        '203.0.113.9 - - [27/Nov/2026:15:04:05 +0100] "GET /x?q=1 HTTP/1.1" 404 153 '
        '"https://example.com/" "Mozilla/5.0 (X11)"\n'
    )

    assert entry is not None
    assert (entry.at, entry.client_ip, entry.status) == (AT, "203.0.113.9", 404)
    assert entry.request.method == "GET"
    assert entry.request.target == "/x?q=1"
    assert entry.request.version == "1.1"
    assert entry.request.user_agent == "Mozilla/5.0 (X11)"


def test_reads_the_common_format_without_an_agent() -> None:
    entry = parse_access_line(
        '2001:db8::1 - bob [27/Nov/2026:15:04:05 +0100] "POST /login HTTP/1.0" 200 -'
    )

    assert entry is not None
    assert entry.client_ip == "2001:db8::1"
    assert entry.request.user_agent is None


def test_escaped_quotes_stay_in_their_field() -> None:
    entry = parse_access_line(
        '1.2.3.4 - - [27/Nov/2026:15:04:05 +0100] "GET /a HTTP/1.1" 200 1 "-" '
        '"sqlmap \\"1.7\\""'
    )

    assert entry is not None
    assert entry.request.user_agent == 'sqlmap \\"1.7\\"'


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not an access log",
        # A TLS handshake sent to the plain port: logged, but not a request.
        '1.2.3.4 - - [27/Nov/2026:15:04:05 +0100] "\\x16\\x03\\x01" 400 157 "-" "-"',
        '1.2.3.4 - - [99/Nov/2026:15:04:05 +0100] "GET / HTTP/1.1" 200 1 "-" "-"',
    ],
)
def test_other_lines_are_skipped(line: str) -> None:
    assert parse_access_line(line) is None


def test_auto_picks_the_first_log_that_exists(tmp_path: Path) -> None:
    assert resolve_access_log(str(tmp_path / "x.log")) == tmp_path / "x.log"
    resolved = resolve_access_log(AUTO)
    assert resolved in ACCESS_LOGS
