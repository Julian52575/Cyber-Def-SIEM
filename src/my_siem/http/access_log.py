"""Requests read back from a web server's access log, for the log import.

nginx's and Apache's default "combined" format, or "common" (without referer and agent):

    203.0.113.9 - - [27/Nov/2026:15:04:05 +0100] "GET /x HTTP/1.1" 404 153 "-" "curl/8.5"

The log has no client port nor server address: those attributes are left out.
"""

import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from my_siem.http.wire import MAX_FIELD, HttpRequest, parse_request

AUTO = "auto"
# Debian's nginx and Apache, then Red Hat's Apache.
ACCESS_LOGS = (
    Path("/var/log/nginx/access.log"),
    Path("/var/log/apache2/access.log"),
    Path("/var/log/httpd/access_log"),
)

# Apache escapes a quote as \", nginx as \x22.
_QUOTED = r'"((?:[^"\\]|\\.)*)"'
_LINE = re.compile(
    rf"^(\S+) \S+ \S+ \[([^\]]+)\] {_QUOTED} (\d{{3}}) \S+(?: {_QUOTED} {_QUOTED})?"
)


@dataclass(frozen=True)
class AccessEntry:
    at: float
    client_ip: str
    request: HttpRequest
    status: int


def resolve_access_log(setting: str) -> Path:
    """With "auto", the first default that exists (else nginx's, which then fails to open)."""
    if setting != AUTO:
        return Path(setting)
    return next((p for p in ACCESS_LOGS if p.exists()), ACCESS_LOGS[0])


def parse_access_line(line: str) -> AccessEntry | None:
    """One access log line, or None if it is not a well-formed request."""
    m = _LINE.match(line)
    if m is None:
        return None
    ip, stamp, request_line, status, _, agent = m.groups()
    try:
        at = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None
    # Junk such as a TLS handshake sent to the plain port is logged as the request.
    req = parse_request(f"{request_line}\r\n".encode("utf-8", "replace"))
    if req is None:
        return None
    if agent and agent != "-":
        req = replace(req, user_agent=agent[:MAX_FIELD])
    return AccessEntry(at, ip, req, int(status))
