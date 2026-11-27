"""HTTP/1.x requests and responses read from TCP payloads, and the attacks they show.

Only the start of a request or response is parsed, so a request line or header
split across TCP segments is missed; requests almost always fit in one.
"""

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

# Requests are attacker-controlled: keep what is logged short.
MAX_FIELD = 512

_REQUEST_LINE = re.compile(
    rb"([A-Z][A-Z_-]{1,15}) (\S{1,8192}) HTTP/(\d(?:\.\d)?)\r?\n"
)
_STATUS_LINE = re.compile(rb"HTTP/\d(?:\.\d)? ([1-5]\d\d)[ \r\n]")


@dataclass(frozen=True)
class HttpRequest:
    method: str
    target: str
    version: str
    host: str | None = None
    user_agent: str | None = None

    @property
    def path(self) -> str:
        return self.target.partition("?")[0]


def _text(raw: bytes) -> str:
    return raw[:MAX_FIELD].decode("latin-1")


def parse_request(payload: bytes) -> HttpRequest | None:
    """The request starting `payload`, or None if it does not start one."""
    m = _REQUEST_LINE.match(payload)
    if m is None:
        return None
    headers: dict[bytes, bytes] = {}
    head = payload[m.end() :].split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\n"):
        name, sep, value = line.partition(b":")
        if sep:
            headers.setdefault(name.strip().lower(), value.strip())
    host, agent = headers.get(b"host"), headers.get(b"user-agent")
    return HttpRequest(
        method=m[1].decode(),
        target=_text(m[2]),
        version=m[3].decode(),
        host=None if host is None else _text(host),
        user_agent=None if agent is None else _text(agent),
    )


def parse_response(payload: bytes) -> int | None:
    """The status code of the response starting `payload`, if it starts one."""
    m = _STATUS_LINE.match(payload)
    return None if m is None else int(m[1])


# Matched against the lowercased target, both as sent and URL-decoded.
TARGET_RULES: dict[str, re.Pattern[str]] = {
    "path_traversal": re.compile(r"\.\.[/\\]|%2e%2e|%252e"),
    "sql_injection": re.compile(
        r"union(\s|\+|/\*.*?\*/)+(all\s+)?select|'\s*(or|and)\s+'?\w+'?\s*=|"
        r"\bor\s+1\s*=\s*1|sleep\(\s*\d|benchmark\(|information_schema"
    ),
    "xss": re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg"),
    "command_injection": re.compile(
        r"[;|`]\s*(cat|wget|curl|id|uname|whoami|sh|bash|nc)\b|\$\(|\$\{ifs\}"
    ),
    "log4shell": re.compile(r"\$\{(jndi|\$\{|lower:|upper:|env:)"),
    "sensitive_file": re.compile(
        r"/\.env\b|/\.git/|/etc/(passwd|shadow)|/\.ht(access|passwd)|"
        r"/wp-config\.php|/\.aws/|/id_rsa|/\.ssh/|/\.ds_store|/server-status"
    ),
    "admin_probe": re.compile(
        r"/wp-login\.php|/wp-admin|/phpmyadmin|/xmlrpc\.php|/administrator/|"
        r"/manager/html|/cgi-bin/|/actuator|/console\b|/solr/|/boaform"
    ),
}
SCANNER_AGENT = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|\bdirb\b|wfuzz|ffuf|"
    r"nuclei|acunetix|nessus|openvas|whatweb|wpscan|hydra|feroxbuster|jaeles",
    re.IGNORECASE,
)


def match_rules(req: HttpRequest) -> list[str]:
    """The attack patterns `req` shows, by rule name."""
    raw = req.target.lower()
    targets = (raw, unquote_plus(raw))
    found = [
        name
        for name, pattern in TARGET_RULES.items()
        if any(pattern.search(t) for t in targets)
    ]
    agent = req.user_agent or ""
    if SCANNER_AGENT.search(agent):
        found.append("scanner_user_agent")
    if "log4shell" not in found and TARGET_RULES["log4shell"].search(agent.lower()):
        found.append("log4shell")
    return found
