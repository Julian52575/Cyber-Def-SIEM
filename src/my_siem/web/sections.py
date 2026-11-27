"""What each dashboard section shows, built from a snapshot and its sampled history."""

import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from typing import Any

from my_siem.clock import TZ, local
from my_siem.logs import LogManager, Window
from my_siem.logs.reader import Kinds, Record, at_of
from my_siem.logs.rollup import Bucket
from my_siem.web.charts import Series, bar_list, flow_diagram, line_chart

type Snapshot = dict[str, Any]
type Metrics = dict[str, float]
# (epoch seconds, metrics) as recorded by the sampler, oldest first.
type Samples = Sequence[tuple[float, Metrics]]


def fmt_number(n: float) -> str:
    return f"{n:,.0f}" if n == int(n) else f"{n:,.2f}".rstrip("0")


def fmt_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s % 60}s"
    return f"{s}s"


def fmt_bytes(n: float) -> str:
    units = ["B", "KB", "MB", "GB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


def fmt_clock(at: str | float) -> str:
    """Time of day in Paris, like the log files and counts."""
    t = local(at) if isinstance(at, float) else datetime.fromisoformat(at)
    return t.astimezone(TZ).strftime("%H:%M:%S")


@dataclass(frozen=True)
class View:
    """One section's data for a time window, read from its command's logs."""

    window: Window
    logs: LogManager
    now: float = field(default_factory=time.time)

    @cached_property
    def buckets(self) -> list[Bucket]:
        return self.logs.counts(self.window)

    @cached_property
    def totals(self) -> Counter[str]:
        total: Counter[str] = Counter()
        for b in self.buckets:
            total.update(b.counts)
        return total

    def total(self, *keys: str) -> int:
        return sum(self.totals.get(k, 0) for k in keys)

    def faceted(self, prefix: str) -> list[tuple[str, float]]:
        """Totals of the keys `prefix:<value>`, largest first, by value."""
        rows = [
            (k.removeprefix(prefix), float(v))
            for k, v in self.totals.items()
            if k.startswith(prefix)
        ]
        return sorted(rows, key=lambda kv: -kv[1])

    def recent(self, kinds: Kinds) -> list[Record]:
        return self.logs.recent(kinds, self.window)

    def per_bucket(self, *keys: str) -> list[float | None]:
        return [float(sum(b.counts.get(k, 0) for k in keys)) for b in self.buckets]

    @property
    def labels(self) -> list[str]:
        fmt = {"minute": "%H:%M", "hour": "%H:00", "day": "%a %d %b"}[self.window.unit]
        return [local(b.start).strftime(fmt) for b in self.buckets]

    @property
    def per(self) -> str:
        return self.window.unit

    def describe(self) -> str:
        """The window in words, e.g. "Last 3 hours, since 12:00"."""
        since = local(self.window.since(self.now))
        if self.window.unit == "day":
            when = since.strftime("%a %d %b")
        elif since.date() == local(self.now).date():
            when = since.strftime("%H:%M")
        else:
            when = since.strftime("%a %d %b %H:%M")
        return f"{self.window.label()}, since {when}"


def record_time(record: Record) -> str:
    """Time of day, with the date when not today: windows reach back 100 days."""
    t = local(at_of(record))
    if t.date() == local(time.time()).date():
        return t.strftime("%H:%M:%S")
    return t.strftime("%a %d %b %H:%M:%S")


def attrs(record: Record) -> dict[str, Any]:
    return record.get("attributes") or {}


def alert_rows(view: View) -> list[dict[str, Any]]:
    return [
        {
            "time": record_time(r),
            "name": r["event_name"].removeprefix("siem.alert."),
            "ip": attrs(r).get("client.address", "–"),
            "message": r["body"],
        }
        for r in view.recent(ALERTS)
    ]


def top_counts(
    rows: list[dict[str, Any]], key: str, limit: int = 8
) -> list[tuple[str, float]]:
    """The most frequent values of `key` among `rows`, skipping empty ones."""
    counts: dict[str, float] = {}
    for row in rows:
        value = row.get(key)
        if value:
            counts[str(value)] = counts.get(str(value), 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])[:limit]


def _sources(snap: Snapshot) -> list[dict[str, str]]:
    return [
        {"name": SOURCE_NAMES.get(name, name), **src}
        for name, src in snap["sources"].items()
    ]


def _uptime_tile(snap: Snapshot) -> tuple[str, str, str]:
    return (
        "Uptime",
        fmt_duration(snap["uptime"]),
        f"since {fmt_clock(snap['started_at'])}",
    )


def _active_tile(active: list[dict[str, Any]]) -> tuple[str, str, str]:
    return (
        "Active connections",
        fmt_number(len(active)),
        fmt_bytes(sum(c["bytes"] for c in active)),
    )


def active_metrics(snap: Snapshot) -> Metrics:
    return {"active": len(snap["active_connections"])}


def _active_chart(samples: Samples, what: str) -> dict[str, Any]:
    """Live, whatever the window: open connections are not logged, only sampled."""
    return line_chart(
        "Active connections",
        f"Open {what} connections, sampled live over the last 10 minutes.",
        [fmt_clock(at) for at, _ in samples],
        [
            Series(
                "Active connections",
                "var(--series-1)",
                [m.get("active", 0) for _, m in samples],
            )
        ],
        fmt_number,
    )


def _events_chart(
    view: View, series: list[tuple[str, tuple[str, ...]]]
) -> dict[str, Any]:
    colors = ("var(--series-1)", "var(--series-2)", "var(--series-3)")
    return line_chart(
        f"Events per {view.per}",
        f"{view.describe()}.",
        view.labels,
        [
            Series(name, color, view.per_bucket(*keys))
            for (name, keys), color in zip(series, colors, strict=False)
        ],
        fmt_number,
    )


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    template: str
    # What the sampler keeps of each snapshot for the live charts; None keeps nothing.
    metrics: Callable[[Snapshot], Metrics] | None
    context: Callable[[Snapshot, Samples, View], dict[str, Any]]
    # The records its tables show, by name prefix; also served by the JSON API.
    kinds: dict[str, Kinds]


# --- ssh -------------------------------------------------------------------

AUTH_KINDS = {
    "login_success": "Successful login",
    "login_failure": "Failed login",
    "invalid_user": "Invalid user",
    "logout": "Logout",
}
SOURCE_NAMES = {"sshd_log": "sshd logs", "network": "Network sniffer"}
FAILED = ("siem.ssh.login_failure", "siem.ssh.invalid_user")
ALERTS: Kinds = ("siem.alert.",)
LOGINS: Kinds = tuple(f"siem.ssh.{k}" for k in AUTH_KINDS)


def top_failed_ips(
    logins: list[dict[str, Any]], limit: int = 8
) -> list[tuple[str, float]]:
    by_ip: dict[str, float] = {}
    for login in logins:
        if login["failed"]:
            by_ip[login["ip"]] = by_ip.get(login["ip"], 0) + 1
    return sorted(by_ip.items(), key=lambda kv: -kv[1])[:limit]


def _describe_edge(client: str, server: str, conns: list[Any]) -> str:
    total = sum(c["bytes"] for c in conns)
    longest = max(c["duration"] for c in conns)
    return (
        f"{client} → {server}: {len(conns)} connection(s), "
        f"{fmt_bytes(total)}, longest {fmt_duration(longest)}"
    )


def login_row(r: Record) -> dict[str, Any]:
    a = attrs(r)
    kind = r["event_name"].removeprefix("siem.ssh.")
    return {
        "time": record_time(r),
        "outcome": AUTH_KINDS.get(kind, kind),
        "failed": r["event_name"] in FAILED,
        "user": a.get("user.name", ""),
        "ip": a.get("client.address", ""),
        "port": a.get("client.port", ""),
        "method": a.get("siem.ssh.auth.method"),
    }


def ssh_context(snap: Snapshot, samples: Samples, view: View) -> dict[str, Any]:
    active = snap["active_connections"]
    logins = [login_row(r) for r in view.recent(LOGINS)]
    return {
        "sources": _sources(snap),
        "tiles": [
            _uptime_tile(snap),
            _active_tile(active),
            ("Successful logins", fmt_number(view.total("siem.ssh.login_success")), ""),
            ("Failed logins", fmt_number(view.total(*FAILED)), "incl. invalid users"),
            ("Alerts", fmt_number(view.total("alerts")), ""),
        ],
        "line_charts": [
            _active_chart(samples, "SSH"),
            _events_chart(
                view,
                [
                    ("New connections", ("siem.ssh.connection.opened",)),
                    ("Failed logins", FAILED),
                    ("Alerts", ("alerts",)),
                ],
            ),
        ],
        "bar_lists": [
            bar_list(
                "Authentication outcomes",
                view.describe(),
                [
                    (label, view.total(f"siem.ssh.{kind}"))
                    for kind, label in AUTH_KINDS.items()
                ],
                fmt_number,
            ),
            bar_list(
                "Top failing source addresses",
                f"Failed logins among the last {len(logins)} logins in the window.",
                top_failed_ips(logins),
                fmt_number,
                empty="No failed login.",
            ),
        ],
        "flow": flow_diagram(active, _describe_edge) if active else None,
        "alerts": alert_rows(view),
        "logins": logins,
        "config": snap["config"],
    }


# --- http ------------------------------------------------------------------

STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")
REQUESTS: Kinds = ("siem.http.request",)


def request_row(r: Record) -> dict[str, Any]:
    a = attrs(r)
    query = a.get("url.query")
    return {
        "time": record_time(r),
        "client_ip": a.get("client.address", ""),
        "client_port": a.get("client.port", ""),
        "method": a.get("http.request.method", ""),
        "host": a.get("http.request.header.host"),
        "target": a.get("url.path", "") + (f"?{query}" if query else ""),
        "user_agent": a.get("user_agent.original"),
        "rules": a.get("siem.http.rules") or [],
    }


def http_context(snap: Snapshot, samples: Samples, view: View) -> dict[str, Any]:
    active = snap["active_connections"]
    requests = [request_row(r) for r in view.recent(REQUESTS)]
    errors = ("status:4xx", "status:5xx")
    return {
        "sources": _sources(snap),
        "tiles": [
            _uptime_tile(snap),
            _active_tile(active),
            ("Requests", fmt_number(view.total("siem.http.request")), ""),
            ("Error responses", fmt_number(view.total(*errors)), "4xx and 5xx"),
            ("Suspicious requests", fmt_number(view.total("suspicious")), ""),
            ("Alerts", fmt_number(view.total("alerts")), ""),
        ],
        "line_charts": [
            _active_chart(samples, "HTTP"),
            _events_chart(
                view,
                [
                    ("Requests", ("siem.http.request",)),
                    ("Error responses", errors),
                    ("Suspicious requests", ("suspicious",)),
                ],
            ),
        ],
        "bar_lists": [
            bar_list(
                "Response status",
                view.describe(),
                [(c, view.total(f"status:{c}")) for c in STATUS_CLASSES],
                fmt_number,
            ),
            bar_list(
                "Attack patterns",
                f"Suspicious requests by rule. {view.describe()}.",
                view.faceted("rule:"),
                fmt_number,
                empty="No suspicious request.",
            ),
            bar_list(
                "Top client addresses",
                f"Among the last {len(requests)} requests in the window.",
                top_counts(requests, "client_ip"),
                fmt_number,
                empty="No request seen.",
            ),
            bar_list(
                "Top hosts",
                f"Host header of the last {len(requests)} requests in the window.",
                top_counts(requests, "host"),
                fmt_number,
                empty="No request seen.",
            ),
        ],
        "flow": flow_diagram(active, _describe_edge) if active else None,
        "alerts": alert_rows(view),
        "requests": requests,
        "config": snap["config"],
    }


# --- https -----------------------------------------------------------------

HANDSHAKE_KINDS = {
    "siem.https.client_hello": "TLS handshake",
    "siem.https.not_tls": "Not TLS",
    "siem.https.plaintext_http": "Plaintext HTTP",
}
HANDSHAKES: Kinds = tuple(HANDSHAKE_KINDS)


def handshake_row(r: Record) -> dict[str, Any]:
    a = attrs(r)
    version = a.get("tls.protocol.version")
    proto = str(a.get("tls.protocol.name", "tls")).upper()
    return {
        "time": record_time(r),
        "outcome": HANDSHAKE_KINDS.get(r["event_name"], r["event_name"]),
        "client_ip": a.get("client.address", ""),
        "client_port": a.get("client.port", ""),
        "server_ip": a.get("server.address", ""),
        "server_port": a.get("server.port", ""),
        "server_name": a.get("tls.server_name"),
        "version": f"{proto} {version}" if version else None,
        "alpn": a.get("tls.client.supported_alpn") or [],
    }


def https_context(snap: Snapshot, samples: Samples, view: View) -> dict[str, Any]:
    active = snap["active_connections"]
    handshakes = [handshake_row(r) for r in view.recent(HANDSHAKES)]
    hellos = [h for h in handshakes if h["outcome"] == "TLS handshake"]
    not_tls = ("siem.https.not_tls", "siem.https.plaintext_http")
    return {
        "sources": _sources(snap),
        "tiles": [
            _uptime_tile(snap),
            _active_tile(active),
            ("TLS handshakes", fmt_number(view.total("siem.https.client_hello")), ""),
            ("Without server name", fmt_number(view.total("no_sni")), "no SNI"),
            ("Legacy TLS", fmt_number(view.total("legacy_tls")), "below TLS 1.2"),
            ("Alerts", fmt_number(view.total("alerts")), ""),
        ],
        "line_charts": [
            _active_chart(samples, "HTTPS"),
            _events_chart(
                view,
                [
                    ("TLS handshakes", ("siem.https.client_hello",)),
                    ("Not TLS", not_tls),
                    ("Alerts", ("alerts",)),
                ],
            ),
        ],
        "bar_lists": [
            bar_list(
                "TLS versions offered",
                f"Highest version each client offered. {view.describe()}.",
                view.faceted("tls:"),
                fmt_number,
                empty="No handshake seen.",
            ),
            bar_list(
                "Connection openings",
                f"What clients sent first. {view.describe()}.",
                [(label, view.total(k)) for k, label in HANDSHAKE_KINDS.items()],
                fmt_number,
            ),
            bar_list(
                "Top server names",
                f"SNI of the last {len(hellos)} handshakes in the window.",
                top_counts(hellos, "server_name"),
                fmt_number,
                empty="No server name seen.",
            ),
            bar_list(
                "Top client addresses",
                f"Among the last {len(handshakes)} connections in the window.",
                top_counts(handshakes, "client_ip"),
                fmt_number,
                empty="No connection seen.",
            ),
        ],
        "flow": flow_diagram(active, _describe_edge) if active else None,
        "alerts": alert_rows(view),
        "handshakes": handshakes,
        "config": snap["config"],
    }


# --- dummy -----------------------------------------------------------------


def dummy_context(snap: Snapshot, samples: Samples, view: View) -> dict[str, Any]:
    rules = view.faceted("rule:")
    return {
        "tiles": [
            ("Events", fmt_number(view.total("allowed", "blocked")), ""),
            ("Blocked", fmt_number(view.total("blocked")), ""),
            ("Rules triggered", fmt_number(sum(v for _, v in rules)), ""),
        ],
        "line_charts": [
            line_chart(
                f"Events per {view.per}",
                f"Allowed and blocked traffic. {view.describe()}.",
                view.labels,
                [
                    Series("Allowed", "var(--series-1)", view.per_bucket("allowed")),
                    Series("Blocked", "var(--series-2)", view.per_bucket("blocked")),
                ],
                fmt_number,
            )
        ],
        "bar_lists": [
            bar_list(
                "Detections by rule",
                view.describe(),
                rules,
                fmt_number,
                empty="No rule triggered.",
            )
        ],
        "config": snap["config"],
    }


# One tab per command, keyed by command name, shown while that command runs.
SECTIONS = {
    "ssh": Section(
        "ssh",
        "SSH",
        "ssh.html",
        active_metrics,
        ssh_context,
        {"logins": LOGINS, "alerts": ALERTS},
    ),
    "http": Section(
        "http",
        "HTTP",
        "http.html",
        active_metrics,
        http_context,
        {"requests": REQUESTS, "alerts": ALERTS},
    ),
    "https": Section(
        "https",
        "HTTPS",
        "https.html",
        active_metrics,
        https_context,
        {"handshakes": HANDSHAKES, "alerts": ALERTS},
    ),
    "dummy": Section(
        "dummy", "Dummy", "dummy.html", None, dummy_context, {"ticks": ("siem.dummy.",)}
    ),
}
