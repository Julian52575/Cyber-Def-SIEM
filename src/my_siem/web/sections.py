"""What each dashboard section shows, built from a snapshot and its sampled history."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from my_siem.clock import TZ, local
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


def per_sample(totals: list[float]) -> list[float | None]:
    """Running totals to the increase since the previous sample.

    A drop means the SIEM restarted, so that point is unknown.
    """
    return [
        None if i == 0 or v < totals[i - 1] else v - totals[i - 1]
        for i, v in enumerate(totals)
    ]


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    template: str
    # What the sampler keeps of each snapshot for the charts; None keeps no history.
    metrics: Callable[[Snapshot], Metrics] | None
    context: Callable[[Snapshot, Samples], dict[str, Any]]


# --- ssh -------------------------------------------------------------------

AUTH_KINDS = {
    "login_success": "Successful login",
    "login_failure": "Failed login",
    "invalid_user": "Invalid user",
    "logout": "Logout",
}
SOURCE_NAMES = {"sshd_log": "sshd logs", "network": "Network sniffer"}
FAILED = ("login_failure", "invalid_user")


def _failed(counts: dict[str, int]) -> int:
    return sum(counts.get(k, 0) for k in FAILED)


def ssh_metrics(snap: Snapshot) -> Metrics:
    counts = snap["counts"]
    return {
        "active": len(snap["active_connections"]),
        "conn_opened": counts.get("conn_opened", 0),
        "failed": _failed(counts),
        "alerts": counts.get("alerts", 0),
    }


def top_failed_ips(
    logins: list[dict[str, Any]], limit: int = 8
) -> list[tuple[str, float]]:
    by_ip: dict[str, float] = {}
    for login in logins:
        if login["kind"] in FAILED:
            by_ip[login["ip"]] = by_ip.get(login["ip"], 0) + 1
    return sorted(by_ip.items(), key=lambda kv: -kv[1])[:limit]


def _describe_edge(client: str, server: str, conns: list[Any]) -> str:
    total = sum(c["bytes"] for c in conns)
    longest = max(c["duration"] for c in conns)
    return (
        f"{client} → {server}: {len(conns)} connection(s), "
        f"{fmt_bytes(total)}, longest {fmt_duration(longest)}"
    )


def ssh_context(snap: Snapshot, samples: Samples) -> dict[str, Any]:
    counts = snap["counts"]
    active = snap["active_connections"]
    logins = snap["recent_logins"]
    times = [fmt_clock(at) for at, _ in samples]

    def column(key: str) -> list[float]:
        return [m[key] for _, m in samples]

    return {
        "sources": [
            {"name": SOURCE_NAMES.get(name, name), **src}
            for name, src in snap["sources"].items()
        ],
        "tiles": [
            (
                "Uptime",
                fmt_duration(snap["uptime"]),
                f"since {fmt_clock(snap['started_at'])}",
            ),
            (
                "Active connections",
                fmt_number(len(active)),
                fmt_bytes(sum(c["bytes"] for c in active)),
            ),
            ("Successful logins", fmt_number(counts.get("login_success", 0)), ""),
            ("Failed logins", fmt_number(_failed(counts)), "incl. invalid users"),
            ("Alerts", fmt_number(counts.get("alerts", 0)), ""),
        ],
        "line_charts": [
            line_chart(
                "Active connections",
                "Open SSH connections at each sample.",
                times,
                [Series("Active connections", "var(--series-1)", column("active"))],
                fmt_number,
            ),
            line_chart(
                "New events per sample",
                "Increase since the previous sample.",
                times,
                [
                    Series(
                        "New connections",
                        "var(--series-1)",
                        per_sample(column("conn_opened")),
                    ),
                    Series(
                        "Failed logins", "var(--series-2)", per_sample(column("failed"))
                    ),
                    Series("Alerts", "var(--series-3)", per_sample(column("alerts"))),
                ],
                fmt_number,
            ),
        ],
        "bar_lists": [
            bar_list(
                "Authentication outcomes",
                "Since the SIEM started.",
                [(label, counts.get(kind, 0)) for kind, label in AUTH_KINDS.items()],
                fmt_number,
            ),
            bar_list(
                "Top failing source addresses",
                f"Failed logins among the last {len(logins)} logins.",
                top_failed_ips(logins),
                fmt_number,
                empty="No failed login.",
            ),
        ],
        "flow": flow_diagram(active, _describe_edge) if active else None,
        "alerts": [
            {**a, "time": fmt_clock(a["at"])} for a in reversed(snap["recent_alerts"])
        ],
        "logins": [
            {
                **login,
                "time": fmt_clock(login["at"]),
                "outcome": AUTH_KINDS.get(login["kind"], login["kind"]),
            }
            for login in reversed(logins)
        ],
        "config": snap["config"],
    }


# --- shared by http and https -----------------------------------------------


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


def _alerts(snap: Snapshot) -> list[dict[str, Any]]:
    return [{**a, "time": fmt_clock(a["at"])} for a in reversed(snap["recent_alerts"])]


def _column(samples: Samples, key: str) -> list[float]:
    return [m.get(key, 0) for _, m in samples]


# --- http ------------------------------------------------------------------

STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")


def http_metrics(snap: Snapshot) -> Metrics:
    counts = snap["counts"]
    statuses = snap["status_classes"]
    return {
        "active": len(snap["active_connections"]),
        "requests": counts.get("requests", 0),
        "errors": statuses.get("4xx", 0) + statuses.get("5xx", 0),
        "suspicious": counts.get("suspicious", 0),
    }


def http_context(snap: Snapshot, samples: Samples) -> dict[str, Any]:
    counts = snap["counts"]
    statuses = snap["status_classes"]
    active = snap["active_connections"]
    requests = snap["recent_requests"]
    times = [fmt_clock(at) for at, _ in samples]
    errors = statuses.get("4xx", 0) + statuses.get("5xx", 0)
    return {
        "sources": _sources(snap),
        "tiles": [
            _uptime_tile(snap),
            _active_tile(active),
            ("Requests", fmt_number(counts.get("requests", 0)), ""),
            ("Error responses", fmt_number(errors), "4xx and 5xx"),
            ("Suspicious requests", fmt_number(counts.get("suspicious", 0)), ""),
            ("Alerts", fmt_number(counts.get("alerts", 0)), ""),
        ],
        "line_charts": [
            line_chart(
                "Active connections",
                "Open HTTP connections at each sample.",
                times,
                [
                    Series(
                        "Active connections",
                        "var(--series-1)",
                        _column(samples, "active"),
                    )
                ],
                fmt_number,
            ),
            line_chart(
                "New events per sample",
                "Increase since the previous sample.",
                times,
                [
                    Series(
                        "Requests",
                        "var(--series-1)",
                        per_sample(_column(samples, "requests")),
                    ),
                    Series(
                        "Error responses",
                        "var(--series-2)",
                        per_sample(_column(samples, "errors")),
                    ),
                    Series(
                        "Suspicious requests",
                        "var(--series-3)",
                        per_sample(_column(samples, "suspicious")),
                    ),
                ],
                fmt_number,
            ),
        ],
        "bar_lists": [
            bar_list(
                "Response status",
                "Since the SIEM started.",
                [(c, statuses.get(c, 0)) for c in STATUS_CLASSES],
                fmt_number,
            ),
            bar_list(
                "Attack patterns",
                "Suspicious requests by rule, since the SIEM started.",
                sorted(snap["rules"].items(), key=lambda kv: -kv[1]),
                fmt_number,
                empty="No suspicious request.",
            ),
            bar_list(
                "Top client addresses",
                f"Among the last {len(requests)} requests.",
                top_counts(requests, "client_ip"),
                fmt_number,
                empty="No request seen.",
            ),
            bar_list(
                "Top hosts",
                f"Host header of the last {len(requests)} requests.",
                top_counts(requests, "host"),
                fmt_number,
                empty="No request seen.",
            ),
        ],
        "flow": flow_diagram(active, _describe_edge) if active else None,
        "alerts": _alerts(snap),
        "requests": [{**r, "time": fmt_clock(r["at"])} for r in reversed(requests)],
        "config": snap["config"],
    }


# --- https -----------------------------------------------------------------


def https_metrics(snap: Snapshot) -> Metrics:
    counts = snap["counts"]
    return {
        "active": len(snap["active_connections"]),
        "handshakes": counts.get("hello", 0),
        "conn_opened": counts.get("conn_opened", 0),
        "alerts": counts.get("alerts", 0),
    }


HANDSHAKE_KINDS = {
    "hello": "TLS handshake",
    "not_tls": "Not TLS",
    "plaintext_http": "Plaintext HTTP",
}


def https_context(snap: Snapshot, samples: Samples) -> dict[str, Any]:
    counts = snap["counts"]
    active = snap["active_connections"]
    handshakes = snap["recent_handshakes"]
    hellos = [h for h in handshakes if h["kind"] == "hello"]
    times = [fmt_clock(at) for at, _ in samples]
    return {
        "sources": _sources(snap),
        "tiles": [
            _uptime_tile(snap),
            _active_tile(active),
            ("TLS handshakes", fmt_number(counts.get("hello", 0)), ""),
            ("Without server name", fmt_number(counts.get("no_sni", 0)), "no SNI"),
            ("Legacy TLS", fmt_number(counts.get("legacy_tls", 0)), "below TLS 1.2"),
            ("Alerts", fmt_number(counts.get("alerts", 0)), ""),
        ],
        "line_charts": [
            line_chart(
                "Active connections",
                "Open HTTPS connections at each sample.",
                times,
                [
                    Series(
                        "Active connections",
                        "var(--series-1)",
                        _column(samples, "active"),
                    )
                ],
                fmt_number,
            ),
            line_chart(
                "New events per sample",
                "Increase since the previous sample.",
                times,
                [
                    Series(
                        "New connections",
                        "var(--series-1)",
                        per_sample(_column(samples, "conn_opened")),
                    ),
                    Series(
                        "TLS handshakes",
                        "var(--series-2)",
                        per_sample(_column(samples, "handshakes")),
                    ),
                    Series(
                        "Alerts",
                        "var(--series-3)",
                        per_sample(_column(samples, "alerts")),
                    ),
                ],
                fmt_number,
            ),
        ],
        "bar_lists": [
            bar_list(
                "TLS versions offered",
                "Highest version each client offered, since the SIEM started.",
                sorted(snap["tls_versions"].items(), key=lambda kv: -kv[1]),
                fmt_number,
                empty="No handshake seen.",
            ),
            bar_list(
                "Connection openings",
                "What clients sent first, since the SIEM started.",
                [(label, counts.get(k, 0)) for k, label in HANDSHAKE_KINDS.items()],
                fmt_number,
            ),
            bar_list(
                "Top server names",
                f"SNI of the last {len(hellos)} handshakes.",
                top_counts(hellos, "server_name"),
                fmt_number,
                empty="No server name seen.",
            ),
            bar_list(
                "Top client addresses",
                f"Among the last {len(handshakes)} connections.",
                top_counts(handshakes, "client_ip"),
                fmt_number,
                empty="No connection seen.",
            ),
        ],
        "flow": flow_diagram(active, _describe_edge) if active else None,
        "alerts": _alerts(snap),
        "handshakes": [
            {
                **h,
                "time": fmt_clock(h["at"]),
                "outcome": HANDSHAKE_KINDS.get(h["kind"], h["kind"]),
            }
            for h in reversed(handshakes)
        ],
        "config": snap["config"],
    }


# --- dummy -----------------------------------------------------------------


def dummy_context(snap: Snapshot, samples: Samples) -> dict[str, Any]:
    hours = [f"{h:02d}:00" for h in range(24)]
    allowed: list[float] = snap["allowed"]
    blocked: list[float] = snap["blocked"]
    rules = sorted(snap["rules"].items(), key=lambda r: -r[1])
    return {
        "tiles": [
            ("Events (24h)", fmt_number(sum(allowed) + sum(blocked)), ""),
            ("Blocked (24h)", fmt_number(sum(blocked)), ""),
            ("Rules triggered", fmt_number(sum(v for _, v in rules)), ""),
        ],
        "line_charts": [
            line_chart(
                "Events per hour",
                "Allowed and blocked traffic, by hour of the day.",
                hours,
                [
                    Series("Allowed", "var(--series-1)", allowed),
                    Series("Blocked", "var(--series-2)", blocked),
                ],
                fmt_number,
            )
        ],
        "bar_lists": [
            bar_list(
                "Detections by rule", "Since the command started.", rules, fmt_number
            )
        ],
        "config": snap["config"],
    }


# One tab per command, keyed by command name, shown while that command runs.
SECTIONS = {
    "ssh": Section("ssh", "SSH", "ssh.html", ssh_metrics, ssh_context),
    "http": Section("http", "HTTP", "http.html", http_metrics, http_context),
    "https": Section("https", "HTTPS", "https.html", https_metrics, https_context),
    "dummy": Section("dummy", "Dummy", "dummy.html", None, dummy_context),
}
