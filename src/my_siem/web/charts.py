"""Chart geometry, computed here so the templates only place what they are given."""

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

type Fmt = Callable[[float], str]


def nice_ticks(top: float, count: int = 4) -> list[float]:
    """Clean steps (1, 2, 5 x 10^k) from 0 to at least `top`, so the axis reads at a glance."""
    top = max(top, 1)
    raw = top / count
    mag = 10 ** math.floor(math.log10(raw))
    step = next(s for s in (f * mag for f in (1, 2, 5, 10)) if s >= raw)
    ticks: list[float] = []
    v = 0.0
    while v < top + step:
        ticks.append(round(v, 6))
        v += step
    return ticks


@dataclass(frozen=True)
class Series:
    name: str
    color: str
    values: Sequence[float | None]


def line_chart(
    title: str, subtitle: str, labels: list[str], series: list[Series], fmt: Fmt
) -> dict[str, Any]:
    """A line chart in a 0-100 viewBox, stretched to its box by the SVG.

    Axis labels stay in HTML so they keep their size at any width.
    """
    n = len(labels)
    values = [v for s in series for v in s.values if v is not None]
    ticks = nice_ticks(max(values, default=0))
    top = ticks[-1]

    def x(i: int) -> float:
        return 50.0 if n <= 1 else i * 100 / (n - 1)

    def y(v: float) -> float:
        return 100 - v / top * 100

    def path(vals: Sequence[float | None]) -> str:
        d = []
        for i, v in enumerate(vals):
            if v is None:
                continue
            start = i == 0 or vals[i - 1] is None
            d.append(f"{'M' if start else 'L'}{x(i):.2f},{y(v):.2f}")
            # A lone point has no segment to draw; a zero-length one shows as a dot.
            if start and (i == len(vals) - 1 or vals[i + 1] is None):
                d.append(f"L{x(i):.2f},{y(v):.2f}")
        return "".join(d)

    def cell(v: float | None) -> str:
        return "–" if v is None else fmt(v)

    width = 100 / max(n - 1, 1)
    columns = [
        {
            "x": x(i) - width / 2,
            "width": width,
            "title": "\n".join(
                [labels[i]] + [f"{s.name}: {cell(s.values[i])}" for s in series]
            ),
        }
        for i in range(n)
    ]
    x_ticks = [labels[i] for i in sorted({0, (n - 1) // 2, n - 1})] if n else []
    return {
        "title": title,
        "subtitle": subtitle,
        "empty": n == 0,
        "series": [
            {"name": s.name, "color": s.color, "d": path(s.values)} for s in series
        ],
        "y_ticks": [{"label": fmt(t), "pct": t / top * 100, "y": y(t)} for t in ticks],
        "x_ticks": x_ticks,
        "columns": columns,
        "table": {
            "head": [s.name for s in series],
            "rows": [
                [labels[i], *(cell(s.values[i]) for s in series)] for i in range(n)
            ],
        },
    }


def bar_list(
    title: str,
    subtitle: str,
    rows: list[tuple[str, float]],
    fmt: Fmt,
    empty: str = "No data yet.",
) -> dict[str, Any]:
    top = max([1, *(v for _, v in rows)])
    return {
        "title": title,
        "subtitle": subtitle,
        "empty": empty,
        "rows": [
            {"label": label, "value": fmt(v), "pct": v / top * 100} for label, v in rows
        ],
    }


FLOW_W = 640
FLOW_ROW = 34
FLOW_NODE_W = 190
MAX_CLIENTS = 10


def flow_diagram(
    connections: list[dict[str, Any]], describe: Callable[[str, str, list[Any]], str]
) -> dict[str, Any]:
    """Clients on the left, this host's SSH endpoints on the right, one curve per pair."""
    by_client: dict[str, list[dict[str, Any]]] = {}
    for c in connections:
        by_client.setdefault(c["client_ip"], []).append(c)
    ranked = sorted(by_client.items(), key=lambda kv: -len(kv[1]))
    clients = [ip for ip, _ in ranked[:MAX_CLIENTS]]
    if len(ranked) > MAX_CLIENTS:
        clients.append(f"+{len(ranked) - MAX_CLIENTS} more")

    edges: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for ip, conns in ranked:
        client = ip if ip in clients else clients[-1]
        for c in conns:
            server = f"{c['server_ip']}:{c['server_port']}"
            edges.setdefault((client, server), []).append(c)
    servers = sorted({server for _, server in edges})

    rows = max(len(clients), len(servers), 1)
    height = rows * FLOW_ROW + 16

    def cy(i: int, count: int) -> float:
        return 8 + (rows - count) * FLOW_ROW / 2 + i * FLOW_ROW + FLOW_ROW / 2

    left, right = FLOW_NODE_W, FLOW_W - FLOW_NODE_W
    mid = (left + right) / 2
    paths = []
    for (client, server), conns in edges.items():
        y1 = cy(clients.index(client), len(clients))
        y2 = cy(servers.index(server), len(servers))
        paths.append(
            {
                "d": f"M{left},{y1} C{mid},{y1} {mid},{y2} {right},{y2}",
                "title": describe(client, server, conns),
                "count": len(conns),
                "label_x": mid,
                "label_y": (y1 + y2) / 2 - 6,
            }
        )
    return {
        "width": FLOW_W,
        "height": height,
        "node_w": FLOW_NODE_W - 8,
        "right": right,
        "edges": paths,
        "clients": [
            {"label": c, "y": cy(i, len(clients))} for i, c in enumerate(clients)
        ],
        "servers": [
            {"label": s, "y": cy(i, len(servers))} for i, s in enumerate(servers)
        ],
    }
