"""Server-rendered dashboard, kept live by polling for re-rendered fragments."""

import asyncio
import hashlib
import time
from collections import deque
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Cookie, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, PackageLoader
from markupsafe import Markup

from my_siem.clock import local
from my_siem.logs import DEFAULT_WINDOW, LogManager, Window
from my_siem.logs.importer import UNITS, Importer
from my_siem.logs.window import TIERS
from my_siem.version import VERSION
from my_siem.web.admin import AdminPanel, FolderUsage, Job
from my_siem.web.help import command_help
from my_siem.web.sections import (
    SECTIONS,
    Metrics,
    Section,
    View,
    fmt_bytes,
    fmt_clock,
)

type Snapshot = Callable[[], dict[str, Any]]

STATIC_DIR = Path(__file__).parent / "static"


def _asset_version() -> str:
    """Changes whenever a static file does, so browsers drop their cached copy."""
    digest = hashlib.sha256()
    for f in sorted(STATIC_DIR.iterdir()):
        digest.update(f.read_bytes())
    return digest.hexdigest()[:12]


# ~10 minutes of history at the default 5 s.
MAX_SAMPLES = 120
# Seconds between dashboard refreshes the reader can pick from.
POLL_CHOICES = (1, 2, 5, 10, 15, 30, 60)
THEMES = ("dark", "light")
# Set by live.js; read here so the chosen theme renders without a flash of the other.
THEME_COOKIE = "my_siem_theme"
ThemeCookie = Annotated[str | None, Cookie(alias=THEME_COOKIE)]

# Usernames in sshd logs are attacker-controlled: autoescape everything, run no inline script.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
UI_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff"}

_env = Environment(loader=PackageLoader("my_siem.web"), autoescape=True)
_env.filters["clock"] = fmt_clock
_env.globals["version"] = VERSION
_env.globals["asset_version"] = _asset_version()


class History:
    """What a section's metrics were at each sample, filled while the app runs."""

    def __init__(
        self, snapshot: Snapshot, metrics: Callable[[dict[str, Any]], Metrics]
    ) -> None:
        self._snapshot = snapshot
        self._metrics = metrics
        self.samples: deque[tuple[float, Metrics]] = deque(maxlen=MAX_SAMPLES)

    def record(self, at: float | None = None) -> None:
        at = time.time() if at is None else at
        self.samples.append((at, self._metrics(self._snapshot())))

    async def run(self, every: float) -> None:
        """Sample on wall-clock multiples of `every` (:00, :05...), whenever we started."""
        while True:
            await asyncio.sleep(every - time.time() % every)
            # Stamped on the boundary, not the few ms the wakeup lands after it.
            self.record(round(time.time() / every) * every)


UNIT_LABELS = {"minute": "Minutes", "hour": "Hours", "day": "Days"}
UnitQuery = Annotated[str | None, Query()]
CountQuery = Annotated[int | None, Query()]


def ui_window(unit: str | None, count: int | None) -> Window:
    """The window a page asks for, forgiving: a bad unit or count falls back or clamps."""
    if unit not in TIERS:
        return (
            DEFAULT_WINDOW if count is None else ui_window(DEFAULT_WINDOW.unit, count)
        )
    keep = TIERS[unit].keep
    return Window(unit, keep if count is None else min(max(count, 1), keep))


STATE_BADGES = {
    "running": "badge-warning",
    "done": "badge-good",
    "failed": "badge-critical",
}


def fmt_at(at: float | None, now: float) -> str:
    """Paris time, with the date when not today."""
    if at is None:
        return "–"
    t = local(at)
    day = "" if t.date() == local(now).date() else t.strftime("%a %d %b ")
    return f"{day}{t:%H:%M:%S}"


def _hour(at: int | None) -> str:
    return "–" if at is None else local(at).strftime("%a %d %b %H:00")


def _usage_row(name: str, folders: list[FolderUsage]) -> dict[str, Any]:
    cap = folders[0].cap_bytes if len(folders) == 1 else None
    share = sum(f.log_bytes for f in folders) / cap if cap else None
    return {
        "name": name,
        "files": f"{sum(f.log_files for f in folders):,}",
        "plain": fmt_bytes(sum(f.plain_bytes for f in folders)),
        "gz": fmt_bytes(sum(f.gz_bytes for f in folders)),
        "other": fmt_bytes(sum(f.other_bytes for f in folders)),
        "total": fmt_bytes(sum(f.total_bytes for f in folders)),
        "share": None if share is None else min(share, 1.0),
        "share_text": None if share is None else f"{share:.0%}",
        "oldest": _hour(min((f.oldest for f in folders if f.oldest), default=None)),
        "newest": _hour(max((f.newest for f in folders if f.newest), default=None)),
    }


class Dashboard:
    """One tab per running command, in the order the commands were given, then the
    admin tab."""

    def __init__(
        self,
        snapshots: Mapping[str, Snapshot],
        logs: Mapping[str, LogManager],
        every: float,
        admin: AdminPanel | None = None,
    ) -> None:
        self.every = every
        self._snapshots = dict(snapshots)
        self._logs = dict(logs)
        self.admin = admin or AdminPanel(logs, Importer(logs, {}), None, None)
        self.sections = [SECTIONS[name] for name in snapshots]
        self.histories = {
            s.id: History(snapshots[s.id], s.metrics)
            for s in self.sections
            if s.metrics
        }
        # Read once: the READMEs ship with the package and never change while running.
        self.helps = {s.id: command_help(s.id) for s in self.sections}

    async def run_samplers(self) -> None:
        async with asyncio.TaskGroup() as tg:
            for h in self.histories.values():
                tg.create_task(h.run(self.every))

    def _section(self, section_id: str) -> Section:
        for s in self.sections:
            if s.id == section_id:
                return s
        raise HTTPException(404, f"no section {section_id!r}")

    def view(self, section_id: str, window: Window) -> View:
        return View(window, self._logs[section_id])

    def fragment(self, section: Section, window: Window) -> str:
        history = self.histories.get(section.id)
        view = self.view(section.id, window)
        ctx = section.context(
            self._snapshots[section.id](),
            list(history.samples) if history else [],
            view,
        )
        return _env.get_template(section.template).render(
            **ctx, updated=time.time(), window=view.describe()
        )

    def _layout(
        self, root: str, window: Window, theme: str | None, current: str
    ) -> dict[str, Any]:
        """What every page's top bar and tabs need. `root` leads from the page back to
        the app root, so the links survive a proxy that mounts the app under a prefix."""
        return {
            "root": root,
            "theme": theme if theme in THEMES else THEMES[0],
            "commands": list(self._snapshots),
            "sections": self.sections,
            "current": current,
            "every_ms": int(self.every * 1000),
            "poll_choices": POLL_CHOICES,
            # The admin tab has no window, but keeps it for the tabs it links back to.
            "query": urlencode(window.to_json()),
        }

    def page(
        self,
        section_id: str,
        root: str,
        window: Window,
        theme: str | None = None,
    ) -> HTMLResponse:
        section = self._section(section_id)
        html = _env.get_template("section.html").render(
            **self._layout(root, window, theme, section.id),
            title=section.title,
            window=window,
            units=[(u, label, TIERS[u].keep) for u, label in UNIT_LABELS.items()],
            fragment=Markup(self.fragment(section, window)),
            help=self.helps[section.id],
        )
        return HTMLResponse(html, headers=UI_HEADERS)

    # --- admin tab ----------------------------------------------------------

    def jobs(self) -> list[Job]:
        """Every service's scheduled jobs."""
        jobs = self.admin.jobs()
        for s in self.sections:
            history = self.histories.get(s.id)
            if history is not None:
                last = history.samples[-1][0] if history.samples else None
                jobs.append(
                    Job(
                        f"Dashboard ({s.id})",
                        "Sample active connections for the live chart",
                        f"Every {self.every:g} s",
                        last,
                    )
                )
        return jobs

    def jobs_card(self) -> str:
        """Rendered with the page only: the frequencies say when jobs run, no polling."""
        now = time.time()
        rows = [{**j.to_json(), "last": fmt_at(j.last, now)} for j in self.jobs()]
        return _env.get_template("admin_jobs.html").render(
            jobs=rows, updated=now, state_badges=STATE_BADGES
        )

    def usage_card(self, root: str, window: Window) -> str:
        folders = self.admin.usage()
        retention = self.admin.retention
        return _env.get_template("admin_usage.html").render(
            root=root,
            query=urlencode(window.to_json()),
            log_root=self.admin.log_root,
            scanned=time.time(),
            cap=fmt_bytes(retention.max_size_mb * 1024 * 1024) if retention else "–",
            folders=[_usage_row(f.name, [f]) for f in folders],
            all=_usage_row("All", folders),
        )

    def admin_page(
        self, root: str, window: Window, theme: str | None = None
    ) -> HTMLResponse:
        importer = self.admin.importer
        html = _env.get_template("admin.html").render(
            **self._layout(root, window, theme, "admin"),
            title="Admin",
            help=None,
            jobs=Markup(self.jobs_card()),
            usage=Markup(self.usage_card(root, window)),
            log_root=self.admin.log_root,
            import_token=importer.token,
            sources=[
                {"name": name, "where": s.where} for name, s in importer.sources.items()
            ],
            units=[(u, UNIT_LABELS[u], importer.max_count(u)) for u in UNITS],
        )
        return HTMLResponse(html, headers=UI_HEADERS)

    def router(self) -> APIRouter:
        r = APIRouter(include_in_schema=False)
        first = self.sections[0].id

        # Served in place, not redirected: a redirect behind a proxy can lose the port.
        def index(
            theme: ThemeCookie = None, unit: UnitQuery = None, count: CountQuery = None
        ) -> HTMLResponse:
            return self.page(first, "./", ui_window(unit, count), theme)

        def section(
            section_id: str,
            theme: ThemeCookie = None,
            unit: UnitQuery = None,
            count: CountQuery = None,
        ) -> HTMLResponse:
            return self.page(section_id, "../", ui_window(unit, count), theme)

        def fragment(
            section_id: str, unit: UnitQuery = None, count: CountQuery = None
        ) -> HTMLResponse:
            """Polled rather than streamed: some proxies only forward responses that end."""
            html = self.fragment(self._section(section_id), ui_window(unit, count))
            return HTMLResponse(
                html, headers={"Cache-Control": "no-store", **UI_HEADERS}
            )

        def admin(
            theme: ThemeCookie = None, unit: UnitQuery = None, count: CountQuery = None
        ) -> HTMLResponse:
            return self.admin_page("../", ui_window(unit, count), theme)

        def usage(unit: UnitQuery = None, count: CountQuery = None) -> HTMLResponse:
            # Relative to the page that swaps it in, /ui/admin.
            html = self.usage_card("../", ui_window(unit, count))
            return HTMLResponse(
                html, headers={"Cache-Control": "no-store", **UI_HEADERS}
            )

        r.add_api_route("/", index, methods=["GET"])
        # Before /ui/{section_id}, which would take "admin" for a command.
        r.add_api_route("/ui/admin", admin, methods=["GET"])
        r.add_api_route("/ui/admin/usage", usage, methods=["GET"])
        r.add_api_route("/ui/{section_id}", section, methods=["GET"])
        r.add_api_route("/ui/{section_id}/fragment", fragment, methods=["GET"])
        return r


def static_files() -> StaticFiles:
    return StaticFiles(directory=STATIC_DIR)
