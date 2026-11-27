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

from my_siem.logs import DEFAULT_WINDOW, LogManager, Window
from my_siem.logs.window import TIERS
from my_siem.version import VERSION
from my_siem.web.help import command_help
from my_siem.web.sections import SECTIONS, Metrics, Section, View, fmt_clock

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


class Dashboard:
    """One tab per running command, in the order the commands were given."""

    def __init__(
        self,
        snapshots: Mapping[str, Snapshot],
        logs: Mapping[str, LogManager],
        every: float,
    ) -> None:
        self.every = every
        self._snapshots = dict(snapshots)
        self._logs = dict(logs)
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

    def page(
        self,
        section_id: str,
        root: str,
        window: Window,
        theme: str | None = None,
    ) -> HTMLResponse:
        """`root` leads from the page back to the app root, so the links survive a
        proxy that mounts the app under a prefix."""
        section = self._section(section_id)
        html = _env.get_template("base.html").render(
            root=root,
            theme=theme if theme in THEMES else THEMES[0],
            commands=list(self._snapshots),
            sections=self.sections,
            section=section,
            every_ms=int(self.every * 1000),
            poll_choices=POLL_CHOICES,
            window=window,
            units=[(u, label, TIERS[u].keep) for u, label in UNIT_LABELS.items()],
            query=urlencode(window.to_json()),
            fragment=Markup(self.fragment(section, window)),
            help=self.helps[section.id],
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

        r.add_api_route("/", index, methods=["GET"])
        r.add_api_route("/ui/{section_id}", section, methods=["GET"])
        r.add_api_route("/ui/{section_id}/fragment", fragment, methods=["GET"])
        return r


def static_files() -> StaticFiles:
    return StaticFiles(directory=STATIC_DIR)
