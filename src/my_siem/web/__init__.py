"""Server-rendered dashboard, kept live by Server-Sent Events."""

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator, Callable, Mapping
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, PackageLoader
from markupsafe import Markup

from my_siem.web.sections import SECTIONS, Metrics, Section, fmt_clock

type Snapshot = Callable[[], dict[str, Any]]

STATIC_DIR = Path(__file__).parent / "static"
# ~10 minutes of history at the default 5 s.
MAX_SAMPLES = 120

# Usernames in sshd logs are attacker-controlled: autoescape everything, run no inline script.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
UI_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff"}

_env = Environment(loader=PackageLoader("my_siem.web"), autoescape=True)
_env.filters["clock"] = fmt_clock


class History:
    """What a section's metrics were at each sample, filled while the app runs."""

    def __init__(
        self, snapshot: Snapshot, metrics: Callable[[dict[str, Any]], Metrics]
    ) -> None:
        self._snapshot = snapshot
        self._metrics = metrics
        self.samples: deque[tuple[float, Metrics]] = deque(maxlen=MAX_SAMPLES)

    def record(self) -> None:
        self.samples.append((time.time(), self._metrics(self._snapshot())))

    async def run(self, every: float) -> None:
        while True:
            self.record()
            await asyncio.sleep(every)


def sse(event: str, data: str) -> str:
    # Each line of the payload needs its own `data:` field.
    lines = "".join(f"data: {line}\n" for line in data.splitlines())
    return f"event: {event}\n{lines}\n"


class Dashboard:
    """One tab per running command, in the order the commands were given."""

    def __init__(self, snapshots: Mapping[str, Snapshot], every: float) -> None:
        self.every = every
        self._snapshots = dict(snapshots)
        self.sections = [SECTIONS[name] for name in snapshots]
        self.histories = {
            s.id: History(snapshots[s.id], s.metrics)
            for s in self.sections
            if s.metrics
        }

    async def run_samplers(self) -> None:
        async with asyncio.TaskGroup() as tg:
            for h in self.histories.values():
                tg.create_task(h.run(self.every))

    def _section(self, section_id: str) -> Section:
        for s in self.sections:
            if s.id == section_id:
                return s
        raise HTTPException(404, f"no section {section_id!r}")

    def fragment(self, section: Section) -> str:
        history = self.histories.get(section.id)
        ctx = section.context(
            self._snapshots[section.id](), list(history.samples) if history else []
        )
        return _env.get_template(section.template).render(**ctx, updated=time.time())

    def page(self, section_id: str) -> HTMLResponse:
        section = self._section(section_id)
        html = _env.get_template("base.html").render(
            commands=list(self._snapshots),
            sections=self.sections,
            section=section,
            fragment=Markup(self.fragment(section)),
        )
        return HTMLResponse(html, headers=UI_HEADERS)

    def stream(self, section_id: str) -> StreamingResponse:
        section = self._section(section_id)

        async def events() -> AsyncIterator[str]:
            # The browser reconnects by itself, e.g. after the SIEM restarts.
            yield f"retry: {int(self.every * 1000)}\n\n"
            while True:
                yield sse("update", self.fragment(section))
                await asyncio.sleep(self.every)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", **UI_HEADERS},
        )

    def router(self) -> APIRouter:
        r = APIRouter(include_in_schema=False)
        first = self.sections[0].id
        # Served in place, not redirected: a redirect behind a proxy can lose the port.
        r.add_api_route("/", lambda: self.page(first), methods=["GET"])
        r.add_api_route("/ui/{section_id}", self.page, methods=["GET"])
        r.add_api_route("/ui/{section_id}/stream", self.stream, methods=["GET"])
        return r


def static_files() -> StaticFiles:
    return StaticFiles(directory=STATIC_DIR)
