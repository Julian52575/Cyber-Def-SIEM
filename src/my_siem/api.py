"""HTTP server for the running commands: dashboard and live data (`--api`).

Read-only but for one route, which starts a log import from the admin tab.
"""

import asyncio
import socket
import threading
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from my_siem.live import iso
from my_siem.logs import DEFAULT_WINDOW, LogManager, Retention, Window
from my_siem.logs.importer import ImportBusy, Importer, ImportJob, Source
from my_siem.web import Dashboard, static_files
from my_siem.web.admin import AdminPanel
from my_siem.web.sections import SECTIONS

type Snapshot = Callable[[], dict[str, Any]]

READ_METHODS = frozenset({"GET", "HEAD"})
# The only writes: each also has to come from the dashboard itself (see `_cross_site`).
WRITE_ROUTES = frozenset({("POST", "/admin/import")})
SAMPLE_EVERY = 5.0


def _host_pattern(host: str) -> str:
    # The Host header brackets IPv6 addresses.
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _cross_site(request: Request, hosts: frozenset[str]) -> Response | None:
    """Refuse a write a browser was made to send from another site (CSRF).

    A page elsewhere can submit a form here, but not with a JSON body, nor with its own
    Origin passing for ours. Clients that are not browsers send no Origin.
    """
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        return JSONResponse({"detail": "expected a JSON body"}, status_code=415)
    origin = request.headers.get("origin")
    site = request.headers.get("sec-fetch-site", "same-origin")
    if (origin is not None and urlsplit(origin).hostname not in hosts) or site not in {
        "same-origin",
        "none",
    }:
        return JSONResponse({"detail": "cross-site write refused"}, status_code=403)
    return None


def create_app(
    snapshots: Mapping[str, Snapshot],
    allowed_hosts: Sequence[str],
    every: float = SAMPLE_EVERY,
    logs: Mapping[str, LogManager] | None = None,
    sources: Mapping[str, Source] | None = None,
    log_root: Path | None = None,
    retention: Retention | None = None,
) -> FastAPI:
    """`snapshots` gives the live state of each running command, by name, and `logs`
    what they logged (default: empty, in memory). The admin tab imports past events
    from `sources`, and scans the log folders under `log_root`."""
    if logs is None:
        logs = {name: LogManager(name, None) for name in snapshots}
    importer = Importer(logs, sources or {})
    admin = AdminPanel(logs, importer, log_root, retention)
    dashboard = Dashboard(snapshots, logs, every, admin)
    hosts = frozenset(h.strip("[]") for h in allowed_hosts)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        samplers = asyncio.create_task(dashboard.run_samplers())
        yield
        samplers.cancel()

    app = FastAPI(
        title="my_siem",
        description="Live monitoring data of my_siem",
        lifespan=lifespan,
    )
    # Against DNS rebinding: a page whose name resolves to this host would otherwise
    # be same-origin with it and could read the logins.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[_host_pattern(h) for h in allowed_hosts],
    )

    # Added last so it runs first: no other write can reach a route.
    @app.middleware("http")
    async def read_only(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method not in READ_METHODS:
            if (request.method, request.url.path) not in WRITE_ROUTES:
                return JSONResponse(
                    {"detail": "read-only API"},
                    status_code=405,
                    headers={"Allow": ", ".join(sorted(READ_METHODS))},
                )
            refused = _cross_site(request, hosts)
            if refused is not None:
                return refused
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "commands": list(snapshots)}

    for name in snapshots:
        app.add_api_route(
            f"/{name}",
            _state_route(name, snapshots[name], logs[name]),
            methods=["GET"],
            summary=f"State of the `{name}` command, and what it logged in a window",
        )
    _admin_routes(app, dashboard, importer)
    app.include_router(dashboard.router())
    app.mount("/static", static_files(), name="static")
    return app


class ImportRequest(BaseModel):
    commands: list[str] = Field(min_length=1)
    unit: Literal["hour", "day"]
    count: int = Field(ge=1)


def _admin_routes(app: FastAPI, dashboard: Dashboard, importer: Importer) -> None:
    @app.get("/admin/jobs", summary="Every service's scheduled jobs")
    def jobs() -> list[dict[str, Any]]:
        return [j.to_json() for j in dashboard.jobs(time.time())]

    @app.get("/admin/logs", summary="Size of each log folder")
    def log_usage() -> list[dict[str, Any]]:
        return [f.to_json() for f in dashboard.admin.usage()]

    @app.get("/admin/import", summary="The last log import, as it goes")
    def import_status() -> dict[str, Any]:
        return {"state": "idle"} if importer.job is None else _job_json(importer.job)

    @app.get(
        "/admin/import/estimate",
        summary="What an import would read and write, without writing it",
    )
    def estimate(
        command: Annotated[list[str], Query(min_length=1)],
        unit: Literal["hour", "day"],
        count: Annotated[int, Query(ge=1)],
    ) -> dict[str, Any]:
        try:
            return _job_json(importer.estimate(command, unit, count))
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    @app.post("/admin/import", status_code=202, summary="Start a log import")
    def start_import(body: ImportRequest) -> dict[str, Any]:
        try:
            return _job_json(importer.start(body.commands, body.unit, body.count))
        except ImportBusy as e:
            raise HTTPException(409, str(e)) from e
        except ValueError as e:
            raise HTTPException(422, str(e)) from e


def _job_json(job: ImportJob) -> dict[str, Any]:
    data = job.to_json()
    for key in ("since", "until", "started_at", "finished_at"):
        if data[key] is not None:
            data[key] = iso(data[key])
    return data


def _state_route(
    name: str, snapshot: Snapshot, logs: LogManager
) -> Callable[..., dict[str, Any]]:
    kinds = SECTIONS[name].kinds

    def state(
        unit: Annotated[
            Literal["minute", "hour", "day"], Query(description="Bucket size")
        ] = DEFAULT_WINDOW.unit,  # type: ignore[assignment]
        count: Annotated[
            int, Query(ge=1, description="Buckets, the current one included")
        ] = DEFAULT_WINDOW.count,
    ) -> dict[str, Any]:
        """The live state, and under `window` the counts per bucket and the newest
        records of each kind, from the logs."""
        try:
            window = Window(unit, count)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        buckets = logs.counts(window)
        totals: Counter[str] = Counter()
        for b in buckets:
            totals.update(b.counts)
        return {
            **snapshot(),
            "window": {
                **window.to_json(),
                "since": iso(window.since(time.time())),
                "totals": dict(totals),
                "buckets": [
                    {"start": iso(b.start), "counts": b.counts} for b in buckets
                ],
                "events": {
                    k: logs.recent(prefixes, window) for k, prefixes in kinds.items()
                },
            },
        }

    return state


class ApiServer:
    """Uvicorn in a background thread, next to the command running in the main one."""

    def __init__(self, app: FastAPI, host: str, port: int) -> None:
        # Bind here, in the main thread, so a busy port fails before monitoring starts.
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.socket = socket.create_server((host, port), family=family)
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                log_level="warning",
                access_log=False,
                # Do not let a lingering keep-alive connection hold up the exit.
                timeout_graceful_shutdown=1,
            )
        )
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [self.socket]}, daemon=True
        )

    @property
    def url(self) -> str:
        host, port = self.socket.getsockname()[:2]
        return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Also safe before start(), when setup failed after the port was bound."""
        if self._thread.is_alive():
            self._server.should_exit = True
            self._thread.join(timeout=5)
        self.socket.close()
