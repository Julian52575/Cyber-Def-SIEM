"""Read-only HTTP server for the running commands: dashboard and live data (`--api`)."""

import asyncio
import socket
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from my_siem.web import Dashboard, static_files

type Snapshot = Callable[[], dict[str, Any]]

READ_METHODS = frozenset({"GET", "HEAD"})
SAMPLE_EVERY = 5.0


def _host_pattern(host: str) -> str:
    # The Host header brackets IPv6 addresses.
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def create_app(
    snapshots: Mapping[str, Snapshot],
    allowed_hosts: Sequence[str],
    every: float = SAMPLE_EVERY,
) -> FastAPI:
    """`snapshots` gives the live state of each running command, by name."""
    dashboard = Dashboard(snapshots, every)

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

    # Added last so it runs first: nothing that writes can reach a route.
    @app.middleware("http")
    async def read_only(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method not in READ_METHODS:
            return JSONResponse(
                {"detail": "read-only API"},
                status_code=405,
                headers={"Allow": ", ".join(sorted(READ_METHODS))},
            )
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "commands": list(snapshots)}

    for name, snapshot in snapshots.items():
        app.add_api_route(
            f"/{name}",
            snapshot,
            methods=["GET"],
            summary=f"Live state of the `{name}` command",
        )
    app.include_router(dashboard.router())
    app.mount("/static", static_files(), name="static")
    return app


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
