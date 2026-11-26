"""Read-only HTTP API serving the running command's live state (`--api`)."""

import socket
import threading
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

type Snapshot = Callable[[], dict[str, Any]]

# OPTIONS is the browser's CORS preflight; it never reaches a route.
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def create_app(
    command: str, snapshot: Snapshot, cors_origins: Sequence[str]
) -> FastAPI:
    app = FastAPI(title="my_siem", description="Live monitoring data of my_siem")
    # The frontend runs on another origin; logs reveal users, so allow only listed ones.
    app.add_middleware(
        CORSMiddleware, allow_origins=list(cors_origins), allow_methods=["GET"]
    )

    # Added last so it wraps CORS: nothing that writes can reach a route.
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
    def healthz() -> dict[str, str]:
        return {"status": "ok", "command": command}

    app.add_api_route(
        f"/{command}",
        snapshot,
        methods=["GET"],
        summary=f"Live state of the `{command}` command",
    )
    return app


class ApiServer:
    """Uvicorn in a background thread, next to the command running in the main one."""

    def __init__(self, app: FastAPI, host: str, port: int) -> None:
        # Bind here, in the main thread, so a busy port fails before monitoring starts.
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.socket = socket.create_server((host, port), family=family)
        self._server = uvicorn.Server(
            uvicorn.Config(app, log_level="warning", access_log=False)
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
        self._server.should_exit = True
        self._thread.join(timeout=5)
        self.socket.close()
