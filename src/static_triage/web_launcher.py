"""Launch the authenticated Mantha Ray desktop application."""

from __future__ import annotations

import secrets
import socket
import threading
import time
from pathlib import Path
from urllib.parse import quote

from .host_scan import DockerScanController
from .web_service import ScanService


_STATIC_DIRECTORY = (
    Path(__file__).resolve().parent
    / "web_dist"
)


def launch_web(
    engine: str = "docker",
    image: str = "static-triage:core",
    port: int = 0,
    open_browser: bool = True,
) -> int:
    """Run Mantha Ray until its window closes."""

    if not 0 <= port <= 65_535:
        raise RuntimeError(
            "The local web port must be between "
            "0 and 65535."
        )

    index_path = (
        _STATIC_DIRECTORY / "index.html"
    )

    if not index_path.is_file():
        raise RuntimeError(
            "The Mantha Ray web frontend has not "
            "been built. Run npm install and "
            "npm run build in the frontend "
            "directory."
        )

    try:
        import uvicorn

        from .web_api import create_app

    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "The Mantha Ray web dependencies are "
            "missing. Install the project with "
            "its web extra."
        ) from exc

    if open_browser:
        try:
            import webview

        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "The Mantha Ray desktop dependencies "
                "are missing. Install the project "
                "with its desktop extra."
            ) from exc

    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    listener.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    try:
        listener.bind(
            (
                "127.0.0.1",
                port,
            )
        )

        listener.listen(128)

    except OSError as exc:
        listener.close()

        raise RuntimeError(
            "Mantha Ray could not bind its "
            "local web port."
        ) from exc

    selected_port = listener.getsockname()[1]

    origin = (
        f"http://127.0.0.1:{selected_port}"
    )

    session_token = secrets.token_urlsafe(32)

    launch_url = (
        f"{origin}/?token="
        f"{quote(session_token, safe='')}"
    )

    controller = DockerScanController(
        engine=engine,
        image=image,
    )

    service = ScanService(controller)

    app = create_app(
        service=service,
        session_token=session_token,
        static_directory=_STATIC_DIRECTORY,
        allowed_origin=origin,
    )

    config = uvicorn.Config(
        app,
        log_level="warning",
        access_log=False,
        server_header=False,
    )

    server = uvicorn.Server(config)

    server_thread: threading.Thread | None = None

    try:
        if not open_browser:
            print(
                launch_url,
                flush=True,
            )

            server.run(
                sockets=[listener]
            )

            return 0

        server_thread = threading.Thread(
            target=server.run,
            kwargs={
                "sockets": [listener],
            },
            name="mantha-ray-server",
            daemon=True,
        )

        server_thread.start()

        deadline = time.monotonic() + 10.0

        while not server.started:
            if not server_thread.is_alive():
                raise RuntimeError(
                    "The Mantha Ray local server "
                    "stopped during startup."
                )

            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "The Mantha Ray local server "
                    "did not start within 10 seconds."
                )

            time.sleep(0.05)

        webview.settings[
            "ALLOW_DOWNLOADS"
        ] = False

        webview.settings[
            "ALLOW_FILE_URLS"
        ] = False

        webview.settings[
            "REMOTE_DEBUGGING_PORT"
        ] = None

        webview.create_window(
            "Mantha Ray",
            launch_url,
            width=1200,
            height=800,
            min_size=(900, 600),
            resizable=True,
            background_color="#080d1c",
            text_select=True,
            zoomable=True,
        )

        webview.start(
            gui="qt",
            debug=False,
            private_mode=True,
        )

        return 0

    finally:
        if server_thread is not None:
            server.should_exit = True
            server_thread.join(timeout=10)

        service.shutdown()
        listener.close()