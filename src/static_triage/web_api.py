"""Authenticated loopback API for the Mantha Ray web interface."""



import asyncio
import hmac
from pathlib import Path
from typing import Annotated, Literal

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import (
    TrustedHostMiddleware,
)

from .desktop_dialogs import (
    choose_directory,
    open_directory,
)
from .host_scan import HostScanError
from .web_service import ScanService


_COOKIE_NAME = "mantha_ray_session"


class DirectoryDialogRequest(BaseModel):
    purpose: Literal["source", "results"]

    current_path: str | None = Field(
        default=None,
        max_length=4096,
    )


class ScanStartRequest(BaseModel):
    source_directory: str = Field(
        min_length=1,
        max_length=4096,
    )

    results_directory: str = Field(
        min_length=1,
        max_length=4096,
    )


def create_app(
    service: ScanService,
    session_token: str,
    static_directory: Path,
    allowed_origin: str,
) -> FastAPI:
    """Build the authenticated loopback application."""

    app = FastAPI(
        title="Mantha Ray Local API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "127.0.0.1",
            "localhost",
        ],
    )

    @app.middleware("http")
    async def secure_headers(
        request: Request,
        call_next,
    ) -> Response:
        response = await call_next(request)

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )

        response.headers[
            "Referrer-Policy"
        ] = "no-referrer"

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        response.headers[
            "X-Frame-Options"
        ] = "DENY"

        response.headers[
            "Cache-Control"
        ] = "no-store"

        return response

    def check_origin(
        request: Request,
    ) -> None:
        origin = request.headers.get("origin")

        if (
            origin is not None
            and origin != allowed_origin
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_403_FORBIDDEN
                ),
                detail=(
                    "Request origin was rejected."
                ),
            )

    def require_session(
        request: Request,
        session_cookie: Annotated[
            str | None,
            Cookie(alias=_COOKIE_NAME),
        ] = None,
    ) -> None:
        check_origin(request)

        if (
            session_cookie is None
            or not hmac.compare_digest(
                session_cookie,
                session_token,
            )
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_401_UNAUTHORIZED
                ),
                detail=(
                    "A valid local session is required."
                ),
            )

    def api_error(
        exc: HostScanError,
    ) -> HTTPException:
        if "already running" in str(exc):
            code = status.HTTP_409_CONFLICT
        else:
            code = status.HTTP_400_BAD_REQUEST

        return HTTPException(
            status_code=code,
            detail=str(exc),
        )

    @app.post("/api/session")
    async def establish_session(
        request: Request,
        response: Response,
        token: Annotated[
            str | None,
            Header(
                alias="X-Mantha-Ray-Token"
            ),
        ] = None,
    ) -> dict[str, bool]:
        check_origin(request)

        if (
            token is None
            or not hmac.compare_digest(
                token,
                session_token,
            )
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_401_UNAUTHORIZED
                ),
                detail=(
                    "The launch token is invalid."
                ),
            )

        response.set_cookie(
            key=_COOKIE_NAME,
            value=session_token,
            httponly=True,
            secure=False,
            samesite="strict",
            path="/",
        )

        return {
            "ok": True,
        }

    @app.get("/api/health")
    async def health(
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, object]:
        try:
            version = await asyncio.to_thread(
                service.controller.preflight
            )

        except HostScanError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "image": (
                    service.controller.image
                ),
            }

        return {
            "ok": True,
            "docker_version": version,
            "image": service.controller.image,
        }

    @app.get("/api/config")
    async def configuration(
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, str]:
        return {
            "application_name": "Mantha Ray",
            "default_results_directory": str(
                Path.home()
                / "mantha-ray-results"
            ),
        }

    @app.post("/api/dialogs/directory")
    async def directory_dialog(
        payload: DirectoryDialogRequest,
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, str | None]:
        try:
            selected = await asyncio.to_thread(
                choose_directory,
                payload.purpose,
                payload.current_path,
            )

        except HostScanError as exc:
            raise api_error(exc) from exc

        return {
            "path": selected,
        }

    @app.post(
        "/api/scans",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_scan(
        payload: ScanStartRequest,
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, object]:
        try:
            return await asyncio.to_thread(
                service.start,
                payload.source_directory,
                payload.results_directory,
            )

        except HostScanError as exc:
            raise api_error(exc) from exc

    @app.get("/api/scans/{scan_id}")
    async def scan_status(
        scan_id: str,
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, object]:
        try:
            return service.get(scan_id)

        except HostScanError as exc:
            raise HTTPException(
                status_code=(
                    status.HTTP_404_NOT_FOUND
                ),
                detail=str(exc),
            ) from exc

    @app.delete("/api/scans/{scan_id}")
    async def cancel_scan(
        scan_id: str,
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, object]:
        try:
            return await asyncio.to_thread(
                service.cancel,
                scan_id,
            )

        except HostScanError as exc:
            raise api_error(exc) from exc

    @app.post(
        "/api/scans/{scan_id}/open-folder"
    )
    async def open_case_folder(
        scan_id: str,
        _: Annotated[
            None,
            Depends(require_session),
        ],
    ) -> dict[str, bool]:
        try:
            case_directory = (
                service.case_directory(scan_id)
            )

            await asyncio.to_thread(
                open_directory,
                case_directory,
            )

        except HostScanError as exc:
            raise api_error(exc) from exc

        return {
            "ok": True,
        }

    app.mount(
        "/",
        StaticFiles(
            directory=static_directory,
            html=True,
        ),
        name="frontend",
    )

    return app