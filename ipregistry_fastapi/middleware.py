"""
    Copyright 2026 Ipregistry (https://ipregistry.co).

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

from __future__ import annotations

from typing import Callable, Sequence, Union

from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse
from ipregistry import UserAgents

from .blocking import Blocker
from .dependencies import SERVICE_UNAVAILABLE_DETAIL
from .service import Ipregistry
from .settings import IpregistrySettings

STATIC_ASSET_SUFFIXES = (
    ".avif", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mjs",
    ".otf", ".png", ".svg", ".ttf", ".txt", ".webmanifest", ".webp", ".woff", ".woff2",
)


class IpregistryMiddleware:
    """Pure ASGI middleware enriching every HTTP request with IP intelligence.

    Performs a single cached lookup per request, stores the result on
    request.state.ipregistry (shared with the IpInfoDep dependency), and
    optionally applies blocking actions before the request reaches the router:

        app.add_middleware(
            IpregistryMiddleware,
            actions=[block_countries("XX"), block_threats(tor=True)],
        )

    Prefer route dependencies for per-endpoint rules; use the middleware to
    enforce app-wide policies or to eagerly enrich every request.

    Parameters:
    service: the Ipregistry service to use. Defaults to the one attached to
        the application state, else one built from settings / the environment.
    settings: settings used when building a service lazily.
    fields / hostname: per-lookup overrides forwarded to the lookup.
    actions: blocking rules (block_countries, block_threats, or any Blocker)
        evaluated in order; the first match returns its error response.
    fail_closed: when True, respond with 503 if the lookup fails; an int
        customizes the status code. Defaults to False (fail open).
    skip_static_assets: skip lookups for common static file extensions.
    skip_bots: skip lookups when the User-Agent looks like a bot or crawler.
    skip: custom predicate receiving the request; return True to skip.
    """

    def __init__(
        self,
        app,
        *,
        service: Ipregistry | None = None,
        settings: IpregistrySettings | None = None,
        fields: str | None = None,
        hostname: bool | None = None,
        actions: Sequence[Blocker] = (),
        fail_closed: Union[bool, int] = False,
        skip_static_assets: bool = True,
        skip_bots: bool = False,
        skip: Callable[[Request], bool] | None = None,
    ):
        self.app = app
        self._service = service
        self._settings = settings
        self._fields = fields
        self._hostname = hostname
        self._actions = tuple(actions)
        self._fail_closed = fail_closed
        self._skip_static_assets = skip_static_assets
        self._skip_bots = skip_bots
        self._skip = skip

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        scope.setdefault("state", {})
        request = Request(scope, receive)

        if not self._should_skip(request):
            service = self._resolve_service(scope)
            info = await service.for_request(request, fields=self._fields, hostname=self._hostname)

            if info is None and self._fail_closed and service.request_error(request) is not None:
                status_code = 503 if self._fail_closed is True else int(self._fail_closed)
                response = PlainTextResponse(SERVICE_UNAVAILABLE_DETAIL, status_code=status_code)
                await response(scope, receive, send)
                return

            for action in self._actions:
                try:
                    action.check(info)
                except HTTPException as exception:
                    response = PlainTextResponse(
                        str(exception.detail),
                        status_code=exception.status_code,
                        headers=exception.headers,
                    )
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)

    def _resolve_service(self, scope) -> Ipregistry:
        if self._service is not None:
            return self._service
        app = scope.get("app")
        if app is not None:
            existing = getattr(app.state, "ipregistry", None)
            if existing is not None:
                self._service = existing
                return existing
        service = Ipregistry(self._settings)
        if app is not None:
            app.state.ipregistry = service
        self._service = service
        return service

    def _should_skip(self, request: Request) -> bool:
        if self._skip_static_assets and request.url.path.lower().endswith(STATIC_ASSET_SUFFIXES):
            return True
        if self._skip_bots:
            user_agent = request.headers.get("user-agent", "")
            if user_agent and UserAgents.is_bot(user_agent):
                return True
        return self._skip is not None and self._skip(request)
