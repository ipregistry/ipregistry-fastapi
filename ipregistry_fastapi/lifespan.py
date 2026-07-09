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

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from ipregistry import AsyncIpregistryClient

from .ip import IpSource
from .service import Ipregistry
from .settings import IpregistrySettings


def add_ipregistry(
    app: FastAPI,
    settings: IpregistrySettings | None = None,
    *,
    client: AsyncIpregistryClient | None = None,
    ip_extractor: IpSource | None = None,
    service: Ipregistry | None = None,
) -> Ipregistry:
    """Attach an Ipregistry service to the application state.

    The service is picked up by the dependencies (IpInfoDep, IpregistryDep, ...)
    and the middleware. Pass a pre-built service (e.g. an IpregistryFake in
    tests) or let one be created from the given settings and environment.
    """
    if service is None:
        service = Ipregistry(settings, client=client, ip_extractor=ip_extractor)
    app.state.ipregistry = service
    return service


@asynccontextmanager
async def ipregistry_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan managing the Ipregistry service lifecycle.

    Use directly (FastAPI(lifespan=ipregistry_lifespan)) or compose it inside
    your own lifespan with an AsyncExitStack. Creates a service from the
    environment unless one was already attached with add_ipregistry, and
    releases its HTTP resources on shutdown.
    """
    service = getattr(app.state, "ipregistry", None)
    if service is None:
        service = add_ipregistry(app)
    try:
        yield
    finally:
        await service.aclose()
