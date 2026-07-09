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

from typing import Annotated, Optional

from fastapi import Depends, HTTPException
from fastapi.requests import HTTPConnection
from ipregistry import IpInfo

from .service import Ipregistry

SERVICE_UNAVAILABLE_DETAIL = "IP intelligence is temporarily unavailable."


async def get_ipregistry(connection: HTTPConnection) -> Ipregistry:
    """Provide the application's Ipregistry service.

    Uses the service attached with add_ipregistry; otherwise lazily creates one
    from the environment and stores it on the application state.
    """
    service = getattr(connection.app.state, "ipregistry", None)
    if service is None:
        service = Ipregistry()
        connection.app.state.ipregistry = service
    return service


IpregistryDep = Annotated[Ipregistry, Depends(get_ipregistry)]
"""The Ipregistry service, for explicit lookups and access to the raw client."""


async def get_ip_info(connection: HTTPConnection, service: IpregistryDep) -> Optional[IpInfo]:
    """Provide IP intelligence for the request's client, in both HTTP and
    WebSocket endpoints.

    A single lookup is performed per request and shared by every consumer.
    Returns None when no public client IP is available or, with fail_open
    enabled (the default), when the lookup fails. With fail_open disabled a
    lookup failure responds with 503.
    """
    info = await service.for_request(connection)
    if info is None and not service.settings.fail_open and service.request_error(connection) is not None:
        raise HTTPException(status_code=503, detail=SERVICE_UNAVAILABLE_DETAIL)
    return info


IpInfoDep = Annotated[Optional[IpInfo], Depends(get_ip_info)]
"""IP intelligence for the request's client, or None when unavailable."""


async def get_client_ip(connection: HTTPConnection, service: IpregistryDep) -> Optional[str]:
    """Provide the client IP resolved by the configured IP source, or None."""
    return service.client_ip(connection)


ClientIpDep = Annotated[Optional[str], Depends(get_client_ip)]
"""The resolved public client IP address, or None."""
