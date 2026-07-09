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

import logging
from typing import Any, Iterable, Union

from fastapi.requests import HTTPConnection
from ipregistry import (
    AsyncIpregistryClient,
    InMemoryCache,
    IpInfo,
    IpregistryConfig,
    IpregistryError,
    IpregistryLookupError,
    NoCache,
    RequesterIpInfo,
    UserAgent,
)

from .errors import MissingApiKeyError
from .ip import IpExtractor, IpSource, anonymize_ip, build_ip_extractor, is_public_ip
from .settings import IpregistrySettings
from .version import __version__

logger = logging.getLogger("ipregistry_fastapi")

STATE_KEY = "ipregistry"
"""Attribute under which the looked up IpInfo is memoized on request.state."""

ERROR_STATE_KEY = "ipregistry_error"
"""Attribute under which a lookup failure is recorded on request.state."""


class Ipregistry:
    """Request-aware Ipregistry service built on the asynchronous Ipregistry client.

    Explicit lookups (lookup, lookup_batch, lookup_origin, parse_user_agent) raise
    on failure. The request-aware for_request never raises: it memoizes a single
    lookup per request on request.state and fails open, recording the error under
    request.state.ipregistry_error.
    """

    def __init__(
        self,
        settings: IpregistrySettings | None = None,
        *,
        client: AsyncIpregistryClient | None = None,
        ip_extractor: IpSource | None = None,
    ):
        self._settings = settings if settings is not None else IpregistrySettings()
        self._ip_extractor: IpExtractor = build_ip_extractor(
            ip_extractor if ip_extractor is not None else self._settings.ip_source
        )
        if client is None:
            if not self._settings.api_key:
                raise MissingApiKeyError()
            config = IpregistryConfig(
                key=self._settings.api_key,
                base_url=self._settings.resolved_base_url,
                timeout=self._settings.timeout,
                retry_max_attempts=self._settings.retries + 1,
                retry_interval=self._settings.retry_interval,
                retry_on_server_error=self._settings.retry_on_server_error,
                retry_on_too_many_requests=self._settings.retry_on_too_many_requests,
                user_agent=f"IpregistryFastAPI/{__version__}",
            )
            cache = (
                InMemoryCache(maxsize=self._settings.cache_max_size, ttl=self._settings.cache_ttl)
                if self._settings.cache_enabled
                else NoCache()
            )
            client = AsyncIpregistryClient(config, cache=cache)
        self._client = client

    @property
    def client(self) -> AsyncIpregistryClient:
        """The underlying asynchronous Ipregistry client, for advanced use cases
        such as ASN lookups or credits/throttling introspection."""
        return self._client

    @property
    def settings(self) -> IpregistrySettings:
        return self._settings

    async def aclose(self) -> None:
        """Release the underlying HTTP resources."""
        await self._client.aclose()

    async def __aenter__(self) -> "Ipregistry":
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.aclose()

    async def lookup(
        self,
        ip: str,
        *,
        fields: str | None = None,
        hostname: bool | None = None,
        **params: Any,
    ) -> IpInfo:
        """Look up IP intelligence for the given address. Raises ApiError or
        ClientError on failure."""
        response = await self._client.lookup_ip(ip, **self._options(fields, hostname, params))
        return response.data

    async def lookup_batch(
        self,
        ips: Iterable[str],
        *,
        fields: str | None = None,
        hostname: bool | None = None,
        **params: Any,
    ) -> list[Union[IpInfo, IpregistryLookupError]]:
        """Look up multiple addresses in one round trip. The result preserves
        input order; failed entries are IpregistryLookupError instances."""
        response = await self._client.batch_lookup_ips(list(ips), **self._options(fields, hostname, params))
        return response.data

    async def lookup_origin(
        self,
        *,
        fields: str | None = None,
        hostname: bool | None = None,
        **params: Any,
    ) -> RequesterIpInfo:
        """Look up IP intelligence for the machine executing this code."""
        response = await self._client.origin_lookup_ip(**self._options(fields, hostname, params))
        return response.data

    async def parse_user_agent(self, user_agent: str, **params: Any) -> UserAgent:
        """Parse a User-Agent header value through the Ipregistry API."""
        response = await self._client.parse_user_agent(user_agent, **params)
        return response.data

    def client_ip(self, request: HTTPConnection) -> str | None:
        """Resolve the client IP for a request using the configured IP source.

        Returns the configured development_ip when the extracted address is
        missing or not publicly routable, and None when no usable address
        remains (private and reserved addresses are never sent to the API).
        """
        ip = self._ip_extractor(request)
        if ip is not None and is_public_ip(ip):
            return ip
        return self._settings.development_ip

    async def for_request(
        self,
        request: HTTPConnection,
        *,
        fields: str | None = None,
        hostname: bool | None = None,
    ) -> IpInfo | None:
        """Look up IP intelligence for the request's client, memoized on
        request.state.ipregistry. Never raises: on failure the request proceeds
        without data and the error is stored on request.state.ipregistry_error."""
        state = request.state
        if hasattr(state, STATE_KEY):
            return getattr(state, STATE_KEY)

        info: IpInfo | None = None
        ip = self.client_ip(request)
        if ip is not None:
            try:
                info = await self.lookup(ip, fields=fields, hostname=hostname)
            except IpregistryError as error:
                setattr(state, ERROR_STATE_KEY, error)
                logger.warning("Ipregistry lookup failed for %s: %s", anonymize_ip(ip), error)
        setattr(state, STATE_KEY, info)
        return info

    @staticmethod
    def request_error(request: HTTPConnection) -> IpregistryError | None:
        """The error recorded by for_request for this request, if any."""
        return getattr(request.state, ERROR_STATE_KEY, None)

    def _options(self, fields: str | None, hostname: bool | None, params: dict[str, Any]) -> dict[str, Any]:
        options = dict(params)
        resolved_fields = fields if fields is not None else self._settings.fields
        if resolved_fields:
            options["fields"] = resolved_fields
        resolved_hostname = hostname if hostname is not None else self._settings.hostname
        if resolved_hostname:
            options["hostname"] = True
        return options
