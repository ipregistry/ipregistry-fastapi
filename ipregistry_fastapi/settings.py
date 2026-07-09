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

import ipaddress

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_BASE_URL = "https://api.ipregistry.co"
EU_BASE_URL = "https://eu.api.ipregistry.co"


class IpregistrySettings(BaseSettings):
    """Ipregistry configuration, loaded from IPREGISTRY_* environment variables.

    Every field can also be set programmatically:
    IpregistrySettings(api_key="...", base_url="eu").
    """

    model_config = SettingsConfigDict(env_prefix="IPREGISTRY_", case_sensitive=False, extra="ignore")

    api_key: str = ""
    """Your Ipregistry API key. Required unless a pre-configured client is injected."""

    base_url: str | None = None
    """API base URL. None uses the default endpoint; the shorthand 'eu' selects the
    EU-only endpoint (https://eu.api.ipregistry.co); any other value is used verbatim."""

    fields: str | None = None
    """Default field selection applied to lookups (e.g. 'location,security'), reducing
    payload size and latency. None returns the full response."""

    hostname: bool = False
    """Whether to resolve the hostname associated with looked up IP addresses."""

    timeout: float = 5.0
    """Timeout in seconds for API requests. Kept low by default since lookups run on
    the request path."""

    retries: int = 1
    """Number of retry attempts after a failed request (0 disables retries)."""

    retry_interval: float = 0.5
    """Base delay in seconds between retries; grows exponentially with each attempt."""

    retry_on_server_error: bool = True
    """Whether to retry requests failing with a 5xx status."""

    retry_on_too_many_requests: bool = False
    """Whether to retry requests failing with a 429 status, honoring Retry-After."""

    cache_enabled: bool = True
    """Whether to cache lookup responses in memory."""

    cache_max_size: int = 2048
    """Maximum number of cached lookup responses."""

    cache_ttl: int = 600
    """Time-to-live in seconds for cached lookup responses."""

    development_ip: str | None = None
    """Fallback IP address used when the client IP is private or missing, e.g. when
    developing on localhost. Must be a valid IP address."""

    fail_open: bool = True
    """When True (default), requests proceed without IP data if a lookup fails.
    When False, request-aware helpers respond with 503 on lookup failure."""

    ip_source: str = "client"
    """How to determine the client IP: 'client' (the ASGI client address, honoring
    your server's proxy-headers configuration), a trusted-proxy preset ('auto',
    'cloudflare', 'nginx', 'forwarded-for'), or 'header:<name>' for a custom header."""

    @field_validator("development_ip")
    @classmethod
    def _validate_development_ip(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        try:
            ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError(f"development_ip is not a valid IP address: {value!r}") from error
        return value

    @field_validator("timeout", "retry_interval")
    @classmethod
    def _validate_positive(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("must be greater than 0")
        return value

    @field_validator("retries", "cache_max_size", "cache_ttl")
    @classmethod
    def _validate_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("must not be negative")
        return value

    @property
    def resolved_base_url(self) -> str:
        if not self.base_url:
            return DEFAULT_BASE_URL
        if self.base_url.strip().lower() == "eu":
            return EU_BASE_URL
        return self.base_url
