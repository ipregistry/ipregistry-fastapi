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
from typing import Callable, Optional, Union

from fastapi import Request

IpExtractor = Callable[[Request], Optional[str]]
"""A callable that extracts the client IP address from a request, or None."""

IpSource = Union[str, IpExtractor]
"""An IP source: 'client', a trusted-proxy preset name, 'header:<name>' or a callable."""

PRESET_HEADERS: dict[str, tuple[str, ...]] = {
    "auto": ("x-real-ip", "x-forwarded-for"),
    "cloudflare": ("cf-connecting-ip",),
    "nginx": ("x-real-ip", "x-forwarded-for"),
    "forwarded-for": ("x-forwarded-for",),
}
"""Headers consulted, in order, for each trusted-proxy preset."""


def sanitize_ip(value: str | None) -> str | None:
    """Normalize a raw header or address value to a bare IP string.

    Strips whitespace, IPv6 brackets (with an optional port, e.g. '[::1]:8080'),
    an IPv4 port suffix (e.g. '1.2.3.4:443') and IPv6 zone identifiers ('%eth0').
    Returns None when nothing is left.
    """
    if value is None:
        return None
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        value = value[1:end]
    elif value.count(":") == 1 and "." in value:
        value = value.split(":", 1)[0]
    zone = value.find("%")
    if zone != -1:
        value = value[:zone]
    return value or None


def is_valid_ip(value: str) -> bool:
    """Return True when the value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_public_ip(value: str) -> bool:
    """Return True when the value is a valid, publicly routable IP address.

    Private, loopback, link-local, carrier-grade NAT and other reserved ranges
    return False: the Ipregistry API rejects them with RESERVED_IP_ADDRESS, so
    lookups for such addresses are skipped.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def anonymize_ip(value: str) -> str:
    """Mask an IP address for log output; this library never logs full client IPs."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "<invalid>"
    if isinstance(address, ipaddress.IPv4Address):
        octets = str(address).split(".")
        return ".".join(octets[:3]) + ".x"
    groups = address.exploded.split(":")
    return ":".join(groups[:3]) + "::x"


def build_ip_extractor(source: IpSource = "client") -> IpExtractor:
    """Build an IP extractor from an IP source specification.

    Accepts 'client' (the ASGI client address), a trusted-proxy preset name
    ('auto', 'cloudflare', 'nginx', 'forwarded-for'), 'header:<name>' for a
    custom header, or a callable taking a request and returning an IP or None.

    Only configure headers set by a proxy you control: client-supplied headers
    are trivially spoofable.
    """
    if callable(source):
        return source

    normalized = source.strip().lower()
    if normalized == "client":
        return _extract_from_client

    if normalized.startswith("header:"):
        header = normalized.split(":", 1)[1].strip()
        if not header:
            raise ValueError("Invalid IP source: 'header:' requires a header name, e.g. 'header:x-client-ip'")
        headers: tuple[str, ...] = (header,)
    elif normalized in PRESET_HEADERS:
        headers = PRESET_HEADERS[normalized]
    else:
        presets = ", ".join(sorted(PRESET_HEADERS))
        raise ValueError(
            f"Unknown IP source {source!r}: expected 'client', a preset ({presets}), "
            "'header:<name>' or a callable"
        )

    def extract(request: Request) -> str | None:
        return _extract_from_headers(request, headers)

    return extract


def _extract_from_client(request: Request) -> str | None:
    client = request.client
    if client is None or not client.host:
        return None
    ip = sanitize_ip(client.host)
    return ip if ip is not None and is_valid_ip(ip) else None


def _extract_from_headers(request: Request, headers: tuple[str, ...]) -> str | None:
    for name in headers:
        raw = request.headers.get(name)
        if not raw:
            continue
        ip = sanitize_ip(raw.split(",", 1)[0])
        if ip is not None and is_valid_ip(ip):
            return ip
    return None
