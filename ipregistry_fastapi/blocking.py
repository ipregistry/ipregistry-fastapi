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

import re
from typing import Iterable, Literal, Union

from fastapi import HTTPException
from fastapi.requests import HTTPConnection
from ipregistry import IpInfo

from .dependencies import SERVICE_UNAVAILABLE_DETAIL, IpregistryDep
from .guards import is_threat

_COUNTRY_CODE_PATTERN = re.compile(r"^[A-Za-z]{2}$")


class Blocker:
    """Base for blocking rules, usable both as a FastAPI dependency and as a
    middleware action."""

    async def __call__(self, connection: HTTPConnection, service: IpregistryDep) -> None:
        info = await service.for_request(connection)
        if info is None and not service.settings.fail_open and service.request_error(connection) is not None:
            raise HTTPException(status_code=503, detail=SERVICE_UNAVAILABLE_DETAIL)
        self.check(info)

    def check(self, info: IpInfo | None) -> None:
        """Raise HTTPException when the request must be blocked."""
        raise NotImplementedError


class CountryBlocker(Blocker):
    def __init__(
        self,
        countries: Iterable[str],
        mode: Literal["block", "allow"],
        unknown: Literal["allow", "block"],
        status_code: int,
        detail: str,
    ):
        codes = set()
        for country in countries:
            if not isinstance(country, str) or not _COUNTRY_CODE_PATTERN.match(country):
                raise ValueError(f"Invalid ISO 3166-1 alpha-2 country code: {country!r}")
            codes.add(country.upper())
        if not codes:
            raise ValueError("At least one country code is required")
        if mode not in ("block", "allow"):
            raise ValueError(f"Invalid mode {mode!r}: expected 'block' or 'allow'")
        if unknown not in ("allow", "block"):
            raise ValueError(f"Invalid unknown policy {unknown!r}: expected 'allow' or 'block'")
        self.countries = frozenset(codes)
        self.mode = mode
        self.unknown = unknown
        self.status_code = status_code
        self.detail = detail

    def check(self, info: IpInfo | None) -> None:
        location = info.location if info is not None else None
        country = location.country if location is not None else None
        code = country.code if country is not None else None
        if code is None:
            if self.unknown == "block":
                raise HTTPException(status_code=self.status_code, detail=self.detail)
            return
        blocked = code in self.countries if self.mode == "block" else code not in self.countries
        if blocked:
            raise HTTPException(status_code=self.status_code, detail=self.detail)


def block_countries(
    *countries: Union[str, Iterable[str]],
    mode: Literal["block", "allow"] = "block",
    unknown: Literal["allow", "block"] = "allow",
    status_code: int = 451,
    detail: str = "Access restricted in your region.",
) -> CountryBlocker:
    """Block (or, with mode='allow', restrict to) visitors from the given
    ISO 3166-1 alpha-2 countries.

    Use as a route dependency (dependencies=[Depends(block_countries("XX"))])
    or as a middleware action. Requests whose country cannot be determined are
    allowed unless unknown='block'. Responds with 451 Unavailable For Legal
    Reasons by default. Country codes are validated eagerly, at declaration time.
    """
    if len(countries) == 1 and not isinstance(countries[0], str):
        countries = tuple(countries[0])
    return CountryBlocker(countries, mode, unknown, status_code, detail)


class ThreatBlocker(Blocker):
    def __init__(self, signals: dict[str, bool], status_code: int, detail: str):
        self.signals = signals
        self.status_code = status_code
        self.detail = detail

    def check(self, info: IpInfo | None) -> None:
        if is_threat(info, **self.signals):
            raise HTTPException(status_code=self.status_code, detail=self.detail)


def block_threats(
    *,
    proxy: bool = False,
    tor: bool = False,
    vpn: bool = False,
    relay: bool = False,
    anonymous: bool = False,
    cloud_provider: bool = False,
    bogon: bool = False,
    status_code: int = 403,
    detail: str = "Access denied.",
) -> ThreatBlocker:
    """Block visitors flagged as threats by Ipregistry.

    Known threats, attackers and abusers are always blocked. Anonymization and
    infrastructure signals (proxy, tor, vpn, relay, anonymous, cloud_provider,
    bogon) are opt-in. Requests without security data are allowed (fail open).
    Use as a route dependency or as a middleware action.
    """
    signals = {
        "proxy": proxy,
        "tor": tor,
        "vpn": vpn,
        "relay": relay,
        "anonymous": anonymous,
        "cloud_provider": cloud_provider,
        "bogon": bogon,
    }
    return ThreatBlocker(signals, status_code, detail)
