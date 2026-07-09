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

from typing import Any, Iterable, Mapping, Union

from fastapi import Request
from ipregistry import ApiError, IpInfo, IpregistryError, IpregistryLookupError, RequesterIpInfo, UserAgent

from .ip import IpSource, is_valid_ip
from .service import Ipregistry
from .settings import IpregistrySettings

ResponseStub = Union[Mapping[str, Any], IpInfo, Exception]

WILDCARD = "*"
ORIGIN = "origin"


class _UnusedClient:
    """Placeholder ensuring an IpregistryFake never reaches the network."""

    def __getattr__(self, name: str):
        raise AssertionError("IpregistryFake performs no real API calls")


class IpregistryFake(Ipregistry):
    """Drop-in Ipregistry service for tests: no network, canned responses.

    Responses are keyed by IP address; '*' matches any address and 'origin'
    serves origin lookups. A value may be an API-shaped dict (the 'ip' field is
    filled in automatically), an IpInfo instance, or an exception to raise:

        fake = IpregistryFake({
            "66.165.2.7": {"location": {"country": {"code": "US"}}},
            "*": {"security": {"is_threat": False}},
        })
        add_ipregistry(app, service=fake)

    Unlike the real service, private and loopback client addresses are used
    verbatim so requests made through TestClient resolve out of the box.
    Lookups without a matching stub raise an ApiError (which request-aware
    helpers turn into a fail-open None).
    """

    def __init__(
        self,
        responses: Mapping[str, ResponseStub] | None = None,
        *,
        settings: IpregistrySettings | None = None,
        ip_extractor: IpSource | None = None,
    ):
        super().__init__(
            settings if settings is not None else IpregistrySettings(api_key="fake"),
            client=_UnusedClient(),  # type: ignore[arg-type]
            ip_extractor=ip_extractor,
        )
        self._responses: dict[str, ResponseStub] = {}
        self.lookups: list[str] = []
        self.origin_lookups: int = 0
        self.parsed_user_agents: list[str] = []
        if responses:
            self.stub(responses)

    def stub(self, responses: Mapping[str, ResponseStub]) -> "IpregistryFake":
        """Register additional canned responses, keyed by IP ('*', 'origin')."""
        self._responses.update(responses)
        return self

    def reset(self) -> "IpregistryFake":
        """Clear all recorded lookups."""
        self.lookups.clear()
        self.origin_lookups = 0
        self.parsed_user_agents.clear()
        return self

    async def aclose(self) -> None:
        pass

    async def lookup(self, ip: str, *, fields=None, hostname=None, **params: Any) -> IpInfo:
        self.lookups.append(ip)
        stub = self._resolve_stub(ip)
        if isinstance(stub, Exception):
            raise stub
        if isinstance(stub, IpInfo):
            return stub
        data = dict(stub)
        data.setdefault("ip", ip if is_valid_ip(ip) else None)
        return IpInfo(**data)

    async def lookup_batch(self, ips: Iterable[str], *, fields=None, hostname=None, **params: Any):
        results: list[Union[IpInfo, IpregistryLookupError]] = []
        for ip in ips:
            try:
                results.append(await self.lookup(ip, fields=fields, hostname=hostname, **params))
            except IpregistryLookupError as error:
                results.append(error)
            except IpregistryError as error:
                results.append(IpregistryLookupError({"code": "UNKNOWN", "message": str(error), "resolution": ""}))
        return results

    async def lookup_origin(self, *, fields=None, hostname=None, **params: Any) -> RequesterIpInfo:
        self.origin_lookups += 1
        stub = self._responses.get(ORIGIN)
        if stub is None:
            raise self._missing(ORIGIN)
        if isinstance(stub, Exception):
            raise stub
        if isinstance(stub, RequesterIpInfo):
            return stub
        if isinstance(stub, IpInfo):
            return RequesterIpInfo(**stub.model_dump())
        return RequesterIpInfo(**dict(stub))

    async def parse_user_agent(self, user_agent: str, **params: Any) -> UserAgent:
        self.parsed_user_agents.append(user_agent)
        stub = self._responses.get(user_agent)
        if isinstance(stub, Exception):
            raise stub
        if isinstance(stub, Mapping):
            data = dict(stub)
            data.setdefault("header", user_agent)
            return UserAgent(**data)
        return UserAgent(header=user_agent)

    def client_ip(self, request: Request) -> str | None:
        ip = self._ip_extractor(request)
        if ip:
            return ip
        if request.client is not None and request.client.host:
            return request.client.host
        return self.settings.development_ip

    # Assertions

    def assert_looked_up(self, ip: str) -> None:
        assert ip in self.lookups, f"Expected a lookup for {ip!r}; recorded lookups: {self.lookups!r}"

    def assert_not_looked_up(self, ip: str) -> None:
        assert ip not in self.lookups, f"Did not expect a lookup for {ip!r}"

    def assert_looked_up_times(self, ip: str, times: int) -> None:
        count = self.lookups.count(ip)
        assert count == times, f"Expected {times} lookup(s) for {ip!r}, recorded {count}"

    def assert_nothing_looked_up(self) -> None:
        assert not self.lookups and self.origin_lookups == 0, (
            f"Expected no lookups; recorded lookups: {self.lookups!r}, origin lookups: {self.origin_lookups}"
        )

    def assert_origin_looked_up(self) -> None:
        assert self.origin_lookups > 0, "Expected at least one origin lookup"

    def assert_user_agents_parsed(self, *user_agents: str) -> None:
        for user_agent in user_agents:
            assert user_agent in self.parsed_user_agents, (
                f"Expected {user_agent!r} to be parsed; recorded: {self.parsed_user_agents!r}"
            )

    def _resolve_stub(self, ip: str) -> ResponseStub:
        stub = self._responses.get(ip, self._responses.get(WILDCARD))
        if stub is None:
            raise self._missing(ip)
        return stub

    @staticmethod
    def _missing(key: str) -> ApiError:
        return ApiError(
            "FAKE_RESPONSE_MISSING",
            f"No fake response registered for {key!r}.",
            "Register a response with IpregistryFake({...}) or a '*' wildcard entry.",
        )
