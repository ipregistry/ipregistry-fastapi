import pytest
from ipregistry import ApiError, ApiResponse, ApiResponseCredits, ApiResponseThrottling, IpInfo

from ipregistry_fastapi import Ipregistry, IpregistrySettings, MissingApiKeyError

from .conftest import make_request


class DuckClient:
    """Duck-typed stand-in for AsyncIpregistryClient."""

    def __init__(self, data=None, error=None):
        self._data = data if data is not None else IpInfo(ip="66.165.2.7")
        self._error = error
        self.calls = []
        self.closed = False

    async def lookup_ip(self, ip, **options):
        self.calls.append(("lookup_ip", ip, options))
        if self._error is not None:
            raise self._error
        return self._response(self._data)

    async def batch_lookup_ips(self, ips, **options):
        self.calls.append(("batch_lookup_ips", ips, options))
        return self._response([self._data for _ in ips])

    async def origin_lookup_ip(self, **options):
        self.calls.append(("origin_lookup_ip", options))
        return self._response(self._data)

    async def parse_user_agent(self, user_agent, **options):
        self.calls.append(("parse_user_agent", user_agent, options))
        return self._response(self._data)

    async def aclose(self):
        self.closed = True

    @staticmethod
    def _response(data):
        return ApiResponse(ApiResponseCredits(), data, ApiResponseThrottling())


def make_service(settings=None, client=None, **settings_kwargs):
    if settings is None:
        settings = IpregistrySettings(api_key="test", **settings_kwargs)
    return Ipregistry(settings, client=client or DuckClient())


class TestConstruction:
    def test_requires_api_key(self):
        with pytest.raises(MissingApiKeyError):
            Ipregistry(IpregistrySettings(api_key=""))

    def test_injected_client_needs_no_api_key(self):
        service = Ipregistry(IpregistrySettings(), client=DuckClient())
        assert service.client is not None

    def test_builds_real_client_from_settings(self):
        service = Ipregistry(IpregistrySettings(api_key="test"))
        assert service.client is not None

    async def test_context_manager_closes_client(self):
        client = DuckClient()
        async with Ipregistry(IpregistrySettings(api_key="test"), client=client):
            pass
        assert client.closed


class TestLookup:
    async def test_lookup_returns_data(self):
        service = make_service()
        info = await service.lookup("66.165.2.7")
        assert info.ip == "66.165.2.7"

    async def test_default_fields_and_hostname_applied(self):
        client = DuckClient()
        service = make_service(client=client, fields="location", hostname=True)
        await service.lookup("66.165.2.7")
        _, _, options = client.calls[0]
        assert options == {"fields": "location", "hostname": True}

    async def test_explicit_fields_override_defaults(self):
        client = DuckClient()
        service = make_service(client=client, fields="location")
        await service.lookup("66.165.2.7", fields="security")
        assert client.calls[0][2]["fields"] == "security"

    async def test_no_options_by_default(self):
        client = DuckClient()
        service = make_service(client=client)
        await service.lookup("66.165.2.7")
        assert client.calls[0][2] == {}

    async def test_lookup_batch(self):
        service = make_service()
        results = await service.lookup_batch(["66.165.2.7", "1.1.1.1"])
        assert len(results) == 2

    async def test_parse_user_agent(self):
        client = DuckClient(data=IpInfo())
        service = make_service(client=client)
        await service.parse_user_agent("Mozilla/5.0")
        assert client.calls[0][0] == "parse_user_agent"


class TestClientIp:
    def test_public_client_ip(self):
        service = make_service()
        assert service.client_ip(make_request(client_host="66.165.2.7")) == "66.165.2.7"

    def test_private_ip_skipped(self):
        service = make_service()
        assert service.client_ip(make_request(client_host="192.168.1.10")) is None

    def test_private_ip_falls_back_to_development_ip(self):
        service = make_service(development_ip="66.165.2.7")
        assert service.client_ip(make_request(client_host="127.0.0.1")) == "66.165.2.7"

    def test_header_source(self):
        settings = IpregistrySettings(api_key="test", ip_source="auto")
        service = Ipregistry(settings, client=DuckClient())
        request = make_request(client_host="10.0.0.1", headers={"x-real-ip": "66.165.2.7"})
        assert service.client_ip(request) == "66.165.2.7"


class TestForRequest:
    async def test_lookup_for_public_client(self):
        service = make_service()
        info = await service.for_request(make_request(client_host="66.165.2.7"))
        assert info is not None
        assert info.ip == "66.165.2.7"

    async def test_memoized_per_request(self):
        client = DuckClient()
        service = make_service(client=client)
        request = make_request(client_host="66.165.2.7")
        first = await service.for_request(request)
        second = await service.for_request(request)
        assert first is second
        assert len(client.calls) == 1

    async def test_no_public_ip_returns_none_without_lookup(self):
        client = DuckClient()
        service = make_service(client=client)
        info = await service.for_request(make_request(client_host="127.0.0.1"))
        assert info is None
        assert client.calls == []

    async def test_failure_is_swallowed_and_recorded(self):
        error = ApiError("INVALID_API_KEY", "boom", "fix it")
        service = make_service(client=DuckClient(error=error))
        request = make_request(client_host="66.165.2.7")
        info = await service.for_request(request)
        assert info is None
        assert service.request_error(request) is error

    async def test_failure_memoized(self):
        client = DuckClient(error=ApiError("INTERNAL", "boom", ""))
        service = make_service(client=client)
        request = make_request(client_host="66.165.2.7")
        await service.for_request(request)
        await service.for_request(request)
        assert len(client.calls) == 1
