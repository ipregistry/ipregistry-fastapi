import pytest
from ipregistry import ApiError, IpInfo, IpregistryError, IpregistryLookupError

from ipregistry_fastapi.testing import IpregistryFake

from .conftest import make_request


class TestLookup:
    async def test_dict_stub_builds_ip_info(self):
        fake = IpregistryFake({"66.165.2.7": {"location": {"country": {"code": "US"}}}})
        info = await fake.lookup("66.165.2.7")
        assert isinstance(info, IpInfo)
        assert info.ip == "66.165.2.7"
        assert info.location.country.code == "US"

    async def test_ip_info_stub_returned_as_is(self):
        canned = IpInfo(ip="66.165.2.7")
        fake = IpregistryFake({"66.165.2.7": canned})
        assert await fake.lookup("66.165.2.7") is canned

    async def test_wildcard_fallback(self):
        fake = IpregistryFake({"*": {"location": {"country": {"code": "FR"}}}})
        info = await fake.lookup("1.2.3.4")
        assert info.ip == "1.2.3.4"
        assert info.location.country.code == "FR"

    async def test_exact_match_wins_over_wildcard(self):
        fake = IpregistryFake(
            {
                "66.165.2.7": {"location": {"country": {"code": "US"}}},
                "*": {"location": {"country": {"code": "FR"}}},
            }
        )
        info = await fake.lookup("66.165.2.7")
        assert info.location.country.code == "US"

    async def test_exception_stub_raised(self):
        fake = IpregistryFake({"66.165.2.7": ApiError("INSUFFICIENT_CREDITS", "no credits", "")})
        with pytest.raises(ApiError):
            await fake.lookup("66.165.2.7")

    async def test_unstubbed_raises_ipregistry_error(self):
        fake = IpregistryFake()
        with pytest.raises(IpregistryError):
            await fake.lookup("66.165.2.7")

    async def test_batch(self):
        fake = IpregistryFake(
            {
                "66.165.2.7": {"location": {"country": {"code": "US"}}},
                "1.1.1.1": IpregistryLookupError({"code": "INVALID_IP_ADDRESS", "message": "", "resolution": ""}),
            }
        )
        results = await fake.lookup_batch(["66.165.2.7", "1.1.1.1"])
        assert isinstance(results[0], IpInfo)
        assert isinstance(results[1], IpregistryLookupError)


class TestOriginAndUserAgent:
    async def test_origin_lookup(self):
        fake = IpregistryFake({"origin": {"ip": "66.165.2.7"}})
        info = await fake.lookup_origin()
        assert info.ip == "66.165.2.7"
        fake.assert_origin_looked_up()

    async def test_origin_unstubbed_raises(self):
        fake = IpregistryFake()
        with pytest.raises(IpregistryError):
            await fake.lookup_origin()

    async def test_parse_user_agent_default(self):
        fake = IpregistryFake()
        user_agent = await fake.parse_user_agent("Mozilla/5.0")
        assert user_agent.header == "Mozilla/5.0"
        fake.assert_user_agents_parsed("Mozilla/5.0")

    async def test_parse_user_agent_stub(self):
        fake = IpregistryFake({"Mozilla/5.0": {"name": "Firefox"}})
        user_agent = await fake.parse_user_agent("Mozilla/5.0")
        assert user_agent.name == "Firefox"
        assert user_agent.header == "Mozilla/5.0"


class TestClientIp:
    def test_accepts_private_addresses(self):
        fake = IpregistryFake()
        assert fake.client_ip(make_request(client_host="127.0.0.1")) == "127.0.0.1"

    def test_accepts_test_client_host(self):
        fake = IpregistryFake()
        assert fake.client_ip(make_request(client_host="testclient")) == "testclient"

    async def test_for_request_records_lookup(self):
        fake = IpregistryFake({"*": {}})
        request = make_request(client_host="127.0.0.1")
        info = await fake.for_request(request)
        assert info is not None
        fake.assert_looked_up("127.0.0.1")


class TestAssertions:
    async def test_assert_looked_up(self):
        fake = IpregistryFake({"*": {}})
        await fake.lookup("66.165.2.7")
        fake.assert_looked_up("66.165.2.7")
        fake.assert_looked_up_times("66.165.2.7", 1)
        fake.assert_not_looked_up("1.1.1.1")
        with pytest.raises(AssertionError):
            fake.assert_looked_up("1.1.1.1")
        with pytest.raises(AssertionError):
            fake.assert_nothing_looked_up()

    def test_assert_nothing_looked_up(self):
        IpregistryFake().assert_nothing_looked_up()

    async def test_reset(self):
        fake = IpregistryFake({"*": {}})
        await fake.lookup("66.165.2.7")
        fake.reset()
        fake.assert_nothing_looked_up()

    async def test_stub_after_construction(self):
        fake = IpregistryFake()
        fake.stub({"66.165.2.7": {"location": {"country": {"code": "US"}}}})
        info = await fake.lookup("66.165.2.7")
        assert info.location.country.code == "US"
