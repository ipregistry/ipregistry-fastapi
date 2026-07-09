"""Live tests against the Ipregistry API. Skipped unless IPREGISTRY_API_KEY is set."""

import os

import pytest

from ipregistry_fastapi import Ipregistry, IpregistrySettings

API_KEY = os.environ.get("IPREGISTRY_API_KEY", "")

pytestmark = pytest.mark.skipif(not API_KEY, reason="IPREGISTRY_API_KEY is not set")


@pytest.fixture
async def service():
    async with Ipregistry(IpregistrySettings(api_key=API_KEY)) as service:
        yield service


async def test_lookup(service):
    info = await service.lookup("66.165.2.7")
    assert info.ip == "66.165.2.7"
    assert info.location is not None
    assert info.location.country is not None
    assert info.security is not None


async def test_lookup_with_fields(service):
    info = await service.lookup("66.165.2.7", fields="location.country.code")
    assert info.location.country.code is not None
    assert info.security is None


async def test_lookup_batch(service):
    results = await service.lookup_batch(["66.165.2.7", "1.1.1.1"])
    assert len(results) == 2
    assert results[0].ip == "66.165.2.7"
    assert results[1].ip == "1.1.1.1"


async def test_lookup_origin(service):
    info = await service.lookup_origin()
    assert info.ip is not None


async def test_parse_user_agent(service):
    user_agent = await service.parse_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )
    assert user_agent.name is not None
