import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from ipregistry import ApiError

from ipregistry_fastapi import (
    ClientIpDep,
    IpInfoDep,
    IpregistryDep,
    IpregistrySettings,
    add_ipregistry,
    get_ipregistry,
    ipregistry_lifespan,
)
from ipregistry_fastapi.testing import IpregistryFake


def build_app(fake: IpregistryFake) -> FastAPI:
    app = FastAPI(lifespan=ipregistry_lifespan)
    add_ipregistry(app, service=fake)

    @app.get("/country")
    async def country(info: IpInfoDep):
        return {"country": info.location.country.code if info and info.location and info.location.country else None}

    @app.get("/shared")
    async def shared(first: IpInfoDep, second: IpInfoDep):
        return {"same": first is second}

    @app.get("/ip")
    async def client_ip(ip: ClientIpDep):
        return {"ip": ip}

    @app.get("/service")
    async def service(ipregistry: IpregistryDep):
        return {"configured": ipregistry is not None}

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket, info: IpInfoDep):
        await websocket.accept()
        country = info.location.country.code if info and info.location and info.location.country else None
        await websocket.send_json({"country": country})
        await websocket.close()

    return app


FR_RESPONSE = {"location": {"country": {"code": "FR"}, "in_eu": True}}


class TestIpInfoDep:
    def test_returns_ip_info(self):
        fake = IpregistryFake({"*": FR_RESPONSE})
        with TestClient(build_app(fake)) as client:
            response = client.get("/country")
        assert response.status_code == 200
        assert response.json() == {"country": "FR"}

    def test_ip_specific_stub_with_proxy_header(self):
        fake = IpregistryFake({"66.165.2.7": {"location": {"country": {"code": "US"}}}}, ip_extractor="auto")
        with TestClient(build_app(fake)) as client:
            response = client.get("/country", headers={"x-real-ip": "66.165.2.7"})
        assert response.json() == {"country": "US"}
        fake.assert_looked_up("66.165.2.7")

    def test_single_lookup_shared_between_dependencies(self):
        fake = IpregistryFake({"*": FR_RESPONSE})
        with TestClient(build_app(fake)) as client:
            response = client.get("/shared")
        assert response.json() == {"same": True}
        assert len(fake.lookups) == 1

    def test_fail_open_returns_none(self):
        fake = IpregistryFake({"*": ApiError("INTERNAL", "boom", "")})
        with TestClient(build_app(fake)) as client:
            response = client.get("/country")
        assert response.status_code == 200
        assert response.json() == {"country": None}

    def test_fail_closed_returns_503(self):
        fake = IpregistryFake(
            {"*": ApiError("INTERNAL", "boom", "")},
            settings=IpregistrySettings(api_key="fake", fail_open=False),
        )
        with TestClient(build_app(fake)) as client:
            response = client.get("/country")
        assert response.status_code == 503

    def test_unstubbed_lookup_fails_open(self):
        fake = IpregistryFake()
        with TestClient(build_app(fake)) as client:
            response = client.get("/country")
        assert response.status_code == 200
        assert response.json() == {"country": None}


class TestClientIpDep:
    def test_resolves_header_ip(self):
        fake = IpregistryFake(ip_extractor="auto")
        with TestClient(build_app(fake)) as client:
            response = client.get("/ip", headers={"x-real-ip": "66.165.2.7"})
        assert response.json() == {"ip": "66.165.2.7"}


class TestIpregistryDep:
    def test_provides_service(self):
        fake = IpregistryFake({"*": FR_RESPONSE})
        with TestClient(build_app(fake)) as client:
            response = client.get("/service")
        assert response.json() == {"configured": True}


class TestWebSockets:
    def test_ip_info_dep_in_websocket_endpoint(self):
        fake = IpregistryFake({"*": FR_RESPONSE})
        with TestClient(build_app(fake)) as client:
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_json() == {"country": "FR"}
        assert len(fake.lookups) == 1

    def test_websocket_with_proxy_header(self):
        fake = IpregistryFake({"66.165.2.7": {"location": {"country": {"code": "US"}}}}, ip_extractor="auto")
        with TestClient(build_app(fake)) as client:
            with client.websocket_connect("/ws", headers={"x-real-ip": "66.165.2.7"}) as websocket:
                assert websocket.receive_json() == {"country": "US"}
        fake.assert_looked_up("66.165.2.7")


class TestWebSocketDenial:
    def test_fail_closed_denies_handshake_with_503(self):
        from starlette.testclient import WebSocketDenialResponse

        fake = IpregistryFake(
            {"*": ApiError("INTERNAL", "boom", "")},
            settings=IpregistrySettings(api_key="fake", fail_open=False),
        )
        with TestClient(build_app(fake)) as client:
            with pytest.raises(WebSocketDenialResponse) as denial:
                with client.websocket_connect("/ws"):
                    pass
        assert denial.value.status_code == 503


class TestDependencyOverrides:
    def test_get_ipregistry_can_be_overridden(self):
        app = build_app(IpregistryFake())  # attached service returns no data
        override = IpregistryFake({"*": FR_RESPONSE})
        app.dependency_overrides[get_ipregistry] = lambda: override
        with TestClient(app) as client:
            response = client.get("/country")
        assert response.json() == {"country": "FR"}
        assert len(override.lookups) == 1


class TestAddIpregistry:
    def test_attaches_service_to_state(self):
        app = FastAPI()
        fake = IpregistryFake()
        assert add_ipregistry(app, service=fake) is fake
        assert app.state.ipregistry is fake
