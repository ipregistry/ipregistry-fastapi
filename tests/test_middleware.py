from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from ipregistry import ApiError

from ipregistry_fastapi import (
    IpregistryMiddleware,
    IpregistrySettings,
    block_countries,
    block_threats,
)
from ipregistry_fastapi.testing import IpregistryFake

US_RESPONSE = {"location": {"country": {"code": "US"}}}


def build_app(**middleware_options) -> FastAPI:
    app = FastAPI()
    app.add_middleware(IpregistryMiddleware, **middleware_options)

    @app.get("/{path:path}")
    async def catch_all(request: Request):
        info = getattr(request.state, "ipregistry", None)
        country = info.location.country.code if info and info.location and info.location.country else None
        return {"country": country}

    return app


class TestEnrichment:
    def test_populates_request_state(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake)
        response = TestClient(app).get("/")
        assert response.json() == {"country": "US"}

    def test_lookup_shared_with_dependencies(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake)
        TestClient(app).get("/")
        assert len(fake.lookups) == 1

    def test_uses_service_from_app_state(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app()
        app.state.ipregistry = fake
        response = TestClient(app).get("/")
        assert response.json() == {"country": "US"}
        assert len(fake.lookups) == 1


class TestSkipping:
    def test_skips_static_assets(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake)
        TestClient(app).get("/assets/app.css")
        fake.assert_nothing_looked_up()

    def test_static_assets_lookup_when_disabled(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake, skip_static_assets=False)
        TestClient(app).get("/assets/app.css")
        assert len(fake.lookups) == 1

    def test_skips_bots(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake, skip_bots=True)
        TestClient(app).get("/", headers={"user-agent": "Googlebot/2.1"})
        fake.assert_nothing_looked_up()

    def test_custom_skip_predicate(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake, skip=lambda request: request.url.path.startswith("/health"))
        client = TestClient(app)
        client.get("/health")
        fake.assert_nothing_looked_up()
        client.get("/page")
        assert len(fake.lookups) == 1


class TestActions:
    def test_block_countries_action(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake, actions=[block_countries("US")])
        response = TestClient(app).get("/")
        assert response.status_code == 451
        assert response.text == "Access restricted in your region."

    def test_block_threats_action(self):
        fake = IpregistryFake({"*": {"security": {"is_threat": True}}})
        app = build_app(service=fake, actions=[block_threats()])
        assert TestClient(app).get("/").status_code == 403

    def test_actions_pass_through_clean_requests(self):
        fake = IpregistryFake({"*": US_RESPONSE})
        app = build_app(service=fake, actions=[block_countries("FR"), block_threats()])
        assert TestClient(app).get("/").status_code == 200


class TestFailureModes:
    def test_fail_open_by_default(self):
        fake = IpregistryFake({"*": ApiError("INTERNAL", "boom", "")})
        app = build_app(service=fake)
        response = TestClient(app).get("/")
        assert response.status_code == 200
        assert response.json() == {"country": None}

    def test_fail_closed(self):
        fake = IpregistryFake({"*": ApiError("INTERNAL", "boom", "")})
        app = build_app(service=fake, fail_closed=True)
        assert TestClient(app).get("/").status_code == 503

    def test_fail_closed_custom_status(self):
        fake = IpregistryFake({"*": ApiError("INTERNAL", "boom", "")})
        app = build_app(service=fake, fail_closed=429)
        assert TestClient(app).get("/").status_code == 429

    def test_no_public_ip_is_not_a_failure(self):
        from ipregistry_fastapi import Ipregistry

        from .test_service import DuckClient

        # The real service skips the lookup when no public client IP exists
        # (TestClient's host is not an IP address): not an error, no 503.
        client = DuckClient()
        service = Ipregistry(IpregistrySettings(api_key="test"), client=client)
        app = build_app(service=service, fail_closed=True)
        response = TestClient(app).get("/")
        assert response.status_code == 200
        assert response.json() == {"country": None}
        assert client.calls == []
