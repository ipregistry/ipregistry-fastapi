import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from ipregistry_fastapi import add_ipregistry, block_countries, block_threats
from ipregistry_fastapi.testing import IpregistryFake


def build_app(fake: IpregistryFake, *dependencies) -> FastAPI:
    app = FastAPI()
    add_ipregistry(app, service=fake)

    @app.get("/", dependencies=[Depends(dependency) for dependency in dependencies])
    async def index():
        return {"ok": True}

    return app


def fake_for_country(code: str | None) -> IpregistryFake:
    location = {"country": {"code": code}} if code is not None else {}
    return IpregistryFake({"*": {"location": location}})


def fake_for_security(**flags) -> IpregistryFake:
    return IpregistryFake({"*": {"security": flags}})


class TestBlockCountries:
    def test_blocks_listed_country(self):
        app = build_app(fake_for_country("FR"), block_countries("FR"))
        response = TestClient(app).get("/")
        assert response.status_code == 451

    def test_allows_other_countries(self):
        app = build_app(fake_for_country("US"), block_countries("FR"))
        assert TestClient(app).get("/").status_code == 200

    def test_allow_mode(self):
        blocker = block_countries("FR", "BE", mode="allow")
        assert TestClient(build_app(fake_for_country("FR"), blocker)).get("/").status_code == 200
        assert TestClient(build_app(fake_for_country("US"), blocker)).get("/").status_code == 451

    def test_unknown_country_allowed_by_default(self):
        app = build_app(fake_for_country(None), block_countries("FR"))
        assert TestClient(app).get("/").status_code == 200

    def test_unknown_country_blocked_on_demand(self):
        app = build_app(fake_for_country(None), block_countries("FR", unknown="block"))
        assert TestClient(app).get("/").status_code == 451

    def test_accepts_iterable(self):
        app = build_app(fake_for_country("FR"), block_countries(["FR", "BE"]))
        assert TestClient(app).get("/").status_code == 451

    def test_codes_case_insensitive(self):
        app = build_app(fake_for_country("FR"), block_countries("fr"))
        assert TestClient(app).get("/").status_code == 451

    def test_custom_status_and_detail(self):
        app = build_app(fake_for_country("FR"), block_countries("FR", status_code=403, detail="Nope"))
        response = TestClient(app).get("/")
        assert response.status_code == 403
        assert response.json() == {"detail": "Nope"}

    def test_invalid_country_code_rejected_at_declaration(self):
        with pytest.raises(ValueError):
            block_countries("FRA")
        with pytest.raises(ValueError):
            block_countries("F1")
        with pytest.raises(ValueError):
            block_countries()

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError):
            block_countries("FR", mode="deny")


class TestBlockThreats:
    def test_blocks_threat(self):
        app = build_app(fake_for_security(is_threat=True), block_threats())
        assert TestClient(app).get("/").status_code == 403

    def test_blocks_attacker_and_abuser(self):
        assert TestClient(build_app(fake_for_security(is_attacker=True), block_threats())).get("/").status_code == 403
        assert TestClient(build_app(fake_for_security(is_abuser=True), block_threats())).get("/").status_code == 403

    def test_allows_clean_ip(self):
        app = build_app(fake_for_security(), block_threats())
        assert TestClient(app).get("/").status_code == 200

    def test_vpn_opt_in(self):
        fake = fake_for_security(is_vpn=True)
        assert TestClient(build_app(fake, block_threats())).get("/").status_code == 200
        fake = fake_for_security(is_vpn=True)
        assert TestClient(build_app(fake, block_threats(vpn=True))).get("/").status_code == 403

    def test_tor_opt_in_covers_exit_nodes(self):
        fake = fake_for_security(is_tor_exit=True)
        assert TestClient(build_app(fake, block_threats(tor=True))).get("/").status_code == 403

    def test_no_data_fails_open(self):
        app = build_app(IpregistryFake({"*": {}}), block_threats())
        assert TestClient(app).get("/").status_code == 200

    def test_custom_status(self):
        app = build_app(fake_for_security(is_threat=True), block_threats(status_code=429))
        assert TestClient(app).get("/").status_code == 429


class TestCombined:
    def test_multiple_guards(self):
        fake = IpregistryFake({"*": {"location": {"country": {"code": "US"}}, "security": {"is_threat": True}}})
        app = build_app(fake, block_countries("FR"), block_threats())
        assert TestClient(app).get("/").status_code == 403

    def test_single_lookup_for_multiple_guards(self):
        fake = IpregistryFake({"*": {"location": {"country": {"code": "US"}}, "security": {}}})
        app = build_app(fake, block_countries("FR"), block_threats())
        assert TestClient(app).get("/").status_code == 200
        assert len(fake.lookups) == 1
