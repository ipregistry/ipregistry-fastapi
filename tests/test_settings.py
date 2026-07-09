import pytest
from pydantic import ValidationError

from ipregistry_fastapi import DEFAULT_BASE_URL, EU_BASE_URL, IpregistrySettings


class TestDefaults:
    def test_defaults(self):
        settings = IpregistrySettings()
        assert settings.api_key == ""
        assert settings.base_url is None
        assert settings.fields is None
        assert settings.hostname is False
        assert settings.timeout == 5.0
        assert settings.retries == 1
        assert settings.cache_enabled is True
        assert settings.cache_max_size == 2048
        assert settings.cache_ttl == 600
        assert settings.development_ip is None
        assert settings.fail_open is True
        assert settings.ip_source == "client"


class TestEnvironment:
    def test_reads_env_vars(self, monkeypatch):
        monkeypatch.setenv("IPREGISTRY_API_KEY", "secret")
        monkeypatch.setenv("IPREGISTRY_BASE_URL", "eu")
        monkeypatch.setenv("IPREGISTRY_FIELDS", "location,security")
        monkeypatch.setenv("IPREGISTRY_TIMEOUT", "2.5")
        monkeypatch.setenv("IPREGISTRY_CACHE_ENABLED", "false")
        monkeypatch.setenv("IPREGISTRY_FAIL_OPEN", "false")
        monkeypatch.setenv("IPREGISTRY_IP_SOURCE", "cloudflare")
        settings = IpregistrySettings()
        assert settings.api_key == "secret"
        assert settings.base_url == "eu"
        assert settings.fields == "location,security"
        assert settings.timeout == 2.5
        assert settings.cache_enabled is False
        assert settings.fail_open is False
        assert settings.ip_source == "cloudflare"

    def test_explicit_values_override_env(self, monkeypatch):
        monkeypatch.setenv("IPREGISTRY_API_KEY", "from-env")
        settings = IpregistrySettings(api_key="explicit")
        assert settings.api_key == "explicit"


class TestBaseUrl:
    def test_default(self):
        assert IpregistrySettings().resolved_base_url == DEFAULT_BASE_URL

    def test_eu_shorthand(self):
        assert IpregistrySettings(base_url="eu").resolved_base_url == EU_BASE_URL
        assert IpregistrySettings(base_url="EU").resolved_base_url == EU_BASE_URL

    def test_custom_url(self):
        url = "https://proxy.example.com"
        assert IpregistrySettings(base_url=url).resolved_base_url == url


class TestValidation:
    def test_invalid_development_ip(self):
        with pytest.raises(ValidationError):
            IpregistrySettings(development_ip="not-an-ip")

    def test_empty_development_ip_is_none(self):
        assert IpregistrySettings(development_ip="").development_ip is None

    def test_valid_development_ip(self):
        assert IpregistrySettings(development_ip="66.165.2.7").development_ip == "66.165.2.7"

    def test_negative_retries(self):
        with pytest.raises(ValidationError):
            IpregistrySettings(retries=-1)

    def test_zero_timeout(self):
        with pytest.raises(ValidationError):
            IpregistrySettings(timeout=0)

    def test_invalid_ip_source(self):
        with pytest.raises(ValidationError):
            IpregistrySettings(ip_source="cloudfare")  # typo caught at settings load

    def test_valid_ip_sources(self):
        for source in ("client", "auto", "cloudflare", "nginx", "forwarded-for", "header:x-client-ip"):
            assert IpregistrySettings(ip_source=source).ip_source == source
