import pytest

from ipregistry_fastapi.ip import (
    anonymize_ip,
    build_ip_extractor,
    is_public_ip,
    is_valid_ip,
    sanitize_ip,
)

from .conftest import make_request


class TestSanitizeIp:
    def test_plain_ipv4(self):
        assert sanitize_ip("66.165.2.7") == "66.165.2.7"

    def test_strips_whitespace(self):
        assert sanitize_ip("  66.165.2.7 ") == "66.165.2.7"

    def test_strips_ipv4_port(self):
        assert sanitize_ip("66.165.2.7:8080") == "66.165.2.7"

    def test_strips_ipv6_brackets(self):
        assert sanitize_ip("[2001:db8::1]") == "2001:db8::1"

    def test_strips_ipv6_brackets_with_port(self):
        assert sanitize_ip("[2001:db8::1]:443") == "2001:db8::1"

    def test_strips_zone_id(self):
        assert sanitize_ip("fe80::1%eth0") == "fe80::1"

    def test_keeps_plain_ipv6(self):
        assert sanitize_ip("2001:db8::1") == "2001:db8::1"

    def test_empty_returns_none(self):
        assert sanitize_ip("") is None
        assert sanitize_ip("   ") is None
        assert sanitize_ip(None) is None

    def test_unclosed_bracket_returns_none(self):
        assert sanitize_ip("[2001:db8::1") is None


class TestIsValidIp:
    def test_valid(self):
        assert is_valid_ip("66.165.2.7")
        assert is_valid_ip("2001:db8::1")

    def test_invalid(self):
        assert not is_valid_ip("testclient")
        assert not is_valid_ip("999.1.1.1")
        assert not is_valid_ip("")


class TestIsPublicIp:
    @pytest.mark.parametrize("ip", ["66.165.2.7", "8.8.8.8", "2606:4700::1111"])
    def test_public(self, ip):
        assert is_public_ip(ip)

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.0.1",
            "100.64.0.1",  # carrier-grade NAT
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:192.168.1.1",  # IPv4-mapped private address
            "224.0.0.1",  # multicast
            "not-an-ip",
        ],
    )
    def test_not_public(self, ip):
        assert not is_public_ip(ip)


class TestAnonymizeIp:
    def test_ipv4(self):
        assert anonymize_ip("66.165.2.7") == "66.165.2.x"

    def test_ipv6(self):
        assert anonymize_ip("2001:db8:85a3::8a2e:370:7334") == "2001:0db8:85a3::x"

    def test_invalid(self):
        assert anonymize_ip("nope") == "<invalid>"


class TestBuildIpExtractor:
    def test_client_source(self):
        extract = build_ip_extractor("client")
        assert extract(make_request(client_host="66.165.2.7")) == "66.165.2.7"

    def test_client_source_invalid_host(self):
        extract = build_ip_extractor("client")
        assert extract(make_request(client_host="testclient")) is None

    def test_client_source_no_client(self):
        extract = build_ip_extractor("client")
        assert extract(make_request(client_host=None)) is None

    def test_auto_prefers_x_real_ip(self):
        extract = build_ip_extractor("auto")
        request = make_request(headers={"x-real-ip": "66.165.2.7", "x-forwarded-for": "1.1.1.1"})
        assert extract(request) == "66.165.2.7"

    def test_auto_falls_back_to_forwarded_for(self):
        extract = build_ip_extractor("auto")
        request = make_request(headers={"x-forwarded-for": "66.165.2.7, 10.0.0.1"})
        assert extract(request) == "66.165.2.7"

    def test_cloudflare(self):
        extract = build_ip_extractor("cloudflare")
        request = make_request(headers={"cf-connecting-ip": "66.165.2.7", "x-forwarded-for": "1.1.1.1"})
        assert extract(request) == "66.165.2.7"

    def test_cloudflare_ignores_other_headers(self):
        extract = build_ip_extractor("cloudflare")
        assert extract(make_request(headers={"x-forwarded-for": "1.1.1.1"})) is None

    def test_forwarded_for_takes_first_entry(self):
        extract = build_ip_extractor("forwarded-for")
        request = make_request(headers={"x-forwarded-for": "66.165.2.7, 172.16.0.9"})
        assert extract(request) == "66.165.2.7"

    def test_custom_header(self):
        extract = build_ip_extractor("header:x-client-ip")
        assert extract(make_request(headers={"x-client-ip": "66.165.2.7"})) == "66.165.2.7"

    def test_custom_header_requires_name(self):
        with pytest.raises(ValueError):
            build_ip_extractor("header:")

    def test_invalid_header_value_ignored(self):
        extract = build_ip_extractor("auto")
        assert extract(make_request(headers={"x-real-ip": "spoofed"})) is None

    def test_callable_passthrough(self):
        extract = build_ip_extractor(lambda request: "66.165.2.7")
        assert extract(make_request()) == "66.165.2.7"

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError):
            build_ip_extractor("nope")
