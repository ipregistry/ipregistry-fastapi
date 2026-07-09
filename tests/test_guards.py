from ipregistry import IpInfo, Location, Security

from ipregistry_fastapi import is_bot, is_eu, is_threat

from .conftest import make_request


def info_with_security(**flags) -> IpInfo:
    return IpInfo(ip="66.165.2.7", security=Security(**flags))


class TestIsEu:
    def test_eu_visitor(self):
        assert is_eu(IpInfo(location=Location(in_eu=True)))

    def test_non_eu_visitor(self):
        assert not is_eu(IpInfo(location=Location(in_eu=False)))

    def test_unknown_defaults_to_false(self):
        assert not is_eu(None)
        assert not is_eu(IpInfo())
        assert not is_eu(IpInfo(location=Location()))

    def test_assume_eu(self):
        assert is_eu(None, assume_eu=True)
        assert is_eu(IpInfo(location=Location()), assume_eu=True)
        assert not is_eu(IpInfo(location=Location(in_eu=False)), assume_eu=True)


class TestIsThreat:
    def test_core_signals_always_checked(self):
        assert is_threat(info_with_security(is_threat=True))
        assert is_threat(info_with_security(is_attacker=True))
        assert is_threat(info_with_security(is_abuser=True))

    def test_clean_ip(self):
        assert not is_threat(info_with_security())

    def test_no_data_fails_open(self):
        assert not is_threat(None)
        assert not is_threat(IpInfo())

    def test_anonymization_signals_opt_in(self):
        vpn_user = info_with_security(is_vpn=True, is_anonymous=True)
        assert not is_threat(vpn_user)
        assert is_threat(vpn_user, vpn=True)
        assert is_threat(vpn_user, anonymous=True)

    def test_tor_covers_exit_nodes(self):
        assert is_threat(info_with_security(is_tor_exit=True), tor=True)
        assert is_threat(info_with_security(is_tor=True), tor=True)
        assert not is_threat(info_with_security(is_tor=True))

    def test_proxy_relay_cloud_bogon(self):
        assert is_threat(info_with_security(is_proxy=True), proxy=True)
        assert is_threat(info_with_security(is_relay=True), relay=True)
        assert is_threat(info_with_security(is_cloud_provider=True), cloud_provider=True)
        assert is_threat(info_with_security(is_bogon=True), bogon=True)


class TestIsBot:
    def test_bot_user_agent_string(self):
        assert is_bot("Googlebot/2.1 (+http://www.google.com/bot.html)")

    def test_regular_user_agent_string(self):
        assert not is_bot("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

    def test_request_subject(self):
        assert is_bot(make_request(headers={"user-agent": "bingbot/2.0"}))
        assert not is_bot(make_request(headers={"user-agent": "Mozilla/5.0"}))

    def test_missing_user_agent(self):
        assert not is_bot(make_request())
        assert not is_bot(None)
        assert not is_bot("")
