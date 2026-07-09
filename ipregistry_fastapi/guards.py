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

from typing import Union

from fastapi.requests import HTTPConnection
from ipregistry import IpInfo, UserAgents


def is_eu(info: IpInfo | None, *, assume_eu: bool = False) -> bool:
    """Return True when the IP is located in the European Union.

    Useful for GDPR consent flows. When the EU membership is unknown (no data),
    returns assume_eu, so pass assume_eu=True to err on the side of showing a
    consent banner.
    """
    in_eu = info.location.in_eu if info is not None and info.location is not None else None
    return assume_eu if in_eu is None else in_eu


def is_threat(
    info: IpInfo | None,
    *,
    proxy: bool = False,
    tor: bool = False,
    vpn: bool = False,
    relay: bool = False,
    anonymous: bool = False,
    cloud_provider: bool = False,
    bogon: bool = False,
) -> bool:
    """Return True when the IP is a known threat.

    Known threats, attackers and abusers are always flagged. Anonymization
    signals (proxy, tor, vpn, relay, anonymous) and infrastructure signals
    (cloud_provider, bogon) are opt-in since they are not inherently malicious.
    Returns False when no security data is available (fail open).
    """
    security = info.security if info is not None else None
    if security is None:
        return False
    signals = [security.is_threat, security.is_attacker, security.is_abuser]
    if proxy:
        signals.append(security.is_proxy)
    if tor:
        signals.extend((security.is_tor, security.is_tor_exit))
    if vpn:
        signals.append(security.is_vpn)
    if relay:
        signals.append(security.is_relay)
    if anonymous:
        signals.append(security.is_anonymous)
    if cloud_provider:
        signals.append(security.is_cloud_provider)
    if bogon:
        signals.append(security.is_bogon)
    return any(bool(signal) for signal in signals)


def is_bot(subject: Union[HTTPConnection, str, None]) -> bool:
    """Return True when the request or User-Agent string looks like a bot or
    crawler. Heuristic string check; no API call and no credit consumed."""
    if subject is None:
        return False
    header = subject if isinstance(subject, str) else subject.headers.get("user-agent", "")
    return bool(header) and UserAgents.is_bot(header)
