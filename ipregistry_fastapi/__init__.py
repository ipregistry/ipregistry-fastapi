"""
    Official Ipregistry integration for FastAPI.

    Dependency-driven IP geolocation and threat detection for every request,
    built on the asynchronous Ipregistry Python client.

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

from ipregistry import (
    ApiError as ApiError,
    ApiResponse as ApiResponse,
    Carrier as Carrier,
    ClientError as ClientError,
    Company as Company,
    Connection as Connection,
    Country as Country,
    Currency as Currency,
    ErrorCode as ErrorCode,
    IpInfo as IpInfo,
    IpregistryError as IpregistryError,
    IpregistryLookupError as IpregistryLookupError,
    Location as Location,
    RequesterIpInfo as RequesterIpInfo,
    Security as Security,
    TimeZone as TimeZone,
    UserAgent as UserAgent,
)

from .blocking import (
    Blocker as Blocker,
    CountryBlocker as CountryBlocker,
    ThreatBlocker as ThreatBlocker,
    block_countries as block_countries,
    block_threats as block_threats,
)
from .dependencies import (
    ClientIpDep as ClientIpDep,
    IpInfoDep as IpInfoDep,
    IpregistryDep as IpregistryDep,
    get_client_ip as get_client_ip,
    get_ip_info as get_ip_info,
    get_ipregistry as get_ipregistry,
)
from .exceptions import MissingApiKeyError as MissingApiKeyError
from .guards import is_bot as is_bot, is_eu as is_eu, is_threat as is_threat
from .ip import (
    IpExtractor as IpExtractor,
    IpSource as IpSource,
    anonymize_ip as anonymize_ip,
    build_ip_extractor as build_ip_extractor,
    is_public_ip as is_public_ip,
)
from .lifespan import add_ipregistry as add_ipregistry, ipregistry_lifespan as ipregistry_lifespan
from .middleware import IpregistryMiddleware as IpregistryMiddleware
from .service import Ipregistry as Ipregistry
from .settings import (
    DEFAULT_BASE_URL as DEFAULT_BASE_URL,
    EU_BASE_URL as EU_BASE_URL,
    IpregistrySettings as IpregistrySettings,
)
from .version import __version__ as __version__
