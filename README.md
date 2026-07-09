# Ipregistry FastAPI

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.txt)
[![Tests](https://github.com/ipregistry/ipregistry-fastapi/actions/workflows/tests.yaml/badge.svg)](https://github.com/ipregistry/ipregistry-fastapi/actions/workflows/tests.yaml)
[![PyPI](https://img.shields.io/pypi/v/ipregistry-fastapi.svg)](https://pypi.org/project/ipregistry-fastapi/)

Official [Ipregistry](https://ipregistry.co) integration for [FastAPI](https://fastapi.tiangolo.com):
dependency-driven IP geolocation and threat detection for every request, built on the asynchronous
[Ipregistry Python client](https://github.com/ipregistry/ipregistry-python).

```python
from fastapi import FastAPI
from ipregistry_fastapi import IpInfoDep, ipregistry_lifespan

app = FastAPI(lifespan=ipregistry_lifespan)

@app.get("/")
async def index(info: IpInfoDep):
    return {"country": info.location.country.name if info else None}
```

## Features

- **Async-first**: non-blocking lookups through the official asynchronous Ipregistry client, with
  connection reuse managed by the application lifespan.
- **Idiomatic dependencies**: `IpInfoDep`, `IpregistryDep` and `ClientIpDep` annotated types plug
  straight into path operations; one cached lookup per request, shared by every consumer.
- **Guards**: block countries (HTTP 451) and threats (HTTP 403) per route, per router, or app-wide.
- **Middleware**: optional pure-ASGI middleware for global enrichment and blocking, with static
  asset and bot skipping to save credits.
- **Safe by default**: fails open, never sends private or reserved addresses to the API, validates
  proxy headers, and never logs full client IPs.
- **Configuration via environment**: `IPREGISTRY_*` variables parsed with pydantic-settings.
- **Typed responses**: lookups return the client's Pydantic v2 models, ready to embed in your own
  response models.
- **First-class testing**: `IpregistryFake` swaps in canned responses with call assertions —
  no network, no API key.

## Getting started

### Requirements

- Python 3.10+
- FastAPI 0.115+
- An [Ipregistry API key](https://dashboard.ipregistry.co) — the free tier includes 100,000 lookups

### Installation

```console
pip install ipregistry-fastapi
```

or with [uv](https://docs.astral.sh/uv/):

```console
uv add ipregistry-fastapi
```

### Quick start

Set your API key:

```console
export IPREGISTRY_API_KEY=YOUR_API_KEY
```

Wire the lifespan and use the dependency:

```python
from fastapi import FastAPI
from ipregistry_fastapi import IpInfoDep, ipregistry_lifespan

app = FastAPI(lifespan=ipregistry_lifespan)

@app.get("/whoami")
async def whoami(info: IpInfoDep):
    if info is None:
        return {"detail": "No IP intelligence available"}
    return {
        "ip": info.ip,
        "country": info.location.country.name,
        "city": info.location.city,
        "threat": info.security.is_threat,
    }
```

`IpInfoDep` resolves to an [`IpInfo`](https://ipregistry.co/docs/) model — or `None` when the
client IP is private (e.g. on localhost) or the lookup failed. One lookup runs per request no
matter how many dependencies, guards or middleware consume it, and responses are cached in memory
across requests.

To configure programmatically instead of via the environment:

```python
from ipregistry_fastapi import IpregistrySettings, add_ipregistry, ipregistry_lifespan

app = FastAPI(lifespan=ipregistry_lifespan)
add_ipregistry(app, IpregistrySettings(api_key="...", base_url="eu", fields="location,security"))
```

## Blocking countries

`block_countries` returns a dependency enforcing an ISO 3166-1 alpha-2 country list. Blocked
visitors receive `451 Unavailable For Legal Reasons` by default. Invalid codes fail at declaration
time, not at request time.

```python
from fastapi import APIRouter, Depends
from ipregistry_fastapi import block_countries

router = APIRouter(dependencies=[Depends(block_countries("KP", "SY"))])

# Allowlist mode: only serve the EU single market
checkout = APIRouter(dependencies=[Depends(block_countries(EU_COUNTRIES, mode="allow"))])
```

Requests whose country cannot be determined are allowed unless you pass `unknown="block"`.

## Blocking threats

`block_threats` blocks IPs flagged as threats, attackers or abusers, and responds with `403`.
Anonymization signals are opt-in — a VPN user is not necessarily hostile:

```python
from fastapi import Depends, FastAPI
from ipregistry_fastapi import block_threats

app = FastAPI(dependencies=[Depends(block_threats())])

# Stricter variant for sensitive routes:
admin = APIRouter(dependencies=[Depends(block_threats(proxy=True, tor=True, vpn=True, relay=True))])
```

Requests without security data are allowed (fail open), so an Ipregistry outage never locks users
out of your API.

## Middleware

Prefer dependencies for per-route rules. Reach for the middleware to enforce app-wide policies or
eagerly enrich every request — including ones that never match a route:

```python
from ipregistry_fastapi import IpregistryMiddleware, block_countries, block_threats

app.add_middleware(
    IpregistryMiddleware,
    actions=[block_countries("KP"), block_threats(tor=True)],
    skip_bots=True,          # skip lookups for crawler user agents
    skip_static_assets=True, # default: skip .css/.js/images/fonts
    skip=lambda request: request.url.path.startswith("/health"),
)
```

The middleware stores the lookup on `request.state.ipregistry`, so `IpInfoDep` and route guards
reuse it for free.

### Fail open or closed

By default a failed lookup lets the request proceed with `info = None` (fail open). To refuse
requests instead when IP intelligence is unavailable:

- set `IPREGISTRY_FAIL_OPEN=false` — `IpInfoDep` and blocking dependencies respond with `503`;
- or pass `fail_closed=True` (or a custom status code) to `IpregistryMiddleware`.

## GDPR & EU detection

```python
from ipregistry_fastapi import IpInfoDep, is_eu

@app.get("/consent")
async def consent(info: IpInfoDep):
    return {"show_banner": is_eu(info, assume_eu=True)}
```

`is_eu` reads `location.in_eu`; `assume_eu=True` errs on the side of showing a consent banner when
the location is unknown. For EU data residency, set `IPREGISTRY_BASE_URL=eu` to route all API
requests to `https://eu.api.ipregistry.co`.

Related helpers: `is_threat(info, vpn=True, ...)` and `is_bot(request)` (heuristic, no API call).

## Configuration

All settings load from the environment via
[pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/), or can be passed
programmatically with `IpregistrySettings`:

| Environment variable                  | Default  | Description                                                          |
| ------------------------------------- | -------- | -------------------------------------------------------------------- |
| `IPREGISTRY_API_KEY`                   | —        | **Required.** Your Ipregistry API key.                               |
| `IPREGISTRY_BASE_URL`                  | default  | API endpoint; `eu` selects the EU-only endpoint; full URLs verbatim. |
| `IPREGISTRY_FIELDS`                    | all      | Default field selection, e.g. `location,security`.                   |
| `IPREGISTRY_HOSTNAME`                  | `false`  | Resolve the hostname of looked up IPs.                               |
| `IPREGISTRY_TIMEOUT`                   | `5.0`    | Request timeout in seconds.                                          |
| `IPREGISTRY_RETRIES`                   | `1`      | Retry attempts after a failed request.                               |
| `IPREGISTRY_RETRY_INTERVAL`            | `0.5`    | Base delay between retries (exponential backoff).                    |
| `IPREGISTRY_RETRY_ON_SERVER_ERROR`     | `true`   | Retry on 5xx responses.                                              |
| `IPREGISTRY_RETRY_ON_TOO_MANY_REQUESTS`| `false`  | Retry on 429 responses (honors `Retry-After`).                       |
| `IPREGISTRY_CACHE_ENABLED`             | `true`   | Cache lookups in memory.                                             |
| `IPREGISTRY_CACHE_MAX_SIZE`            | `2048`   | Maximum cached lookups.                                              |
| `IPREGISTRY_CACHE_TTL`                 | `600`    | Cache time-to-live in seconds.                                       |
| `IPREGISTRY_DEVELOPMENT_IP`            | —        | Fallback IP when the client IP is private (e.g. localhost).          |
| `IPREGISTRY_FAIL_OPEN`                 | `true`   | Proceed without data when a lookup fails.                            |
| `IPREGISTRY_IP_SOURCE`                 | `client` | How to resolve the client IP (see below).                            |

Selecting only the fields you need (e.g. `IPREGISTRY_FIELDS=location,security`) reduces latency
and response size.

## IP extraction behind proxies

By default (`client`) the library uses the ASGI client address — the right choice when uvicorn
runs with `--proxy-headers --forwarded-allow-ips` or behind
`ProxyHeadersMiddleware`, which already resolve the real client IP.

If your server does not rewrite the client address, pick the header set by a proxy you trust:

| `IPREGISTRY_IP_SOURCE` | Headers consulted (in order)     |
| ---------------------- | -------------------------------- |
| `client` (default)     | none — ASGI client address       |
| `auto`                 | `X-Real-IP`, `X-Forwarded-For`   |
| `cloudflare`           | `CF-Connecting-IP`               |
| `nginx`                | `X-Real-IP`, `X-Forwarded-For`   |
| `forwarded-for`        | `X-Forwarded-For` (first entry)  |
| `header:<name>`        | the named header                 |

A callable `ip_extractor` can also be passed to `Ipregistry`/`add_ipregistry` for full control.
Values are sanitized (ports, IPv6 brackets and zone IDs stripped) and validated; only configure
headers your proxy overwrites — client-supplied headers are trivially spoofable. Private,
loopback and carrier-grade NAT addresses are never sent to the API; set
`IPREGISTRY_DEVELOPMENT_IP` to test with a fixed address on localhost.

## Caching and credits

Lookups are cached in memory (2048 entries, 10 minutes by default), so repeated requests from the
same address consume a single credit. On top of that:

- one lookup per request, however many consumers;
- static asset and bot skipping in the middleware;
- private/reserved IPs short-circuit before reaching the API.

Multi-worker deployments (`uvicorn --workers`, gunicorn) hold one cache per process.

## Testing your app

`IpregistryFake` is a drop-in service with canned responses and no network access:

```python
from fastapi.testclient import TestClient
from ipregistry_fastapi import add_ipregistry
from ipregistry_fastapi.testing import IpregistryFake

fake = IpregistryFake({
    "66.165.2.7": {"location": {"country": {"code": "US"}}},
    "*": {"security": {"is_threat": False}},   # any other address
})
add_ipregistry(app, service=fake)

client = TestClient(app)
response = client.get("/whoami", headers={"x-real-ip": "66.165.2.7"})

fake.assert_looked_up("66.165.2.7")
```

Stubs are API-shaped dicts, `IpInfo` instances, or exceptions to raise. Unlike the real service,
the fake accepts private addresses so requests made through `TestClient` resolve out of the box.
Assertions: `assert_looked_up`, `assert_not_looked_up`, `assert_looked_up_times`,
`assert_nothing_looked_up`, `assert_origin_looked_up`, `assert_user_agents_parsed`.

## Errors

Request-aware helpers (`IpInfoDep`, guards, middleware) never raise on lookup failure — they fail
open and record the exception on `request.state.ipregistry_error`. Explicit lookups raise the
client's exceptions:

```python
from ipregistry_fastapi import ApiError, ClientError, ErrorCode, IpregistryDep

@app.get("/lookup/{ip}")
async def lookup(ip: str, ipregistry: IpregistryDep):
    try:
        return await ipregistry.lookup(ip)
    except ApiError as error:
        if error.error_code == ErrorCode.INVALID_IP_ADDRESS:
            raise HTTPException(status_code=400, detail=error.message)
        raise HTTPException(status_code=502, detail="Lookup failed")
    except ClientError:
        raise HTTPException(status_code=504, detail="Ipregistry unreachable")
```

## Beyond IP lookups

The full asynchronous client remains available for batch lookups, ASN data, user-agent parsing and
credits introspection:

```python
@app.post("/enrich")
async def enrich(ips: list[str], ipregistry: IpregistryDep):
    results = await ipregistry.lookup_batch(ips)          # order-preserving
    origin = await ipregistry.lookup_origin()             # the server's own IP
    asn = await ipregistry.client.lookup_asn(400923)      # raw client escape hatch
```

## Migrating from ipregistry-python

Existing `ipregistry` client code keeps working — this package layers FastAPI wiring on top:

- replace manual client creation with `ipregistry_lifespan` / `add_ipregistry`;
- replace per-endpoint lookups of the request IP with `IpInfoDep`;
- move country/threat checks into `block_countries` / `block_threats` dependencies;
- configuration moves to `IPREGISTRY_*` environment variables.

## Other resources

- [Ipregistry documentation](https://ipregistry.co/docs)
- [Ipregistry Python client](https://github.com/ipregistry/ipregistry-python)
- [API status](https://status.ipregistry.co)

## License

[Apache-2.0](LICENSE.txt) © [Ipregistry](https://ipregistry.co)
