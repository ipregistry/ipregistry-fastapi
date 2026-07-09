# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-09

### Added

- `Ipregistry` request-aware service built on the asynchronous Ipregistry Python client, with
  per-request memoization, fail-open semantics and in-memory response caching.
- Annotated dependencies: `IpInfoDep`, `IpregistryDep`, `ClientIpDep`.
- `ipregistry_lifespan` and `add_ipregistry` for application wiring and client lifecycle.
- Blocking guards usable as route dependencies or middleware actions: `block_countries`
  (HTTP 451, block/allow modes, unknown-country policy) and `block_threats` (HTTP 403, opt-in
  anonymization signals).
- `IpregistryMiddleware` pure-ASGI middleware with global enrichment, blocking actions,
  fail-closed mode and static asset/bot/custom skipping.
- Helpers: `is_eu`, `is_threat`, `is_bot`.
- Client IP resolution with trusted-proxy presets (`client`, `auto`, `cloudflare`, `nginx`,
  `forwarded-for`), custom headers and callables; private and reserved addresses are never sent
  to the API.
- Configuration from `IPREGISTRY_*` environment variables via pydantic-settings, including the
  `eu` base URL shorthand for EU data residency.
- `IpregistryFake` testing double with canned responses and lookup assertions.

[Unreleased]: https://github.com/ipregistry/ipregistry-fastapi/compare/1.0.0...HEAD
[1.0.0]: https://github.com/ipregistry/ipregistry-fastapi/releases/tag/1.0.0
