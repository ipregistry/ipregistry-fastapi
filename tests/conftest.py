import os

import pytest
from fastapi import Request


@pytest.fixture(autouse=True)
def _clean_ipregistry_env(monkeypatch):
    """Keep tests deterministic regardless of IPREGISTRY_* variables in the host environment."""
    for key in list(os.environ):
        if key.startswith("IPREGISTRY_"):
            monkeypatch.delenv(key)


def make_request(
    client_host: str | None = "203.0.113.5",
    headers: dict[str, str] | None = None,
    path: str = "/",
) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()],
        "client": (client_host, 12345) if client_host is not None else None,
        "server": ("testserver", 80),
    }
    return Request(scope)
