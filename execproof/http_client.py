from __future__ import annotations

import threading
import time
from urllib.parse import urlparse

import requests

from .config import enforce_scope


class ScopeViolation(Exception):
    pass


class HttpClient:
    def __init__(self, timeout: float = 15.0, rate: float = 5.0, headers: dict | None = None,
                 scope_regex: str | None = None):
        self.timeout = timeout
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self.scope_regex = scope_regex
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "execproof/0.2.0"})
        if headers:
            self.session.headers.update(headers)
        self.requests_sent = 0

    def _throttle(self):
        with self._lock:
            wait = self._interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def request(self, method: str, url: str, data: str | None = None, params: dict | None = None,
                timeout: float | None = None):
        if not enforce_scope(url, self.scope_regex):
            raise ScopeViolation(f"URL outside declared scope: {url}")
        if urlparse(url).scheme not in ("http", "https"):
            raise ScopeViolation(f"Non-http(s) target: {url}")
        self._throttle()
        self.requests_sent += 1
        t0 = time.monotonic()
        resp = self.session.request(
            method=method,
            url=url,
            data=data,
            params=params,
            timeout=timeout or self.timeout,
            allow_redirects=True,
        )
        elapsed = time.monotonic() - t0
        return resp, elapsed

    def close(self):
        self.session.close()
