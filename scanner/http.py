"""Async HTTP layer shared by every check.

Centralizes what a well-behaved scan needs: rate limiting, concurrency limiting, retries with
backoff (honoring Retry-After), proxy, custom headers/User-Agent, error classification (timeout,
TLS, connection) and a per-host circuit breaker so it never keeps hammering a target that's down.
"""
import asyncio
import random
import ssl
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import httpx

from . import __version__

DEFAULT_USER_AGENT = f"web-vuln-scanner/{__version__}"
RETRY_STATUSES = {429, 502, 503, 504}
# Passive public services queried instead of the target (not the target itself; exempt from scope).
PASSIVE_SERVICES = {"crt.sh"}
CIRCUIT_THRESHOLD = 8  # consecutive failures on a host before giving up on it


@dataclass
class ScanConfig:
    timeout: float = 10.0
    rate: float = 10.0          # total requests per second (0 = unlimited)
    concurrency: int = 10
    retries: int = 2
    proxy: str = None           # http://host:port or socks5://host:port
    headers: dict = field(default_factory=dict)
    user_agent: str = DEFAULT_USER_AGENT
    verify: bool = True
    max_backoff: float = 30.0
    allow_active: bool = False  # unlocks intrusive checks (CheckSpec.active)
    scope: object = None        # scanner.scope.Scope; if set, enforced on EVERY request
    ports: list = None          # port list for portscan; None = default table


class RequestFailed(Exception):
    """Classified network failure. `kind`: timeout | tls | connect | proxy | redirects |
    circuit_open | out_of_scope | network."""

    def __init__(self, kind: str, url: str, message: str):
        super().__init__(message)
        self.kind, self.url = kind, url

    def describe(self) -> str:
        return f"{self.kind}: {self}"


def _has_tls_cause(exc) -> bool:
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, ssl.SSLError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def classify_error(exc: Exception, url: str) -> RequestFailed:
    msg = str(exc) or type(exc).__name__
    if isinstance(exc, httpx.TimeoutException):
        kind = "timeout"
    elif _has_tls_cause(exc) or "CERTIFICATE_VERIFY_FAILED" in msg:
        kind = "tls"
    elif isinstance(exc, httpx.ProxyError):
        kind = "proxy"
    elif isinstance(exc, httpx.TooManyRedirects):
        kind = "redirects"
    elif isinstance(exc, httpx.ConnectError):
        kind = "connect"
    else:
        kind = "network"
    return RequestFailed(kind, url, msg)


class RateLimiter:
    """Spaces requests at least 1/rate seconds apart."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)


class HttpClient:
    def __init__(self, config: ScanConfig = None, transport=None, sleep=asyncio.sleep):
        self.config = config or ScanConfig()
        self._limiter = RateLimiter(self.config.rate)
        self._sem = asyncio.Semaphore(max(1, self.config.concurrency))
        self._sleep = sleep
        self._failures = {}  # host -> consecutive failures
        self.stats = {"requests": 0, "retries": 0, "throttled": 0, "forbidden": 0, "failures": 0, "out_of_scope": 0}
        headers = {"User-Agent": self.config.user_agent, **self.config.headers}
        self._client = httpx.AsyncClient(
            headers=headers, proxy=self.config.proxy, verify=self.config.verify,
            timeout=self.config.timeout, transport=transport, follow_redirects=False,
            # The hook runs on every request, including each redirect hop.
            event_hooks={"request": [self._enforce_scope]},
        )

    async def _enforce_scope(self, request: httpx.Request):
        scope, host = self.config.scope, request.url.host
        if scope is not None and host not in PASSIVE_SERVICES and not scope.allows(host):
            self.stats["out_of_scope"] += 1
            raise RequestFailed("out_of_scope", str(request.url),
                                f"{host} is out of scope ({scope.source or 'scope file'}); request blocked")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self._client.aclose()

    def _retry_delay(self, response, attempt: int) -> float:
        cap = self.config.max_backoff
        retry_after = response.headers.get("retry-after") if response is not None else None
        if retry_after:
            try:
                return min(float(retry_after), cap)
            except ValueError:
                try:
                    wait = parsedate_to_datetime(retry_after).timestamp() - time.time()
                    return min(max(wait, 0.0), cap)
                except (TypeError, ValueError):
                    pass
        return min(cap, 0.5 * 2 ** attempt + random.uniform(0, 0.25))

    async def request(self, method: str, url: str, *, headers=None, timeout=None,
                      follow_redirects: bool = False, retries: int = None) -> httpx.Response:
        host = urlparse(url).hostname or url
        if self._failures.get(host, 0) >= CIRCUIT_THRESHOLD:
            raise RequestFailed("circuit_open", url,
                                f"{host} failed {CIRCUIT_THRESHOLD}x in a row; requests suspended")
        attempts = (self.config.retries if retries is None else retries) + 1

        for attempt in range(attempts):
            last_attempt = attempt + 1 >= attempts
            response, error = None, None
            async with self._sem:  # the backoff sleep stays outside the semaphore
                await self._limiter.wait()
                self.stats["requests"] += 1
                try:
                    response = await self._client.request(
                        method, url, headers=headers, timeout=timeout or self.config.timeout,
                        follow_redirects=follow_redirects)
                except RequestFailed:  # scope block: final, no retry and no circuit breaker
                    raise
                except httpx.HTTPError as e:
                    error = classify_error(e, url)
                except httpx.InvalidURL as e:
                    raise RequestFailed("network", url, f"invalid URL: {e}") from e

            if error is not None:
                retryable = error.kind in ("timeout", "connect", "network")
                if retryable and not last_attempt:
                    self.stats["retries"] += 1
                    await self._sleep(self._retry_delay(None, attempt))
                    continue
                self._failures[host] = self._failures.get(host, 0) + 1
                self.stats["failures"] += 1
                raise error

            if response.status_code == 429:
                self.stats["throttled"] += 1
            elif response.status_code in (403, 406):
                self.stats["forbidden"] += 1
            if response.status_code in RETRY_STATUSES and not last_attempt:
                self.stats["retries"] += 1
                await self._sleep(self._retry_delay(response, attempt))
                continue
            self._failures[host] = 0
            return response
        raise AssertionError("unreachable")  # pragma: no cover


class ScanContext:
    """What every check receives: the HTTP client, the config, and the (cached) homepage response."""

    def __init__(self, url: str, client: HttpClient, config: ScanConfig):
        self.url, self.client, self.config = url, client, config
        self.domain = (urlparse(url).hostname or "").lower()
        self._index = None
        self._index_error = None
        self._lock = asyncio.Lock()

    async def index(self) -> httpx.Response:
        async with self._lock:
            if self._index_error:
                raise self._index_error
            if self._index is None:
                try:
                    self._index = await self.client.request("GET", self.url, follow_redirects=True)
                except RequestFailed as e:
                    self._index_error = e
                    raise
            return self._index
