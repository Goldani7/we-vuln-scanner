import hmac
import os
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from scanner.core import ALL_CHECKS, REGISTRY, scan
from scanner.http import ScanConfig

from .validation import validate_public_url

SCAN_DEADLINE = float(os.environ.get("WVS_API_DEADLINE", "120"))  # seconds, whole scan

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="web-vuln-scanner API", version="0.3.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    """If WVS_API_KEY is set, /scan requires a matching X-API-Key header (constant-time compare).
    Unset = open API (fine on localhost; set it before exposing the service)."""
    expected = os.environ.get("WVS_API_KEY")
    if expected and not hmac.compare_digest(x_api_key or "", expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def api_scan_config() -> ScanConfig:
    """Config for untrusted callers: never touch internal addresses, never run active checks,
    and never run past the deadline."""
    return ScanConfig(timeout=8, public_only=True, allow_active=False, max_duration=SCAN_DEADLINE)


class ScanRequest(BaseModel):
    url: str
    checks: Optional[List[str]] = None

    @field_validator("url")
    @classmethod
    def _check_url(cls, v):
        return validate_public_url(v)

    @field_validator("checks")
    @classmethod
    def _check_names(cls, v):
        if v is not None:
            invalid = [c for c in v if c not in ALL_CHECKS]
            if invalid:
                raise ValueError(f"Invalid checks: {', '.join(invalid)}")
        return v


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/checks")
def list_checks():
    return [{"name": n, "description": REGISTRY.description(n)} for n in ALL_CHECKS]


@app.post("/scan", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
def run_scan(request: Request, body: ScanRequest):
    findings = scan(body.url, checks=body.checks, config=api_scan_config())
    return [f.to_dict() for f in findings]
