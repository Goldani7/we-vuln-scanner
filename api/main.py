from typing import List, Optional

from fastapi import FastAPI, Request
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from scanner.core import ALL_CHECKS, REGISTRY, scan

from .validation import validate_public_url

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="web-vuln-scanner API", version="0.2.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


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


@app.post("/scan")
@limiter.limit("10/minute")
def run_scan(request: Request, body: ScanRequest):
    findings = scan(body.url, checks=body.checks)
    return [f.to_dict() for f in findings]
