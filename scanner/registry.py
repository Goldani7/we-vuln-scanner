"""Check registry: the core of the plugin architecture.

Each check is described by a `CheckSpec` (name, signature kind, category, description). Built-in
checks and third-party ones use the same mechanism: plugins announce themselves via the
`wvs.checks` entry point and show up in the CLI and the API without touching `core.py`. A plugin
that fails to load is logged and skipped: a broken plugin never takes down the scan.

Signature kinds (`kind`):
- "response": `fn(response) -> list[Finding]`  (sync; receives the httpx response of the homepage)
- "async":    `async fn(ctx) -> list[Finding]`  (receives the ScanContext: HTTP client, config, domain)
- "url":      `fn(url, timeout=) -> list[Finding]`  (sync/blocking, runs in a thread)
- "domain":   `fn(domain, timeout=) -> list[Finding]` (sync/blocking, runs in a thread)

Categories: "web" (web mode), "email" (email mode) and "recon" (recon mode; "async" kind only).
`active=True` marks checks that send intrusive traffic: they only run with --allow-active.
"""
import importlib.metadata
import logging
import re
from dataclasses import dataclass, replace
from typing import Callable

log = logging.getLogger(__name__)

KINDS = ("response", "async", "url", "domain")
CATEGORIES = ("web", "email", "recon")
ENTRY_POINT_GROUP = "wvs.checks"
_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class CheckSpec:
    name: str
    kind: str
    func: Callable
    category: str = "web"
    description: str = ""
    active: bool = False
    source: str = "builtin"

    def __post_init__(self):
        if not _NAME.match(self.name or ""):
            raise ValueError(f"invalid check name: {self.name!r} (use lowercase letters, digits and _)")
        if self.kind not in KINDS:
            raise ValueError(f"{self.name}: kind must be one of {KINDS}, not {self.kind!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"{self.name}: category must be one of {CATEGORIES}, not {self.category!r}")
        if not callable(self.func):
            raise ValueError(f"{self.name}: func is not callable")
        if self.category == "recon" and self.kind != "async":
            raise ValueError(f"{self.name}: recon checks must be of kind 'async'")


class Registry:
    def __init__(self):
        self._specs = {}
        self.plugin_errors = []  # (entry point, message) for plugins that failed to load

    def register(self, spec: CheckSpec) -> CheckSpec:
        if spec.name in self._specs:
            raise ValueError(f"check '{spec.name}' is already registered by {self._specs[spec.name].source}")
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> CheckSpec:
        return self._specs[name]

    def __contains__(self, name) -> bool:
        return name in self._specs

    def names(self, category: str = None, include_active: bool = False) -> list:
        return [s.name for s in self._specs.values()
                if (category is None or s.category == category) and (include_active or not s.active)]

    def by_kind(self, kind: str) -> dict:
        return {s.name: s.func for s in self._specs.values() if s.kind == kind}

    def description(self, name: str) -> str:
        return self._specs[name].description

    def load_plugins(self, entry_points=None) -> list:
        """Loads third-party checks. Returns the names loaded; errors go into plugin_errors."""
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP) if entry_points is None else entry_points
        loaded = []
        for ep in eps:
            try:
                obj = ep.load()
                specs = list(obj) if isinstance(obj, (list, tuple)) else [obj]
                for spec in specs:
                    if not isinstance(spec, CheckSpec):
                        raise TypeError(f"entry point must point to a CheckSpec, not {type(spec).__name__}")
                    self.register(replace(spec, source=f"plugin:{ep.name}"))
                    loaded.append(spec.name)
            except Exception as e:  # noqa: BLE001 - third-party plugin: never take down the scan
                self.plugin_errors.append((ep.name, f"{type(e).__name__}: {e}"))
                log.warning("plugin '%s' skipped: %s: %s", ep.name, type(e).__name__, e)
        return loaded
