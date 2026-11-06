"""Registro de checks: núcleo da arquitetura de plugins.

Cada check é descrito por um `CheckSpec` (nome, tipo de assinatura, categoria, descrição). Os checks
embutidos e os de terceiros usam o mesmo mecanismo: plugins se anunciam pelo entry point
`wvs.checks` e passam a aparecer na CLI e na API sem tocar em `core.py`. Falha ao carregar um plugin
é registrada e ignorada: um plugin quebrado nunca derruba o scan.

Tipos de assinatura (`kind`):
- "response": `fn(response) -> list[Finding]`  (síncrono; recebe a resposta httpx da página inicial)
- "async":    `async fn(ctx) -> list[Finding]`  (recebe o ScanContext: cliente HTTP, config, domínio)
- "url":      `fn(url, timeout=) -> list[Finding]`  (síncrono/bloqueante, roda em thread)
- "domain":   `fn(domain, timeout=) -> list[Finding]` (síncrono/bloqueante, roda em thread)

Categorias: "web" (modo web), "email" (modo email) e "recon" (modo recon; só tipo async).
`active=True` marca checks que enviam tráfego intrusivo: só rodam com --allow-active.
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
            raise ValueError(f"nome de check inválido: {self.name!r} (use minúsculas, dígitos e _)")
        if self.kind not in KINDS:
            raise ValueError(f"{self.name}: kind deve ser um de {KINDS}, não {self.kind!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"{self.name}: category deve ser um de {CATEGORIES}, não {self.category!r}")
        if not callable(self.func):
            raise ValueError(f"{self.name}: func não é chamável")
        if self.category == "recon" and self.kind != "async":
            raise ValueError(f"{self.name}: checks de recon devem ser do tipo 'async'")


class Registry:
    def __init__(self):
        self._specs = {}
        self.plugin_errors = []  # (entry point, mensagem) de plugins que não carregaram

    def register(self, spec: CheckSpec) -> CheckSpec:
        if spec.name in self._specs:
            raise ValueError(f"check '{spec.name}' já registrado por {self._specs[spec.name].source}")
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
        """Carrega checks de terceiros. Devolve os nomes carregados; erros ficam em plugin_errors."""
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP) if entry_points is None else entry_points
        loaded = []
        for ep in eps:
            try:
                obj = ep.load()
                specs = list(obj) if isinstance(obj, (list, tuple)) else [obj]
                for spec in specs:
                    if not isinstance(spec, CheckSpec):
                        raise TypeError(f"o entry point deve apontar para CheckSpec, não {type(spec).__name__}")
                    self.register(replace(spec, source=f"plugin:{ep.name}"))
                    loaded.append(spec.name)
            except Exception as e:  # noqa: BLE001 - plugin de terceiros: nunca derrubar o scan
                self.plugin_errors.append((ep.name, f"{type(e).__name__}: {e}"))
                log.warning("plugin '%s' ignorado: %s: %s", ep.name, type(e).__name__, e)
        return loaded
