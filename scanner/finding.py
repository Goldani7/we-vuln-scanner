import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(Enum):
    """Valores em inglês e estáveis: são o contrato dos formatos JSON/SARIF e da API."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)

    @property
    def label(self) -> str:
        """Rótulo em português para relatórios legíveis."""
        return {"info": "INFO", "low": "BAIXO", "medium": "MÉDIO",
                "high": "ALTO", "critical": "CRÍTICO"}[self.value]


@dataclass
class Finding:
    """Um achado acionável.

    Os seis primeiros campos são posicionais e mantêm a ordem original; os demais enriquecem o
    achado para o pentester: `evidence` (o que foi observado, com segredos mascarados),
    `cwe`/`references` (classificação), `confidence` (probabilidade de ser verdadeiro positivo)
    e `target` (preenchido pelo orquestrador).
    """
    check: str
    severity: Severity
    title: str
    detail: str = ""
    remediation: str = ""
    metadata: dict = field(default_factory=dict)
    evidence: str = ""
    cwe: str = ""
    references: list = field(default_factory=list)
    confidence: str = "medium"  # low | medium | high
    rule_id: str = ""
    target: str = ""

    @property
    def rule(self) -> str:
        return self.rule_id or self.check

    @property
    def fingerprint(self) -> str:
        """Identificador estável para deduplicar achados entre execuções."""
        raw = f"{self.rule}|{self.title}|{self.target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["rule_id"] = self.rule
        d["fingerprint"] = self.fingerprint
        return d
