import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(Enum):
    """Stable English values: these are the contract for the JSON/SARIF formats and the API."""
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
        """Display label for human-readable reports."""
        return {"info": "INFO", "low": "LOW", "medium": "MEDIUM",
                "high": "HIGH", "critical": "CRITICAL"}[self.value]


@dataclass
class Finding:
    """An actionable finding.

    The first six fields are positional and keep their original order; the rest enrich the
    finding for the pentester: `evidence` (what was observed, with secrets masked),
    `cwe`/`references` (classification), `confidence` (likelihood of being a true positive)
    and `target` (filled in by the orchestrator).
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
    status: str = ""  # "new" | "unchanged" when compared against --baseline

    @property
    def rule(self) -> str:
        return self.rule_id or self.check

    @property
    def exploitability(self) -> str:
        """Slug derived from severity+confidence: how much this finding, on its own, suggests a
        real exploitation path (rather than just weakening defenses). Never more confident than
        the finding's own confidence: a CRITICAL with confidence 'low' never comes out as 'high'
        without verification."""
        if self.severity is Severity.INFO:
            return "informational"
        if self.severity.rank >= Severity.HIGH.rank and self.confidence in ("high", "medium"):
            return "high"
        if self.severity.rank >= Severity.MEDIUM.rank:
            return "moderate"
        return "low"

    @property
    def exploitability_label(self) -> str:
        return {"high": "High (likely exploitable)", "moderate": "Moderate — verify manually",
               "low": "Low / hardening", "informational": "Informational"}[self.exploitability]

    @property
    def fingerprint(self) -> str:
        """Stable identifier used to deduplicate findings across runs."""
        raw = f"{self.rule}|{self.title}|{self.target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["rule_id"] = self.rule
        d["fingerprint"] = self.fingerprint
        d["exploitability"] = self.exploitability
        return d
