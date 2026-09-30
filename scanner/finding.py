from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "baixo"
    MEDIUM = "médio"
    HIGH = "alto"

    @property
    def rank(self) -> int:
        return {"info": 0, "baixo": 1, "médio": 2, "alto": 3}[self.value]


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
