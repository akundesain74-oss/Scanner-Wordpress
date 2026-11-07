
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Finding:
    template: str
    protocol: str
    severity: str
    target: str
    detail: str
    evidence: Optional[str] = None
    source: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    def validate(self):
        allowed = {
            "info",
            "warning",
            "verified",
            "unknown",
            "error"
        }

        if self.severity not in allowed:
            raise ValueError("Invalid severity")

        if not self.template or not self.target:
            raise ValueError("Missing finding identity")

        return True
