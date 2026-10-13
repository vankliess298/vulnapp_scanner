"""Data models and JSON serialization for scan results."""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str = ""
    source: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    apk_path: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    tool_metadata: Dict[str, Any] = field(default_factory=dict)
    dynamic_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "files_scanned": self.files_scanned,
            "apk_path": self.apk_path,
            "errors": list(self.errors),
            "tools": dict(self.tool_metadata),
            "dynamic": dict(self.dynamic_metadata),
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)
