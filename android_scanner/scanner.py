"""High-level APK scanner orchestration."""

from pathlib import Path
from typing import Union

from .adapter import StaticAnalysisAdapter
from .models import ScanSummary


class APKScanner:
    def __init__(self, adapter: StaticAnalysisAdapter | None = None) -> None:
        self.adapter = adapter or StaticAnalysisAdapter()

    def scan(self, apk_path: Union[str, Path]) -> ScanSummary:
        path = Path(apk_path)
        summary = ScanSummary(apk_path=str(path))
        try:
            result = self.adapter.analyze(path)
            summary.files_scanned = result.files_scanned
            summary.findings.extend(result.findings)
            summary.errors.extend(result.errors)
            summary.tool_metadata = {name: metadata.to_dict() for name, metadata in result.tools.items()}
        except Exception as exc:
            summary.errors.append(str(exc))
        return summary
