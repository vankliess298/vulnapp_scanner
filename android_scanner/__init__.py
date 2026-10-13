"""Reusable static analysis core for Android APKs."""

from .archive import APKValidationError, validate_apk, safe_extract_apk
from .models import Finding, ScanSummary
from .adapter import AdapterResult, StaticAnalysisAdapter, ToolMetadata
from .scanner import APKScanner
from .adb import ADBController, ADBDevice
from .capture import PacketCapture, SCAPY_AVAILABLE
from .dynamic import DynamicAnalysis, DynamicAnalyzer, PacketObservation, PacketParser, analyze_observations

__all__ = [
    "APKScanner",
    "APKValidationError",
    "Finding",
    "ScanSummary",
    "safe_extract_apk",
    "validate_apk",
    "AdapterResult",
    "StaticAnalysisAdapter",
    "ToolMetadata",
    "ADBController",
    "ADBDevice",
    "PacketCapture",
    "SCAPY_AVAILABLE",
    "DynamicAnalysis",
    "DynamicAnalyzer",
    "PacketObservation",
    "PacketParser",
    "analyze_observations",
]
