"""Compatibility-facing names for the dynamic analysis layer."""
from .dynamic import (
    DynamicAnalysis,
    DynamicAnalyzer,
    PacketAnalyzer,
    PacketObservation,
    PacketParser,
    analyze_observations,
)

__all__ = [
    "DynamicAnalysis", "DynamicAnalyzer", "PacketAnalyzer", "PacketObservation",
    "PacketParser", "analyze_observations",
]
