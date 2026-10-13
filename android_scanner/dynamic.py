"""Deterministic analysis of packet-like observations (without a device)."""
from dataclasses import dataclass, field
import re
from typing import Any, Iterable, List, Mapping, Optional

@dataclass(frozen=True)
class PacketObservation:
    protocol: str
    host: Optional[str] = None
    path: Optional[str] = None
    payload: str = ""
    encrypted: bool = False

class PacketParser:
    def parse(self, observations: Iterable[Any]) -> List[PacketObservation]:
        result = []
        for raw in observations:
            item = self._one(raw)
            if item is not None: result.append(item)
        return result

    def _one(self, raw: Any) -> Optional[PacketObservation]:
        if isinstance(raw, Mapping):
            protocol = str(raw.get("protocol", raw.get("proto", ""))).lower()
            payload = raw.get("payload", raw.get("data", ""))
            host, path = raw.get("host") or raw.get("hostname"), raw.get("path") or raw.get("api_path")
            encrypted = bool(raw.get("encrypted", raw.get("tls", protocol in {"tls", "https"})))
            return self._normalize(protocol, host, path, payload, encrypted)
        if isinstance(raw, (bytes, str)):
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            lines = text.splitlines(); first = lines[0] if lines else text
            protocol = "http" if re.match(r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", first, re.I) else ("tls" if "TLS" in text.upper() else "")
            host_match = re.search(r"^Host\s*:\s*(\S+)", text, re.I | re.M)
            path_match = re.match(r"\S+\s+(\S+)", first)
            return self._normalize(protocol, host_match.group(1) if host_match else None,
                                   path_match.group(1) if path_match else None, text, protocol == "tls")
        protocol = getattr(raw, "protocol", getattr(raw, "proto", ""))
        if protocol:
            return self._normalize(str(protocol), getattr(raw, "host", None), getattr(raw, "path", None),
                                   getattr(raw, "payload", ""), bool(getattr(raw, "encrypted", False)))
        return None

    @staticmethod
    def _normalize(protocol: str, host: Any, path: Any, payload: Any, encrypted: bool) -> Optional[PacketObservation]:
        protocol = protocol.lower().strip()
        if not protocol: return None
        payload = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload or "")
        return PacketObservation(protocol, str(host) if host else None, str(path) if path else None, payload,
                                 encrypted or protocol in {"tls", "https"})

@dataclass
class DynamicAnalysis:
    cleartext_http: bool = False
    sensitive_cleartext: List[str] = field(default_factory=list)
    contacted_hosts: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    tls_ratio: float = 0.0
    api_paths: List[str] = field(default_factory=list)
    observation_count: int = 0

    @property
    def cleartext_http_detected(self) -> bool:
        return self.cleartext_http

    @property
    def sensitive_keywords(self) -> List[str]:
        return self.sensitive_cleartext

class DynamicAnalyzer:
    SENSITIVE = ("password", "passwd", "token", "api_key", "apikey", "secret", "authorization", "bearer", "ssn")

    def analyze(self, observations: Iterable[Any]) -> DynamicAnalysis:
        parsed = PacketParser().parse(observations)
        result = DynamicAnalysis(observation_count=len(parsed))
        result.protocols = list(dict.fromkeys(item.protocol for item in parsed))
        result.contacted_hosts = list(dict.fromkeys(item.host for item in parsed if item.host))
        tls_count = sum(item.protocol in {"tls", "https"} or item.encrypted for item in parsed)
        result.tls_ratio = tls_count / len(parsed) if parsed else 0.0
        for item in parsed:
            if item.path and (item.path == "/api" or item.path.startswith("/api/")) and item.path not in result.api_paths:
                result.api_paths.append(item.path)
            if item.protocol == "http" and not item.encrypted:
                result.cleartext_http = True
                lowered = item.payload.lower()
                for word in self.SENSITIVE:
                    if word in lowered and word not in result.sensitive_cleartext: result.sensitive_cleartext.append(word)
        return result

def analyze_observations(observations: Iterable[Any]) -> DynamicAnalysis:
    return DynamicAnalyzer().analyze(observations)

# Descriptive aliases for callers that use the capture terminology.
PacketAnalyzer = DynamicAnalyzer
