"""Optional Scapy capture adapter."""
try:
    from scapy.all import sniff  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    sniff = None
    SCAPY_AVAILABLE = False

class PacketCapture:
    def __init__(self) -> None: self.last_error = None
    @property
    def available(self) -> bool: return SCAPY_AVAILABLE
    def capture(self, timeout: int = 10, count: int = 0):
        if not SCAPY_AVAILABLE:
            self.last_error = "Scapy is unavailable; packet capture is disabled"; return []
        try: return list(sniff(timeout=max(0, int(timeout)), count=max(0, int(count)), store=True))
        except Exception as exc:
            self.last_error = str(exc); return []
