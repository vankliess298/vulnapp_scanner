"""Small, bounded wrapper around the Android Debug Bridge executable."""
from dataclasses import dataclass
import re
import subprocess
from pathlib import Path
from typing import List, Optional
import zipfile

@dataclass(frozen=True)
class ADBDevice:
    serial: str
    state: str

class ADBController:
    def __init__(self, adb_path: str = "adb", timeout: float = 15.0) -> None:
        self.adb_path, self.timeout, self.last_error = adb_path, timeout, None

    def _run(self, args: List[str]) -> str:
        self.last_error = None
        try:
            result = subprocess.run([self.adb_path, *args], capture_output=True, text=True,
                                    timeout=self.timeout, check=False, shell=False)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            self.last_error = f"ADB unavailable: {exc}"
            raise
        if result.returncode:
            self.last_error = (result.stderr or result.stdout or "ADB command failed").strip()
            raise RuntimeError(self.last_error)
        return result.stdout

    @property
    def available(self) -> bool:
        try:
            self._run(["version"])
            return True
        except (OSError, subprocess.SubprocessError, RuntimeError):
            return False

    def list_devices(self) -> List[ADBDevice]:
        try:
            output = self._run(["devices"])
        except (OSError, subprocess.SubprocessError, RuntimeError):
            return []
        devices = []
        for line in output.splitlines():
            match = re.match(r"^([^\s]+)\s+(\S+)$", line.strip())
            if match and match.group(1) != "List":
                devices.append(ADBDevice(match.group(1), match.group(2)))
        return devices

    def package_from_apk(self, apk_path: str) -> Optional[str]:
        try:
            result = subprocess.run(["aapt", "dump", "badging", str(apk_path)], capture_output=True,
                                    text=True, timeout=self.timeout, check=False, shell=False)
            match = re.search(r"package:\s+name='([^']+)'", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        try:
            with zipfile.ZipFile(apk_path) as archive:
                text = archive.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
            match = re.search(r'(?:package|name)=["\']([^"\']+)', text)
            return match.group(1) if match else None
        except (OSError, KeyError, zipfile.BadZipFile):
            return None

    def install(self, apk_path: str, serial: Optional[str] = None) -> bool:
        args = (["-s", serial] if serial else []) + ["install", "-r", str(Path(apk_path))]
        try:
            self._run(args); return True
        except (OSError, subprocess.SubprocessError, RuntimeError):
            return False

    def launch(self, package: str, serial: Optional[str] = None) -> bool:
        args = (["-s", serial] if serial else []) + ["shell", "monkey", "-p", package, "1"]
        try:
            self._run(args); return True
        except (OSError, subprocess.SubprocessError, RuntimeError):
            return False

    def install_and_launch(self, apk_path: str, serial: Optional[str] = None) -> bool:
        package = self.package_from_apk(apk_path)
        return bool(package and self.install(apk_path, serial) and self.launch(package, serial))
