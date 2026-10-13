"""Optional external-tool integration for static APK analysis.

APKTool and Androguard decode compiled artifacts when installed. The stdlib
text scanner remains usable without either, with explicit coverage warnings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Union
import xml.etree.ElementTree as ET

from .archive import safe_extract_apk
from .models import Finding
from .rules import TEXT_SUFFIXES, analyze_file, analyze_manifest
from .dex_rules import inspect_dex


MAX_TOOL_OUTPUT = 8192


@dataclass
class ToolMetadata:
    name: str
    available: bool = False
    version: Optional[str] = None
    error: Optional[str] = None
    details: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdapterResult:
    findings: List[Finding]
    files_scanned: int
    tools: Dict[str, ToolMetadata]
    errors: List[str]


class StaticAnalysisAdapter:
    """Run optional APKTool/Androguard analysis with safe fallbacks."""

    def __init__(
        self,
        apktool_command: str = "apktool",
        timeout: float = 60.0,
        max_output: int = MAX_TOOL_OUTPUT,
        use_apktool: bool = True,
        use_androguard: bool = True,
    ) -> None:
        self.apktool_command = apktool_command
        self.timeout = timeout
        self.max_output = max(256, max_output)
        self.use_apktool = use_apktool
        self.use_androguard = use_androguard

    def analyze(self, apk_path: Union[str, Path]) -> AdapterResult:
        path = Path(apk_path)
        tools: Dict[str, ToolMetadata] = {}
        findings: List[Finding] = []
        errors: List[str] = []
        manifest_scanned = False
        files_scanned = 0

        with tempfile.TemporaryDirectory(prefix="android-scanner-") as directory:
            workspace = Path(directory) / "decoded"
            root = self._decode(path, workspace, tools)
            for file_path in root.rglob("*"):
                if file_path.is_file() and (file_path.suffix.lower() in TEXT_SUFFIXES or file_path.name == "AndroidManifest.xml"):
                    if file_path.name == "AndroidManifest.xml":
                        try:
                            ET.fromstring(file_path.read_bytes())
                        except (ET.ParseError, ValueError):
                            # Compiled AXML is not text and cannot be scanned by regex.
                            continue
                        manifest_scanned = True
                    file_findings = analyze_file(file_path)
                    for finding in file_findings:
                        finding.source = "apk:" + file_path.relative_to(root).as_posix()
                    findings.extend(file_findings)
                    files_scanned += 1

        if self.use_androguard:
            findings.extend(self._inspect_with_androguard(path, tools))
        else:
            tools["androguard"] = ToolMetadata("androguard", error="disabled")
        guard = tools["androguard"]
        details = guard.details or {}
        if details.get("manifest_decoded"):
            if not manifest_scanned:
                files_scanned += 1
            manifest_scanned = True
        files_scanned += details.get("dex_files_scanned", 0)
        for metadata in tools.values():
            if metadata.error and metadata.error != "disabled":
                errors.append(f"{metadata.name}: {metadata.error}")
        errors.extend(details.get("warnings", []))
        if not manifest_scanned:
            errors.append("Incomplete manifest coverage: no readable AndroidManifest.xml was decoded. "
                          "Install/enable Androguard or APKTool to inspect compiled manifest settings.")
        apktool_decoded = bool((tools["apktool"].details or {}).get("decoded"))
        if not details.get("dex_complete") and not apktool_decoded:
            errors.append("Incomplete DEX coverage: compiled bytecode was not fully inspected. "
                          "Zero findings does not establish that the APK is safe.")
        # XML may have been decoded by both integrations. Keep one manifest
        # finding per evidence item while preserving separate DEX call sites.
        unique_findings = []
        seen = set()
        for finding in findings:
            origin = finding.source or ""
            if origin.endswith("AndroidManifest.xml"):
                origin = "AndroidManifest.xml"
            identity = (finding.rule_id, finding.evidence, origin)
            if identity not in seen:
                seen.add(identity)
                unique_findings.append(finding)
        return AdapterResult(unique_findings, files_scanned, tools, errors)

    def _decode(self, apk_path: Path, workspace: Path, tools: Dict[str, ToolMetadata]) -> Path:
        if not self.use_apktool:
            tools["apktool"] = ToolMetadata("apktool", error="disabled", details={"decoded": False, "fallback": "ZIP text extraction"})
            return safe_extract_apk(apk_path, workspace)

        executable = shutil.which(self.apktool_command)
        if not executable:
            tools["apktool"] = ToolMetadata("apktool", error="executable not found", details={"decoded": False, "fallback": "ZIP text extraction"})
            return safe_extract_apk(apk_path, workspace)

        metadata = ToolMetadata("apktool", available=True, details={"decoded": False, "fallback": "ZIP text extraction"})
        tools["apktool"] = metadata
        version = self._run([executable, "--version"])
        if version[0] is not None:
            metadata.version = version[0]
        elif version[1]:
            metadata.error = version[1]
        command = [executable, "d", "-f", "-o", str(workspace), str(apk_path)]
        result, error = self._run(command)
        if error:
            metadata.error = error
            return safe_extract_apk(apk_path, workspace.with_name("extracted"))
        if not workspace.is_dir():
            metadata.error = "apktool completed without creating a decoded workspace"
            return safe_extract_apk(apk_path, workspace)
        metadata.details = {"decoded": True, "manifest": "decoded XML", "dex": "decoded smali text rules"}
        return workspace

    def _run(self, command: Sequence[str]) -> tuple[Optional[str], Optional[str]]:
        try:
            completed = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return None, f"timed out after {self.timeout:g}s"
        except OSError as exc:
            return None, str(exc)
        stdout = (completed.stdout or "")[: self.max_output].strip()
        stderr = (completed.stderr or "")[: self.max_output].strip()
        if completed.returncode:
            return None, stderr or stdout or f"process exited with code {completed.returncode}"
        return stdout or None, None

    def _inspect_with_androguard(self, apk_path: Path, tools: Dict[str, ToolMetadata]) -> List[Finding]:
        try:
            # Avoid verbose parser output containing APK contents in desktop logs.
            try:
                from loguru import logger
                logger.disable("androguard")
            except ImportError:
                pass
            module = importlib.import_module("androguard")
            apk_class = importlib.import_module("androguard.core.apk").APK
            dex_class = importlib.import_module("androguard.core.dex").DEX
        except (ImportError, AttributeError) as exc:
            tools["androguard"] = ToolMetadata("androguard", error=f"not installed: {exc}")
            return []
        except Exception as exc:
            tools["androguard"] = ToolMetadata("androguard", error=f"could not load: {str(exc)[:self.max_output]}")
            return []

        details: Dict[str, Any] = {
            "manifest_decoded": False, "dex_files": 0, "dex_files_scanned": 0,
            "classes": 0, "methods": 0, "instructions": 0, "strings": 0,
            "dex_complete": False, "warnings": [],
            "analysis_scope": "Static manifest and standard classes*.dex string pools/method instructions; "
                              "local constants plus single initializer field writes and one-hop static crypto wrappers within each DEX. "
                              "Field-derived findings are possible static indicators, not proof of runtime immutability. No native code, dynamically loaded code, "
                              "whole-program data flow, exploit or runtime verification.",
        }
        metadata = ToolMetadata("androguard", available=True, version=getattr(module, "__version__", None), details=details)
        tools["androguard"] = metadata
        findings: List[Finding] = []
        try:
            apk = apk_class(str(apk_path))
        except Exception as exc:  # optional integration must never break stdlib scanning
            metadata.error = str(exc)[: self.max_output]
            return findings
        try:
            manifest = apk.get_android_manifest_xml()
            if manifest is None:
                raise ValueError("binary manifest decoder returned no XML")
            findings.extend(analyze_manifest(ET.tostring(manifest, encoding="unicode"),
                                             "androguard:AndroidManifest.xml"))
            details["manifest_decoded"] = True
        except Exception as exc:
            details["warnings"].append(f"Incomplete manifest coverage (Androguard): {str(exc)[:self.max_output]}")
        try:
            # Use the actual ZIP member names (including multidex), not method-id
            # references from DEX.get_methods(), which contain no executable code.
            dex_names = list(apk.get_dex_names())
            details["dex_files"] = len(dex_names)
            complete = True
            for name in dex_names:
                try:
                    dex = dex_class(apk.get_file(name))
                    dex_findings, counts, warnings = inspect_dex(dex, f"androguard:{name}")
                    findings.extend(dex_findings)
                    details["dex_files_scanned"] += 1
                    for key, count in counts.items():
                        details[key] += count
                    details["warnings"].extend(warnings)
                    complete = complete and not warnings
                except Exception as exc:
                    complete = False
                    details["warnings"].append(f"Incomplete DEX coverage ({name}): {str(exc)[:self.max_output]}")
            details["dex_complete"] = complete
        except Exception as exc:
            details["warnings"].append(f"Incomplete DEX coverage (Androguard): {str(exc)[:self.max_output]}")
        return findings
