"""Small, explainable static-analysis rules for decoded Android artifacts."""

import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET

from .models import Finding

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TEXT_SUFFIXES = {".xml", ".smali", ".java", ".kt", ".txt", ".json", ".properties", ".cfg"}


def _finding(rule: str, title: str, severity: str, description: str, evidence: str, source: str) -> Finding:
    return Finding(rule, title, severity, description, evidence[:500], source)


def analyze_manifest(text: str, source: str = "AndroidManifest.xml") -> List[Finding]:
    """Apply manifest rules to decoded XML (or XML-like text from a decoder)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Retain support for the historical XML-like, namespace-less input.
        pass
    else:
        return _analyze_manifest_xml(root, source)
    findings: List[Finding] = []
    permissions = set(re.findall(r'(?:uses-permission[^>]+android:name\s*=\s*["\']([^"\']+)["\'])', text, re.I))
    dangerous = {
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS", "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    }
    for permission in sorted(permissions & dangerous):
        findings.append(_finding("dangerous-permission", "Dangerous permission", "medium",
            "The application requests a permission that can expose sensitive user data or actions.", permission, source))
    if re.search(r'android:debuggable\s*=\s*["\']true', text, re.I):
        findings.append(_finding("debuggable", "Debuggable application", "high",
            "Debuggable builds can expose runtime inspection and debugging capabilities.", "android:debuggable=\"true\"", source))
    if re.search(r'android:allowBackup\s*=\s*["\']true', text, re.I):
        findings.append(_finding("backup-enabled", "Application backup enabled", "medium",
            "Backups may expose application data outside the app's security boundary.", "android:allowBackup=\"true\"", source))
    if re.search(r'android:usesCleartextTraffic\s*=\s*["\']true', text, re.I):
        findings.append(_finding("cleartext-traffic", "Cleartext traffic enabled", "high",
            "Network traffic may be sent without transport encryption.", "android:usesCleartextTraffic=\"true\"", source))
    for match in re.finditer(r'<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*["\']true["\'][^>]*', text, re.I | re.S):
        findings.append(_finding("exported-component", "Exported component", "medium",
            "An exported component can be invoked by other applications; verify its access controls.", match.group(0), source))
    return findings


def _analyze_manifest_xml(root: ET.Element, source: str) -> List[Finding]:
    """AXML serializers may use ns0 instead of the literal android prefix."""
    findings: List[Finding] = []
    dangerous = {
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "RECORD_AUDIO",
        "CAMERA", "ACCESS_FINE_LOCATION", "READ_CALL_LOG", "WRITE_EXTERNAL_STORAGE",
    }
    permissions = {element.get(ANDROID_NS + "name", "") for element in root
                   if element.tag in {"uses-permission", "uses-permission-sdk-23"}}
    for permission in sorted(permissions):
        if permission in {"android.permission." + name for name in dangerous}:
            findings.append(_finding("dangerous-permission", "Dangerous permission", "medium",
                "The application requests a sensitive permission; a declaration does not prove it is granted or abused.",
                permission, source))
    application = root.find("application")
    if application is None:
        return findings
    settings = (
        ("debuggable", "debuggable", "Debuggable application", "high",
         "Debuggable builds can expose runtime inspection and debugging capabilities."),
        ("allowBackup", "backup-enabled", "Application backup enabled", "medium",
         "Application backup is enabled; actual data exposure depends on backup rules, Android version and device policy."),
        ("usesCleartextTraffic", "cleartext-traffic", "Cleartext traffic enabled", "high",
         "The manifest permits cleartext traffic; network security configuration and runtime behavior need review."),
    )
    for attribute, rule, title, severity, description in settings:
        value = application.get(ANDROID_NS + attribute, "").lower()
        if value in {"true", "1", "0xffffffff"}:
            findings.append(_finding(rule, title, severity, description, f'android:{attribute}="{value}"', source))
    sdk = root.find("uses-sdk")
    target = sdk.get(ANDROID_NS + "targetSdkVersion", sdk.get(ANDROID_NS + "minSdkVersion", "1")) if sdk is not None else "1"
    try:
        target_number = int(target)
    except ValueError:
        target_number = None
    for component in application:
        if component.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        exported = component.get(ANDROID_NS + "exported")
        reason = None
        if exported is not None and exported.lower() in {"true", "1", "0xffffffff"}:
            reason = 'android:exported="true"'
        elif exported is None and target_number is not None:
            if component.tag == "provider" and target_number <= 16:
                reason = f"implicit exported default for provider targeting SDK {target_number}"
            elif component.tag != "provider" and component.find("intent-filter") is not None and target_number < 31:
                reason = f"implicit exported default from intent-filter (target SDK {target_number})"
        if reason:
            name = component.get(ANDROID_NS + "name", "(unnamed)")
            permission = component.get(ANDROID_NS + "permission", application.get(ANDROID_NS + "permission", ""))
            evidence = f"{component.tag} {name}: {reason}"
            if permission:
                evidence += f"; permission={permission}"
            findings.append(_finding("exported-component", "Exported component", "medium",
                "This component is declared exported or uses an exported platform default. Review permissions and input validation; export alone is not proof of exploitation.",
                evidence, source))
    return findings


SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic API key", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_./+=-]{12,}[\"']")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


def analyze_text(text: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    for name, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(_finding("hardcoded-secret", "Hardcoded secret", "high",
                f"A possible {name} was found in application text.", match.group(0), source))
    weak_patterns = (r"DES/ECB", r"AES/ECB", r"Cipher\.getInstance\(\s*[\"'](?:DES|RC4)", r"MessageDigest\.getInstance\(\s*[\"']MD5")
    for pattern in weak_patterns:
        match = re.search(pattern, text, re.I)
        if match:
            findings.append(_finding("weak-crypto", "Weak cryptography", "high",
                "A weak or insecure cryptographic algorithm/mode was detected.", match.group(0), source))
    return findings


def analyze_file(path: Path) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    findings = analyze_text(text, str(path))
    if path.name == "AndroidManifest.xml":
        findings.extend(analyze_manifest(text, str(path)))
    return findings
