"""Validation and extraction helpers that treat APKs as untrusted ZIP files."""

from pathlib import Path
import os
import stat
from typing import Union
import zipfile


class APKValidationError(ValueError):
    """Raised when an APK is not a safe, readable ZIP archive."""


def validate_apk(apk_path: Union[str, os.PathLike[str]]) -> None:
    path = Path(apk_path)
    if not path.is_file():
        raise APKValidationError("APK does not exist or is not a file")
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise APKValidationError("APK contains a corrupt ZIP member")
    except (OSError, zipfile.BadZipFile) as exc:
        raise APKValidationError("APK is not a readable ZIP archive") from exc


def _safe_member_path(destination: Path, member: zipfile.ZipInfo) -> Path:
    # APKs should not contain links; refusing them prevents link-based escapes.
    mode = (member.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        raise APKValidationError(f"symbolic links are not allowed: {member.filename}")
    name = member.filename.replace("\\", "/")
    if name.startswith("/") or any(part == ".." for part in Path(name).parts):
        raise APKValidationError(f"unsafe ZIP path: {member.filename}")
    target = (destination / name).resolve()
    root = destination.resolve()
    if target != root and root not in target.parents:
        raise APKValidationError(f"unsafe ZIP path: {member.filename}")
    return target


def safe_extract_apk(
    apk_path: Union[str, os.PathLike[str]],
    destination: Union[str, os.PathLike[str]],
) -> Path:
    """Extract an APK after validating every member stays inside destination."""
    validate_apk(apk_path)
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path) as archive:
        members = archive.infolist()
        targets = [(member, _safe_member_path(root, member)) for member in members]
        for member, target in targets:
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                output.write(source.read())
    return root
