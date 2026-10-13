# PyInstaller build description for the Windows tkinter desktop application.
# Build from the project directory with:
#   python -m PyInstaller --clean --noconfirm AegisScan.spec

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules, collect_data_files, copy_metadata


# PyInstaller exposes SPECPATH while evaluating a spec file (``__file__`` is
# intentionally not defined in that evaluation context).
project_dir = Path(SPECPATH).resolve()
android_scanner_imports = collect_submodules("android_scanner")

analysis = Analysis(
    [str(project_dir / "app.py")],
    pathex=[str(project_dir)],
    binaries=[],
    datas=collect_data_files("androguard") + copy_metadata("androguard"),
    hiddenimports=android_scanner_imports + ["androguard.core.apk", "androguard.core.dex"],
    hookspath=[],
    hooksconfig={"matplotlib": {"backends": ["Agg"]}},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="AegisScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
