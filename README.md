# AegisScan — Android Vulnerability Scanner

A lightweight, offline-first desktop application for the major project report
**Automated Android Application Vulnerability Scanner Using Hybrid Static and
Dynamic Security Testing**.

## Current vertical slice

### Latest compiled-APK repair

Use `dist/compiled-analysis/AegisScan.exe` instead of older builds. This version
bundles Androguard 4.1.3, including its APK/DEX modules and resource data. It
decodes binary manifests and inspects DEX instructions and string pools, with
bounded constant tracking into cryptographic calls. Findings are static
indicators requiring review, not proof of exploitability. Missing tools and
incomplete coverage now appear in scan warnings and exported `errors`.

The supplied InsecureBankv2 APK produced 21 findings in the packaged executable:
3 permission, 1 debug, 1 backup, 7 exported-component, 5 weak-hash references,
2 possible hardcoded-key and 2 constant-IV indicators. Key/IV findings include
encryption/decryption call sites, not four independent secrets. The verified
report is `dist/compiled-analysis/InsecureBankv2-verified.json`.
The earlier `InsecureBankv2-report.json` in that folder is a failed packaging
diagnostic, not the verified result. APKTool remains optional and was absent;
Androguard successfully decoded the manifest and inspected the single DEX.
AndroGoat, live network capture, WebView coverage, and comprehensive insecure
storage detection have not been validated by this repair.

Build in an isolated environment (do not install packages globally):

```powershell
python -m venv .venv-analysis
.\.venv-analysis\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv-analysis\Scripts\python.exe -m unittest discover -v
.\.venv-analysis\Scripts\python.exe -m PyInstaller --noconfirm --distpath dist/compiled-analysis AegisScan.spec
```

The 40-test regression suite passed. The executable was verified by static-only
scanning, without installing or running the APK. For repeatable offline checks,
the executable also accepts `--static-apk <path> --report <new-json-path>`; report
creation refuses to overwrite an existing file. Windowed builds provide null
console streams for parser imports; verbose Androguard logging is disabled.

- Desktop dashboard built with Python's standard-library `tkinter`.
- Safe APK ZIP validation and extraction (including path traversal and symlink rejection).
- Static checks for dangerous permissions, debug/backup/cleartext configuration,
  exported components, hardcoded secrets, and weak cryptography.
- Optional `apktool` decoding and `androguard` DEX inspection when installed;
  the application reports tool availability and safely falls back when they are
  missing.
- Background scanning so the interface remains responsive.
- Severity-ranked findings and a JSON audit export.
- ADB/emulator workflow that installs and launches the APK, captures traffic
  with optional Scapy, and reports cleartext HTTP, sensitive keywords, hosts,
  protocols, TLS ratio, and API paths.

## Run it

```bash
python app.py
```

Select an APK, run the static scan, review the findings, and export the result
as JSON. If an authorized emulator/device and Scapy are available, use **Run
dynamic scan** after selecting the APK. The scanner never uploads the APK.

## Build a Windows executable

The repository includes `AegisScan.spec`, a reproducible PyInstaller
configuration for the tkinter entry point. It explicitly collects every module
under the local `android_scanner` package so package imports are present in the
frozen application.

From a Windows PowerShell prompt in the project directory:

```powershell
python -m pip install -r requirements-build.txt
python -m PyInstaller --clean --noconfirm AegisScan.spec
```

The finished single-file executable is `dist\AegisScan.exe`. Remove `build` and
`dist` before a clean rebuild if needed.
Optional runtime tools such as `adb`, `apktool`, `androguard`, and Scapy remain
optional; install them separately when using those scanner features.

## Optional analysis tools

For decoded manifests and better bytecode coverage, install `apktool` and
`androguard` separately. For dynamic testing, install Android Platform Tools,
start an emulator or connect a test device with USB debugging enabled, and
install Scapy. The core app still runs without these optional tools and reports
when they are unavailable.

## Verify it

### Navigation repair build

The corrected executable is `dist/navigation-fix/AegisScan.exe`. Close the old
application and launch this file rather than the older `dist/AegisScan.exe`.
Rebuild this version with:

```powershell
python -m PyInstaller --noconfirm --distpath dist/navigation-fix AegisScan.spec
```

The sidebar now opens Overview, Static analysis, Dynamic analysis, and Reports.
Choose an APK before starting a scan; use Reports for JSON export. Scroll the
main content to reach lower controls on smaller windows, and use the findings
table scrollbars for wide evidence columns. Scans cannot overlap.

Dynamic analysis asks before installing and launching the APK on an authorized
test device. Its capture uses the host default interface, is not scoped to the
APK, and may miss device traffic. ADB and a working capture driver/permissions
are required. The Windows build reported missing `wpcap.dll`; live packet
capture has not been verified. Zero findings does not establish APK safety.

Verification: 14 unit/real-Tk tests passed, including sidebar navigation at
980x640 and 1180x760, report accessibility, filters, stale-result reset, and
scan-state recovery. The corrected executable built successfully and opened a
responding application window in a launch smoke test.

```bash
python -m unittest discover -v
python -m compileall -q android_scanner tests app.py
```

Dynamic capture is platform-dependent: packet capture permissions and the
network interface used by an emulator may require local configuration. Use a
test APK/device only; this tool is an analyzer, not an exploit generator.
