"""Desktop entry point for the Android Vulnerability Scanner.

The first release keeps the static scan fully offline and dependency-free. A
dynamic-scan panel is included so the workflow has a clear place for the ADB
and emulator integration described in the project report.
"""

from __future__ import annotations

import json
import os
import sys

# Windowed PyInstaller builds have no console streams. Third-party parsers
# register stderr log sinks while importing; provide a sink without saving APK data.
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")

import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from android_scanner import APKScanner
from android_scanner.adb import ADBController
from android_scanner.capture import PacketCapture
from android_scanner.dynamic import DynamicAnalyzer
from android_scanner.models import ScanSummary


COLORS = {
    "bg": "#0b1220",
    "panel": "#111c2e",
    "panel_2": "#16243a",
    "text": "#e7eef9",
    "muted": "#91a4bf",
    "accent": "#56c2a3",
    "accent_2": "#74a8ff",
    "danger": "#ff7c86",
    "warning": "#f4c36a",
    "line": "#243650",
}


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("AegisScan · Android Vulnerability Scanner")
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.configure(bg=COLORS["bg"])
        self.selected_apk: Path | None = None
        self.summary: ScanSummary | None = None
        self.dynamic_report: object | None = None
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.visible_findings: list[object] = []
        self.scan_in_progress = False
        self.dynamic_metadata: dict[str, object] = {}
        self.active_section = "Overview"
        self._configure_styles()
        self._build_layout()
        self.after(100, self._poll_events)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("Card.TFrame", background=COLORS["panel_2"])
        style.configure("PanelMuted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=COLORS["bg"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI Semibold", 23))
        style.configure("PanelTitle.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI Semibold", 12))
        style.configure("CardValue.TLabel", background=COLORS["panel_2"], foreground=COLORS["text"], font=("Segoe UI Semibold", 22))
        style.configure("CardLabel.TLabel", background=COLORS["panel_2"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("Treeview", background=COLORS["panel_2"], fieldbackground=COLORS["panel_2"], foreground=COLORS["text"], rowheight=34, borderwidth=0)
        style.configure("Treeview.Heading", background=COLORS["line"], foreground=COLORS["text"], font=("Segoe UI Semibold", 9), relief="flat")
        style.map("Treeview", background=[("selected", "#214c61")])
        style.configure("Horizontal.TProgressbar", troughcolor=COLORS["line"], background=COLORS["accent"], bordercolor=COLORS["line"])
        style.configure("Filter.TCombobox", fieldbackground=COLORS["panel_2"], background=COLORS["panel_2"], foreground=COLORS["text"])
        style.map("Filter.TCombobox", fieldbackground=[("readonly", COLORS["panel_2"])], foreground=[("readonly", COLORS["text"])], selectbackground=[("readonly", COLORS["line"])], selectforeground=[("readonly", COLORS["text"])])
        self.option_add("*TCombobox*Listbox.background", COLORS["panel_2"])
        self.option_add("*TCombobox*Listbox.foreground", COLORS["text"])

    def _build_layout(self) -> None:
        shell = ttk.Frame(self)
        shell.pack(fill="both", expand=True)
        sidebar = tk.Frame(shell, bg=COLORS["panel"], width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="AEGISSCAN", bg=COLORS["panel"], fg=COLORS["accent"], font=("Segoe UI Semibold", 17)).pack(anchor="w", padx=24, pady=(28, 3))
        tk.Label(sidebar, text="ANDROID SECURITY WORKBENCH", bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 8)).pack(anchor="w", padx=25, pady=(0, 34))
        self.nav_buttons = {}
        for label in ("Overview", "Static analysis", "Dynamic analysis", "Reports"):
            button = tk.Button(sidebar, text=label, command=lambda section=label: self.show_section(section), anchor="w", bg=COLORS["panel"], fg=COLORS["muted"], activebackground=COLORS["line"], activeforeground=COLORS["text"], relief="flat", padx=24, pady=12, font=("Segoe UI", 10))
            button.pack(fill="x")
            self.nav_buttons[label] = button
        tk.Label(sidebar, text="OFFLINE STATIC ANALYSIS\nDynamic mode runs the APK\non a connected Android device.", justify="left", bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(side="bottom", anchor="w", padx=25, pady=28)

        viewport = ttk.Frame(shell)
        viewport.pack(side="left", fill="both", expand=True)
        self.content_canvas = tk.Canvas(viewport, bg=COLORS["bg"], highlightthickness=0)
        self.content_scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=self.content_canvas.yview)
        self.content_scrollbar.pack(side="right", fill="y")
        self.content_canvas.pack(side="left", fill="both", expand=True)
        self.content_canvas.configure(yscrollcommand=self.content_scrollbar.set)
        main = ttk.Frame(self.content_canvas, padding=(24, 24))
        self.content_window = self.content_canvas.create_window((0, 0), window=main, anchor="nw")
        main.bind("<Configure>", lambda _event: self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all")))
        self.content_canvas.bind("<Configure>", lambda event: self.content_canvas.itemconfigure(self.content_window, width=event.width))
        self.bind("<MouseWheel>", self._scroll_content)
        title_row = ttk.Frame(main)
        title_row.pack(fill="x")
        self.section_title = ttk.Label(title_row, text="Overview", style="Title.TLabel")
        self.section_title.pack(side="left")
        self.connection_var = tk.StringVar(value="●  LOCAL · OFFLINE")
        ttk.Label(title_row, textvariable=self.connection_var, style="Muted.TLabel").pack(side="right", pady=(10, 0))
        ttk.Label(main, text="Hybrid Android application assessment · static engine ready", style="Muted.TLabel").pack(anchor="w", pady=(2, 23))

        self._build_input_card(main)
        self.section_frames = {name: ttk.Frame(main) for name in self.nav_buttons}
        overview = self.section_frames["Overview"]
        self._build_metrics(overview)
        ttk.Label(overview, text="Use Static analysis to inspect findings, Dynamic analysis for device capture, and Reports to export results.\n\nScores summarize detected rules only. Zero findings does not prove an APK is safe; scan coverage and runtime visibility are limited.", style="Muted.TLabel", wraplength=620, justify="left").pack(anchor="w")
        self._build_findings(self.section_frames["Static analysis"])
        self._build_dynamic_panel(self.section_frames["Dynamic analysis"])
        self._build_reports_panel(self.section_frames["Reports"])
        self.show_section("Overview")

    def _scroll_content(self, event: tk.Event) -> None:
        if isinstance(event.widget, (ttk.Treeview, ttk.Combobox)):
            return
        if self.content_canvas.yview() != (0.0, 1.0):
            self.content_canvas.yview_scroll(-int(event.delta / 120), "units")

    def show_section(self, section: str) -> None:
        """Navigate to a named sidebar page and expose its active state."""
        if section not in self.section_frames:
            raise ValueError(f"Unknown section: {section}")
        for name, frame in self.section_frames.items():
            frame.pack_forget()
            self.nav_buttons[name].configure(bg=COLORS["line"] if name == section else COLORS["panel"], fg=COLORS["accent"] if name == section else COLORS["muted"], text=("●  " if name == section else "") + name)
        self.section_frames[section].pack(fill="both", expand=True)
        self.active_section = section
        self.section_title.configure(text=section)
        self.update_idletasks()
        self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))
        self.content_canvas.yview_moveto(0)

    def _build_dynamic_panel(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Device execution & host capture", style="Title.TLabel").pack(anchor="w")
        ttk.Label(parent, text="Requires Android platform-tools (adb), an authorized test device/emulator, Scapy and a working capture driver/permissions.\n\nThe scan installs or replaces this APK and launches it on the first authorized device. The app may access the network. Capture then listens on the host's default interface for 12 seconds; it is not scoped to the APK and may miss device traffic, startup traffic or encrypted payloads.\n\nUnrelated host traffic can appear in results. No observations or findings does not establish safety.", style="Muted.TLabel", wraplength=620, justify="left").pack(anchor="w", pady=(12, 18))
        self.dynamic_status_var = tk.StringVar(value="No dynamic capture has run for this APK.")
        ttk.Label(parent, textvariable=self.dynamic_status_var, style="Muted.TLabel", wraplength=620, justify="left").pack(anchor="w")

    def _build_reports_panel(self, parent: ttk.Frame) -> None:
        self.report_status_var = tk.StringVar(value="Run a scan to enable JSON export.")
        ttk.Label(parent, textvariable=self.report_status_var, style="Muted.TLabel", wraplength=620).pack(anchor="w", pady=(0, 16))
        self.export_button = tk.Button(parent, text="Export JSON report", command=self.export_json, state="disabled", bg=COLORS["panel_2"], fg=COLORS["text"], activebackground=COLORS["line"], relief="flat", padx=14, pady=8, font=("Segoe UI Semibold", 9))
        self.export_button.pack(anchor="w")
        ttk.Label(parent, text="Reports contain detected indicators and capture limitations, not a safety certification. Review scan errors and coverage before interpreting a zero score.", style="Muted.TLabel", wraplength=620, justify="left").pack(anchor="w", pady=(16, 0))

    def _build_input_card(self, parent: ttk.Frame) -> None:
        card = ttk.Frame(parent, style="Panel.TFrame", padding=18)
        card.pack(fill="x", pady=(0, 18))
        ttk.Label(card, text="1  Select an APK", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(card, text="Choose a compiled Android package to validate and inspect locally.", style="PanelMuted.TLabel").pack(anchor="w", pady=(3, 14))
        row = ttk.Frame(card, style="Panel.TFrame")
        row.pack(fill="x")
        self.apk_var = tk.StringVar(value="No APK selected")
        entry = tk.Entry(row, textvariable=self.apk_var, state="readonly", bg=COLORS["panel_2"], fg=COLORS["text"], readonlybackground=COLORS["panel_2"], relief="flat", font=("Segoe UI", 10))
        entry.pack(side="left", fill="x", expand=True, ipady=9, padx=(0, 10))
        self.choose_button = tk.Button(row, text="Choose APK", command=self.choose_apk, bg=COLORS["accent_2"], fg="#08111f", activebackground="#9bc1ff", relief="flat", padx=18, pady=9, font=("Segoe UI Semibold", 9))
        self.choose_button.pack(side="right")
        actions = ttk.Frame(card, style="Panel.TFrame")
        actions.pack(anchor="e", pady=(14, 0))
        self.scan_button = tk.Button(actions, text="Run static security scan", command=self.start_scan, state="disabled", bg=COLORS["accent"], fg="#08111f", activebackground="#8be2c8", relief="flat", padx=18, pady=9, font=("Segoe UI Semibold", 10))
        self.scan_button.pack(side="left", padx=(0, 8))
        self.dynamic_button = tk.Button(actions, text="Run dynamic scan", command=self.start_dynamic_scan, state="disabled", bg=COLORS["panel_2"], fg=COLORS["text"], activebackground=COLORS["line"], relief="flat", padx=18, pady=9, font=("Segoe UI Semibold", 10))
        self.dynamic_button.pack(side="left")
        self.progress = ttk.Progressbar(card, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress_text = tk.StringVar(value="")
        ttk.Label(card, textvariable=self.progress_text, style="PanelMuted.TLabel", wraplength=580).pack(anchor="w", pady=(8, 0))

    def _build_metrics(self, parent: ttk.Frame) -> None:
        metrics = ttk.Frame(parent)
        metrics.pack(fill="x", pady=(0, 18))
        self.metric_vars = {key: tk.StringVar(value="—") for key in ("risk", "critical", "high", "files")}
        labels = (("risk", "RISK SCORE"), ("critical", "CRITICAL"), ("high", "HIGH"), ("files", "FILES REVIEWED"))
        for index, (key, label) in enumerate(labels):
            card = ttk.Frame(metrics, style="Card.TFrame", padding=15)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 0))
            ttk.Label(card, textvariable=self.metric_vars[key], style="CardValue.TLabel").pack(anchor="w")
            ttk.Label(card, text=label, style="CardLabel.TLabel").pack(anchor="w", pady=(2, 0))
            metrics.columnconfigure(index, weight=1)

    def _build_findings(self, parent: ttk.Frame) -> None:
        card = ttk.Frame(parent, style="Panel.TFrame", padding=18)
        card.pack(fill="both", expand=True)
        header = ttk.Frame(card, style="Panel.TFrame")
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="Findings", style="PanelTitle.TLabel").pack(side="left")
        self.status_var = tk.StringVar(value="Select an APK to begin")
        ttk.Label(header, textvariable=self.status_var, style="PanelMuted.TLabel", wraplength=420).pack(side="right")
        toolbar = ttk.Frame(card, style="Panel.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        self.finding_search_var = tk.StringVar()
        search = tk.Entry(toolbar, textvariable=self.finding_search_var, bg=COLORS["panel_2"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", font=("Segoe UI", 9))
        search.insert(0, "Search findings…")
        search.bind("<FocusIn>", lambda _event: search.delete(0, "end") if search.get() == "Search findings…" else None)
        search.bind("<KeyRelease>", lambda _event: self._refresh_findings())
        search.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        self.severity_var = tk.StringVar(value="All severities")
        severity = ttk.Combobox(toolbar, textvariable=self.severity_var, values=("All severities", "Critical", "High", "Medium", "Low"), state="readonly", width=16, style="Filter.TCombobox")
        severity.bind("<<ComboboxSelected>>", lambda _event: self._refresh_findings())
        severity.pack(side="right")
        columns = ("severity", "title", "rule", "source", "evidence")
        table = ttk.Frame(card, style="Panel.TFrame")
        table.pack(fill="both", expand=True)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.findings_tree = ttk.Treeview(table, columns=columns, show="headings", height=8)
        self.findings_tree.bind("<<TreeviewSelect>>", self._show_finding_details)
        headings = {"severity": "SEVERITY", "title": "FINDING", "rule": "OWASP / RULE", "source": "LOCATION", "evidence": "EVIDENCE"}
        widths = {"severity": 90, "title": 210, "rule": 155, "source": 180, "evidence": 260}
        for column in columns:
            self.findings_tree.heading(column, text=headings[column])
            self.findings_tree.column(column, width=widths[column], minwidth=widths[column], stretch=False, anchor="w")
        self.findings_tree.grid(row=0, column=0, sticky="nsew")
        self.findings_y_scrollbar = ttk.Scrollbar(table, orient="vertical", command=self.findings_tree.yview)
        self.findings_y_scrollbar.grid(row=0, column=1, sticky="ns")
        self.findings_x_scrollbar = ttk.Scrollbar(table, orient="horizontal", command=self.findings_tree.xview)
        self.findings_x_scrollbar.grid(row=1, column=0, sticky="ew")
        self.findings_tree.configure(yscrollcommand=self.findings_y_scrollbar.set, xscrollcommand=self.findings_x_scrollbar.set)
        self.findings_tree.tag_configure("high", foreground=COLORS["danger"])
        self.findings_tree.tag_configure("medium", foreground=COLORS["warning"])
        self.findings_tree.tag_configure("low", foreground=COLORS["muted"])
        self.empty_findings = ttk.Label(self.findings_tree, text="No findings to display yet. Run a static scan.", style="CardLabel.TLabel", wraplength=450, justify="center")
        self.empty_findings.place(relx=0.5, rely=0.5, anchor="center")
        detail = ttk.Frame(card, style="Panel.TFrame")
        detail.pack(fill="x", pady=(10, 0))
        ttk.Label(detail, text="SELECTED FINDING", style="PanelMuted.TLabel").pack(anchor="w")
        self.detail_var = tk.StringVar(value="Select a finding to inspect its evidence and location.")
        self.detail_label = ttk.Label(detail, textvariable=self.detail_var, style="PanelMuted.TLabel", wraplength=580, justify="left")
        self.detail_label.pack(anchor="w", pady=(3, 0))
        detail.bind("<Configure>", lambda event: self.detail_label.configure(wraplength=max(200, event.width)))

    def choose_apk(self) -> None:
        if self.scan_in_progress:
            return
        path = filedialog.askopenfilename(title="Select Android APK", filetypes=(("Android packages", "*.apk"), ("All files", "*.*")))
        if path:
            self.selected_apk = Path(path)
            self.apk_var.set(str(self.selected_apk))
            self._reset_results()
            self._set_busy(False)
            self.status_var.set("Ready to scan")
            self.progress_text.set("")
            self._set_empty_state("Ready when you are — no scan results yet.")

    def _reset_results(self) -> None:
        self.summary = None
        self.dynamic_report = None
        self.dynamic_metadata = {}
        self.visible_findings = []
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        for variable in self.metric_vars.values():
            variable.set("—")
        self.finding_search_var.set("")
        self.severity_var.set("All severities")
        self.detail_var.set("Select a finding to inspect its evidence and location.")
        self.dynamic_status_var.set("No dynamic capture has run for this APK.")
        self.report_status_var.set("Run a scan to enable JSON export.")
        self.export_button.configure(state="disabled")
        self._set_empty_state("No scan results yet.")

    def _set_busy(self, busy: bool) -> None:
        self.scan_in_progress = busy
        self.choose_button.configure(state="disabled" if busy else "normal")
        state = "normal" if self.selected_apk and not busy else "disabled"
        self.scan_button.configure(state=state)
        self.dynamic_button.configure(state=state)
        self.export_button.configure(state="normal" if not busy and (self.summary is not None or self.dynamic_report is not None) else "disabled")
        if busy:
            self.progress.pack(fill="x", pady=(12, 0))
            self.progress.start(10)
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.progress_text.set("")

    def start_scan(self) -> None:
        if not self.selected_apk or self.scan_in_progress:
            return
        self._reset_results()
        self._set_busy(True)
        self.show_section("Static analysis")
        self.progress_text.set("Scanning archive and applying security rules…")
        self.status_var.set("Validating archive and running static rules…")
        try:
            threading.Thread(target=self._scan_worker, args=(self.selected_apk,), daemon=True).start()
        except Exception as exc:
            self._show_scan_error(str(exc))

    def _scan_worker(self, path: Path) -> None:
        try:
            self.events.put(("done", APKScanner().scan(path)))
        except Exception as exc:  # keep worker failures visible in the dashboard
            self.events.put(("scan_error", str(exc)))

    def _poll_events(self) -> None:
        try:
            event, payload = self.events.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_events)
            return
        if event == "done":
            self._show_summary(payload)  # type: ignore[arg-type]
        elif event == "scan_error":
            self._show_scan_error(str(payload))
        elif event == "dynamic_error":
            self._show_dynamic_error(str(payload))
        elif event == "dynamic_done":
            self._show_dynamic_result(payload)
        self.after(100, self._poll_events)

    def _show_summary(self, summary: ScanSummary) -> None:
        self.summary = summary
        self._set_busy(False)
        self._refresh_findings()
        counts = {level: sum(1 for f in summary.findings if f.severity.lower() == level) for level in ("critical", "high")}
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        score = min(100, sum(weights.get(f.severity.lower(), 0) for f in summary.findings))
        self.metric_vars["risk"].set(str(score))
        self.metric_vars["critical"].set(str(counts["critical"]))
        self.metric_vars["high"].set(str(counts["high"]))
        self.metric_vars["files"].set(str(summary.files_scanned))
        self.export_button.configure(state="normal")
        self.report_status_var.set("Static report ready. Review coverage and errors; zero findings does not prove safety.")
        if summary.errors:
            self.status_var.set("Scan finished with warnings")
            messagebox.showwarning("Scan finished with warnings", "\n".join(summary.errors))
        else:
            self.status_var.set(f"Scan complete · {summary.finding_count} finding(s)")

    def _set_empty_state(self, message: str) -> None:
        self.empty_findings.configure(text=message)
        self.empty_findings.place(relx=0.5, rely=0.5, anchor="center")

    def _refresh_findings(self) -> None:
        self.visible_findings = []
        self.detail_var.set("Select a finding to inspect its evidence and location.")
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        if not self.summary:
            self._set_empty_state("No findings to display yet. Run a static scan to populate this workspace.")
            return
        query = self.finding_search_var.get().strip().lower()
        if query == "search findings…":
            query = ""
        selected_severity = self.severity_var.get().lower()
        self.visible_findings = [finding for finding in self.summary.findings if (not query or query in f"{finding.title} {finding.rule_id} {finding.source or ''} {finding.evidence}".lower()) and (selected_severity == "all severities" or finding.severity.lower() == selected_severity)]
        for finding in self.visible_findings:
            self.findings_tree.insert("", "end", values=(finding.severity.upper(), finding.title, finding.rule_id, finding.source or "—", finding.evidence), tags=(finding.severity.lower(),))
        if self.visible_findings:
            self.empty_findings.place_forget()
        elif self.summary.findings:
            self._set_empty_state("No findings match the current filters.")
        else:
            self._set_empty_state("No findings detected by these rules. This does not prove the APK is safe; review scan coverage and warnings.")

    def _show_finding_details(self, _event: object = None) -> None:
        selected = self.findings_tree.selection()
        if not selected:
            return
        values = self.findings_tree.item(selected[0], "values")
        self.detail_var.set(f"{values[0]} · {values[1]}  |  {values[2]}  |  {values[3]}\nEvidence: {values[4]}")

    def _show_scan_error(self, error: str) -> None:
        self._set_busy(False)
        self.status_var.set("Scan could not be completed")
        self._set_empty_state("The scan failed before results were produced. Check the APK and try again.")
        messagebox.showerror("Scan failed", error)

    def start_dynamic_scan(self) -> None:
        if not self.selected_apk or self.scan_in_progress:
            return
        self.show_section("Dynamic analysis")
        self._set_busy(True)
        if not messagebox.askokcancel("Install, launch and capture?", "This installs (or replaces) the selected APK and launches it on the first authorized ADB device/emulator. Use a test device you control. The app may access the network.\n\nScapy captures for 12 seconds on the HOST's default interface after launch, not directly on the Android device. Traffic is not scoped to this APK; unrelated host traffic may appear, and device/startup traffic or encrypted payloads may be missed. Capture requires Scapy and a working driver/permissions.\n\nNo observations or findings does not prove safety. Continue?", parent=self):
            self._set_busy(False)
            return
        self.dynamic_report = None
        self.dynamic_metadata = {}
        if self.summary:
            self.summary.dynamic_metadata = {}
        self.dynamic_status_var.set("Connecting to ADB; preparing host capture…")
        self.status_var.set("Dynamic scan in progress…")
        self.progress_text.set("Installing/launching via ADB, then capturing host traffic for 12 seconds…")
        try:
            threading.Thread(target=self._dynamic_worker, args=(self.selected_apk,), daemon=True).start()
        except Exception as exc:
            self._show_dynamic_error(str(exc))

    def _show_dynamic_error(self, error: str) -> None:
        self._set_busy(False)
        self.status_var.set("Dynamic scan unavailable")
        self.dynamic_status_var.set("Dynamic scan could not complete: " + error + "\nNo conclusion about APK safety can be drawn.")
        self.report_status_var.set("Static results remain available; dynamic scan could not complete." if self.summary else "Dynamic scan failed; no report is available.")
        messagebox.showwarning("Dynamic scan unavailable", error)

    def _dynamic_worker(self, path: Path) -> None:
        try:
            adb = ADBController()
            devices = [device for device in adb.list_devices() if device.state == "device"]
            if not devices:
                self.events.put(("dynamic_error", adb.last_error or "No authorized ADB device or emulator is connected. Connect a test device and accept its USB debugging authorization."))
                return
            capture = PacketCapture()
            if not capture.available:
                self.events.put(("dynamic_error", "Scapy is unavailable; packet capture cannot run. Install the optional capture dependency and a host capture driver/permissions before retrying. The APK has not been installed or launched."))
                return
            device = devices[0]
            if not adb.install_and_launch(str(path), device.serial):
                self.events.put(("dynamic_error", adb.last_error or "ADB could not install or launch the APK."))
                return
            raw_packets = capture.capture(timeout=12)
            observations = self._packet_observations(raw_packets)
            report = DynamicAnalyzer().analyze(observations)
            self.events.put(("dynamic_done", (report, device.serial, capture.last_error)))
        except Exception as exc:
            self.events.put(("dynamic_error", str(exc)))

    @staticmethod
    def _packet_observations(packets: list[object]) -> list[dict[str, object]]:
        """Convert common Scapy packet layers into the analyzer's stable input."""
        observations: list[dict[str, object]] = []
        for packet in packets:
            try:
                haslayer = getattr(packet, "haslayer")
                ip = packet.getlayer("IP") if haslayer("IP") else None
                tcp = packet.getlayer("TCP") if haslayer("TCP") else None
                raw = packet.getlayer("Raw") if haslayer("Raw") else None
                if not ip or not tcp:
                    continue
                destination_port = int(getattr(tcp, "dport", 0))
                protocol = "https" if destination_port == 443 else "http" if destination_port == 80 else "tcp"
                payload = bytes(getattr(raw, "load", b"")).decode("utf-8", errors="ignore") if raw else ""
                observations.append({"protocol": protocol, "host": str(getattr(ip, "dst", "")), "payload": payload, "encrypted": destination_port == 443})
            except (AttributeError, TypeError, ValueError):
                continue
        return observations

    def _show_dynamic_result(self, payload: object) -> None:
        report, serial, capture_error = payload  # type: ignore[misc]
        self.dynamic_report = report
        self.dynamic_metadata = {
                "device": serial,
                "observations": report.observation_count,
                "cleartext_http": report.cleartext_http,
                "sensitive_cleartext": report.sensitive_cleartext,
                "contacted_hosts": report.contacted_hosts,
                "protocols": report.protocols,
                "tls_ratio": report.tls_ratio,
                "api_paths": report.api_paths,
                "capture_note": capture_error,
                "capture_scope": "Host default interface; not scoped to APK or device. Capture begins after launch and may miss device/startup traffic and encrypted payloads.",
                "interpretation": "Host observations are not proof of APK behavior. Zero observations or findings does not prove safety.",
            }
        if self.summary:
            self.summary.dynamic_metadata = self.dynamic_metadata
        self._set_busy(False)
        warning = " · capture warning: " + capture_error if capture_error else ""
        self.status_var.set("Dynamic capture unavailable" if capture_error else f"Host capture finished · {report.observation_count} observations")
        self.dynamic_status_var.set(f"Device: {serial}\nHost observations: {report.observation_count}{warning}\nCleartext HTTP: {report.cleartext_http} · sensitive cleartext: {report.sensitive_cleartext}\nTraffic is not attributed to this APK. Zero observations does not prove safety.")
        self.report_status_var.set("Dynamic report ready" + (" with capture warnings" if capture_error else "") + ". Includes host-capture limitations.")
        if capture_error:
            messagebox.showwarning("Host capture unavailable", capture_error + "\nThe APK was installed/launched, but capture failed. No conclusion about its network safety can be drawn.")
        if report.cleartext_http:
            messagebox.showwarning("Host cleartext traffic detected", "HTTP traffic was observed on the host; it is not attributed to this APK. Review the JSON report for hosts, paths, and sensitive keywords.")

    def export_json(self) -> None:
        if self.scan_in_progress or (self.summary is None and self.dynamic_report is None):
            return
        path = filedialog.asksaveasfilename(title="Export audit report", defaultextension=".json", filetypes=(("JSON report", "*.json"),))
        if path:
            data = self.summary.to_dict() if self.summary else {"apk_path": str(self.selected_apk), "static_analysis": "not run", "dynamic": self.dynamic_metadata}
            try:
                Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            except (OSError, TypeError, ValueError) as exc:
                messagebox.showerror("Export failed", str(exc))
                return
            messagebox.showinfo("Report exported", f"Saved audit report to:\n{path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AegisScan desktop and offline static analysis")
    parser.add_argument("--static-apk", type=Path, help="Analyze an APK without installing or executing it")
    parser.add_argument("--report", type=Path, help="Write a new JSON report (will not overwrite an existing file)")
    args = parser.parse_args()
    if args.static_apk is not None:
        if args.report is None:
            parser.error("--static-apk requires --report")
        result = APKScanner().scan(args.static_apk)
        with args.report.open("x", encoding="utf-8") as report:
            json.dump(result.to_dict(), report, indent=2)
    elif args.report is not None:
        parser.error("--report requires --static-apk")
    else:
        ScannerApp().mainloop()
