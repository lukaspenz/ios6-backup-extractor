#!/usr/bin/env python3
"""
iOS 6 Backup Extractor — Tkinter GUI

Provides a simple graphical interface for selecting the backup folder,
choosing an output directory, and running the extraction with a live
progress bar and scrolling log.

Usage:
    python gui.py
    # — or —
    python -m ios6_backup_extractor.gui
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import tkinter as tk
from multiprocessing import cpu_count
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

# Allow running from the project root or inside the package
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import extract_backup as engine  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_TITLE = "iOS 6 Backup Extractor"
PAD = 8
MIN_W, MIN_H = 700, 560


# ---------------------------------------------------------------------------
# Queue-based log handler for tkinter (thread-safe)
# ---------------------------------------------------------------------------
class QueueLogHandler(logging.Handler):
    """Emit log records into a ``queue.Queue`` to be consumed by the GUI."""

    def __init__(self, q: queue.Queue):
        super().__init__()
        self.q = q

    def emit(self, record):
        try:
            self.q.put(self.format(record))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(MIN_W, MIN_H)
        self.resizable(True, True)
        self._center()

        # State
        self._backup_dir = tk.StringVar()
        self._output_dir = tk.StringVar()
        self._workers = tk.IntVar(value=min(cpu_count() or 4, 16))
        self._running = False
        self._log_queue: queue.Queue[str] = queue.Queue()

        # Build UI
        self._build_header()
        self._build_path_form()
        self._build_options()
        self._build_device_info()
        self._build_progress()
        self._build_log()
        self._build_buttons()

        # Log handler
        handler = QueueLogHandler(self._log_queue)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        engine.log.addHandler(handler)
        engine.log.setLevel(logging.DEBUG)

        # Start polling the queue
        self._poll_log_queue()

    # ---- layout helpers ---------------------------------------------------
    def _center(self):
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = (sw - MIN_W) // 2
        y = (sh - MIN_H) // 2
        self.geometry(f"{MIN_W}x{MIN_H}+{x}+{y}")

    def _build_header(self):
        frame = ttk.Frame(self, padding=(PAD, PAD, PAD, 0))
        frame.pack(fill="x")
        ttk.Label(frame, text=APP_TITLE, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text=f"v{engine.__version__} — Extract media, messages, contacts & more from unencrypted iOS 5/6 backups",
            foreground="gray",
        ).pack(anchor="w")

    def _build_path_form(self):
        frame = ttk.LabelFrame(self, text="Paths", padding=PAD)
        frame.pack(fill="x", padx=PAD, pady=(PAD, 0))

        # Backup dir
        ttk.Label(frame, text="Backup Folder:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(frame, textvariable=self._backup_dir, width=60).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(frame, text="Browse …", command=self._browse_backup).grid(row=0, column=2)

        # Output dir
        ttk.Label(frame, text="Output Folder:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(frame, textvariable=self._output_dir, width=60).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Button(frame, text="Browse …", command=self._browse_output).grid(row=1, column=2)

        frame.columnconfigure(1, weight=1)

    def _build_options(self):
        frame = ttk.LabelFrame(self, text="Options", padding=PAD)
        frame.pack(fill="x", padx=PAD, pady=(PAD, 0))
        ttk.Label(frame, text="Worker threads:").pack(side="left")
        spin = ttk.Spinbox(frame, from_=1, to=16, width=4, textvariable=self._workers)
        spin.pack(side="left", padx=4)

        ttk.Separator(frame, orient="vertical").pack(side="left", fill="y", padx=12, pady=2)

        self._include_raw = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame, text="Include raw data (databases, plists, manifest report)",
            variable=self._include_raw,
        ).pack(side="left", padx=4)

    def _build_device_info(self):
        self._info_frame = ttk.LabelFrame(self, text="Device Info", padding=PAD)
        self._info_frame.pack(fill="x", padx=PAD, pady=(PAD, 0))
        self._info_label = ttk.Label(self._info_frame, text="(select a backup folder to see device info)")
        self._info_label.pack(anchor="w")
        self._backup_dir.trace_add("write", self._on_backup_dir_changed)

    def _build_progress(self):
        frame = ttk.Frame(self, padding=(PAD, PAD, PAD, 0))
        frame.pack(fill="x")
        self._progress_label = ttk.Label(frame, text="Ready")
        self._progress_label.pack(anchor="w")
        self._progress_bar = ttk.Progressbar(frame, mode="determinate", maximum=100)
        self._progress_bar.pack(fill="x", pady=2)

    def _build_log(self):
        frame = ttk.LabelFrame(self, text="Log", padding=PAD)
        frame.pack(fill="both", expand=True, padx=PAD, pady=(PAD, 0))
        self._log_text = scrolledtext.ScrolledText(frame, height=10, state="disabled", font=("Consolas", 9))
        self._log_text.pack(fill="both", expand=True)

    def _build_buttons(self):
        frame = ttk.Frame(self, padding=PAD)
        frame.pack(fill="x")
        self._btn_run = ttk.Button(frame, text="▶  Extract", command=self._run, style="Accent.TButton")
        self._btn_run.pack(side="right", padx=2)
        ttk.Button(frame, text="Quit", command=self._quit).pack(side="right", padx=2)

    # ---- callbacks --------------------------------------------------------
    def _browse_backup(self):
        d = filedialog.askdirectory(title="Select iOS Backup Folder")
        if d:
            d = os.path.normpath(d)
            self._backup_dir.set(d)
            # Default output
            if not self._output_dir.get():
                self._output_dir.set(os.path.join(os.path.dirname(d), "extracted"))

    def _browse_output(self):
        d = filedialog.askdirectory(title="Select Output Folder")
        if d:
            self._output_dir.set(os.path.normpath(d))

    def _on_backup_dir_changed(self, *_args):
        bd = self._backup_dir.get()
        if bd and os.path.isdir(bd):
            info = engine.get_device_info(bd)
            if info:
                text = (
                    f"{info.get('device', '?')} ({info.get('model', '?')})  —  "
                    f"\"{info.get('name', '?')}\"  —  iOS {info.get('ios_version', '?')} "
                    f"({info.get('build', '?')})  —  S/N: {info.get('serial', '?')}"
                )
            else:
                text = "(no Info.plist found)"
            self._info_label.config(text=text)
        else:
            self._info_label.config(text="(select a backup folder)")

    def _log(self, msg: str):
        self._log_text.configure(state="normal")
        self._log_text.insert("end", msg + "\n")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def _poll_log_queue(self):
        """Drain the log queue into the text widget (called every 100 ms)."""
        while True:
            try:
                msg = self._log_queue.get_nowait()
                self._log(msg)
            except queue.Empty:
                break
        self.after(100, self._poll_log_queue)

    def _run(self):
        if self._running:
            return

        bd = self._backup_dir.get().strip()
        od = self._output_dir.get().strip()
        if not bd:
            messagebox.showwarning("Missing path", "Please select a backup folder.")
            return

        ok, msg = engine.validate_backup(bd)
        if not ok:
            messagebox.showerror("Invalid backup", msg)
            return

        if not od:
            od = os.path.join(os.path.dirname(bd), "extracted")
            self._output_dir.set(od)

        # Warn if the output folder already contains data
        if os.path.isdir(od) and os.listdir(od):
            overwrite = messagebox.askyesno(
                "Output folder not empty",
                f"The output folder already contains files:\n\n{od}\n\n"
                "Existing files may be overwritten. Continue?",
            )
            if not overwrite:
                return

        self._running = True
        self._btn_run.configure(state="disabled")
        self._progress_bar["value"] = 0
        self._progress_label.config(text="Starting …")
        self._log("=" * 60)
        self._log(f"  Backup: {bd}")
        self._log(f"  Output: {od}")
        self._log(f"  Workers: {self._workers.get()}")
        self._log("=" * 60)

        thread = threading.Thread(target=self._extraction_thread, args=(bd, od), daemon=True)
        thread.start()

    def _extraction_thread(self, bd: str, od: str):
        """Runs in a background thread."""
        def _progress(phase: str, detail: str, frac: Optional[float]):
            self.after(0, self._update_progress, phase, detail, frac)

        try:
            stats = engine.run_extraction(
                bd, od,
                max_workers=self._workers.get(),
                include_raw=self._include_raw.get(),
                progress=_progress,
            )
            self.after(0, self._extraction_done, stats)
        except Exception as exc:
            self.after(0, self._extraction_error, str(exc))

    def _update_progress(self, phase: str, detail: str, frac: Optional[float]):
        self._progress_label.config(text=f"{phase}: {detail}")
        if frac is not None:
            self._progress_bar["value"] = int(frac * 100)

    def _extraction_done(self, stats: engine.ExtractionStats):
        self._running = False
        self._btn_run.configure(state="normal")
        self._progress_bar["value"] = 100
        self._progress_label.config(text=f"Done — {stats.grand_total} items extracted")

        self._log("")
        self._log("=" * 60)
        self._log("  EXTRACTION RESULTS")
        self._log("=" * 60)
        for cat, cnt in stats.totals.items():
            self._log(f"  {cat:<25} {cnt:>6}")
        self._log(f"  {'-' * 35}")
        self._log(f"  {'TOTAL':<25} {stats.grand_total:>6}")
        if stats.errors:
            self._log(f"\n  Errors ({len(stats.errors)}):")
            for e in stats.errors:
                self._log(f"    - {e}")
        self._log("")

        messagebox.showinfo(
            "Extraction Complete",
            f"Successfully extracted {stats.grand_total} items.\n\n"
            f"Output: {self._output_dir.get()}",
        )

    def _extraction_error(self, msg: str):
        self._running = False
        self._btn_run.configure(state="normal")
        self._progress_label.config(text="Error!")
        self._log(f"FATAL ERROR: {msg}")
        messagebox.showerror("Extraction Failed", msg)

    def _quit(self):
        if self._running:
            if not messagebox.askyesno("Confirm", "Extraction is running. Quit anyway?"):
                return
        self.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
