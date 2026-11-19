#!/usr/bin/env python3
"""Nutiscan GUI - double-click friendly overlay over the scan engine."""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import traceback
import urllib.parse
import webbrowser
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, Tk, Button, Entry, Frame, Label, Listbox,
    Scrollbar, StringVar, Text, Toplevel, WORD, messagebox, ttk,
)

from nutiscan import __version__, export
from nutiscan.config import Config
from nutiscan.engine import Engine, new_job

DEFAULT_OUT = Path.home() / "Desktop" / "Nutiscan-reports"


class App:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title(f"Nutiscan {__version__}")
        self.root.geometry("980x680")
        self.root.minsize(760, 520)
        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.current_job = None
        self.last_snapshot: dict | None = None
        self._build()

    def _build(self) -> None:
        top = Frame(self.root, padx=12, pady=10)
        top.pack(fill="x")

        Label(top, text="Sihtmärk", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        row = Frame(top)
        row.pack(fill="x", pady=4)
        self.url = Entry(row, font=("Consolas", 11))
        self.url.pack(side=LEFT, fill="x", expand=True, padx=(0, 8))
        self.url.insert(0, "https://example.com")
        self.url.bind("<Return>", lambda _: self.start())

        self.start_btn = Button(row, text="Skanni", command=self.start, width=12)
        self.start_btn.pack(side=LEFT)
        self.stop_btn = Button(row, text="Peata", command=self.stop, width=10, state="disabled")
        self.stop_btn.pack(side=LEFT, padx=6)

        opts = Frame(top)
        opts.pack(fill="x", pady=(6, 0))
        self.pages = self._number(opts, "Lehti", 60, 5, 300)
        self.depth = self._number(opts, "Sügavus", 2, 0, 5)
        self.rate = self._number(opts, "Päringut/s", 8.0, 0.5, 50.0)
        self.private = StringVar(value="0")
        ttk.Checkbutton(opts, text="Luba lokaalne/era-aadress", variable=self.private).pack(side=LEFT, padx=(14, 0))

        bar = Frame(self.root, padx=12)
        bar.pack(fill="x")
        self.progress = ttk.Progressbar(bar, mode="determinate")
        self.progress.pack(fill="x")
        self.status = Label(self.root, text="Valmis. Sisesta URL ja vajuta Skanni.", anchor="w", padx=12)
        self.status.pack(fill="x", pady=6)

        middle = Frame(self.root, padx=12)
        middle.pack(fill="both", expand=True)
        left = Frame(middle)
        left.pack(side=LEFT, fill="both", expand=True)

        Label(left, text="Leiud", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        list_frame = Frame(left)
        list_frame.pack(fill="both", expand=True, pady=4)
        self.findings = Listbox(list_frame, font=("Consolas", 10))
        self.findings.pack(side=LEFT, fill="both", expand=True)
        scroll = Scrollbar(list_frame, command=self.findings.yview)
        scroll.pack(side=RIGHT, fill="y")
        self.findings.config(yscrollcommand=scroll.set)
        self.findings.bind("<<ListboxSelect>>", self.show_finding)

        right = Frame(middle, width=360)
        right.pack(side=RIGHT, fill="both", padx=(12, 0))
        Label(right, text="Detail", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.detail = Text(right, wrap=WORD, font=("Consolas", 9), height=16)
        self.detail.pack(fill="both", expand=True, pady=4)

        bottom = Frame(self.root, padx=12, pady=8)
        bottom.pack(fill="x")
        self.triage_btn = Button(bottom, text="Ava aruanne (HTML)", command=self.open_report, state="disabled")
        self.triage_btn.pack(side=LEFT)
        self.folder_btn = Button(bottom, text="Ava kaust", command=self.open_folder)
        self.folder_btn.pack(side=LEFT, padx=6)
        self.log_btn = Button(bottom, text="Logi", command=self.show_log)
        self.log_btn.pack(side=LEFT, padx=6)

    def _number(self, parent, label, default, low, high):
        frame = Frame(parent)
        frame.pack(side=LEFT, padx=(0, 12))
        Label(frame, text=label, font=("Segoe UI", 9)).pack(anchor="w")
        var = StringVar(value=str(default))
        spin = ttk.Spinbox(frame, from_=low, to=high, textvariable=var, width=9)
        spin.pack()
        return var

    def _config(self) -> Config:
        return Config(
            max_pages=self._int(self.pages.get(), 60, 5, 300),
            max_depth=self._int(self.depth.get(), 2, 0, 5),
            rate_limit=self._float(self.rate.get(), 8.0, 0.5, 50.0),
            allow_private=self.private.get() == "1",
            timeout=10.0,
        )

    @staticmethod
    def _int(value, default, low, high) -> int:
        try:
            return max(low, min(high, int(float(value))))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _float(value, default, low, high) -> float:
        try:
            return max(low, min(high, float(value)))
        except (TypeError, ValueError):
            return default

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        url = self.url.get().strip()
        if not url:
            messagebox.showwarning("Nutiscan", "Sisesta sihtmärgi URL.")
            return
        self.findings.delete(0, END)
        self.detail.delete("1.0", END)
        self.progress["value"] = 0
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.triage_btn.config(state="disabled")
        self.status.config(text=f"Skannin: {url}")
        self.last_snapshot = None

        config = self._config()
        job = new_job(url, config)
        self.current_job = job

        def work() -> None:
            try:
                Engine(config).run(job)
                self.events.put(("done", job.snapshot()))
            except Exception as exc:  # noqa: BLE001
                self.events.put(("crash", f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=4)}"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.root.after(250, self.poll)

    def stop(self) -> None:
        if self.current_job:
            self.current_job.request_stop()
            self.status.config(text="Peatamislähetus saadetud…")

    def poll(self) -> None:
        events = 0
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            events += 1
            if kind == "done":
                self.finish(payload)
            elif kind == "crash":
                self.status.config(text="Viga")
                messagebox.showerror("Nutiscan", str(payload))

        if self.current_job and self.current_job.status == "running":
            snapshot = self.current_job.snapshot()
            self.progress["value"] = snapshot["progress"]
            self.status.config(text=f"{snapshot['stage']} — {snapshot['progress']}%")
            self.render_findings(snapshot)
        if events == 0 and self.worker and self.worker.is_alive():
            self.root.after(250, self.poll)

    def render_findings(self, snapshot: dict) -> None:
        current = list(self.findings.get(0, END))
        incoming = [f"[{f['severity'].upper():8}] {f['title']}" for f in snapshot["findings"]]
        if current != incoming:
            self.findings.delete(0, END)
            for item in incoming:
                self.findings.insert(END, item)

    def finish(self, snapshot: dict) -> None:
        self.last_snapshot = snapshot
        self.progress["value"] = 100
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.triage_btn.config(state="normal")
        counts = snapshot["counts"]
        risk = snapshot["triageSummary"].get("riskScore", 0)
        self.status.config(
            text=f"Valmis: {len(snapshot['findings'])} leidu, risk {risk}/100 "
                 f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, "
                 f"low {counts['low']}, info {counts['info']})"
        )
        self.render_findings(snapshot)
        out = self.output_dir()
        out.mkdir(parents=True, exist_ok=True)
        stem = self.stem(snapshot["url"])
        (out / f"{stem}.raw.json").write_bytes(export.to_json(snapshot))
        for fmt in ("md", "html", "csv", "sarif"):
            _, extension, render = export.FORMATS[fmt]
            (out / f"{stem}.{extension}").write_bytes(render(snapshot))

    def stem(self, url: str) -> str:
        import re
        parts = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        raw = (parts.netloc + parts.path).strip("/") or "target"
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)[:80] + "-" + time.strftime("%Y%m%d-%H%M%S")

    def output_dir(self) -> Path:
        env = os.environ.get("NUTISCAN_OUT", "").strip()
        return Path(env).expanduser() if env else DEFAULT_OUT

    def show_finding(self, _event=None) -> None:
        selection = self.findings.curselection()
        if not selection or not self.last_snapshot:
            return
        index = selection[0]
        findings = self.last_snapshot["findings"]
        if index >= len(findings):
            return
        item = findings[index]
        text = self.detail
        text.delete("1.0", END)
        lines = [
            f"{item['title']}",
            f"Raskusaste: {item['severity']} ({item['score']}/10, {item['confidence']})",
            f"Kategooria: {item['category']}",
            f"Kontroll: {item['check']}",
            f"Asukoht: {item['url']}",
            "",
            item.get("detail", ""),
            "",
        ]
        if item.get("request"):
            lines += ["TAASESTUS"]
            lines += [f"  {k}: {v}" for k, v in item["request"].items()]
            lines.append("")
        if item.get("evidence"):
            lines += ["TÕEND", item["evidence"], ""]
        if item.get("remediation"):
            lines += ["PARANDUS", item["remediation"]]
        text.insert("1.0", "\n".join(lines))

    def open_report(self) -> None:
        if not self.last_snapshot:
            return
        path = self.output_dir() / (self.stem(self.last_snapshot["url"]) + ".html")
        if path.exists():
            webbrowser.open("file:///" + str(path).replace("\\", "/"))

    def open_folder(self) -> None:
        path = self.output_dir()
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(str(path))

    def show_log(self) -> None:
        if not self.last_snapshot:
            messagebox.showinfo("Nutiscan", "Logi on olemas pärast skanni.")
            return
        window = Toplevel(self.root)
        window.title("Nutiscan — logi")
        window.geometry("820x520")
        text = Text(window, wrap=WORD, font=("Consolas", 9))
        text.pack(fill=BOTH, expand=True)
        text.insert("1.0", "\n".join(self.last_snapshot["logs"]))


def main() -> None:
    root = Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
