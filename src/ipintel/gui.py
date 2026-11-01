"""Dark console-style Tkinter interface for passive IP intelligence."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any

from .engine import Analyzer
from .reporting import write_csv, write_json


BG = "#080d0d"
BAR = "#0d1514"
PANEL = "#0e1716"
FIELD = "#0b1413"
BORDER = "#294039"
TEXT = "#d9ede4"
MUTED = "#88a39a"
ACCENT = "#9de06e"
AMBER = "#e9b86d"
RED = "#ed867d"
FONT = "Consolas"
PROVIDERS = (
    ("abuseipdb", "AbuseIPDB"),
    ("virustotal", "VirusTotal"),
    ("shodan", "Shodan"),
    ("greynoise", "GreyNoise"),
)
RISK_LEVELS = {
    "low": ("DÜŞÜK", ACCENT),
    "medium": ("ORTA", AMBER),
    "high": ("YÜKSEK", RED),
    "critical": ("KRİTİK", RED),
}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Barracuda IP Intelligence")
        self.geometry("1100x690")
        self.minsize(850, 590)
        self.configure(bg=BG)
        self.report: dict[str, Any] | None = None
        self.result_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.ip_var = tk.StringVar(self, value="8.8.8.8")
        self.keyless_var = tk.BooleanVar(self, value=True)
        self.provider_vars = {name: tk.BooleanVar(self, value=True) for name, _ in PROVIDERS}
        self.toggle_labels: dict[str, tk.StringVar] = {}
        self._build()

    def _label(
        self, parent: tk.Misc, value: str, *, color: str = TEXT,
        size: int = 10, weight: str = "normal", **kwargs: Any,
    ) -> tk.Label:
        return tk.Label(
            parent, text=value, bg=parent.cget("bg"), fg=color,
            font=(FONT, size, weight), **kwargs,
        )

    def _panel(self, parent: tk.Misc) -> tk.Frame:
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, bd=0)

    def _rule(self, parent: tk.Misc) -> None:
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = tk.Frame(self, bg=BAR, height=50, highlightbackground=BORDER, highlightthickness=1)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        self._label(header, "[ BARRACUDA // IP INTELLIGENCE ]", color=ACCENT, weight="bold").pack(
            side="left", padx=20, pady=13,
        )
        self.status_label = self._label(header, "● HAZIR", color=ACCENT, size=9)
        self.status_label.pack(side="right", padx=20)

        main = tk.Frame(self, bg=BG)
        main.grid(row=1, column=0, sticky="nsew", padx=20, pady=(16, 18))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        search = self._panel(main)
        search.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self._label(search, "TARGET / IP ADRESİ", color=ACCENT, size=9).pack(
            anchor="w", padx=16, pady=(13, 8),
        )
        query = tk.Frame(search, bg=PANEL)
        query.pack(fill="x", padx=16, pady=(0, 14))
        self._label(query, ">", color=ACCENT, size=13).pack(side="left", padx=(0, 9))
        self.ip_entry = tk.Entry(
            query, textvariable=self.ip_var, bg=FIELD, fg=TEXT, insertbackground=ACCENT,
            selectbackground=BORDER, relief="flat", highlightbackground=BORDER,
            highlightcolor=ACCENT, highlightthickness=1, font=(FONT, 11),
        )
        self.ip_entry.pack(side="left", fill="x", expand=True, ipady=9)
        self.ip_entry.bind("<Return>", lambda _event: self.start_analysis())
        self.analyze_button = tk.Button(
            query, text="ANALİZ ET  →", command=self.start_analysis,
            bg=ACCENT, fg=BG, activebackground="#b6f18c", activeforeground=BG,
            relief="flat", bd=0, font=(FONT, 10, "bold"), padx=16, pady=10,
        )
        self.analyze_button.pack(side="left", padx=(9, 0))

        body = tk.Frame(main, bg=BG)
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=5, uniform="content")
        body.grid_columnconfigure(1, weight=3, uniform="content")
        self._build_profile(body)
        self._build_risk_sources(body)
        self._build_footer(main)
        self.ip_entry.focus_set()

    def _build_profile(self, parent: tk.Misc) -> None:
        profile = self._panel(parent)
        profile.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        profile.grid_columnconfigure(0, weight=1)
        profile.grid_rowconfigure(1, weight=1)
        title = tk.Frame(profile, bg=PANEL)
        title.grid(row=0, column=0, sticky="ew", padx=14, pady=12)
        self._label(title, "IP_PROFILE.JSON", color=ACCENT, size=9, weight="bold").pack(side="left")
        self.profile_meta = self._label(title, "● ANALİZ BEKLENİYOR", color=MUTED, size=9)
        self.profile_meta.pack(side="right")

        text_area = tk.Frame(profile, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        text_area.grid(row=1, column=0, sticky="nsew")
        text_area.grid_columnconfigure(0, weight=1)
        text_area.grid_rowconfigure(0, weight=1)
        self.output = tk.Text(
            text_area, wrap="none", bg=PANEL, fg=TEXT, insertbackground=ACCENT,
            selectbackground=BORDER, relief="flat", bd=0, padx=14, pady=12,
            font=(FONT, 10), state="disabled",
        )
        self.output.grid(row=0, column=0, sticky="nsew")
        scroll_y = tk.Scrollbar(
            text_area, orient="vertical", command=self.output.yview,
            bg=BAR, activebackground=BORDER, troughcolor=PANEL, highlightthickness=0, bd=0,
        )
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x = tk.Scrollbar(
            text_area, orient="horizontal", command=self.output.xview,
            bg=BAR, activebackground=BORDER, troughcolor=PANEL, highlightthickness=0, bd=0,
        )
        scroll_x.grid(row=1, column=0, sticky="ew")
        self.output.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self._set_output(
            "# HENÜZ ANALİZ YOK\n\n"
            "Hedef IP adresini girin ve ANALİZ ET düğmesine basın.\n"
            "Sonuç burada JSON olarak görüntülenecektir."
        )

    def _build_risk_sources(self, parent: tk.Misc) -> None:
        side = self._panel(parent)
        side.grid(row=0, column=1, sticky="nsew")
        title = tk.Frame(side, bg=PANEL)
        title.pack(fill="x", padx=15, pady=12)
        self._label(title, "RISK_ENGINE", color=ACCENT, size=9, weight="bold").pack(side="left")
        self._label(title, "v1", color=MUTED, size=9).pack(side="right")
        self._rule(side)

        risk = tk.Frame(side, bg=PANEL)
        risk.pack(fill="x", padx=16, pady=(18, 17))
        self._label(risk, "RISK SCORE", color=MUTED, size=9).pack(anchor="w")
        score_row = tk.Frame(risk, bg=PANEL)
        score_row.pack(fill="x", pady=(5, 0))
        self.risk_value = self._label(score_row, "--", color=MUTED, size=30)
        self.risk_value.pack(side="left")
        self.risk_context = self._label(score_row, " / 100 · BEKLENİYOR", color=MUTED, size=10)
        self.risk_context.pack(side="left", padx=(6, 0), pady=(12, 0))
        self.risk_track = tk.Frame(risk, bg=BORDER, height=6)
        self.risk_track.pack(fill="x", pady=(14, 7))
        self.risk_track.pack_propagate(False)
        self.risk_fill = tk.Frame(self.risk_track, bg=ACCENT)
        self.evidence_label = self._label(risk, "SAĞLAYICI KANITI: --", color=MUTED, size=9)
        self.evidence_label.pack(anchor="w")
        self._rule(side)

        sources = tk.Frame(side, bg=PANEL)
        sources.pack(fill="x", padx=16, pady=(15, 8))
        self._label(sources, "KAYNAK SEÇİMİ", color=MUTED, size=9).pack(anchor="w", pady=(0, 11))
        self._source_row(sources, "keyless", "Anahtarsız kaynaklar", self.keyless_var)
        for name, label in PROVIDERS:
            self._source_row(sources, name, label, self.provider_vars[name])

    def _source_row(self, parent: tk.Misc, name: str, label: str, variable: tk.BooleanVar) -> None:
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x", pady=3)
        self._label(row, label, size=9).pack(side="left")
        state = tk.StringVar(self)
        self.toggle_labels[name] = state
        tk.Checkbutton(
            row, textvariable=state, variable=variable, command=self._refresh_toggles,
            indicatoron=False, bg=PANEL, fg=ACCENT, selectcolor=PANEL,
            activebackground=PANEL, activeforeground=ACCENT,
            relief="flat", bd=0, highlightthickness=0, font=(FONT, 9), padx=3, pady=2,
        ).pack(side="right")
        self._refresh_toggles()

    def _refresh_toggles(self) -> None:
        values = {"keyless": self.keyless_var, **self.provider_vars}
        for name, label in self.toggle_labels.items():
            label.set("[ ON ]" if values[name].get() else "[ OFF ]")

    def _build_footer(self, parent: tk.Misc) -> None:
        footer = tk.Frame(parent, bg=BG)
        footer.grid(row=2, column=0, sticky="ew", pady=(13, 0))
        self._label(
            footer, "Yalnızca pasif kaynaklar kullanılır. Konum bilgisi yaklaşık değerdir.",
            color=MUTED, size=9,
        ).pack(side="left", pady=8)
        for label, command in (("↓ CSV", self.save_csv), ("↓ JSON", self.save_json)):
            tk.Button(
                footer, text=label, command=command, bg=BG, fg=TEXT,
                activebackground=PANEL, activeforeground=ACCENT,
                relief="flat", bd=0, highlightbackground=BORDER,
                highlightthickness=1, font=(FONT, 9), padx=11, pady=8,
            ).pack(side="right", padx=(8, 0))

    def _set_output(self, content: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", content)
        self.output.configure(state="disabled")

    def _set_status(self, label: str, color: str) -> None:
        self.status_label.configure(text=f"● {label}", fg=color)

    def _set_risk(self, risk: dict[str, Any] | None = None) -> None:
        self.risk_fill.place_forget()
        if risk is None:
            self.risk_value.configure(text="--", fg=MUTED)
            self.risk_context.configure(text=" / 100 · BEKLENİYOR", fg=MUTED)
            self.evidence_label.configure(text="SAĞLAYICI KANITI: --")
            return
        count = int(risk.get("provider_count", 0))
        score = max(0, min(100, int(risk.get("score", 0))))
        level, color = RISK_LEVELS.get(str(risk.get("level", "")), ("BELİRSİZ", AMBER))
        if count == 0:
            level, color = "KANIT YOK", AMBER
        self.risk_value.configure(text="--" if count == 0 else f"{score:02d}", fg=color)
        self.risk_context.configure(text=f" / 100 · {level}", fg=color)
        self.evidence_label.configure(text=f"SAĞLAYICI KANITI: {count}")
        if count and score:
            self.risk_fill.configure(bg=color)
            self.risk_fill.place(x=0, y=0, relwidth=score / 100, relheight=1)

    def start_analysis(self) -> None:
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showwarning("IP adresi eksik", "Bir IPv4 veya IPv6 adresi girin.")
            return
        selected = {name for name, variable in self.provider_vars.items() if variable.get()}
        use_keyless = self.keyless_var.get()
        self.report = None
        self.analyze_button.configure(state="disabled")
        self._set_status("SORGULANIYOR", ACCENT)
        self.profile_meta.configure(text="● SORGULANIYOR", fg=ACCENT)
        self._set_risk()
        self._set_output(f"# PASİF ANALİZ\n\nHedef: {ip}\nKaynaklardan yanıt bekleniyor...")

        def worker() -> None:
            try:
                result = Analyzer().analyze(ip, use_keyless=use_keyless, provider_names=selected)
                self.result_queue.put(("ok", result))
            except Exception as exc:
                self.result_queue.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self._poll)

    def _poll(self) -> None:
        try:
            status, payload = self.result_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll)
            return
        self.analyze_button.configure(state="normal")
        if status == "error":
            self._set_status("HATA", RED)
            self.profile_meta.configure(text="● HATA", fg=RED)
            self._set_output(f"# ANALİZ BAŞARISIZ\n\n{payload}")
            messagebox.showerror("Analiz hatası", str(payload))
            return
        self.report = payload
        self._set_status("TAMAMLANDI", ACCENT)
        self.profile_meta.configure(text=f"● {self.report['target']}", fg=ACCENT)
        self._set_risk(self.report["risk"])
        self._set_output(json.dumps(self.report, indent=2, ensure_ascii=False))

    def save_json(self) -> None:
        self._save("json")

    def save_csv(self) -> None:
        self._save("csv")

    def _save(self, kind: str) -> None:
        if not self.report:
            messagebox.showinfo("Rapor yok", "Önce bir analiz çalıştırın.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{kind}",
            initialfile=f"ip-report-{self.report['target'].replace(':', '_')}.{kind}",
            filetypes=[(kind.upper(), f"*.{kind}"), ("All files", "*.*")],
        )
        if not path:
            return
        output = write_json(self.report, Path(path)) if kind == "json" else write_csv(self.report, Path(path))
        messagebox.showinfo("Kaydedildi", f"Rapor kaydedildi:\n{output}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
