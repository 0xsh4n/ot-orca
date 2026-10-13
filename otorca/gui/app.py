"""OT-ORCA graphical interface (Tkinter / ttk).

Chosen deliberately: Tkinter ships with CPython on Windows, macOS and most Linux
distros, so the GUI runs *everywhere* with zero extra install. The layout is a
tabbed workspace:

  * **Capture** — pick an interface (or type an IP/BPF, or load a pcap), set
    limits, start/stop, watch live counters and a log.
  * **Findings** — severity-coloured, click a row for full description &
    mitigation.
  * **Assets** — the discovered OT inventory (role, Purdue level, vendor).
  * **Topology** — the rendered network diagram.
  * **Report & AI** — configure the optional AI analyst, opt in to active nmap,
    export HTML/JSON/Markdown.

All capture work runs off the Tk thread; UI updates are marshalled back with
``root.after`` so the interface stays responsive.
"""

from __future__ import annotations

import os
import queue
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from ..version import __version__
from ..core.capture import CaptureConfig, list_interfaces, tshark_version
from ..core.session import ScanSession
from ..ai.base import AIConfig

_SEV_COLORS = {"Critical": "#d7263d", "High": "#e4572e", "Medium": "#f4a259",
               "Low": "#4c9f70", "Info": "#2e86ab"}
_BG = "#0f1115"
_CARD = "#171b22"
_FG = "#e8eaed"
_MUTED = "#8a93a3"
_ACCENT = "#e4572e"


class OtOrcaGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.session: ScanSession | None = None
        self.result = None
        self._ui_queue: queue.Queue = queue.Queue()
        self._topo_img = None
        self._tmpdir = tempfile.mkdtemp(prefix="otorca_gui_")

        root.title(f"OT-ORCA {__version__} — Passive OT Security Toolkit")
        root.geometry("1180x760")
        root.configure(bg=_BG)
        self._init_style()
        self._build()
        self.root.after(200, self._drain_queue)

    # --- styling -------------------------------------------------------------
    def _init_style(self) -> None:
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=_BG, foreground=_FG, fieldbackground=_CARD)
        st.configure("TFrame", background=_BG)
        st.configure("Card.TFrame", background=_CARD)
        st.configure("TLabel", background=_BG, foreground=_FG)
        st.configure("Muted.TLabel", background=_BG, foreground=_MUTED)
        st.configure("Head.TLabel", background=_BG, foreground=_FG,
                     font=("TkDefaultFont", 13, "bold"))
        st.configure("TButton", background=_CARD, foreground=_FG, borderwidth=0,
                     padding=6)
        st.map("TButton", background=[("active", "#232a35")])
        st.configure("Accent.TButton", background=_ACCENT, foreground="#fff",
                     font=("TkDefaultFont", 10, "bold"))
        st.map("Accent.TButton", background=[("active", "#c8451f")])
        st.configure("TNotebook", background=_BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=_CARD, foreground=_MUTED,
                     padding=(16, 8))
        st.map("TNotebook.Tab", background=[("selected", _BG)],
               foreground=[("selected", _FG)])
        st.configure("Treeview", background=_CARD, fieldbackground=_CARD,
                     foreground=_FG, rowheight=24, borderwidth=0)
        st.configure("Treeview.Heading", background="#1b2029", foreground=_MUTED,
                     relief="flat")
        st.map("Treeview", background=[("selected", "#2a3340")])
        st.configure("TEntry", fieldbackground=_CARD, foreground=_FG)
        st.configure("TCombobox", fieldbackground=_CARD, foreground=_FG)
        st.configure("TCheckbutton", background=_BG, foreground=_FG)
        st.configure("Horizontal.TProgressbar", background=_ACCENT)

    # --- layout --------------------------------------------------------------
    def _build(self) -> None:
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=16, pady=(12, 4))
        ttk.Label(header, text="🐋 OT-ORCA", style="Head.TLabel").pack(side="left")
        ttk.Label(header, text=f"  passive · {tshark_version()}",
                  style="Muted.TLabel").pack(side="left")
        self.status_var = tk.StringVar(value="idle")
        ttk.Label(header, textvariable=self.status_var,
                  style="Muted.TLabel").pack(side="right")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=8)
        self._build_capture_tab()
        self._build_findings_tab()
        self._build_assets_tab()
        self._build_topology_tab()
        self._build_report_tab()

    def _build_capture_tab(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Capture  ")
        ctrl = ttk.Frame(f, style="Card.TFrame")
        ctrl.pack(fill="x", padx=10, pady=10, ipady=8)

        row1 = ttk.Frame(ctrl, style="Card.TFrame")
        row1.pack(fill="x", padx=12, pady=6)
        ttk.Label(row1, text="Interface:", background=_CARD).pack(side="left")
        self.iface_var = tk.StringVar()
        ifaces = [n for n, _ in list_interfaces()] or ["eth0"]
        self.iface_cb = ttk.Combobox(row1, textvariable=self.iface_var,
                                     values=ifaces, width=18)
        self.iface_cb.pack(side="left", padx=6)
        if ifaces:
            self.iface_var.set(ifaces[0])
        ttk.Button(row1, text="↻", width=3,
                   command=self._refresh_ifaces).pack(side="left")

        ttk.Label(row1, text="  BPF / host filter:",
                  background=_CARD).pack(side="left", padx=(16, 0))
        self.filter_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.filter_var, width=28).pack(side="left",
                                                                     padx=6)
        ttk.Label(row1, text="(e.g. 'host 192.168.1.10' — optional)",
                  background=_CARD, foreground=_MUTED).pack(side="left")

        row2 = ttk.Frame(ctrl, style="Card.TFrame")
        row2.pack(fill="x", padx=12, pady=6)
        ttk.Label(row2, text="Duration (s):", background=_CARD).pack(side="left")
        self.dur_var = tk.StringVar(value="60")
        ttk.Entry(row2, textvariable=self.dur_var, width=7).pack(side="left", padx=6)
        ttk.Label(row2, text="Max packets:", background=_CARD).pack(side="left",
                                                                    padx=(12, 0))
        self.count_var = tk.StringVar(value="0")
        ttk.Entry(row2, textvariable=self.count_var, width=9).pack(side="left",
                                                                   padx=6)
        ttk.Button(row2, text="Load pcap…",
                   command=self._load_pcap).pack(side="left", padx=(16, 0))
        self.pcap_lbl = ttk.Label(row2, text="(live)", background=_CARD,
                                  foreground=_MUTED)
        self.pcap_lbl.pack(side="left", padx=6)
        self._pcap_path = None

        row3 = ttk.Frame(ctrl, style="Card.TFrame")
        row3.pack(fill="x", padx=12, pady=6)
        self.start_btn = ttk.Button(row3, text="▶  Start passive scan",
                                    style="Accent.TButton", command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(row3, text="■  Stop", command=self._stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.analyze_btn = ttk.Button(row3, text="⟳  Re-analyze",
                                      command=self._analyze, state="disabled")
        self.analyze_btn.pack(side="left", padx=8)

        # Live counters
        kp = ttk.Frame(f)
        kp.pack(fill="x", padx=10, pady=4)
        self.kpi_vars = {}
        for name in ("packets", "assets", "flows", "events", "duration_s"):
            card = ttk.Frame(kp, style="Card.TFrame")
            card.pack(side="left", padx=6, ipadx=14, ipady=8)
            v = tk.StringVar(value="0")
            self.kpi_vars[name] = v
            ttk.Label(card, textvariable=v, background=_CARD, foreground=_FG,
                      font=("TkDefaultFont", 18, "bold")).pack()
            ttk.Label(card, text=name, background=_CARD,
                      foreground=_MUTED).pack()

        self.pbar = ttk.Progressbar(f, mode="indeterminate",
                                    style="Horizontal.TProgressbar")
        self.pbar.pack(fill="x", padx=12, pady=(6, 0))

        ttk.Label(f, text="Live log", style="Muted.TLabel").pack(anchor="w",
                                                                 padx=14, pady=(8, 0))
        self.log = tk.Text(f, height=12, bg=_CARD, fg=_FG, insertbackground=_FG,
                           relief="flat", font=("TkFixedFont", 9))
        self.log.pack(fill="both", expand=True, padx=12, pady=(2, 12))
        self._log("OT-ORCA ready. Default mode is strictly passive — no packets "
                  "are transmitted.\nSelect an interface and press Start, or load "
                  "a pcap for offline analysis.")

    def _build_findings_tab(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Findings  ")
        cols = ("sev", "id", "title", "assets", "count")
        self.find_tree = ttk.Treeview(f, columns=cols, show="headings",
                                      height=14)
        for c, w, t in (("sev", 90, "Severity"), ("id", 180, "Rule"),
                        ("title", 420, "Title"), ("assets", 240, "Assets"),
                        ("count", 60, "Count")):
            self.find_tree.heading(c, text=t)
            self.find_tree.column(c, width=w, anchor="w")
        self.find_tree.pack(fill="both", expand=True, padx=10, pady=(10, 4))
        for sev, color in _SEV_COLORS.items():
            self.find_tree.tag_configure(sev, foreground=color)
        self.find_tree.bind("<<TreeviewSelect>>", self._on_finding_select)
        self.find_detail = tk.Text(f, height=12, bg=_CARD, fg=_FG, relief="flat",
                                   wrap="word", font=("TkDefaultFont", 10),
                                   insertbackground=_FG)
        self.find_detail.pack(fill="both", expand=False, padx=10, pady=(4, 10))
        self.find_detail.tag_configure("h", foreground=_ACCENT,
                                       font=("TkDefaultFont", 11, "bold"))
        self.find_detail.tag_configure("k", foreground=_MUTED)

    def _build_assets_tab(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Assets  ")
        cols = ("name", "ip", "role", "purdue", "vendor", "product", "proto", "pkts")
        self.asset_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w, t in (("name", 150, "Name"), ("ip", 120, "IP"),
                        ("role", 110, "Role"), ("purdue", 130, "Purdue"),
                        ("vendor", 150, "Vendor"), ("product", 160, "Product"),
                        ("proto", 180, "Protocols"), ("pkts", 70, "Pkts")):
            self.asset_tree.heading(c, text=t)
            self.asset_tree.column(c, width=w, anchor="w")
        self.asset_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_topology_tab(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Topology  ")
        bar = ttk.Frame(f)
        bar.pack(fill="x", padx=10, pady=8)
        ttk.Button(bar, text="⟳ Render topology",
                   command=self._render_topology).pack(side="left")
        ttk.Label(bar, text="  Red edges = control/write command flows",
                  style="Muted.TLabel").pack(side="left", padx=10)
        canvas_frame = ttk.Frame(f, style="Card.TFrame")
        canvas_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.topo_canvas = tk.Canvas(canvas_frame, bg=_BG, highlightthickness=0)
        self.topo_canvas.pack(fill="both", expand=True)
        self.topo_canvas.create_text(
            300, 200, text="Run a scan, then render the topology.",
            fill=_MUTED, anchor="nw", tags="hint")

    def _build_report_tab(self) -> None:
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Report & AI  ")
        ai = ttk.LabelFrame(f, text="AI analyst (optional)")
        ai.configure(style="Card.TFrame")
        ai.pack(fill="x", padx=12, pady=10, ipady=6)
        r = ttk.Frame(ai, style="Card.TFrame"); r.pack(fill="x", padx=10, pady=4)
        self.ai_enable = tk.BooleanVar(value=False)
        ttk.Checkbutton(r, text="Enable AI narrative", variable=self.ai_enable,
                        style="TCheckbutton").pack(side="left")
        ttk.Label(r, text="Provider:", background=_CARD).pack(side="left",
                                                              padx=(16, 4))
        self.ai_provider = tk.StringVar(value="ollama")
        ttk.Combobox(r, textvariable=self.ai_provider, width=12,
                     values=["ollama", "openai", "none"]).pack(side="left")
        ttk.Label(r, text="Model:", background=_CARD).pack(side="left", padx=(12, 4))
        self.ai_model = tk.StringVar(value="qwen2.5")
        ttk.Entry(r, textvariable=self.ai_model, width=18).pack(side="left")
        r2 = ttk.Frame(ai, style="Card.TFrame"); r2.pack(fill="x", padx=10, pady=4)
        ttk.Label(r2, text="Base URL:", background=_CARD).pack(side="left")
        self.ai_url = tk.StringVar(value="")
        ttk.Entry(r2, textvariable=self.ai_url, width=36).pack(side="left", padx=6)
        ttk.Label(r2, text="API key:", background=_CARD).pack(side="left",
                                                              padx=(12, 4))
        self.ai_key = tk.StringVar(value="")
        ttk.Entry(r2, textvariable=self.ai_key, width=24, show="•").pack(side="left")

        act = ttk.LabelFrame(f, text="Active options (NOT passive — opt-in)")
        act.configure(style="Card.TFrame")
        act.pack(fill="x", padx=12, pady=6, ipady=6)
        self.nmap_enable = tk.BooleanVar(value=False)
        ttk.Checkbutton(act, text="Run active nmap on discovered hosts "
                        "(I am authorized to probe these devices)",
                        variable=self.nmap_enable,
                        style="TCheckbutton").pack(anchor="w", padx=10, pady=4)

        exp = ttk.Frame(f); exp.pack(fill="x", padx=12, pady=16)
        ttk.Button(exp, text="💾 Export HTML report", style="Accent.TButton",
                   command=lambda: self._export("html")).pack(side="left")
        ttk.Button(exp, text="Export JSON",
                   command=lambda: self._export("json")).pack(side="left", padx=8)
        ttk.Button(exp, text="Export Markdown",
                   command=lambda: self._export("md")).pack(side="left")
        self.ai_status = ttk.Label(f, text="", style="Muted.TLabel")
        self.ai_status.pack(anchor="w", padx=14)

    # --- actions -------------------------------------------------------------
    def _refresh_ifaces(self) -> None:
        ifaces = [n for n, _ in list_interfaces()]
        if ifaces:
            self.iface_cb["values"] = ifaces

    def _load_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="Open capture", filetypes=[("Capture", "*.pcap *.pcapng *.cap"),
                                             ("All", "*.*")])
        if path:
            self._pcap_path = path
            self.pcap_lbl.config(text=os.path.basename(path))

    def _log(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def _start(self) -> None:
        if self.session and self.session.running:
            return
        try:
            dur = int(self.dur_var.get() or 0)
            cnt = int(self.count_var.get() or 0)
        except ValueError:
            messagebox.showerror("OT-ORCA", "Duration/packets must be integers.")
            return
        cfg = CaptureConfig(
            interface=None if self._pcap_path else (self.iface_var.get() or None),
            pcap=self._pcap_path, bpf=self.filter_var.get() or None,
            duration=dur, packet_limit=cnt)
        self.session = ScanSession(cfg, progress_cb=self._progress_cb,
                                   progress_every=50)
        self.result = None
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("capturing…")
        self.pbar.start(12)
        src = self._pcap_path or self.iface_var.get()
        self._log(f"\n[{time.strftime('%H:%M:%S')}] starting passive scan of {src}")
        self.session.start_async()
        threading.Thread(target=self._watch_session, daemon=True).start()

    def _watch_session(self) -> None:
        assert self.session
        while self.session.running:
            time.sleep(0.2)
        self._ui_queue.put(("done", None))

    def _stop(self) -> None:
        if self.session:
            self.session.stop()
            self._log(f"[{time.strftime('%H:%M:%S')}] stop requested")

    def _progress_cb(self, summary: dict) -> None:
        self._ui_queue.put(("progress", summary))

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                if kind == "progress":
                    for k, var in self.kpi_vars.items():
                        var.set(str(payload.get(k, 0)))
                elif kind == "done":
                    self._on_capture_done()
        except queue.Empty:
            pass
        self.root.after(200, self._drain_queue)

    def _on_capture_done(self) -> None:
        self.pbar.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.analyze_btn.config(state="normal")
        if self.session and self.session.error:
            self._log(f"[error] {self.session.error}")
            self.status_var.set("error")
        else:
            self.status_var.set("capture complete — analyzing")
        self._log(f"[{time.strftime('%H:%M:%S')}] capture finished; analyzing…")
        self._analyze()

    def _analyze(self) -> None:
        if not self.session:
            return
        self.result = self.session.build_result()
        self._populate_findings()
        self._populate_assets()
        d = self.result.to_dict()
        sev = d["stats"].get("severity_matrix", {})
        self._log(f"[analysis] {len(d['findings'])} findings — "
                  f"Critical={sev.get('Critical',0)} High={sev.get('High',0)} "
                  f"Medium={sev.get('Medium',0)}")
        self.status_var.set(
            f"done · {d['summary'].get('assets')} assets · "
            f"{len(d['findings'])} findings")
        self._render_topology()

    def _populate_findings(self) -> None:
        self.find_tree.delete(*self.find_tree.get_children())
        self._finding_map = {}
        for f in self.result.to_dict()["findings"]:
            iid = self.find_tree.insert(
                "", "end", values=(f["severity"], f["rule_id"], f["title"],
                                   ", ".join(f["assets"][:3]), f.get("count", 1)),
                tags=(f["severity"],))
            self._finding_map[iid] = f

    def _on_finding_select(self, _evt) -> None:
        sel = self.find_tree.selection()
        if not sel:
            return
        f = self._finding_map.get(sel[0])
        if not f:
            return
        t = self.find_detail
        t.delete("1.0", "end")
        t.insert("end", f"{f['title']}\n", "h")
        t.insert("end", f"{f['rule_id']}  ·  {f['severity']}  ·  "
                        f"{f['category']}  ·  confidence {f.get('confidence')}\n\n")
        t.insert("end", "Affected assets: ", "k")
        t.insert("end", ", ".join(f["assets"]) + "\n\n")
        t.insert("end", "Description\n", "k")
        t.insert("end", f["description"] + "\n\n")
        t.insert("end", "Mitigation\n", "k")
        t.insert("end", f["mitigation"] + "\n\n")
        if f.get("evidence"):
            t.insert("end", "Evidence\n", "k")
            for e in f["evidence"][:8]:
                t.insert("end", f"  • {e}\n")
            t.insert("end", "\n")
        t.insert("end", "References\n", "k")
        t.insert("end", "  " + "; ".join(f["references"]))

    def _populate_assets(self) -> None:
        self.asset_tree.delete(*self.asset_tree.get_children())
        for a in self.result.to_dict()["assets"]:
            self.asset_tree.insert("", "end", values=(
                a.get("display_name", ""), a.get("ip") or "", a.get("role"),
                a.get("purdue"), a.get("vendor") or "", a.get("product") or "",
                ",".join(a.get("protocols", [])), a.get("packets", 0)))

    def _render_topology(self) -> None:
        if not self.session or not self.session.inv.assets:
            return
        from ..viz import topology
        path = os.path.join(self._tmpdir, "topo.png")
        try:
            if topology.render(self.session.inv, path):
                self._topo_img = tk.PhotoImage(file=path)
                self.topo_canvas.delete("all")
                self.topo_canvas.create_image(0, 0, image=self._topo_img,
                                              anchor="nw")
                self.topo_canvas.config(scrollregion=self.topo_canvas.bbox("all"))
        except Exception as exc:
            self._log(f"[topology] render failed: {exc}")

    def _export(self, kind: str) -> None:
        if not self.result:
            messagebox.showinfo("OT-ORCA", "Run a scan first.")
            return
        ai_narrative, ai_source = self._maybe_ai()
        if kind == "html":
            path = filedialog.asksaveasfilename(defaultextension=".html",
                    initialfile="otorca-report.html",
                    filetypes=[("HTML", "*.html")])
            if not path:
                return
            from .. import report
            report.write_report(self.result, path, inv=self.session.inv,
                                 ai_narrative=ai_narrative, ai_source=ai_source)
        elif kind == "json":
            path = filedialog.asksaveasfilename(defaultextension=".json",
                    initialfile="otorca-result.json")
            if not path:
                return
            from .. import report
            report.write_json(self.result, path)
        else:
            path = filedialog.asksaveasfilename(defaultextension=".md",
                    initialfile="otorca-report.md")
            if not path:
                return
            from .. import report
            report.write_markdown(self.result, path, ai_narrative)
        self._log(f"[export] wrote {path}")
        messagebox.showinfo("OT-ORCA", f"Report written to:\n{path}")

    def _maybe_ai(self):
        if not self.ai_enable.get():
            from ..ai.analyst import deterministic_narrative
            return deterministic_narrative(self.result), "deterministic (no AI)"
        from ..ai.analyst import Analyst
        cfg = AIConfig(provider=self.ai_provider.get(),
                       model=self.ai_model.get(),
                       base_url=self.ai_url.get() or "",
                       api_key=self.ai_key.get() or "")
        analyst = Analyst(cfg)
        self.ai_status.config(text=f"AI backend: {analyst.status()}")
        self._log(f"[ai] querying {cfg.provider}:{cfg.model} ({analyst.status()})…")
        return analyst.analyze(self.result)


def launch() -> None:
    root = tk.Tk()
    OtOrcaGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
