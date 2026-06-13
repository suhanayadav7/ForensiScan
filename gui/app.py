"""ForensiScan — Tkinter GUI."""

import os
import sys
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# Add project root so core imports work when launched from gui/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core import metadata as md_mod
from core import signatures as sig_mod
from core import hasher as hash_mod
from core import hidden_data as hid_mod
from core import timeline as tl_mod
from core import reporter

# ── Palette ──────────────────────────────────────────────────────────────────
BG     = '#1a1a2e'
BG2    = '#16213e'
ACCENT = '#00d4ff'
WARN   = '#ff6b6b'
OK     = '#6bcb77'
FG     = '#e0e0e0'
FONT   = ('Consolas', 10)
FONT_B = ('Consolas', 10, 'bold')


def _apply_theme(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=BG, foreground=FG, font=FONT,
                    fieldbackground=BG2, bordercolor=ACCENT)
    style.configure('TNotebook',       background=BG,  tabmargins=[4, 4, 0, 0])
    style.configure('TNotebook.Tab',   background=BG2, foreground=FG,
                    padding=[10, 4], font=FONT_B)
    style.map('TNotebook.Tab',
              background=[('selected', ACCENT)],
              foreground=[('selected', BG)])
    style.configure('Treeview',        background=BG2, foreground=FG,
                    fieldbackground=BG2, rowheight=20, font=FONT)
    style.configure('Treeview.Heading', background=BG, foreground=ACCENT, font=FONT_B)
    style.map('Treeview', background=[('selected', ACCENT)],
              foreground=[('selected', BG)])
    style.configure('TButton', background=ACCENT, foreground=BG, font=FONT_B, padding=6)
    style.map('TButton', background=[('active', '#00a8cc')])
    style.configure('TLabel',  background=BG, foreground=FG, font=FONT)
    style.configure('TFrame',  background=BG)
    style.configure('TEntry',  fieldbackground=BG2, foreground=FG, font=FONT)
    style.configure('TCheckbutton', background=BG, foreground=FG, font=FONT)
    style.configure('TProgressbar', troughcolor=BG2, background=ACCENT)
    style.configure('TScrollbar', background=BG2, troughcolor=BG)


# ── Reusable table widget ─────────────────────────────────────────────────────

class TableView(ttk.Frame):
    def __init__(self, parent, columns: list[tuple[str, int]], **kw):
        super().__init__(parent, **kw)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        col_ids = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=col_ids, show='headings', selectmode='browse')
        vsb = ttk.Scrollbar(self, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        for col_id, width in columns:
            self.tree.heading(col_id, text=col_id,
                              command=lambda c=col_id: self._sort(c, False))
            self.tree.column(col_id, width=width, minwidth=40, anchor='w')

        self.tree.tag_configure('warn', foreground=WARN)
        self.tree.tag_configure('ok',   foreground=OK)

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def insert(self, values: list, tag: str = ''):
        self.tree.insert('', 'end', values=values, tags=(tag,) if tag else ())

    def row_count(self) -> int:
        return len(self.tree.get_children())

    def _sort(self, col: str, reverse: bool):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            data.sort(key=lambda x: float(x[0]) if x[0].replace('.', '', 1).lstrip('-').isdigit() else x[0].lower(),
                      reverse=reverse)
        except Exception:
            data.sort(reverse=reverse)
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, '', idx)
        self.tree.heading(col, command=lambda: self._sort(col, not reverse))


# ── Main application ──────────────────────────────────────────────────────────

class ForensiScanApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ForensiScan — Windows File Analysis Tool")
        self.root.geometry("1280x800")
        self.root.configure(bg=BG)
        _apply_theme(self.root)

        # Scan state
        self._metas:  list[md_mod.FileMetadata]    = []
        self._hashes: list[hash_mod.FileHashes]     = []
        self._sigs:   list[sig_mod.SignatureResult]  = []
        self._hidden: list[hid_mod.HiddenDataResult] = []
        self._events: list[tl_mod.TimelineEvent]     = []
        self._scan_dir = tk.StringVar()
        self._recursive = tk.BooleanVar(value=True)
        self._run_hashes = tk.BooleanVar(value=True)
        self._run_sigs   = tk.BooleanVar(value=True)
        self._run_hidden = tk.BooleanVar(value=True)

        self._build_ui()

    # ── UI layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = ttk.Frame(self.root)
        hdr.pack(fill='x', padx=16, pady=(12, 4))
        tk.Label(hdr, text="ForensiScan", font=('Consolas', 18, 'bold'),
                 fg=ACCENT, bg=BG).pack(side='left')
        tk.Label(hdr, text=" | Windows Digital Forensics Tool",
                 font=('Consolas', 11), fg=FG, bg=BG).pack(side='left')

        # Control bar
        ctrl = ttk.Frame(self.root)
        ctrl.pack(fill='x', padx=16, pady=4)

        ttk.Label(ctrl, text="Target:").pack(side='left')
        ttk.Entry(ctrl, textvariable=self._scan_dir, width=55).pack(side='left', padx=4)
        ttk.Button(ctrl, text="Browse", command=self._browse).pack(side='left')
        ttk.Separator(ctrl, orient='vertical').pack(side='left', padx=8, fill='y')
        ttk.Checkbutton(ctrl, text="Recursive",  variable=self._recursive).pack(side='left')
        ttk.Checkbutton(ctrl, text="Hashing",    variable=self._run_hashes).pack(side='left', padx=4)
        ttk.Checkbutton(ctrl, text="Signatures", variable=self._run_sigs).pack(side='left')
        ttk.Checkbutton(ctrl, text="Hidden",     variable=self._run_hidden).pack(side='left', padx=4)
        ttk.Button(ctrl, text="▶  Scan", command=self._start_scan).pack(side='left', padx=8)

        # Status / progress
        status_row = ttk.Frame(self.root)
        status_row.pack(fill='x', padx=16, pady=2)
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_row, textvariable=self._status_var).pack(side='left')
        self._progress = ttk.Progressbar(status_row, mode='indeterminate', length=200)
        self._progress.pack(side='right')

        # Notebook
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=16, pady=8)

        self._tab_metadata  = self._make_metadata_tab(nb)
        self._tab_sigs      = self._make_sigs_tab(nb)
        self._tab_hashes    = self._make_hashes_tab(nb)
        self._tab_hidden    = self._make_hidden_tab(nb)
        self._tab_timeline  = self._make_timeline_tab(nb)
        self._tab_report    = self._make_report_tab(nb)

        nb.add(self._tab_metadata, text=" Metadata ")
        nb.add(self._tab_sigs,     text=" Signatures ")
        nb.add(self._tab_hashes,   text=" Hashes ")
        nb.add(self._tab_hidden,   text=" Hidden Data ")
        nb.add(self._tab_timeline, text=" Timeline ")
        nb.add(self._tab_report,   text=" Report ")

    def _make_metadata_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('Name', 150), ('Size', 80),
                ('Created', 140), ('Modified', 140), ('Hidden', 55),
                ('System', 55), ('ReadOnly', 65), ('Owner', 120), ('Ext', 55)]
        self._meta_table = TableView(frame, cols)
        self._meta_table.grid(row=0, column=0, sticky='nsew')
        return frame

    def _make_sigs_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('Declared', 70), ('Detected', 130),
                ('MagicHex', 200), ('Mismatch', 65), ('Note', 300)]
        self._sig_table = TableView(frame, cols)
        self._sig_table.grid(row=0, column=0, sticky='nsew')
        return frame

    def _make_hashes_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('MD5', 240), ('SHA-1', 290), ('SHA-256', 430), ('Size', 80)]
        self._hash_table = TableView(frame, cols)
        self._hash_table.grid(row=0, column=0, sticky='nsew')
        return frame

    def _make_hidden_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('ADS Streams', 180), ('Suspicion Flags', 400)]
        self._hidden_table = TableView(frame, cols)
        self._hidden_table.grid(row=0, column=0, sticky='nsew')
        return frame

    def _make_timeline_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        filt_row = ttk.Frame(frame)
        filt_row.grid(row=0, column=0, sticky='ew', padx=4, pady=4)
        ttk.Label(filt_row, text="Show:").pack(side='left')
        self._tl_kind = tk.StringVar(value='all')
        for kind in ('all', 'created', 'modified', 'accessed'):
            ttk.Radiobutton(filt_row, text=kind, variable=self._tl_kind,
                            value=kind, command=self._refresh_timeline).pack(side='left', padx=4)
        self._tl_incl_accessed = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt_row, text="Include accessed events",
                        variable=self._tl_incl_accessed,
                        command=self._rebuild_timeline).pack(side='left', padx=12)

        cols = [('Timestamp', 155), ('Event', 75), ('Path', 400),
                ('Size', 80), ('Ext', 55), ('Hidden', 55)]
        self._tl_table = TableView(frame, cols)
        self._tl_table.grid(row=1, column=0, sticky='nsew')
        return frame

    def _make_report_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.columnconfigure(1, weight=1)

        fields = [
            ("Examiner name:", 'examiner', "Investigator Name"),
            ("Case name:",     'case',     "Case-001"),
        ]
        self._report_vars: dict[str, tk.StringVar] = {}
        for row, (label, key, default) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=12, pady=6)
            var = tk.StringVar(value=default)
            self._report_vars[key] = var
            ttk.Entry(frame, textvariable=var, width=40).grid(row=row, column=1, sticky='ew',
                                                               padx=12, pady=6)

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=len(fields), column=0, columnspan=2, pady=16, padx=12, sticky='w')
        ttk.Button(btn_row, text="Export CSV bundle",  command=self._export_csv).pack(side='left', padx=4)
        ttk.Button(btn_row, text="Export HTML report", command=self._export_html).pack(side='left', padx=4)
        ttk.Button(btn_row, text="Export PDF report",  command=self._export_pdf).pack(side='left', padx=4)

        self._report_log = tk.Text(frame, height=12, bg=BG2, fg=FG, font=FONT,
                                   state='disabled', wrap='word')
        self._report_log.grid(row=len(fields)+1, column=0, columnspan=2,
                               sticky='nsew', padx=12, pady=4)
        frame.rowconfigure(len(fields)+1, weight=1)
        return frame

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse(self):
        d = filedialog.askdirectory(title="Select target directory")
        if d:
            self._scan_dir.set(d)

    def _start_scan(self):
        target = self._scan_dir.get().strip()
        if not target or not os.path.isdir(target):
            messagebox.showerror("Error", "Please select a valid directory.")
            return
        self._progress.start(10)
        self._set_status("Scanning…")
        threading.Thread(target=self._run_scan, args=(target,), daemon=True).start()

    def _run_scan(self, target: str):
        try:
            # 1. Metadata
            self._metas = []
            self._set_status("Extracting metadata…")
            self._metas = md_mod.scan_directory(
                target, recursive=self._recursive.get(),
                progress_cb=lambda m: self._set_status(f"Metadata: {m.name}"))
            self._populate_metadata()

            # 2. Signatures
            self._sigs = []
            if self._run_sigs.get():
                self._set_status("Analyzing file signatures…")
                paths = [m.path for m in self._metas]
                self._sigs = sig_mod.analyze_all(
                    paths,
                    progress_cb=lambda p: self._set_status(f"Sig: {os.path.basename(p)}"))
                self._populate_sigs()

            # 3. Hashes
            self._hashes = []
            if self._run_hashes.get():
                self._set_status("Computing hashes…")
                paths = [m.path for m in self._metas]
                self._hashes = hash_mod.hash_all(
                    paths,
                    progress_cb=lambda p: self._set_status(f"Hash: {os.path.basename(p)}"))
                self._populate_hashes()

            # 4. Hidden data
            self._hidden = []
            if self._run_hidden.get():
                self._set_status("Detecting hidden data…")
                self._hidden = hid_mod.analyze_all(
                    self._metas,
                    progress_cb=lambda p: self._set_status(f"Hidden: {os.path.basename(p)}"))
                self._populate_hidden()

            # 5. Timeline
            self._rebuild_timeline()

            self._set_status(
                f"Done — {len(self._metas)} files | "
                f"{sum(1 for s in self._sigs if s.mismatch)} mismatches | "
                f"{sum(1 for h in self._hidden if h.is_suspicious)} suspicious")

        except Exception as exc:
            self._set_status(f"Error: {exc}")
            messagebox.showerror("Scan error", str(exc))
        finally:
            self.root.after(0, self._progress.stop)

    # ── Table population ──────────────────────────────────────────────────────

    def _populate_metadata(self):
        def _do():
            self._meta_table.clear()
            for m in self._metas:
                tag = 'warn' if (m.is_hidden or m.is_system) else ''
                self._meta_table.insert(
                    [m.path, m.name, m.size, m.created.strftime('%Y-%m-%d %H:%M:%S'),
                     m.modified.strftime('%Y-%m-%d %H:%M:%S'),
                     'Y' if m.is_hidden else '', 'Y' if m.is_system else '',
                     'Y' if m.is_readonly else '', m.owner, m.extension], tag)
        self.root.after(0, _do)

    def _populate_sigs(self):
        def _do():
            self._sig_table.clear()
            for s in self._sigs:
                tag = 'warn' if s.mismatch else ''
                self._sig_table.insert(
                    [s.path, s.declared_ext, ', '.join(s.detected_exts),
                     s.magic_hex, 'YES' if s.mismatch else '', s.note], tag)
        self.root.after(0, _do)

    def _populate_hashes(self):
        def _do():
            self._hash_table.clear()
            for h in self._hashes:
                self._hash_table.insert([h.path, h.md5, h.sha1, h.sha256, h.size])
        self.root.after(0, _do)

    def _populate_hidden(self):
        def _do():
            self._hidden_table.clear()
            for r in self._hidden:
                if not r.is_suspicious:
                    continue
                ads_str = '; '.join(f"{a.stream_name}({a.size}B)" for a in r.ads_streams)
                flg_str = '; '.join(r.suspicion_flags)
                self._hidden_table.insert([r.meta.path, ads_str or '—', flg_str or '—'], 'warn')
        self.root.after(0, _do)

    def _rebuild_timeline(self):
        if not self._metas:
            return
        self._events = tl_mod.build_timeline(
            self._metas, include_accessed=self._tl_incl_accessed.get())
        self._refresh_timeline()

    def _refresh_timeline(self):
        def _do():
            kind = self._tl_kind.get()
            events = self._events if kind == 'all' else tl_mod.filter_by_kind(self._events, kind)
            self._tl_table.clear()
            for e in events:
                tag = 'warn' if (e.is_hidden or e.is_system) else ''
                self._tl_table.insert(
                    [e.timestamp.strftime('%Y-%m-%d %H:%M:%S'), e.kind,
                     e.path, e.size, e.extension, 'Y' if e.is_hidden else ''], tag)
        self.root.after(0, _do)

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _report_kwargs(self):
        return dict(
            examiner=self._report_vars['examiner'].get(),
            case_name=self._report_vars['case'].get(),
            target_path=self._scan_dir.get(),
        )

    def _log_report(self, msg: str):
        def _do():
            self._report_log.config(state='normal')
            self._report_log.insert('end', msg + '\n')
            self._report_log.see('end')
            self._report_log.config(state='disabled')
        self.root.after(0, _do)

    def _export_csv(self):
        if not self._metas:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        out_dir = filedialog.askdirectory(title="Select output folder")
        if not out_dir:
            return
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        reporter.export_metadata_csv(self._metas,  f"{out_dir}/metadata_{ts}.csv")
        reporter.export_hashes_csv(self._hashes,   f"{out_dir}/hashes_{ts}.csv")
        reporter.export_signatures_csv(self._sigs, f"{out_dir}/signatures_{ts}.csv")
        reporter.export_timeline_csv(self._events, f"{out_dir}/timeline_{ts}.csv")
        self._log_report(f"CSV bundle exported to {out_dir}")

    def _export_html(self):
        if not self._metas:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.html', filetypes=[('HTML', '*.html')],
            initialfile='forensiscan_report.html')
        if not path:
            return
        reporter.export_html_report(
            path, self._metas, self._hashes, self._sigs,
            self._hidden, self._events, **self._report_kwargs())
        self._log_report(f"HTML report saved: {path}")

    def _export_pdf(self):
        if not self._metas:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        if not reporter.HAS_REPORTLAB:
            messagebox.showinfo("ReportLab missing",
                                "Install reportlab:\n  pip install reportlab")
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.pdf', filetypes=[('PDF', '*.pdf')],
            initialfile='forensiscan_report.pdf')
        if not path:
            return
        reporter.export_pdf_report(
            path, self._metas, self._hashes, self._sigs, **self._report_kwargs())
        self._log_report(f"PDF report saved: {path}")

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self._status_var.set(msg))

    def run(self):
        self.root.mainloop()
