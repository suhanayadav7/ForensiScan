"""ForensiScan — Tkinter GUI."""

import os
import sys
import platform
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core import metadata as md_mod
from core import signatures as sig_mod
from core import hasher as hash_mod
from core import hidden_data as hid_mod
from core import timeline as tl_mod
from core import reporter
from core import entropy as ent_mod

# Colour constants
BG = '#1a1a2e'
BG2 = '#16213e'
ACCENT = '#00d4ff'
WARN = '#ff6b6b'
OK = '#6bcb77'
FG = '#e0e0e0'
FONT = ('Consolas', 10)
FONT_B = ('Consolas', 10, 'bold')


def _apply_theme(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=BG, foreground=FG, font=FONT,
                    fieldbackground=BG2, bordercolor=ACCENT)
    style.configure('TNotebook',      background=BG, tabmargins=[4, 4, 0, 0])
    style.configure('TNotebook.Tab',  background=BG2, foreground=FG,
                    padding=[10, 4], font=FONT_B)
    style.map('TNotebook.Tab',
              background=[('selected', ACCENT)],
              foreground=[('selected', BG)])
    style.configure('Treeview',       background=BG2, foreground=FG,
                    fieldbackground=BG2, rowheight=20, font=FONT)
    style.configure('Treeview.Heading', background=BG, foreground=ACCENT, font=FONT_B)
    style.map('Treeview', background=[('selected', ACCENT)],
              foreground=[('selected', BG)])
    style.configure('TButton',     background=ACCENT, foreground=BG, font=FONT_B, padding=6)
    style.map('TButton',           background=[('active', '#00a8cc')])
    style.configure('TLabel',      background=BG, foreground=FG, font=FONT)
    style.configure('TFrame',      background=BG)
    style.configure('TEntry',      fieldbackground=BG2, foreground=FG, font=FONT)
    style.configure('TCheckbutton', background=BG, foreground=FG, font=FONT)
    style.configure('TProgressbar', troughcolor=BG2, background=ACCENT)
    style.configure('TScrollbar',  background=BG2, troughcolor=BG)


# TableView widget
# --------------------

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

        self.tree.tag_configure('warn',   foreground=WARN)
        self.tree.tag_configure('ok',     foreground=OK)
        self.tree.tag_configure('orange', foreground='#FFA500')

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def insert(self, values: list, tag: str = ''):
        self.tree.insert('', 'end', values=values, tags=(tag,) if tag else ())

    def row_count(self) -> int:
        return len(self.tree.get_children())

    def _sort(self, col: str, reverse: bool):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            data.sort(
                key=lambda x: float(x[0]) if x[0].replace('.', '', 1).lstrip('-').isdigit()
                else x[0].lower(),
                reverse=reverse)
        except Exception:
            data.sort(reverse=reverse)
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, '', idx)
        self.tree.heading(col, command=lambda: self._sort(col, not reverse))


# Main app class
# =================================

class ForensiScanApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ForensiScan — Windows File Analysis Tool")
        self.root.geometry("1280x800")
        self.root.configure(bg=BG)
        _apply_theme(self.root)

        self._metas: list[md_mod.FileMetadata] = []
        self._hashes: list[hash_mod.FileHashes] = []
        self._sigs: list[sig_mod.SignatureResult] = []
        self._hidden: list[hid_mod.HiddenDataResult] = []
        self._events: list[tl_mod.TimelineEvent] = []
        self._entropy: list[ent_mod.EntropyResult] = []
        self._anomalies: list[dict] = []
        self._duplicates: dict = {}
        self._hashset: set[str] = set()
        self._hashset_matches: set[str] = set()
        self._scan_start = None
        self._scan_end = None

        self._scan_dir = tk.StringVar()
        self._recursive = tk.BooleanVar(value=True)
        self._run_hashes = tk.BooleanVar(value=True)
        self._run_sigs = tk.BooleanVar(value=True)
        self._run_hidden = tk.BooleanVar(value=True)
        self._run_entropy = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self):
        hdr = ttk.Frame(self.root)
        hdr.pack(fill='x', padx=16, pady=(12, 4))
        tk.Label(hdr, text="ForensiScan", font=('Consolas', 18, 'bold'),
                 fg=ACCENT, bg=BG).pack(side='left')
        tk.Label(hdr, text=" | Windows Digital Forensics Tool",
                 font=('Consolas', 11), fg=FG, bg=BG).pack(side='left')

        # On non-Windows platforms st_ctime is inode change time, not creation time
        if platform.system() != 'Windows':
            tk.Label(
                self.root,
                text='Non-Windows: Created timestamps show inode-change time, not creation time.',
                fg=WARN, bg=BG, font=FONT
            ).pack(fill='x', padx=16)

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
        ttk.Checkbutton(ctrl, text="Entropy",    variable=self._run_entropy).pack(side='left')
        ttk.Button(ctrl, text="▶  Scan", command=self._start_scan).pack(side='left', padx=8)
        # Reset button allows examiner to start a new case without restarting
        ttk.Button(ctrl, text="Clear", command=self._reset).pack(side='left', padx=4)

        status_row = ttk.Frame(self.root)
        status_row.pack(fill='x', padx=16, pady=2)
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(status_row, textvariable=self._status_var).pack(side='left')
        self._progress = ttk.Progressbar(status_row, mode='indeterminate', length=200)
        self._progress.pack(side='right')

        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=16, pady=8)

        self._tab_metadata = self._make_metadata_tab(nb)
        self._tab_sigs     = self._make_sigs_tab(nb)
        self._tab_hashes   = self._make_hashes_tab(nb)
        self._tab_hidden   = self._make_hidden_tab(nb)
        self._tab_timeline = self._make_timeline_tab(nb)
        self._tab_entropy  = self._make_entropy_tab(nb)
        self._tab_report   = self._make_report_tab(nb)

        nb.add(self._tab_metadata, text=" Metadata ")
        nb.add(self._tab_sigs,     text=" Signatures ")
        nb.add(self._tab_hashes,   text=" Hashes ")
        nb.add(self._tab_hidden,   text=" Hidden Data ")
        nb.add(self._tab_timeline, text=" Timeline ")
        nb.add(self._tab_entropy,  text=" Entropy ")
        nb.add(self._tab_report,   text=" Report ")

    def _make_metadata_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        # Risk score column - colour coded by severity
        cols = [('Path', 300), ('Name', 150), ('Size', 80),
                ('Created', 140), ('Modified', 140), ('Hidden', 55),
                ('System', 55), ('ReadOnly', 65), ('Owner', 120), ('Ext', 55), ('Risk', 55)]
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
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Hash set loader sits above the results table
        btn_row = ttk.Frame(frame)
        btn_row.grid(row=0, column=0, sticky='ew', padx=4, pady=4)
        ttk.Button(
            btn_row, text='Load Hash Set (NSRL / known-bad)',
            command=self._load_hashset
        ).pack(side='left', padx=4)
        self._hashset_label = ttk.Label(btn_row, text='No hash set loaded')
        self._hashset_label.pack(side='left', padx=8)

        # Extra column shows whether file matched the loaded hash set
        cols = [('Path', 300), ('MD5', 240), ('SHA-1', 290),
                ('SHA-256', 430), ('Size', 80), ('In HashSet?', 80)]
        self._hash_table = TableView(frame, cols)
        self._hash_table.grid(row=1, column=0, sticky='nsew')
        return frame

    def _make_hidden_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # ADS enumeration uses the Windows API - warn when not on Windows
        if platform.system() != 'Windows':
            tk.Label(
                frame,
                text='WARNING: NTFS ADS detection requires Windows.'
                     ' ADS results are empty on this platform.',
                fg=WARN, bg=BG, font=FONT_B, anchor='w'
            ).grid(row=0, column=0, sticky='ew', padx=8, pady=4)

        cols = [('Path', 300), ('ADS Streams', 180), ('Suspicion Flags', 400)]
        self._hidden_table = TableView(frame, cols)
        self._hidden_table.grid(row=1, column=0, sticky='nsew')
        return frame

    def _make_timeline_tab(self, nb):
        frame = ttk.Frame(nb)
        frame.rowconfigure(2, weight=1)
        frame.rowconfigure(4, weight=1)
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

        # Date range filter - lets examiner narrow events to a specific incident window
        ttk.Separator(filt_row, orient='vertical').pack(side='left', padx=8, fill='y')
        ttk.Label(filt_row, text='From:').pack(side='left')
        self._tl_from = ttk.Entry(filt_row, width=12)
        self._tl_from.insert(0, 'YYYY-MM-DD')
        self._tl_from.pack(side='left', padx=2)
        ttk.Label(filt_row, text='To:').pack(side='left', padx=(6, 0))
        self._tl_to = ttk.Entry(filt_row, width=12)
        self._tl_to.insert(0, 'YYYY-MM-DD')
        self._tl_to.pack(side='left', padx=2)
        ttk.Button(filt_row, text='Apply Range',
                   command=self._apply_date_range).pack(side='left', padx=6)
        ttk.Button(filt_row, text='Clear Range',
                   command=self._refresh_timeline).pack(side='left')

        # Daily breakdown label - updated by group_by_day() after each refresh
        self._tl_summary = tk.Label(frame, text='', fg=ACCENT, bg=BG, font=FONT, anchor='w')
        self._tl_summary.grid(row=1, column=0, sticky='ew', padx=8, pady=(0, 2))

        cols = [('Timestamp', 155), ('Event', 75), ('Path', 400),
                ('Size', 80), ('Ext', 55), ('Hidden', 55)]
        self._tl_table = TableView(frame, cols)
        self._tl_table.grid(row=2, column=0, sticky='nsew')

        # Second table shows files with impossible timestamps (modified before created)
        tk.Label(
            frame,
            text='Timestamp Anomalies (Modified before Created — possible tampering)',
            fg=WARN, bg=BG, font=FONT_B, anchor='w'
        ).grid(row=3, column=0, sticky='ew', padx=8, pady=(8, 2))
        anomaly_cols = [('Path', 350), ('Created', 155), ('Modified', 155),
                        ('Delta', 100), ('Note', 280)]
        self._anomaly_table = TableView(frame, anomaly_cols)
        self._anomaly_table.grid(row=4, column=0, sticky='nsew')
        return frame

    def _make_entropy_tab(self, nb):
        # Entropy tab shows Shannon entropy score for each file
        frame = ttk.Frame(nb)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = [('Path', 300), ('Entropy Score', 90), ('High Entropy?', 70), ('Note', 250)]
        self._entropy_table = TableView(frame, cols)
        self._entropy_table.grid(row=0, column=0, sticky='nsew')
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
            ttk.Entry(frame, textvariable=var, width=40).grid(
                row=row, column=1, sticky='ew', padx=12, pady=6)

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
        # Note the start time so it appears in the audit log
        self._scan_start = datetime.datetime.now()
        try:
            # Metadata scan is always run first - other modules depend on the file list
            self._metas = []
            self._set_status("Extracting metadata…")
            self._metas = md_mod.scan_directory(
                target, recursive=self._recursive.get(),
                progress_cb=lambda m: self._set_status(f"Metadata: {m.name}"))
            self._populate_metadata()

            # Signature analysis compares magic bytes against declared extensions
            self._sigs = []
            if self._run_sigs.get():
                self._set_status("Analyzing file signatures…")
                paths = [m.path for m in self._metas]
                self._sigs = sig_mod.analyze_all(
                    paths,
                    progress_cb=lambda p: self._set_status(f"Sig: {os.path.basename(p)}"))
                self._populate_sigs()

            # Hashing runs independently - can be disabled to speed up large scans
            self._hashes = []
            self._duplicates = {}
            if self._run_hashes.get():
                self._set_status("Computing hashes…")
                paths = [m.path for m in self._metas]
                self._hashes = hash_mod.hash_all(
                    paths,
                    progress_cb=lambda p: self._set_status(f"Hash: {os.path.basename(p)}"))
                self._duplicates = hash_mod.find_duplicates(self._hashes)
                self._populate_hashes()

            # Hidden data detection checks ADS streams and attribute combinations
            self._hidden = []
            if self._run_hidden.get():
                self._set_status("Detecting hidden data…")
                self._hidden = hid_mod.analyze_all(
                    self._metas,
                    progress_cb=lambda p: self._set_status(f"Hidden: {os.path.basename(p)}"))
                self._populate_hidden()

            # Entropy is computed last since it reads all file bytes like hashing
            self._entropy = []
            if self._run_entropy.get():
                self._set_status("Computing entropy…")
                paths = [m.path for m in self._metas]
                self._entropy = ent_mod.analyze_all(
                    paths,
                    progress_cb=lambda p: self._set_status(f"Entropy: {os.path.basename(p)}"))
                self._populate_entropy()

            # Metadata table is refreshed here because risk scores need
            # both signature results and entropy scores to be ready first
            self._populate_metadata()

            # Build the timeline and check for impossible timestamp combinations
            self._rebuild_timeline()

            # If a hash set was loaded before the scan started, run matching now
            if self._hashset:
                self._run_hashset_match()

            dup_count = sum(len(v) for v in self._duplicates.values())
            self._set_status(
                f"Done — {len(self._metas)} files | "
                f"{sum(1 for s in self._sigs if s.mismatch)} mismatches | "
                f"{dup_count} duplicate files | "
                f"{sum(1 for h in self._hidden if h.is_suspicious)} suspicious | "
                f"{len(self._anomalies)} timestamp anomalies")

        except PermissionError as exc:
            self._set_status("Permission denied — some files could not be read")
            messagebox.showerror(
                "Permission Error",
                f"Access was denied to one or more files:\n{exc}\n\n"
                "Try running as administrator or choose a different directory.")
        except FileNotFoundError as exc:
            self._set_status("Target directory not found")
            messagebox.showerror(
                "Directory Not Found",
                f"The selected directory no longer exists:\n{exc}")
        except OSError as exc:
            self._set_status(f"File system error: {exc}")
            messagebox.showerror("File System Error", str(exc))
        except Exception as exc:
            self._set_status(f"Unexpected error: {type(exc).__name__}")
            messagebox.showerror(
                "Unexpected Error",
                f"{type(exc).__name__}: {exc}\n\nPlease report this issue.")
        finally:
            # Record end time for duration calculation in the audit log
            self._scan_end = datetime.datetime.now()
            self.root.after(0, self._progress.stop)

    def _populate_metadata(self):
        sig_map = {s.path: s for s in self._sigs}
        ent_map = {e.path: e for e in self._entropy}

        def _do():
            self._meta_table.clear()
            for m in self._metas:
                # Calculate risk score combining signature, entropy and attribute signals
                risk = hid_mod.compute_risk_score(
                    m,
                    sig_result=sig_map.get(m.path),
                    entropy_result=ent_map.get(m.path),
                )
                if risk >= 60:
                    tag = 'warn'
                elif risk >= 30:
                    tag = 'orange'
                elif m.is_hidden or m.is_system:
                    tag = 'warn'
                else:
                    tag = ''
                self._meta_table.insert(
                    [m.path, m.name, m.size,
                     m.created.strftime('%Y-%m-%d %H:%M:%S'),
                     m.modified.strftime('%Y-%m-%d %H:%M:%S'),
                     'Y' if m.is_hidden else '', 'Y' if m.is_system else '',
                     'Y' if m.is_readonly else '', m.owner, m.extension, risk], tag)
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
        dup_md5s = set(self._duplicates.keys())

        def _do():
            self._hash_table.clear()
            for h in self._hashes:
                matched = 'YES' if h.path in self._hashset_matches else ''
                is_dup = h.md5 in dup_md5s
                tag = 'warn' if matched else ('orange' if is_dup else '')
                self._hash_table.insert(
                    [h.path, h.md5, h.sha1, h.sha256, h.size, matched], tag)
        self.root.after(0, _do)

    def _populate_hidden(self):
        def _do():
            self._hidden_table.clear()
            suspicious_items = hid_mod.filter_suspicious(self._hidden)
            for r in suspicious_items:
                ads_str = '; '.join(f"{a.stream_name}({a.size}B)" for a in r.ads_streams)
                flg_str = '; '.join(r.suspicion_flags)
                self._hidden_table.insert([r.meta.path, ads_str or '—', flg_str or '—'], 'warn')
        self.root.after(0, _do)

    def _populate_entropy(self):
        # High entropy files (> 7.2) are highlighted red - likely encrypted or packed
        def _do():
            self._entropy_table.clear()
            for e in self._entropy:
                tag = 'warn' if e.is_high_entropy else ''
                self._entropy_table.insert(
                    [e.path, e.entropy, 'YES' if e.is_high_entropy else '', e.note], tag)
        self.root.after(0, _do)

    def _rebuild_timeline(self):
        if not self._metas:
            return
        self._events = tl_mod.build_timeline(
            self._metas, include_accessed=self._tl_incl_accessed.get())
        # Flag files where modified < created - indicates timestamp tampering
        self._anomalies = tl_mod.find_timestamp_anomalies(self._metas)
        self._refresh_timeline()
        self._populate_anomalies()

    def _refresh_timeline(self):
        def _do():
            kind = self._tl_kind.get()
            events = self._events if kind == 'all' else tl_mod.filter_by_kind(self._events, kind)

            day_groups = tl_mod.group_by_day(events)
            if day_groups:
                summary = ' | '.join(
                    f"{d}: {len(evts)} events"
                    for d, evts in sorted(day_groups.items())[:5]
                )
                self._tl_summary.config(text=f"Daily breakdown: {summary}")
            else:
                self._tl_summary.config(text='')

            self._tl_table.clear()
            for e in events:
                tag = 'warn' if (e.is_hidden or e.is_system) else ''
                self._tl_table.insert(
                    [e.timestamp.strftime('%Y-%m-%d %H:%M:%S'), e.kind,
                     e.path, e.size, e.extension, 'Y' if e.is_hidden else ''], tag)
        self.root.after(0, _do)

    def _populate_anomalies(self):
        # All anomaly rows are red since any timestamp reversal is suspicious
        def _do():
            self._anomaly_table.clear()
            for a in self._anomalies:
                self._anomaly_table.insert(
                    [a['path'], a['created'], a['modified'], a['delta'], a['note']], 'warn')
        self.root.after(0, _do)

    def _apply_date_range(self):
        try:
            start = datetime.datetime.strptime(self._tl_from.get().strip(), '%Y-%m-%d')
            end = datetime.datetime.strptime(self._tl_to.get().strip(), '%Y-%m-%d')
            end = end.replace(hour=23, minute=59, second=59)
        except ValueError:
            messagebox.showerror(
                'Date Error', 'Enter dates in YYYY-MM-DD format, e.g. 2024-01-15')
            return
        filtered = tl_mod.filter_by_range(self._events, start, end)
        self._tl_table.clear()
        for e in filtered:
            tag = 'warn' if (e.is_hidden or e.is_system) else ''
            self._tl_table.insert(
                [e.timestamp.strftime('%Y-%m-%d %H:%M:%S'), e.kind,
                 e.path, e.size, e.extension, 'Y' if e.is_hidden else ''], tag)
        self._set_status(
            f"Timeline filtered: {len(filtered)} events "
            f"between {start.date()} and {end.date()}")

    def _report_kwargs(self):
        return dict(
            examiner=self._report_vars['examiner'].get(),
            case_name=self._report_vars['case'].get(),
            target_path=self._scan_dir.get(),
            scan_start=self._scan_start,
            scan_end=self._scan_end,
        )

    def _log_report(self, msg: str):
        def _do():
            self._report_log.config(state='normal')
            self._report_log.insert('end', msg + '\n')
            self._report_log.see('end')
            self._report_log.config(state='disabled')
        self.root.after(0, _do)

    def _validate_report_fields(self) -> bool:
        # Both fields are required - empty values produce invalid forensic reports
        examiner = self._report_vars["examiner"].get().strip()
        case = self._report_vars["case"].get().strip()
        if not examiner or not case:
            messagebox.showerror("Validation", "Examiner name and case name are required.")
            return False
        if len(examiner) > 100 or len(case) > 100:
            messagebox.showerror(
                "Validation", "Examiner and case name must each be under 100 characters.")
            return False
        return True

    def _export_csv(self):
        if not self._validate_report_fields():
            return
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
        if self._entropy:
            reporter.export_entropy_csv(self._entropy, f"{out_dir}/entropy_{ts}.csv")
        self._log_report(f"CSV bundle exported to {out_dir}")

    def _export_html(self):
        if not self._validate_report_fields():
            return
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
        if not self._validate_report_fields():
            return
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
            path, self._metas, self._hashes, self._sigs,
            self._hidden, self._events, **self._report_kwargs())
        self._log_report(f"PDF report saved: {path}")

    # Hash set operations
    def _load_hashset(self):
        path = filedialog.askopenfilename(
            title='Select hash set file (one hash per line — MD5 or SHA-256)',
            filetypes=[('Text files', '*.txt'), ('All files', '*.*')])
        if not path:
            return
        self._hashset = hash_mod.load_hashset(path)
        self._hashset_label.config(
            text=f'Loaded {len(self._hashset):,} hashes from {os.path.basename(path)}')
        if self._hashes:
            self._run_hashset_match()

    def _run_hashset_match(self):
        if not self._hashset:
            return
        matches = hash_mod.match_against_hashset(self._hashes, self._hashset)
        self._hashset_matches = {m.path for m in matches}
        self._populate_hashes()
        messagebox.showinfo(
            'Hash Set Results',
            f'{len(matches)} file(s) matched the loaded hash set.\n'
            'Matched files are highlighted red in the Hashes tab.')

    # Case reset
    def _reset(self):
        if not messagebox.askyesno('Clear', 'Clear all data for a new case?'):
            return
        self._metas = []
        self._hashes = []
        self._sigs = []
        self._hidden = []
        self._events = []
        self._entropy = []
        self._anomalies = []
        self._duplicates = {}
        self._hashset_matches = set()
        for tbl in [self._meta_table, self._sig_table, self._hash_table,
                    self._hidden_table, self._tl_table, self._anomaly_table,
                    self._entropy_table]:
            tbl.clear()
        self._tl_summary.config(text='')
        self._scan_dir.set('')
        self._hashset_label.config(text='No hash set loaded')
        self._set_status('Cleared. Ready for new case.')

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self._status_var.set(msg))

    def run(self):
        self.root.mainloop()
