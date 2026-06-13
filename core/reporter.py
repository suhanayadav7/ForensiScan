"""Report generation — CSV, HTML, and optional PDF (ReportLab) output."""

import csv
import datetime
import os
from pathlib import Path
from typing import Optional

from .metadata import FileMetadata
from .hasher import FileHashes
from .signatures import SignatureResult
from .hidden_data import HiddenDataResult
from .timeline import TimelineEvent

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                     Paragraph, Spacer)
    from reportlab.lib.styles import getSampleStyleSheet
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


# ── CSV ───────────────────────────────────────────────────────────────────────

def export_metadata_csv(metas: list[FileMetadata], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'Name', 'Size', 'Created', 'Modified',
                    'Accessed', 'Hidden', 'System', 'ReadOnly', 'Owner', 'Extension'])
        for m in metas:
            w.writerow([m.path, m.name, m.size,
                        m.created, m.modified, m.accessed,
                        m.is_hidden, m.is_system, m.is_readonly,
                        m.owner, m.extension])
    return out_path


def export_hashes_csv(hashes: list[FileHashes], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'MD5', 'SHA1', 'SHA256', 'Size'])
        for h in hashes:
            w.writerow([h.path, h.md5, h.sha1, h.sha256, h.size])
    return out_path


def export_signatures_csv(sigs: list[SignatureResult], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Path', 'DeclaredExt', 'DetectedExts', 'MagicHex', 'Mismatch', 'Note'])
        for s in sigs:
            w.writerow([s.path, s.declared_ext, '|'.join(s.detected_exts),
                        s.magic_hex, s.mismatch, s.note])
    return out_path


def export_timeline_csv(events: list[TimelineEvent], out_path: str) -> str:
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Timestamp', 'EventKind', 'Path', 'Size', 'Extension', 'Hidden', 'System'])
        for e in events:
            w.writerow([e.timestamp, e.kind, e.path, e.size, e.extension,
                        e.is_hidden, e.is_system])
    return out_path


# ── HTML ──────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ForensiScan Report — {title}</title>
<style>
  body {{ font-family: Consolas, monospace; font-size: 13px; background: #1a1a2e; color: #e0e0e0; margin: 40px; }}
  h1   {{ color: #00d4ff; border-bottom: 1px solid #00d4ff; padding-bottom: 8px; }}
  h2   {{ color: #7ec8e3; margin-top: 32px; }}
  .meta {{ color: #888; font-size: 11px; margin-bottom: 24px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
  th    {{ background: #0f3460; color: #00d4ff; padding: 8px 12px; text-align: left; }}
  td    {{ padding: 6px 12px; border-bottom: 1px solid #333; }}
  tr:nth-child(even) {{ background: #16213e; }}
  .warn  {{ color: #ff6b6b; font-weight: bold; }}
  .ok    {{ color: #6bcb77; }}
  .badge {{ background: #ff6b6b; color: white; border-radius: 4px;
            padding: 1px 6px; font-size: 10px; margin-left: 6px; }}
</style>
</head>
<body>
<h1>ForensiScan Forensic Report</h1>
<div class="meta">
  Generated: {generated}<br>
  Examiner:  {examiner}<br>
  Case:      {case}<br>
  Target:    {target}
</div>
{body}
</body>
</html>
"""

_TABLE_TMPL = "<h2>{heading}</h2><table><tr>{headers}</tr>{rows}</table>"


def _th(cols: list[str]) -> str:
    return ''.join(f'<th>{c}</th>' for c in cols)


def _tr(cells: list[str]) -> str:
    return '<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>'


def _fmt(val) -> str:
    if val is True:
        return '<span class="warn">YES</span>'
    if val is False:
        return '<span class="ok">no</span>'
    return str(val) if val is not None else ''


def export_html_report(
    out_path: str,
    metas: list[FileMetadata],
    hashes: list[FileHashes],
    sigs: list[SignatureResult],
    hidden: list[HiddenDataResult],
    events: list[TimelineEvent],
    examiner: str = "Unknown",
    case_name: str = "Untitled",
    target_path: str = "",
) -> str:
    sections: list[str] = []

    # Summary
    mismatches  = [s for s in sigs if s.mismatch]
    suspicious  = [h for h in hidden if h.is_suspicious]
    total_files = len(metas)
    sections.append(
        f"<h2>Summary</h2>"
        f"<p>Total files scanned: <strong>{total_files}</strong><br>"
        f"Signature mismatches: <strong class=\"warn\">{len(mismatches)}</strong><br>"
        f"Suspicious items (ADS / flags): <strong class=\"warn\">{len(suspicious)}</strong><br>"
        f"Timeline events: <strong>{len(events)}</strong></p>"
    )

    # Metadata table (first 500 rows to keep HTML manageable)
    rows = ''.join(_tr([_fmt(m.path), _fmt(m.size), _fmt(m.created),
                        _fmt(m.modified), _fmt(m.is_hidden), _fmt(m.is_system),
                        _fmt(m.owner)])
                   for m in metas[:500])
    sections.append(_TABLE_TMPL.format(
        heading=f"File Metadata ({min(len(metas), 500)} of {len(metas)} files)",
        headers=_th(['Path', 'Size', 'Created', 'Modified', 'Hidden', 'System', 'Owner']),
        rows=rows,
    ))

    # Signature mismatches
    if mismatches:
        rows = ''.join(_tr([_fmt(s.path), _fmt(s.declared_ext),
                            _fmt(', '.join(s.detected_exts)), _fmt(s.note)])
                       for s in mismatches)
        sections.append(_TABLE_TMPL.format(
            heading=f"Signature Mismatches ({len(mismatches)})",
            headers=_th(['Path', 'Declared', 'Detected', 'Note']),
            rows=rows,
        ))

    # Hashes (first 200)
    rows = ''.join(_tr([_fmt(h.path), _fmt(h.md5), _fmt(h.sha256)])
                   for h in hashes[:200])
    sections.append(_TABLE_TMPL.format(
        heading=f"Cryptographic Hashes ({min(len(hashes), 200)} of {len(hashes)})",
        headers=_th(['Path', 'MD5', 'SHA-256']),
        rows=rows,
    ))

    # Suspicious items
    if suspicious:
        rows_html = []
        for r in suspicious:
            flags = '; '.join(r.suspicion_flags)
            ads   = '; '.join(f"{a.stream_name} ({a.size}B)" for a in r.ads_streams)
            rows_html.append(_tr([_fmt(r.meta.path), _fmt(flags or '—'), _fmt(ads or '—')]))
        sections.append(_TABLE_TMPL.format(
            heading=f"Suspicious Items ({len(suspicious)})",
            headers=_th(['Path', 'Flags', 'ADS Streams']),
            rows=''.join(rows_html),
        ))

    # Timeline (first 1000)
    rows = ''.join(_tr([_fmt(e.timestamp), _fmt(e.kind), _fmt(e.path)])
                   for e in events[:1000])
    sections.append(_TABLE_TMPL.format(
        heading=f"Timeline ({min(len(events), 1000)} of {len(events)} events)",
        headers=_th(['Timestamp', 'Event', 'Path']),
        rows=rows,
    ))

    html = _HTML_TEMPLATE.format(
        title=case_name,
        generated=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        examiner=examiner,
        case=case_name,
        target=target_path,
        body='\n'.join(sections),
    )

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return out_path


# ── PDF (ReportLab optional) ──────────────────────────────────────────────────

def export_pdf_report(
    out_path: str,
    metas: list[FileMetadata],
    hashes: list[FileHashes],
    sigs: list[SignatureResult],
    examiner: str = "Unknown",
    case_name: str = "Untitled",
    target_path: str = "",
) -> str:
    if not HAS_REPORTLAB:
        raise RuntimeError("ReportLab is not installed. Run: pip install reportlab")

    styles = getSampleStyleSheet()
    doc    = SimpleDocTemplate(out_path, pagesize=A4)
    story  = []

    story.append(Paragraph("ForensiScan — Forensic Report", styles['Title']))
    story.append(Spacer(1, 12))
    meta_text = (f"Case: {case_name} | Examiner: {examiner} | "
                 f"Target: {target_path} | "
                 f"Generated: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    story.append(Paragraph(meta_text, styles['Normal']))
    story.append(Spacer(1, 20))

    # Summary table
    mismatches = [s for s in sigs if s.mismatch]
    story.append(Paragraph("Summary", styles['Heading2']))
    summary_data = [
        ['Metric', 'Value'],
        ['Total files scanned', str(len(metas))],
        ['Signature mismatches', str(len(mismatches))],
        ['Hash records', str(len(hashes))],
    ]
    t = Table(summary_data, colWidths=[200, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.lightgrey, colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Mismatch table
    if mismatches:
        story.append(Paragraph(f"Signature Mismatches ({len(mismatches)})", styles['Heading2']))
        data = [['Path', 'Declared', 'Detected', 'Note']]
        for s in mismatches[:100]:
            data.append([
                Paragraph(s.path[-60:], styles['Normal']),
                s.declared_ext,
                ', '.join(s.detected_exts),
                Paragraph(s.note, styles['Normal']),
            ])
        t = Table(data, colWidths=[200, 60, 80, 160])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
        ]))
        story.append(t)

    doc.build(story)
    return out_path
