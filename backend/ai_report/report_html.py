"""Renders a scan into a standalone, printable HTML report (print-to-PDF ready).

Structured findings always render offline. An AI narrative is included only if
one is passed in, so export never depends on a provider being configured.
"""
from html import escape

_RISK_COLORS = {"critical": "#d64545", "high": "#e08a2b", "medium": "#d4b106", "low": "#3aa76d"}


def _band(score) -> str:
    if score is None:
        return "low"
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _md_to_html(text: str) -> str:
    """Minimal markdown → HTML for the AI narrative (headings, bold, lists)."""
    import re
    out = []
    in_list = False
    for raw in text.splitlines():
        line = escape(raw.rstrip())
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            if in_list:
                out.append("</ul>"); in_list = False
            level = len(m.group(1))
            out.append(f"<h{level+1}>{m.group(2)}</h{level+1}>")
        elif re.match(r"^[-*]\s+", line):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{re.sub(r'^[-*]\\s+', '', line)}</li>")
        elif line.strip():
            if in_list:
                out.append("</ul>"); in_list = False
            out.append(f"<p>{line}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def render(scan_report: dict, ai_narrative: str | None = None) -> str:
    devices = scan_report.get("devices", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in devices:
        counts[_band(d.get("risk_score"))] += 1

    cards = "".join(
        f'<div class="stat"><span class="dot" style="background:{_RISK_COLORS[k]}"></span>'
        f'<b>{counts[k]}</b> {k}</div>'
        for k in ("critical", "high", "medium", "low")
    )

    rows = []
    for d in devices:
        band = _band(d.get("risk_score"))
        ports = ", ".join(f'{p["port"]}/{p.get("service") or "tcp"}' for p in d.get("open_ports", [])) or "—"
        findings = "".join(
            f'<li><span class="sev {escape(f.get("severity") or "low")}">{escape(f.get("severity") or "low")}</span> '
            f'{escape((f.get("cve_id") + ": ") if f.get("cve_id") else "")}{escape(f.get("description") or "")}</li>'
            for f in d.get("findings", []) if f.get("finding_type") != "info"
        ) or "<li>No known vulnerabilities matched.</li>"
        exposed = ' <span class="tag">internet-facing</span>' if d.get("internet_facing") else ""
        rows.append(
            f'<tr><td><b>{escape(d.get("ip_address") or "")}</b>{exposed}<br>'
            f'<span class="muted">{escape(d.get("vendor") or "unknown")} · {escape(d.get("device_type") or "unknown")}</span></td>'
            f'<td><span class="score" style="background:{_RISK_COLORS[band]}">{d.get("risk_score") if d.get("risk_score") is not None else "—"}</span></td>'
            f'<td class="muted">{escape(ports)}</td>'
            f'<td><ul class="findings">{findings}</ul></td></tr>'
        )

    wireless = ""
    if scan_report.get("wireless_findings"):
        wrows = "".join(
            f'<tr><td>{escape(w.get("ssid") or "—")}</td><td class="muted">{escape(w.get("bssid") or "—")}</td>'
            f'<td>{escape(w.get("encryption") or "—")}</td><td>{escape(w.get("finding_type") or "")}</td>'
            f'<td class="muted">{escape(w.get("details") or "")}</td></tr>'
            for w in scan_report["wireless_findings"]
        )
        wireless = (
            "<h2>Wireless findings</h2><table><thead><tr><th>SSID</th><th>BSSID</th>"
            "<th>Encryption</th><th>Finding</th><th>Details</th></tr></thead>"
            f"<tbody>{wrows}</tbody></table>"
        )

    narrative = f'<section class="narrative">{_md_to_html(ai_narrative)}</section>' if ai_narrative else ""

    return _TEMPLATE.format(
        subnet=escape(str(scan_report.get("subnet") or "")),
        started=escape(str(scan_report.get("started_at") or "")),
        device_count=len(devices),
        cards=cards,
        narrative=narrative,
        rows="".join(rows) or '<tr><td colspan="4">No devices discovered.</td></tr>',
        wireless=wireless,
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>IoT-Sentinel Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a1f2b;max-width:940px;margin:32px auto;padding:0 20px;line-height:1.5}}
 h1{{margin:0}} h2{{margin-top:32px;border-bottom:2px solid #eee;padding-bottom:6px}}
 .muted{{color:#6b7280;font-size:13px}} .head{{display:flex;justify-content:space-between;align-items:baseline;border-bottom:3px solid #2f6fed;padding-bottom:12px}}
 .stats{{display:flex;gap:20px;margin:20px 0}} .stat{{font-size:14px}} .dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}}
 table{{width:100%;border-collapse:collapse;margin-top:12px}} th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #eef0f4;vertical-align:top}}
 th{{font-size:12px;text-transform:uppercase;color:#6b7280;letter-spacing:.04em}}
 .score{{color:#fff;font-weight:700;padding:2px 10px;border-radius:20px;font-size:13px}}
 .tag{{background:#fde2e2;color:#b91c1c;font-size:11px;padding:1px 7px;border-radius:10px}}
 ul.findings{{margin:0;padding-left:16px}} ul.findings li{{margin:3px 0;font-size:13px}}
 .sev{{font-size:11px;text-transform:uppercase;font-weight:700;padding:0 5px;border-radius:3px;color:#fff}}
 .sev.critical{{background:#d64545}} .sev.high{{background:#e08a2b}} .sev.medium{{background:#d4b106}} .sev.low{{background:#3aa76d}}
 .narrative{{background:#f7f9fc;padding:16px 22px;border-radius:8px;margin-top:20px}}
 @media print{{body{{margin:0}} .narrative{{background:#fff}}}}
</style></head><body>
<div class="head"><h1>IoT-Sentinel Risk Report</h1><div class="muted">{subnet} · {started}</div></div>
<div class="stats">{cards}<div class="stat muted">{device_count} devices</div></div>
{narrative}
<h2>Devices</h2>
<table><thead><tr><th>Device</th><th>Risk</th><th>Open ports</th><th>Findings</th></tr></thead><tbody>{rows}</tbody></table>
{wireless}
<p class="muted" style="margin-top:32px">Generated by IoT-Sentinel. For networks you own or are authorized to test.</p>
</body></html>"""
