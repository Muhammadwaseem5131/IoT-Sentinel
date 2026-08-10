SYSTEM_PROMPT = """You are a cybersecurity analyst producing a plain-language risk report for a
non-technical audience (a small business owner, NGO IT admin, or home user).

Rules:
- Explain findings in plain English. Avoid unexplained jargon.
- Prioritize risks: critical/high first, then medium, then low.
- For each device with findings, give: device, what the risk is, how likely it is to be
  exploited, and a concrete step the owner can take to fix or reduce it.
- If a device has no findings, say so briefly and move on.
- Never invent CVEs, scores, or devices that are not in the data provided.
- Do not include raw MAC addresses or full internal IPs in the report; refer to devices
  by vendor/hostname/device type and a safe short identifier.
- Do not use em dashes or en dashes; use a period, comma, or colon instead.

Return the report as Markdown with clear headings.
"""

DEVICE_SYSTEM_PROMPT = """You are a friendly cybersecurity analyst explaining ONE device's security to
its non-technical owner (home user, small NGO/school admin).

For this single device:
- Start with one sentence on what the device appears to be and how worried they should be.
- Then, for EACH vulnerability/finding provided, use a short heading and explain:
  1. What it is, in plain English (no unexplained jargon).
  2. Why it matters: what an attacker could actually do.
  3. How to fix it: a concrete, numbered step the owner can follow.
- If there are no real findings, reassure them briefly and give one general hardening tip.
- Never invent CVEs, findings, or facts not present in the data.
- Do not print raw MAC addresses or full internal IP addresses.
- Do not use em dashes or en dashes; use a period, comma, or colon instead.

Keep it concise and practical. Return Markdown with clear headings.
"""


WIRELESS_SYSTEM_PROMPT = """You are a friendly cybersecurity analyst explaining ONE WiFi finding to a
non-technical person (home user, small NGO/school admin).

Explain, in plain English:
1. What this finding means (what was observed on their WiFi).
2. Why it matters: what an attacker nearby could actually do.
3. How to fix it: concrete, numbered steps in a typical home/office router.
Keep it short and practical. Never invent details not in the data. Do not print MAC/BSSID
addresses. Do not use em dashes or en dashes; use a period, comma, or colon instead.
Return Markdown with clear headings.
"""


def build_wireless_payload(finding: dict) -> dict:
    """De-identifies a wireless finding (drops the BSSID MAC) for the AI."""
    return {
        "ssid": finding.get("ssid"),
        "encryption": finding.get("encryption"),
        "finding_type": finding.get("finding_type"),
        "details": finding.get("details"),
    }


def build_device_payload(device: dict) -> dict:
    """De-identifies a single device for a per-device AI explanation."""
    findings = []
    for f in device.get("findings", []):
        if f.get("finding_type") == "info" and not f.get("cve_id"):
            continue
        findings.append({
            "type": f.get("finding_type"),
            "cve_id": f.get("cve_id"),
            "severity": f.get("severity"),
            "description": (f.get("description") or "")[:400],
        })
    return {
        "device_type": device.get("device_type") or "unknown device",
        "vendor": device.get("vendor"),
        "hostname": device.get("hostname"),
        "internet_facing": bool(device.get("internet_facing")),
        "risk_score": device.get("risk_score"),
        "open_services": [
            {"port": p.get("port"), "service": p.get("service"), "banner": p.get("banner")}
            for p in device.get("open_ports", [])
        ],
        "findings": findings,
    }


def build_report_payload(scan_report: dict) -> dict:
    """De-identify scan data before it goes to any LLM provider:
    strip raw MACs and full internal IPs, keep only what's needed for analysis."""
    devices = []
    for i, dev in enumerate(scan_report.get("devices", []), start=1):
        findings = []
        for f in dev.get("findings", []):
            if f.get("finding_type") in ("info",) and not f.get("cve_id"):
                continue
            findings.append({
                "type": f.get("finding_type"),
                "cve_id": f.get("cve_id"),
                "severity": f.get("severity"),
                "description": f.get("description", "")[:300],
            })
        devices.append({
            "id": f"device-{i}",
            "vendor": dev.get("vendor"),
            "hostname": dev.get("hostname"),
            "device_type": dev.get("device_type"),
            "risk_score": dev.get("risk_score"),
            "open_services": [
                {"port": p.get("port"), "service": p.get("service"), "banner": p.get("banner")}
                for p in dev.get("open_ports", [])
            ],
            "findings": findings,
        })
    return {
        "scan_subnet": _summarize_subnet(scan_report.get("subnet")),
        "scan_type": scan_report.get("scan_type"),
        "device_count": len(devices),
        "devices": devices,
        "wireless_findings": [
            {
                "ssid": w.get("ssid"),
                "encryption": w.get("encryption"),
                "finding_type": w.get("finding_type"),
                "details": w.get("details"),
            }
            for w in scan_report.get("wireless_findings", [])
        ],
    }


def _summarize_subnet(subnet: str | None) -> str:
    if not subnet:
        return "unknown"
    return subnet.rsplit("/", 1)[0] + "/24"
