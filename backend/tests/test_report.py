from ai_report import prompts, report_html

SCAN = {
    "subnet": "192.168.1.0/24",
    "scan_type": "core",
    "started_at": "2024-01-01T10:00:00",
    "devices": [
        {
            "ip_address": "192.168.1.24", "mac_address": "38:ed:18:aa:bb:cc",
            "vendor": "Hikvision", "hostname": "ipcam", "device_type": "camera",
            "internet_facing": 1, "risk_score": 99,
            "open_ports": [{"port": 80, "service": "http", "banner": "Hikvision"}],
            "findings": [
                {"finding_type": "cve", "cve_id": "CVE-2021-36260", "severity": "critical",
                 "description": "Auth bypass"},
                {"finding_type": "info", "cve_id": None, "severity": "low", "description": "noise"},
            ],
        }
    ],
    "wireless_findings": [
        {"ssid": "HomeNet", "bssid": "F0:9F:C2:11:22:33", "encryption": "WPA2",
         "finding_type": "info", "details": "ch6"},
    ],
}


def test_deidentification_strips_mac_and_full_ip():
    payload = prompts.build_report_payload(SCAN)
    blob = str(payload)
    assert "38:ed:18:aa:bb:cc" not in blob      # raw MAC gone
    assert "192.168.1.24" not in blob            # full internal IP gone
    assert payload["devices"][0]["id"] == "device-1"
    assert payload["devices"][0]["vendor"] == "Hikvision"


def test_deidentification_drops_info_noise():
    payload = prompts.build_report_payload(SCAN)
    types = [f["type"] for f in payload["devices"][0]["findings"]]
    assert "cve" in types
    assert "info" not in types  # low-value info findings not sent to the LLM


def test_html_report_renders_key_facts():
    html = report_html.render(SCAN, ai_narrative="## Summary\n- fix **camera**")
    assert "192.168.1.24" in html
    assert "99" in html
    assert "CVE-2021-36260" in html
    assert "internet-facing" in html
    assert "<strong>camera</strong>" in html  # markdown bold converted
    assert "HomeNet" in html                    # wireless section present


def test_html_report_works_without_ai():
    html = report_html.render(SCAN, ai_narrative=None)
    assert "<html" in html.lower()
    assert "192.168.1.24" in html
