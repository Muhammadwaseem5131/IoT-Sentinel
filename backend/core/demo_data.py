"""Seeds a realistic sample scan so the app can be demonstrated with no network
access, no privileges, and no hardware. Triggered by scanning the subnet 'demo'.

All data here is fictional and local; nothing is scanned or transmitted.
"""
from correlation import risk_score
from db import models

# (ip, mac, vendor, hostname, type, internet_facing, [ports], [findings])
# ports: (port, service, banner)
# findings: (type, severity, description, cve_id)
_DEVICES = [
    {
        "ip": "192.168.1.1", "mac": "f0:9f:c2:11:22:33", "vendor": "TP-Link",
        "hostname": "router.local", "type": "router", "internet_facing": True,
        "ports": [(80, "http", "TP-Link Archer C7"), (443, "https", "TP-Link Archer C7"),
                  (53, "domain", None)],
        "findings": [
            ("default_cred", "critical",
             "Default credentials accepted over HTTP (username 'admin'). Change this password immediately.", None),
            ("cve", "high", "Command injection in TP-Link router web interface allows authenticated "
             "remote code execution via crafted request.", "CVE-2020-10882"),
        ],
        "cvss": 8.8,
    },
    {
        "ip": "192.168.1.24", "mac": "38:ed:18:aa:bb:cc", "vendor": "Hikvision",
        "hostname": "ipcam-front", "type": "camera", "internet_facing": True,
        "ports": [(80, "http", "Hikvision DS-2CD"), (554, "rtsp", "Hikvision RTSP")],
        "findings": [
            ("cve", "critical", "Improper authentication in Hikvision IP cameras allows an attacker to "
             "gain full admin access via a crafted message to the web server.", "CVE-2021-36260"),
            ("default_cred", "critical",
             "Default credentials accepted over HTTP (username 'admin'). Change this password immediately.", None),
        ],
        "cvss": 9.8,
    },
    {
        "ip": "192.168.1.30", "mac": "b8:27:eb:44:55:66", "vendor": "Raspberry Pi",
        "hostname": "raspberrypi", "type": "raspberry_pi", "internet_facing": False,
        "ports": [(22, "ssh", "OpenSSH 7.9p1"), (1883, "mqtt", "Mosquitto 1.5.7")],
        "findings": [
            ("cve", "medium", "OpenSSH 7.9 user enumeration via timing side-channel on authentication.",
             "CVE-2018-15473"),
        ],
        "cvss": 5.3,
    },
    {
        "ip": "192.168.1.42", "mac": "ac:63:be:77:88:99", "vendor": "Amazon",
        "hostname": "echo-kitchen", "type": "speaker", "internet_facing": False,
        "ports": [(443, "https", None), (4070, "spotify-connect", None)],
        "findings": [("info", "low", "No known vulnerabilities matched for this device.", None)],
        "cvss": None,
    },
    {
        "ip": "192.168.1.55", "mac": "00:11:32:ab:cd:ef", "vendor": "Apple",
        "hostname": "office-printer", "type": "printer", "internet_facing": False,
        "ports": [(631, "ipp", "CUPS 2.2"), (9100, "jetdirect", None)],
        "findings": [
            ("default_cred_candidate", "medium",
             "This device's vendor/type ships with known default credentials. Verify or change the password.", None),
        ],
        "cvss": None,
    },
]

_WIRELESS = [
    {"ssid": "HomeNet", "bssid": "F0:9F:C2:11:22:33", "encryption": "WPA2 CCMP PSK",
     "finding_type": "info", "details": "Channel 6, signal -42"},
    {"ssid": "OldRouter", "bssid": "AA:BB:CC:DD:EE:00", "encryption": "WEP",
     "finding_type": "weak_encryption", "details": "Channel 1, signal -61 — WEP is trivially crackable"},
    {"ssid": "HomeNet", "bssid": "F0:9F:C2:11:22:33", "encryption": "WPA2 CCMP PSK",
     "finding_type": "wps_enabled", "details": "WPS enabled and unlocked — vulnerable to PIN brute-force"},
]


def seed_demo_scan() -> int:
    scan_id = models.create_scan("demo (sample data)", scan_type="demo")
    weak = any(w["finding_type"] == "weak_encryption" for w in _WIRELESS)

    for d in _DEVICES:
        device_id = models.insert_device(
            scan_id, d["ip"], mac=d["mac"], vendor=d["vendor"], hostname=d["hostname"],
            device_type=d["type"], internet_facing=d["internet_facing"],
        )
        for port, service, banner in d["ports"]:
            models.insert_port(device_id, port, service=service, banner=banner)
        for ftype, severity, desc, cve_id in d["findings"]:
            models.insert_finding(device_id, ftype, severity, desc, cve_id=cve_id)

        default_cred = any(f[0] == "default_cred" for f in d["findings"])
        score = risk_score.compute_risk_score(
            internet_facing=d["internet_facing"], max_cve_score=d["cvss"],
            default_cred_found=default_cred, weak_encryption=weak,
        )
        models.insert_risk_score(device_id, score)

    for w in _WIRELESS:
        models.insert_wireless_finding(
            scan_id, ssid=w["ssid"], bssid=w["bssid"], encryption=w["encryption"],
            finding_type=w["finding_type"], details=w["details"],
        )

    models.finish_scan(scan_id)
    return scan_id
