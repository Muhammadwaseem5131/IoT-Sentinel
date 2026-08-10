from wireless import wifi_scan

# A representative airodump-ng CSV: AP section, blank line, then Station section.
SAMPLE_CSV = """
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
F0:9F:C2:11:22:33, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 6, 130, WPA2, CCMP, PSK, -42, 100, 0, 0.0.0.0, 7, HomeNet,
AA:BB:CC:DD:EE:00, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 1, 54, WEP, WEP, , -61, 50, 12, 0.0.0.0, 9, OldRouter,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:05:00, -50, 20, F0:9F:C2:11:22:33,
"""


def test_parses_only_ap_section():
    aps = wifi_scan._parse_airodump_csv(SAMPLE_CSV)
    assert len(aps) == 2  # station row must not be parsed as an AP
    bssids = {a["bssid"] for a in aps}
    assert "11:22:33:44:55:66" not in bssids


def test_fields_extracted():
    aps = {a["ssid"]: a for a in wifi_scan._parse_airodump_csv(SAMPLE_CSV)}
    assert aps["HomeNet"]["channel"] == "6"
    assert aps["HomeNet"]["signal"] == "-42"
    assert "WPA2" in aps["HomeNet"]["encryption"]
    assert "WEP" in aps["OldRouter"]["encryption"]


def test_empty_input():
    assert wifi_scan._parse_airodump_csv("") == []


def test_classify_encryption():
    assert wifi_scan._classify_encryption("WEP")[0] == "weak_encryption"
    assert wifi_scan._classify_encryption("")[0] == "weak_encryption"
    assert wifi_scan._classify_encryption("OPEN")[0] == "weak_encryption"
    assert wifi_scan._classify_encryption("WPA CCMP PSK")[0] == "weak_encryption"  # WPA1, no "2"/"3"
    assert wifi_scan._classify_encryption("WPA2 CCMP PSK") == ("info", None)
    assert wifi_scan._classify_encryption("WPA3 SAE") == ("info", None)


def test_classify_encryption_catches_tkip_under_wpa2():
    # The precision gap: "WPA2" alone looks safe, but TKIP is a deprecated
    # cipher vulnerable to injection/decryption even under WPA2.
    finding_type, reason = wifi_scan._classify_encryption("WPA2 TKIP PSK")
    assert finding_type == "weak_encryption"
    assert "TKIP" in reason


def test_capture_findings_classifies_each_ap(monkeypatch):
    monkeypatch.setattr(wifi_scan, "passive_capture", lambda iface, duration: [
        {"ssid": "HomeNet", "bssid": "AA:AA:AA:AA:AA:AA", "encryption": "WPA2 CCMP PSK",
         "channel": "6", "signal": "-40"},
        {"ssid": "OldRouter", "bssid": "BB:BB:BB:BB:BB:BB", "encryption": "WEP",
         "channel": "1", "signal": "-60"},
    ])
    findings = wifi_scan.capture_findings("wlan0mon", 10)
    by_ssid = {f["ssid"]: f for f in findings}
    assert by_ssid["HomeNet"]["finding_type"] == "info"
    assert by_ssid["OldRouter"]["finding_type"] == "weak_encryption"
    assert "Channel 1" in by_ssid["OldRouter"]["details"]
    assert "WEP" in by_ssid["OldRouter"]["details"]  # reason is included, not just the channel/signal
    assert by_ssid["HomeNet"]["details"] == "Channel 6, signal -40"  # clean network: no reason prefix


def test_is_default_ssid():
    assert wifi_scan.is_default_ssid("NETGEAR54")
    assert wifi_scan.is_default_ssid("TP-LINK_A1B2C3")
    assert wifi_scan.is_default_ssid("dlink-9F3A")
    assert wifi_scan.is_default_ssid("Xfinity")
    assert wifi_scan.is_default_ssid("SomeVendor-4F2A")  # generic word+hex-suffix pattern
    assert not wifi_scan.is_default_ssid("HomeNet")
    assert not wifi_scan.is_default_ssid("MyFamilyWifi")
    assert not wifi_scan.is_default_ssid("")
    assert not wifi_scan.is_default_ssid("hidden")


def test_detect_rogue_aps_flags_duplicate_ssid():
    aps = [
        {"ssid": "HomeNet", "bssid": "AA:AA:AA:AA:AA:AA", "encryption": "WPA2 CCMP PSK", "channel": "6", "signal": "-40"},
        {"ssid": "HomeNet", "bssid": "BB:BB:BB:BB:BB:BB", "encryption": "OPEN", "channel": "6", "signal": "-35"},
        {"ssid": "OtherNet", "bssid": "CC:CC:CC:CC:CC:CC", "encryption": "WPA2 CCMP PSK", "channel": "1", "signal": "-50"},
    ]
    findings = wifi_scan.detect_rogue_aps(aps)
    assert len(findings) == 1  # only the colliding SSID is flagged
    assert findings[0]["finding_type"] == "rogue_ap"
    assert "DIFFERENT" in findings[0]["details"]  # mismatched encryption -> high-confidence wording


def test_detect_rogue_aps_no_collision():
    aps = [
        {"ssid": "HomeNet", "bssid": "AA:AA:AA:AA:AA:AA", "encryption": "WPA2 CCMP PSK", "channel": "6", "signal": "-40"},
        {"ssid": "OtherNet", "bssid": "CC:CC:CC:CC:CC:CC", "encryption": "WPA2 CCMP PSK", "channel": "1", "signal": "-50"},
    ]
    assert wifi_scan.detect_rogue_aps(aps) == []


def test_detect_rogue_aps_ignores_hidden():
    aps = [
        {"ssid": "hidden", "bssid": "AA:AA:AA:AA:AA:AA", "encryption": "WPA2 CCMP PSK", "channel": "6", "signal": "-40"},
        {"ssid": "hidden", "bssid": "BB:BB:BB:BB:BB:BB", "encryption": "WPA2 CCMP PSK", "channel": "1", "signal": "-50"},
    ]
    assert wifi_scan.detect_rogue_aps(aps) == []


def test_capture_findings_includes_default_ssid_and_rogue_ap(monkeypatch):
    monkeypatch.setattr(wifi_scan, "passive_capture", lambda iface, duration: [
        {"ssid": "NETGEAR54", "bssid": "AA:AA:AA:AA:AA:AA", "encryption": "WPA2 CCMP PSK", "channel": "6", "signal": "-40"},
        {"ssid": "NETGEAR54", "bssid": "BB:BB:BB:BB:BB:BB", "encryption": "OPEN", "channel": "6", "signal": "-35"},
    ])
    findings = wifi_scan.capture_findings("wlan0mon", 10)
    types = [f["finding_type"] for f in findings]
    assert "default_ssid" in types  # NETGEAR54 matches the default-SSID pattern
    assert "rogue_ap" in types      # same SSID, two BSSIDs, mismatched encryption


def test_pmkid_capture_reports_missing_tools(monkeypatch):
    monkeypatch.setattr(wifi_scan, "wireless_supported", lambda: True)
    monkeypatch.setattr(wifi_scan.shutil, "which", lambda name: None)
    result = wifi_scan.pmkid_capture("wlan0mon", "AA:BB:CC:DD:EE:FF", timeout=1)
    assert result["pmkid_found"] is False
    assert "not installed" in result["details"]
