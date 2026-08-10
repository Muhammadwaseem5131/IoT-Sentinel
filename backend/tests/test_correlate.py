from correlation import correlate


class _FakeModels:
    """Stand-in for db.models: just provides get_scan_report for one scan."""
    def __init__(self, wireless_findings):
        self._report = {"wireless_findings": wireless_findings}

    def get_scan_report(self, _scan_id):
        return self._report


def test_encryption_flags_ignore_non_encryption_findings(monkeypatch):
    # rogue_ap / wps_enabled / deauth_detected all carry encryption=None; the
    # old check treated None as empty-string and falsely flagged weak.
    monkeypatch.setattr(correlate, "models", _FakeModels([
        {"finding_type": "rogue_ap", "encryption": None},
        {"finding_type": "wps_enabled", "encryption": None},
        {"finding_type": "deauth_detected", "encryption": None},
    ]))
    assert correlate._network_encryption_flags(1) == (False, False)


def test_encryption_flags_detect_wep(monkeypatch):
    monkeypatch.setattr(correlate, "models", _FakeModels([
        {"finding_type": "weak_encryption", "encryption": "WEP"},
    ]))
    assert correlate._network_encryption_flags(1) == (True, False)


def test_encryption_flags_detect_wpa1_partial(monkeypatch):
    monkeypatch.setattr(correlate, "models", _FakeModels([
        {"finding_type": "info", "encryption": "WPA CCMP PSK"},
    ]))
    assert correlate._network_encryption_flags(1) == (False, True)


def test_encryption_flags_clean_network(monkeypatch):
    monkeypatch.setattr(correlate, "models", _FakeModels([
        {"finding_type": "info", "encryption": "WPA2 CCMP PSK"},
    ]))
    assert correlate._network_encryption_flags(1) == (False, False)
