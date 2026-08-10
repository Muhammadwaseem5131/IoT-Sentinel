from core import diff


def test_no_previous_scan():
    assert diff.compute_diff({"devices": []}, None) == {"has_previous": False}


def test_detects_new_removed_and_changed():
    previous = {"id": 1, "devices": [
        {"ip_address": "192.168.1.1", "risk_score": 10},
        {"ip_address": "192.168.1.2", "risk_score": 50},
    ]}
    current = {"id": 2, "devices": [
        {"ip_address": "192.168.1.1", "risk_score": 80},   # risk jumped
        {"ip_address": "192.168.1.3", "risk_score": 20},   # new device
    ]}                                                     # .2 disappeared
    d = diff.compute_diff(current, previous)
    assert d["has_previous"] is True
    assert d["previous_scan_id"] == 1
    assert d["new_devices"] == ["192.168.1.3"]
    assert d["removed_devices"] == ["192.168.1.2"]
    assert d["risk_changes"][0] == {"ip": "192.168.1.1", "old": 10, "new": 80, "delta": 70}


def test_no_changes():
    scan = {"id": 2, "devices": [{"ip_address": "10.0.0.1", "risk_score": 30}]}
    prev = {"id": 1, "devices": [{"ip_address": "10.0.0.1", "risk_score": 30}]}
    d = diff.compute_diff(scan, prev)
    assert d["new_devices"] == [] and d["removed_devices"] == [] and d["risk_changes"] == []


def test_changes_sorted_by_magnitude():
    prev = {"id": 1, "devices": [
        {"ip_address": "a", "risk_score": 10}, {"ip_address": "b", "risk_score": 10}]}
    cur = {"id": 2, "devices": [
        {"ip_address": "a", "risk_score": 15}, {"ip_address": "b", "risk_score": 90}]}
    d = diff.compute_diff(cur, prev)
    assert d["risk_changes"][0]["ip"] == "b"  # largest delta first
