from core import oui_lookup, scan_runner


def test_vendor_from_scapy_oui_db():
    # b8:27:eb is the Raspberry Pi Foundation prefix in the IEEE OUI list.
    vendor = oui_lookup.mac_to_vendor("b8:27:eb:12:34:56")
    assert vendor and "raspberry" in vendor.lower()


def test_vendor_none_for_empty_mac():
    assert oui_lookup.mac_to_vendor(None) is None
    assert oui_lookup.mac_to_vendor("") is None


def test_vendor_suffix_cleaned():
    # 'Amazon Technologies Inc.' should be trimmed to 'Amazon'.
    assert oui_lookup._clean_vendor("Amazon Technologies Inc.") == "Amazon"
    assert oui_lookup._clean_vendor("Ubiquiti Inc") == "Ubiquiti"


def test_type_from_ports_printer():
    t = scan_runner.infer_device_type(None, None, {}, [{"port": 9100}])
    assert t == "printer"


def test_type_from_ports_camera_and_host():
    assert scan_runner.infer_device_type(None, None, {}, [{"port": 554}]) == "camera"
    assert scan_runner.infer_device_type(None, None, {}, [{"port": 445}]) == "windows_host"


def test_hostname_still_wins_over_ports():
    # An explicit hostname hint takes precedence over port inference.
    t = scan_runner.infer_device_type(None, "living-room-camera", {}, [{"port": 9100}])
    assert t == "camera"
