import pytest

from wireless import adapters


def test_windows_parse(monkeypatch):
    sample = (
        "    Name                   : Wi-Fi\n"
        "    Description            : Intel(R) Wireless-AC 9560\n"
        "    State                  : connected\n"
    )
    monkeypatch.setattr(adapters, "_run", lambda *a, **k: (0, sample))
    res = adapters._list_windows()
    assert res["os_supports_monitor"] is False
    assert res["adapters"][0]["interface"] == "Wi-Fi"
    assert res["adapters"][0]["driver"] == "Intel(R) Wireless-AC 9560"
    assert res["adapters"][0]["monitor_capable"] is False
    assert "Linux" in res["hint"]


def test_known_monitor_capable_drivers():
    assert "ath9k" in adapters.MONITOR_CAPABLE_DRIVERS      # your TL-WN781ND chipset driver
    assert "rt2800usb" in adapters.MONITOR_CAPABLE_DRIVERS
    assert "some_fake_driver" not in adapters.MONITOR_CAPABLE_DRIVERS


def test_enable_monitor_rejected_off_linux(monkeypatch):
    monkeypatch.setattr(adapters.sys, "platform", "win32")
    with pytest.raises(RuntimeError, match="Linux"):
        adapters.enable_monitor("wlan0")
