"""Wireless adapter discovery and monitor-mode setup.

Lists WiFi adapters and whether each can do monitor mode, and enables/disables
monitor mode on Linux via airmon-ng. It does NOT install drivers — that needs OS
admin rights and is platform-specific; instead it reports what to install and the
exact command to run.
"""
import logging
import os
import re
import shutil
import subprocess  # nosec B404
import sys

logger = logging.getLogger(__name__)

# Linux drivers known to support monitor mode + injection.
MONITOR_CAPABLE_DRIVERS = {
    "ath9k", "ath9k_htc", "ath5k", "ath10k_pci", "carl9170",
    "rt2800usb", "rt2800pci", "rt73usb", "rt2500usb", "rt2x00",
    "rtl8187", "rtl8812au", "rtl8814au", "rtl88xxau", "rtl8188eu",
    "mt7601u", "mt76x0u", "mt76x2u", "mt7921u", "b43", "p54usb",
    "zd1211rw", "brcmfmac", "iwlwifi",
}


def _run(args, timeout=15):
    # Safe by construction: static argument lists, never a shell.
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)  # nosec B603
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("command %s failed: %s", args, exc)
        return 1, ""


# --- listing ---------------------------------------------------------------

def list_adapters() -> dict:
    if sys.platform.startswith("linux"):
        return _list_linux()
    if sys.platform == "win32":
        return _list_windows()
    return {"platform": sys.platform, "os_supports_monitor": False,
            "tools": {}, "adapters": [],
            "hint": "Monitor mode is supported on Linux only."}


def _is_wireless(iface: str) -> bool:
    return (os.path.exists(f"/sys/class/net/{iface}/wireless")
            or os.path.exists(f"/sys/class/net/{iface}/phy80211"))


def _driver_for(iface: str) -> str | None:
    try:
        return os.path.basename(os.readlink(f"/sys/class/net/{iface}/device/driver"))
    except OSError:
        return None


def _mode(iface: str) -> str | None:
    if not shutil.which("iw"):
        return None
    _, out = _run(["iw", "dev", iface, "info"])
    m = re.search(r"type (\w+)", out)
    return m.group(1) if m else None


def _list_linux() -> dict:
    have_airmon = shutil.which("airmon-ng") is not None
    have_iw = shutil.which("iw") is not None
    adapters = []
    net_dir = "/sys/class/net"
    for iface in sorted(os.listdir(net_dir)) if os.path.isdir(net_dir) else []:
        if not _is_wireless(iface):
            continue
        driver = _driver_for(iface)
        adapters.append({
            "interface": iface,
            "driver": driver or "unknown",
            "mode": _mode(iface),
            "monitor_capable": bool(driver and driver in MONITOR_CAPABLE_DRIVERS),
        })

    hint = None
    if not have_airmon:
        hint = "Install the aircrack-ng suite:  sudo apt install aircrack-ng"
    elif not adapters:
        hint = "No wireless adapters detected. Plug in a monitor-mode-capable adapter."
    return {"platform": "linux", "os_supports_monitor": True,
            "tools": {"airmon-ng": have_airmon, "iw": have_iw},
            "adapters": adapters, "hint": hint}


def _list_windows() -> dict:
    _, out = _run(["netsh", "wlan", "show", "interfaces"])
    adapters, name = [], None
    for line in out.splitlines():
        s = line.strip()
        if s.lower().startswith("name") and ":" in s:
            name = s.split(":", 1)[1].strip()
        elif s.lower().startswith("description") and ":" in s:
            desc = s.split(":", 1)[1].strip()
            adapters.append({"interface": name or desc, "driver": desc,
                             "mode": "managed", "monitor_capable": False})
            name = None
    return {"platform": "windows", "os_supports_monitor": False,
            "tools": {}, "adapters": adapters,
            "hint": "Windows drivers don't expose monitor mode. Run the wireless module on Linux "
                    "with a compatible adapter (Atheros AR9271/AR9227, Ralink RT3070, etc.)."}


# --- monitor mode ----------------------------------------------------------

def _find_monitor_interface() -> str | None:
    for a in _list_linux()["adapters"]:
        if a["mode"] == "monitor":
            return a["interface"]
    return None


def enable_monitor(interface: str) -> dict:
    if sys.platform != "linux":
        raise RuntimeError("Monitor mode is only available on Linux.")
    if not shutil.which("airmon-ng"):
        raise RuntimeError("airmon-ng not found. Install it:  sudo apt install aircrack-ng")

    _run(["airmon-ng", "check", "kill"])          # stop NetworkManager/wpa_supplicant interference
    rc, out = _run(["airmon-ng", "start", interface], timeout=30)
    mon = _find_monitor_interface() or f"{interface}mon"
    if _find_monitor_interface() is None and "monitor mode" not in out.lower():
        raise RuntimeError(f"Could not enable monitor mode (needs root). Output: {out.strip()[-200:]}")
    return {"status": "enabled", "monitor_interface": mon, "message": out.strip()[-300:]}


def disable_monitor(interface: str) -> dict:
    if sys.platform != "linux":
        raise RuntimeError("Monitor mode is only available on Linux.")
    if not shutil.which("airmon-ng"):
        raise RuntimeError("airmon-ng not found.")
    _, out = _run(["airmon-ng", "stop", interface], timeout=30)
    _run(["systemctl", "restart", "NetworkManager"])  # best-effort: restore normal WiFi
    return {"status": "disabled", "message": out.strip()[-300:]}
