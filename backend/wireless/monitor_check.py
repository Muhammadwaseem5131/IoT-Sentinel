import shutil
import subprocess  # nosec B404
import sys


def _run(args, timeout=10):
    # Safe by construction: only static argument lists, never a shell.
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)  # nosec B603
        return proc.returncode == 0, proc.stdout + proc.stderr
    except (subprocess.SubprocessError, OSError):
        return False, ""


def wireless_supported() -> bool:
    """True if the wireless module can run on this host (Linux + monitor-mode tools)."""
    if sys.platform != "linux":
        return False
    if not shutil.which("airmon-ng") or not shutil.which("airodump-ng"):
        return False
    ok, output = _run(["airmon-ng"])
    return ok and "PHY" in output


def list_interfaces() -> list[str]:
    """Lists WiFi interfaces available to airmon-ng."""
    ok, output = _run(["airmon-ng"])
    interfaces = []
    if not ok:
        return interfaces
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isupper():
            interfaces.append(parts[1])
    return interfaces
