import logging
import os
import re
import shutil
import subprocess  # nosec B404
import tempfile
import time
from collections import defaultdict

import requests

from wireless.monitor_check import wireless_supported

logger = logging.getLogger(__name__)


class WirelessUnavailableError(RuntimeError):
    pass


def _run_capture(args, duration: int) -> str:
    """Runs a capture tool that never exits on its own (wash, etc.) for `duration`
    seconds, then returns whatever it printed. Safe: argument lists, never a shell."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=duration)  # nosec B603
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or "", exc.stderr or ""
        out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        err = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
        return out + err


def passive_capture(interface: str, duration: int = 30, outdir: str | None = None) -> list[dict]:
    """Passively captures beacons/probes with airodump-ng and parses nearby APs.

    Returns list of {bssid, ssid, channel, encryption, signal}.
    """
    if not wireless_supported():
        raise WirelessUnavailableError("Wireless module requires Linux with a monitor-mode adapter.")

    workdir = outdir or tempfile.mkdtemp(prefix="iot_wifi_")
    prefix = os.path.join(workdir, "capture")
    # airodump-ng runs until stopped, so launch it, let it collect, then terminate.
    proc = subprocess.Popen(  # nosec B603
        ["airodump-ng", interface, "--write", prefix, "--write-interval", "1",
         "--output-format", "csv", "--band", "bg"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(duration)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    csv_path = f"{prefix}-01.csv"
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        logger.warning("airodump CSV not produced; interface may not support monitor mode.")
        return []
    return _parse_airodump_csv(content)


def _parse_airodump_csv(content: str) -> list[dict]:
    """Parses the AP section of an airodump-ng CSV (stops at the Station section)."""
    lines = content.splitlines()
    # Find the AP header, skipping any leading blank lines the file may have.
    start = next((i + 1 for i, l in enumerate(lines) if l.strip().startswith("BSSID")), None)
    if start is None:
        return []

    results = []
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("Station MAC"):
            break  # end of the AP section
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 14 or ":" not in fields[0]:
            continue
        # Columns: 0 BSSID, 3 channel, 5 Privacy, 6 Cipher, 7 Auth, 8 Power, 13 ESSID
        privacy = " ".join(f for f in (fields[5], fields[6], fields[7]) if f).strip()
        ssid = fields[13] or "hidden"
        results.append({
            "bssid": fields[0],
            "channel": fields[3],
            "signal": fields[8],
            "encryption": privacy or "OPEN",
            "ssid": ssid,
        })
    return results


def detect_deauth(interface: str, target_bssid: str, duration: int = 30) -> int:
    """Counts 802.11 deauthentication frames involving a BSSID by sniffing the
    monitor interface with scapy. Returns the number seen (0 = none)."""
    if not wireless_supported():
        raise WirelessUnavailableError("Wireless module requires Linux with a monitor-mode adapter.")
    from scapy.all import Dot11Deauth, sniff  # imported lazily; only valid on a monitor iface

    target = target_bssid.lower()
    count = 0

    def _seen(pkt) -> bool:
        nonlocal count
        if not pkt.haslayer(Dot11Deauth):
            return False
        addrs = [(getattr(pkt, a, "") or "").lower() for a in ("addr1", "addr2", "addr3")]
        if target in addrs:
            count += 1
        return False

    sniff(iface=interface, stop_filter=_seen, timeout=duration, store=False)
    return count


def check_wps(interface: str, target_bssid: str, timeout: int = 45) -> dict:
    """Runs wash to check WPS status on a target. Returns {'wps_enabled', 'locked', 'details'}."""
    if not wireless_supported():
        raise WirelessUnavailableError("Wireless module requires Linux with a monitor-mode adapter.")
    output = _run_capture(["wash", "-i", interface, "-b", target_bssid], timeout)
    target = target_bssid.lower()
    enabled, locked = False, False
    for line in output.splitlines():
        if target in line.lower():
            cols = line.split()
            locked = "Yes" in cols[-1:] or "Locked" in line
            enabled = not locked
    return {"wps_enabled": enabled, "locked": locked, "details": output.strip()[:500]}


def pmkid_capture(interface: str, bssid: str, timeout: int = 15) -> dict:
    """Active PMKID capture test: requests the target AP's PMKID directly, the
    least-intrusive way to check whether its WPA2 key is offline-crackable.
    Unlike a forced-handshake capture this needs no connected client and never
    deauthenticates anyone (--disable_deauthentication). Requires hcxdumptool +
    hcxtools (Kali: apt install hcxdumptool hcxtools).
    Returns {'pmkid_found': bool, 'details': str}."""
    if not wireless_supported():
        raise WirelessUnavailableError("Wireless module requires Linux with a monitor-mode adapter.")
    if not shutil.which("hcxdumptool") or not shutil.which("hcxpcapngtool"):
        return {"pmkid_found": False,
                "details": "hcxdumptool/hcxtools not installed. Install: sudo apt install hcxdumptool hcxtools"}

    workdir = tempfile.mkdtemp(prefix="iot_pmkid_")
    pcap_path = os.path.join(workdir, "capture.pcapng")
    filter_path = os.path.join(workdir, "filter.txt")
    with open(filter_path, "w", encoding="utf-8") as f:
        f.write(bssid.replace(":", "").upper() + "\n")

    proc = subprocess.Popen(  # nosec B603
        ["hcxdumptool", "-i", interface, "-o", pcap_path, "--filterlist_ap", filter_path,
         "--filtermode", "2", "--disable_deauthentication"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(timeout)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
        return {"pmkid_found": False, "details": "No frames captured; target may be out of range or not responding."}

    hash_path = os.path.join(workdir, "hash.pmkid")
    subprocess.run(["hcxpcapngtool", "-o", hash_path, pcap_path], capture_output=True, timeout=30)  # nosec B603
    found = os.path.exists(hash_path) and os.path.getsize(hash_path) > 0
    details = (
        "PMKID captured: this network's WPA2 key is vulnerable to offline dictionary/brute-force "
        "attacks if the passphrase is weak. Use a long, random passphrase."
        if found else
        "No PMKID captured in the time window. Doesn't prove the network is safe, just that this "
        "check didn't catch a response."
    )
    return {"pmkid_found": found, "details": details}


def _classify_encryption(encryption: str) -> tuple[str, str | None]:
    """Classifies an AP's Privacy/Cipher/Auth string (airodump-ng CSV columns 5-7,
    e.g. "WPA2 TKIP PSK"). Checks the cipher, not just the WPA version: WPA2 with
    the deprecated TKIP cipher is still weak even though "WPA2" alone looks safe.
    Returns (finding_type, reason) where reason is None for a clean network."""
    lowered = (encryption or "").lower()
    if not lowered or "open" in lowered:
        return "weak_encryption", "Network is open (no encryption). All traffic is readable by anyone in range."
    if "wep" in lowered:
        return "weak_encryption", "WEP encryption can be cracked in minutes with tools already in Kali (aircrack-ng)."
    if "tkip" in lowered:
        return "weak_encryption", "Uses the deprecated TKIP cipher, vulnerable to packet injection/decryption attacks even under WPA2."
    if "wpa" in lowered and "2" not in lowered and "3" not in lowered:
        return "weak_encryption", "WPA1 only; upgrade to WPA2/WPA3 with CCMP/AES."
    return "info", None


# Common factory-default SSID patterns. A default SSID usually means the admin
# password and firmware were never touched either, not just the network name.
_DEFAULT_SSID_RE = re.compile(
    r"^(NETGEAR\d*|TP-LINK_[0-9A-F]{4,6}|dlink-?\d*|Linksys\d*|ASUS(_[0-9A-F]{2,6})?|"
    r"Xfinity|ATT[0-9A-Za-z]*|CenturyLink\d*|HUAWEI-[0-9A-Za-z]+|MERCURY_[0-9A-Za-z]+|"
    r"Tenda_[0-9A-F]+|Belkin\.?[0-9A-Za-z]*|HP-Print-[0-9A-Za-z-]+|DIRECT-[0-9A-Za-z-]+|"
    r"[A-Za-z]+[-_][0-9A-F]{4,6})$",
    re.IGNORECASE,
)


def is_default_ssid(ssid: str) -> bool:
    """True if an SSID matches a known factory-default naming pattern."""
    return bool(ssid) and ssid != "hidden" and bool(_DEFAULT_SSID_RE.match(ssid.strip()))


def detect_rogue_aps(aps: list[dict]) -> list[dict]:
    """Flags possible evil-twin/rogue APs: the same SSID broadcast from more than
    one BSSID. Purely passive, offline-testable, no false-positive risk beyond
    legitimate mesh/extender setups (noted in the finding text).

    Returns extra finding dicts (ssid, bssid, encryption, finding_type, details)
    to merge alongside the per-AP encryption findings.
    """
    by_ssid = defaultdict(list)
    for ap in aps:
        if ap.get("ssid") and ap["ssid"] != "hidden":
            by_ssid[ap["ssid"]].append(ap)

    findings = []
    for ssid, group in by_ssid.items():
        bssids = {a["bssid"] for a in group}
        if len(bssids) < 2:
            continue
        encryptions = {a.get("encryption") for a in group}
        mismatched = len(encryptions) > 1
        bssid_list = ", ".join(sorted(bssids))
        if mismatched:
            details = (
                f"Same network name broadcast from {len(bssids)} access points with DIFFERENT "
                f"encryption ({', '.join(sorted(e or 'unknown' for e in encryptions))}). Strong sign "
                f"of an evil-twin/rogue AP impersonating this network. BSSIDs: {bssid_list}"
            )
        else:
            details = (
                f"Same network name broadcast from {len(bssids)} access points. Could be a "
                f"legitimate mesh/extender setup, or a rogue AP cloning this network. BSSIDs: {bssid_list}"
            )
        findings.append({
            "ssid": ssid, "bssid": sorted(bssids)[0], "encryption": None,
            "finding_type": "rogue_ap", "details": details,
        })
    return findings


def capture_findings(interface: str, duration: int = 20) -> list[dict]:
    """Passive capture -> classified wireless findings, ready to insert/post.
    Shared by the CLI and the API-triggered scan so both stay in sync.
    Runs three offline/passive checks: encryption weakness, default-SSID
    naming, and evil-twin/rogue-AP detection (same SSID, multiple BSSIDs)."""
    aps = passive_capture(interface, duration)
    findings = []
    for ap in aps:
        finding_type, reason = _classify_encryption(ap["encryption"])
        details = f"Channel {ap['channel']}, signal {ap['signal']}"
        if reason:
            details = f"{reason} ({details})"
        findings.append({
            "ssid": ap["ssid"], "bssid": ap["bssid"], "encryption": ap["encryption"],
            "finding_type": finding_type, "details": details,
        })
        if is_default_ssid(ap["ssid"]):
            findings.append({
                "ssid": ap["ssid"], "bssid": ap["bssid"], "encryption": ap["encryption"],
                "finding_type": "default_ssid",
                "details": "Factory-default network name. Usually means the admin password and "
                "firmware were never changed either, check the router's admin page.",
            })
    findings.extend(detect_rogue_aps(aps))
    return findings


def push_to_backend(api_endpoint: str, scan_id: int, findings: list[dict]):
    """Posts wireless findings to the Core backend so they land in the shared DB."""
    url = f"{api_endpoint.rstrip('/')}/api/scans/{scan_id}/wireless"
    resp = requests.post(url, json={"findings": findings}, timeout=30)
    resp.raise_for_status()
    return resp.json()
