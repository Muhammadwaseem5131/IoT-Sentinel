import re
import socket

# Small built-in fallback used only if scapy's bundled IEEE OUI DB misses.
OUI_PREFIXES = {
    "00:00:0c": "Cisco", "00:0c:29": "VMware", "00:50:56": "VMware",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "f0:9f:c2": "Ubiquiti", "3c:5a:b4": "Google", "ac:63:be": "Amazon",
    "38:ed:18": "Hikvision", "a4:77:33": "Wyze", "5c:a6:e6": "Ring",
}

_SUFFIX_RE = re.compile(
    r",?\s+(inc\.?|incorporated|llc|ltd\.?|limited|corp\.?|corporation|co\.?|gmbh|"
    r"technologies|technology|electronics|international|company)\b.*$",
    re.IGNORECASE,
)


def _clean_vendor(name: str) -> str:
    """Trims corporate suffixes so 'Amazon Technologies Inc.' -> 'Amazon'."""
    cleaned = _SUFFIX_RE.sub("", name).strip().strip(",") or name
    # Scapy sometimes returns a short lowercase code (e.g. 'zte'); title-case those.
    if cleaned.islower():
        cleaned = cleaned.title()
    return cleaned


def mac_to_vendor(mac: str) -> str | None:
    """Resolves a MAC to a vendor. Uses scapy's full bundled IEEE OUI database
    (~30k vendors); falls back to a small built-in table."""
    if not mac:
        return None
    try:
        from scapy.all import conf
        vendor = conf.manufdb._get_manuf(mac)
        # scapy returns the MAC itself when a prefix is unknown -> reject those.
        if vendor and ":" not in vendor and vendor.lower() not in ("", "unknown"):
            return _clean_vendor(vendor)
    except Exception:  # noqa: BLE001 - never let vendor lookup break a scan
        pass

    normalized = mac.lower().strip().replace("-", ":").replace(".", ":")
    parts = normalized.split(":")
    if len(parts) < 3:
        return None
    return OUI_PREFIXES.get(":".join(parts[:3]))


def resolve_hostname(ip: str, timeout: float = 1.5) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
