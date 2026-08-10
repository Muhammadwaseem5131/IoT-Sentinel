import logging

from core import arp_scan, discovery_mdns, exposure, oui_lookup, port_scan
from db import models

logger = logging.getLogger(__name__)


def run_scan_job(scan_id: int, subnet: str, test_creds: bool = False) -> None:
    """Full scan pipeline for a pre-created scan row: discovery + correlation.
    Runs in a background thread; records success/failure on the scan row."""
    from correlation.correlate import run_correlation
    try:
        _drive_scan(scan_id, subnet)
        run_correlation(scan_id, test_creds=test_creds)
        models.finish_scan(scan_id)
    except Exception as exc:  # noqa: BLE001 - record failure instead of dying silently
        logger.exception("Scan %s failed", scan_id)
        models.fail_scan(scan_id, str(exc))


def _drive_scan(scan_id: int, subnet: str) -> None:
    logger.info("Starting core scan on %s (scan_id=%s)", subnet, scan_id)
    models.set_scan_progress(scan_id, 5, "Discovering hosts (ARP)")
    hosts = arp_scan.arp_scan(subnet)
    logger.info("ARP scan found %d hosts", len(hosts))

    models.set_scan_progress(scan_id, 15, "Service discovery (mDNS/SSDP)")
    hostnames = [h for h in (oui_lookup.resolve_hostname(x["ip"]) for x in hosts) if h]
    discovery = discovery_mdns.discover(hostnames)

    # Merge SSDP-discovered hosts that ARP may have missed.
    known_ips = {h["ip"] for h in hosts}
    for d in discovery["ssdp"]:
        if d["ip"] not in known_ips:
            hosts.append({"ip": d["ip"], "mac": None})
            known_ips.add(d["ip"])

    models.set_scan_progress(scan_id, 25, "Checking internet exposure")
    try:
        exposed = exposure.internet_facing_ips()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Exposure detection failed: %s", exc)
        exposed = set()
    logger.info("%d internet-facing device(s): %s", len(exposed), exposed or "none")

    total = max(len(hosts), 1)
    for i, host in enumerate(hosts):
        ip = host["ip"]
        mac = host.get("mac")
        vendor = oui_lookup.mac_to_vendor(mac) if mac else None
        hostname = oui_lookup.resolve_hostname(ip)
        models.set_scan_progress(scan_id, 25 + int(35 * (i + 1) / total), f"Port-scanning {ip}")

        try:
            ports = port_scan.port_scan(ip)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Port scan failed for %s: %s", ip, exc)
            ports = []

        # SSDP's UPnP "Server:" header often discloses OS/firmware version
        # (e.g. "Linux/3.4 UPnP/1.0 MiniUPnPd/1.4") but nmap's TCP scan never
        # sees it (SSDP is UDP/1900, off COMMON_PORTS). Record it as a real
        # open port so it flows through the existing CVE-matching pipeline
        # instead of being silently discarded, our one signal toward outdated
        # firmware / insecure update mechanisms.
        for d in discovery.get("ssdp", []):
            if d["ip"] == ip and d.get("server"):
                ports.append({"port": 1900, "service": "upnp", "banner": d["server"]})
                break

        # Infer type after the port scan so open ports can identify the device.
        device_type = infer_device_type(vendor, hostname, discovery, ports)
        device_id = models.insert_device(
            scan_id, ip, mac=mac, vendor=vendor, hostname=hostname,
            device_type=device_type, internet_facing=ip in exposed,
        )
        for p in ports:
            models.insert_port(device_id, p["port"], service=p.get("service"), banner=p.get("banner"))

    logger.info("Core scan complete (scan_id=%s)", scan_id)


# Open-port signatures -> device type (used when vendor/hostname don't reveal it).
_PORT_TYPE_HINTS = [
    ({9100, 631, 515}, "printer"),
    ({554, 37777, 34567, 8000}, "camera"),
    ({1883, 8883}, "iot_hub"),
    ({3389}, "windows_host"),
    ({445, 139}, "windows_host"),
    ({502, 102}, "plc"),
    ({53, 67}, "router"),
]


def infer_device_type(vendor: str | None, hostname: str | None,
                      discovery: dict, ports: list[dict] | None = None) -> str | None:
    if hostname:
        lowered = hostname.lower()
        for kw, dtype in (
            ("camera", "camera"), ("cam", "camera"), ("ipc", "camera"),
            ("router", "router"), ("gateway", "router"),
            ("switch", "switch"), ("nas", "nas"),
            ("printer", "printer"), ("phone", "phone"),
            ("thermostat", "thermostat"), ("lock", "smart_lock"),
            ("tv", "tv"), ("speaker", "speaker"), ("hub", "hub"),
            ("pi", "raspberry_pi"), ("raspberry", "raspberry_pi"),
        ):
            if kw in lowered:
                return dtype
    if vendor:
        for kw, dtype in (
            ("tp-link", "router"), ("netgear", "router"), ("huawei", "router"),
            ("zte", "router"), ("zyxel", "router"), ("d-link", "router"),
            ("mikrotik", "router"), ("asus", "router"), ("technicolor", "router"),
            ("google", "speaker"), ("amazon", "speaker"),
            ("hikvision", "camera"), ("ring", "camera"), ("wyze", "camera"),
            ("dahua", "camera"), ("axis", "camera"), ("reolink", "camera"),
            ("hewlett", "printer"), ("ricoh", "printer"), ("brother", "printer"),
            ("canon", "printer"), ("epson", "printer"), ("xerox", "printer"),
            ("ubiquiti", "router"), ("raspberry", "raspberry_pi"),
            ("sonos", "speaker"), ("samsung", "tv"), ("lg electronics", "tv"),
        ):
            if kw in vendor.lower():
                return dtype
    for d in discovery.get("ssdp", []):
        if d["device_type"] and ("camera" in d["device_type"] or "printer" in d["device_type"]):
            return "camera" if "camera" in d["device_type"] else "printer"

    open_ports = {p.get("port") for p in (ports or [])}
    for signature, dtype in _PORT_TYPE_HINTS:
        if open_ports & signature:
            return dtype
    return None
