import logging
import shutil

import nmap

logger = logging.getLogger(__name__)

COMMON_PORTS = "21,22,23,25,53,80,443,445,554,631,8080,8443,1883,8883,5683,9100"


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def port_scan(ip: str, ports: str = COMMON_PORTS, timeout: int = 15) -> list[dict]:
    """Scans a host for open ports and grabs banners. Uses subprocess arg-list internally."""
    if not nmap_available():
        logger.warning("nmap binary not found; skipping port scan for %s", ip)
        return []
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, ports=ports, arguments=f"-sV --version-light -Pn --max-retries 1 --host-timeout {timeout}s")
    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                state = scanner[host][proto][port].get("state", "")
                if state != "open":
                    continue
                service = scanner[host][proto][port].get("name", "")
                product = scanner[host][proto][port].get("product", "")
                version = scanner[host][proto][port].get("version", "")
                banner_parts = [p for p in (product, version) if p]
                banner = " ".join(banner_parts) if banner_parts else None
                results.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                })
    return results
