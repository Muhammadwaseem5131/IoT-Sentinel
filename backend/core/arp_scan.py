from scapy.all import ARP, Ether, srp

from config import validate_subnet


def arp_scan(subnet: str, timeout: int = 3, retries: int = 2) -> list[dict]:
    """Discovers live hosts on a subnet via ARP. Returns list of {ip, mac}."""
    network = validate_subnet(subnet)
    hosts = []
    for _ in range(retries):
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=timeout,
            verbose=0,
        )
        for sent, received in ans:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
            })
    # De-duplicate while preserving order.
    seen = set()
    unique = []
    for h in hosts:
        key = h["mac"]
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique
