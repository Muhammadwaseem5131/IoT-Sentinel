import socket
import struct


def mdns_query(hosts: list[str], timeout: float = 1.0) -> dict[str, str]:
    """Sends mDNS queries for the given hostnames, returns {hostname: ip}."""
    results = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    for host in hosts:
        name = host if host.endswith(".local") else f"{host}.local"
        qname = bytes(name, "utf-8") + b"\x00"
        question = qname + struct.pack(">HH", 1, 1)  # type A, class IN
        header = struct.pack(">HHHHHH", 0x0000, 0x0000, 0x0001, 0x0000, 0x0000, 0x0000)
        try:
            sock.sendto(header + question, ("224.0.0.251", 5353))
            while True:
                data, addr = sock.recvfrom(1024)
                if addr[0] not in results.values() and addr[0].startswith(("192.168", "10.", "172.")):
                    results[host] = addr[0]
                    break
        except socket.timeout:
            continue
    sock.close()
    return results


def ssdp_discover(timeout: float = 2.0) -> list[dict]:
    """UPnP/SSDP discovery. Returns list of {ip, device_type, server}."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.sendto(msg.encode(), ("239.255.255.250", 1900))
        responses = []
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                text = data.decode("utf-8", errors="replace").lower()
                st = None
                server = None
                for line in text.splitlines():
                    if line.startswith("st:"):
                        st = line.split(":", 1)[1].strip()
                    elif line.startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                responses.append({
                    "ip": addr[0],
                    "device_type": st,
                    "server": server,
                })
            except socket.timeout:
                break
        return responses
    finally:
        sock.close()


def discover(hosts: list[str], timeout: float = 2.0) -> dict[str, list]:
    """Runs mDNS + SSDP discovery. Returns {"mdns": {...}, "ssdp": [...]}."""
    mdns = {}
    if hosts:
        mdns = mdns_query(hosts, timeout)
    ssdp = []
    try:
        ssdp = ssdp_discover(timeout)
    except OSError:
        pass
    return {"mdns": mdns, "ssdp": ssdp}
