"""Internet-exposure detection.

Two honest signals for whether a device faces the internet:
  1. It is the default gateway (the router literally sits on the WAN edge).
  2. It has an active UPnP/IGD port-forward mapping the internet in to it.

Both are read-only and best-effort: any failure yields "not exposed" rather
than raising, so a scan never dies on this.

ponytail: gateway + UPnP-mapping heuristic. It does NOT prove a device is
reachable from the public internet (that needs an outside vantage point);
it flags the two locally-observable conditions that usually mean exposure.
"""
import logging
import re
import socket
import subprocess  # nosec B404
import sys
import urllib.parse
from xml.etree import ElementTree

import requests

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def default_gateways() -> set[str]:
    """Returns the set of default-gateway IPs for this host (best-effort)."""
    try:
        if sys.platform == "win32":
            out = _run(["route", "print", "-4"])
            gws = set()
            for line in out.splitlines():
                parts = line.split()
                # "0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>"
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and _IP_RE.fullmatch(parts[2] or ""):
                    gws.add(parts[2])
            return gws
        out = _run(["ip", "route", "show", "default"])
        if out:
            return set(m for line in out.splitlines()
                       for m in _IP_RE.findall(line) if "via" in line) or _fallback_gateways(out)
        # macOS / no `ip`
        out = _run(["netstat", "-rn"])
        return {parts[1] for line in out.splitlines()
                if (parts := line.split()) and parts[0] == "default" and _IP_RE.fullmatch(parts[1] or "")}
    except Exception as exc:  # noqa: BLE001 - never let exposure detection break a scan
        logger.debug("Gateway detection failed: %s", exc)
        return set()


def _fallback_gateways(route_output: str) -> set[str]:
    m = re.search(r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", route_output)
    return {m.group(1)} if m else set()


def upnp_forwarded_ips(timeout: float = 2.0) -> set[str]:
    """Enumerates UPnP/IGD port-forward mappings on the LAN router and returns
    the set of internal client IPs that have an active WAN->LAN forward."""
    try:
        location = _discover_igd(timeout)
        if not location:
            return set()
        control_url, service_type = _igd_control(location, timeout)
        if not control_url:
            return set()
        return _enumerate_mappings(control_url, service_type, timeout)
    except Exception as exc:  # noqa: BLE001
        logger.debug("UPnP mapping enumeration failed: %s", exc)
        return set()


def internet_facing_ips(timeout: float = 2.0) -> set[str]:
    """Union of gateways and UPnP-forwarded internal IPs."""
    return default_gateways() | upnp_forwarded_ips(timeout)


# --- internals -------------------------------------------------------------

def _run(args, timeout=8) -> str:
    # Safe by construction: static argument lists only, never a shell.
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)  # nosec B603
    return proc.stdout + proc.stderr


def _discover_igd(timeout: float) -> str | None:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg.encode(), ("239.255.255.250", 1900))
        while True:
            data, _ = sock.recvfrom(2048)
            for line in data.decode("utf-8", "replace").splitlines():
                if line.lower().startswith("location:"):
                    return line.split(":", 1)[1].strip()
    except socket.timeout:
        return None
    finally:
        sock.close()


def _igd_control(location: str, timeout: float) -> tuple[str | None, str | None]:
    resp = requests.get(location, timeout=timeout)
    resp.raise_for_status()
    # A UPnP descriptor is a few KB; cap it so a malicious LAN device can't feed
    # a huge/expanding XML body. Bounds quadratic-blowup attacks on the parse.
    # ponytail: size cap + the surrounding try/except; swap in defusedxml if this
    # ever parses XML from beyond the local network.
    xml = resp.text[:65536]
    root = ElementTree.fromstring(xml)  # nosec B314 - LAN UPnP descriptor, size-capped, exception-guarded upstream
    ns = {"u": "urn:schemas-upnp-org:device-1-0"}
    for service in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
        st = service.findtext("u:serviceType", default="", namespaces=ns)
        if "WANIPConnection" in st or "WANPPPConnection" in st:
            ctrl = service.findtext("u:controlURL", default="", namespaces=ns)
            return urllib.parse.urljoin(location, ctrl), st
    return None, None


def _enumerate_mappings(control_url: str, service_type: str, timeout: float, limit: int = 64) -> set[str]:
    ips = set()
    for index in range(limit):
        body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
            f"<NewPortMappingIndex>{index}</NewPortMappingIndex>"
            "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
        )
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#GetGenericPortMappingEntry"',
        }
        resp = requests.post(control_url, data=body, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            break  # SpecifiedArrayIndexInvalid => we've read every mapping
        m = re.search(r"<NewInternalClient>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</NewInternalClient>", resp.text)
        if m:
            ips.add(m.group(1))
    return ips
