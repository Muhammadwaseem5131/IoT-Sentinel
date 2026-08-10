"""Active, opt-in vulnerability probes.

These make real connections and are only run when the user enables active checks
(the same gate as default-credential testing). Each probe is read-only, short-
timeout, and fails closed (any error -> no finding). For authorized testing only.
"""
import ftplib
import logging
import socket

import requests

logger = logging.getLogger(__name__)


def _finding(ftype, severity, weight, description):
    return {"finding_type": ftype, "severity": severity, "weight": weight, "description": description}


def run(ip: str, open_ports: list[dict]) -> list[dict]:
    """Dispatches active probes based on a device's open ports/services."""
    findings = []
    for p in open_ports:
        port, service = p.get("port"), (p.get("service") or "").lower()
        try:
            if port == 21 or service == "ftp":
                f = anonymous_ftp(ip, port or 21)
            elif port == 161 or service == "snmp":
                f = snmp_default_community(ip, port or 161)
            elif port == 1883 or service in ("mqtt", "mosquitto"):
                f = open_mqtt(ip, port or 1883)
            elif service in ("http", "https") or port in (80, 443, 8080, 8443):
                f = unauthenticated_firmware_endpoint(ip, port, service)
            else:
                f = None
        except Exception as exc:  # noqa: BLE001 - a probe must never break a scan
            logger.debug("Active probe error on %s:%s: %s", ip, port, exc)
            f = None
        if f:
            findings.append(f)
    return findings


# --- Anonymous FTP ---------------------------------------------------------

def anonymous_ftp(ip: str, port: int = 21, timeout: float = 5.0) -> dict | None:
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        ftp.login()  # no args -> anonymous / anonymous@
        try:
            ftp.quit()
        except Exception:  # noqa: BLE001
            pass
        return _finding("anonymous_ftp", "high", 7.0,
                        "Anonymous FTP login is allowed. Anyone can connect with no credentials "
                        "and may read or upload files. Disable anonymous access.")
    except (ftplib.error_perm, ftplib.error_temp):
        return None  # login rejected: good
    except (socket.timeout, OSError):
        return None


# --- SNMP default community ------------------------------------------------

def _tlv(tag: int, value: bytes) -> bytes:
    # BER TLV; every length here is < 128, so single-byte length encoding is valid.
    return bytes([tag, len(value)]) + value


def snmp_get_request(community: str, request_id: int = 0x01020304) -> bytes:
    """Builds a minimal SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)."""
    version = _tlv(0x02, b"\x00")                      # SNMP v1
    comm = _tlv(0x04, community.encode())
    oid = _tlv(0x06, bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]))
    null = _tlv(0x05, b"")
    varbind = _tlv(0x30, oid + null)
    varbind_list = _tlv(0x30, varbind)
    req_id = _tlv(0x02, request_id.to_bytes(4, "big"))
    err_status = _tlv(0x02, b"\x00")
    err_index = _tlv(0x02, b"\x00")
    pdu = _tlv(0xA0, req_id + err_status + err_index + varbind_list)  # GetRequest PDU
    return _tlv(0x30, version + comm + pdu)


def snmp_default_community(ip: str, port: int = 161, timeout: float = 3.0,
                          communities: tuple[str, ...] = ("public", "private")) -> dict | None:
    # An agent silently drops requests with the wrong community, so *any* well-formed
    # SNMP response means the community string was accepted.
    for community in communities:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(snmp_get_request(community), (ip, port))
            data, _ = sock.recvfrom(2048)
            if data and data[0] == 0x30:
                return _finding("snmp_default_community", "medium", 5.5,
                                f"SNMP responds to the default community string '{community}'. Device "
                                "configuration is readable (and often writable) by anyone on the network. "
                                "Disable SNMP or set a strong community string.")
        except (socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return None


# --- Open MQTT broker ------------------------------------------------------

def _mqtt_remaining_length(n: int) -> bytes:
    out = b""
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out += bytes([byte])
        if n == 0:
            return out


def mqtt_connect_packet(client_id: str = "iot-sentinel") -> bytes:
    """Builds an MQTT 3.1.1 CONNECT packet with a clean session and no credentials."""
    variable_header = b"\x00\x04MQTT" + b"\x04" + b"\x02" + b"\x00\x3c"  # proto, level, flags, keepalive
    cid = client_id.encode()
    payload = len(cid).to_bytes(2, "big") + cid
    body = variable_header + payload
    return b"\x10" + _mqtt_remaining_length(len(body)) + body


def open_mqtt(ip: str, port: int = 1883, timeout: float = 5.0) -> dict | None:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except (socket.timeout, OSError):
        return None
    try:
        sock.sendall(mqtt_connect_packet())
        resp = sock.recv(4)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    # CONNACK = 0x20, remaining len 0x02, ack flags, return code (0x00 = accepted).
    if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
        return _finding("open_mqtt", "medium", 6.0,
                        "MQTT broker accepts anonymous connections. Any client can read and publish "
                        "device messages. Require authentication and enable TLS (port 8883).")
    return None


# --- Unauthenticated firmware-update endpoint -------------------------------

# Common IoT/router/camera firmware-upload paths. Kept to well-known, widely
# reused patterns (many vendors ship the same reference web UI) rather than a
# broad wordlist, to keep this probe fast and its false-positive rate low.
_FIRMWARE_PATHS = (
    "/cgi-bin/upgrade.cgi", "/upgrade.cgi", "/firmware.cgi", "/firmwareupgrade.htm",
    "/upgrade_action.cgi", "/system_upgrade.htm", "/fwupdate.cgi", "/api/v1/firmware/upload",
    "/goform/formFirmwareUpgrade",
)


def unauthenticated_firmware_endpoint(ip: str, port: int, service: str, timeout: float = 5.0) -> dict | None:
    """Checks whether a firmware-upload page is reachable without logging in
    first: "Lack of Secure Update Mechanisms" made concrete. A device that lets
    anyone reach its upload form can potentially be flashed with malicious
    firmware by anyone on the network."""
    scheme = "https" if (service or "").lower() == "https" else "http"
    for path in _FIRMWARE_PATHS:
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)  # nosec B501
        except requests.RequestException:
            continue
        if resp.status_code == 200:
            return _finding("insecure_update_endpoint", "critical", 8.5,
                            f"A firmware-update page ({path}) is reachable without logging in first. "
                            "Anyone on the network could potentially upload malicious firmware. Put this "
                            "page behind authentication.")
    return None
