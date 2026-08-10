"""Offline, rule-based vulnerability detection for common IoT weaknesses.

CVE matching (cve_match.py) needs internet + a product banner and often returns
nothing for generic IoT devices. This engine complements it: it flags insecure,
cleartext, and dangerous services from the open-port profile alone, so every
device gets meaningful findings even offline. Maps to the OWASP IoT Top 10
(insecure network services, insecure defaults, lack of encryption).

Each rule carries a `weight` (0-10, CVSS-like) that feeds the risk score.
"""

# port -> (finding_type, severity, weight, description)
_PORT_RULES = {
    23:   ("insecure_service", "high", 8.0,
           "Telnet is enabled. It sends credentials in cleartext and is the #1 infection "
           "vector for IoT botnets (Mirai). Disable Telnet and use SSH instead."),
    2323: ("insecure_service", "high", 8.0,
           "Telnet on alternate port 2323, a well-known IoT botnet target. Disable it."),
    21:   ("insecure_service", "medium", 5.0,
           "FTP transmits credentials and files in cleartext. Check for anonymous access and "
           "move to SFTP/FTPS."),
    69:   ("insecure_service", "medium", 5.0,
           "TFTP is open. It has no authentication and can leak firmware/config files."),
    445:  ("insecure_service", "medium", 6.0,
           "SMB file sharing is exposed. Ensure the host is patched (EternalBlue/WannaCry) and "
           "never reachable from the internet."),
    139:  ("insecure_service", "medium", 5.0,
           "NetBIOS/legacy SMB is exposed, often leaking host info and enabling lateral movement."),
    3389: ("insecure_service", "high", 7.0,
           "Remote Desktop (RDP) is exposed, a top target for brute-forcing and ransomware. "
           "Restrict it to a VPN or trusted IPs."),
    161:  ("insecure_config", "medium", 5.0,
           "SNMP is enabled. Default community strings ('public'/'private') expose device "
           "configuration. Disable SNMP or set a strong community string."),
    554:  ("insecure_service", "medium", 5.0,
           "RTSP video stream exposed. Many cameras stream with no password; confirm it "
           "requires authentication."),
    1883: ("insecure_service", "medium", 5.0,
           "MQTT broker exposed without TLS. If unauthenticated, anyone on the network can read "
           "and publish device messages. Enable auth and TLS (port 8883)."),
    5683: ("insecure_service", "medium", 4.0,
           "CoAP is exposed and can be abused for reflection/amplification DDoS. Restrict access."),
    502:  ("insecure_service", "high", 7.5,
           "Modbus (industrial control) is exposed. The protocol has no authentication, so exposure "
           "allows direct control of connected equipment."),
    102:  ("insecure_service", "high", 7.0,
           "Siemens S7 / ICS protocol exposed with no authentication."),
    47808:("insecure_service", "medium", 5.0,
           "BACnet building-automation protocol exposed without authentication."),
    9100: ("insecure_service", "low", 3.0,
           "Raw printing port (JetDirect) open. Can be abused to reset the printer, capture "
           "print jobs, or run PJL commands."),
    37777:("insecure_service", "medium", 6.0,
           "Dahua camera/DVR service port exposed, historically vulnerable to authentication "
           "bypass and default credentials."),
    34567:("insecure_service", "medium", 6.0,
           "Xiongmai/generic DVR service port exposed, associated with default credentials and "
           "IoT botnet recruitment."),
    6667: ("suspicious_service", "medium", 5.0,
           "IRC port open. On an IoT device this can indicate botnet command-and-control."),
    5900: ("insecure_service", "high", 7.0,
           "VNC remote-desktop exposed, frequently unauthenticated or weakly authenticated."),
}

# Ports that make a device meaningfully riskier when internet-facing.
_RISKY_WHEN_EXPOSED = {23, 2323, 21, 445, 139, 3389, 5900, 1883, 554, 502, 102, 161, 37777, 34567}

_HTTP_PORTS = {80, 8080, 8000, 8081}
_HTTPS_PORTS = {443, 8443}


def _finding(ftype, severity, weight, description):
    return {"finding_type": ftype, "severity": severity, "weight": weight, "description": description}


def evaluate(open_ports: list[dict], internet_facing: bool = False) -> list[dict]:
    """Returns rule-based vulnerability findings for a device's open ports."""
    ports = {p.get("port") for p in open_ports if p.get("port") is not None}
    findings = []

    for port in sorted(ports):
        rule = _PORT_RULES.get(port)
        if rule:
            findings.append(_finding(*rule))

    # Unencrypted management interface (HTTP with no HTTPS alternative).
    if (ports & _HTTP_PORTS) and not (ports & _HTTPS_PORTS):
        findings.append(_finding(
            "weak_encryption", "low", 3.0,
            "Management/web interface served over unencrypted HTTP. Credentials and session "
            "cookies can be intercepted on the network. Enable HTTPS."))

    # Internet-facing device that also exposes a risky service.
    if internet_facing and (ports & _RISKY_WHEN_EXPOSED):
        exposed = ", ".join(str(p) for p in sorted(ports & _RISKY_WHEN_EXPOSED))
        findings.append(_finding(
            "exposure", "high", 7.5,
            f"This device is internet-facing and exposes network service(s) on port(s) {exposed}. "
            "Internet-reachable IoT services are actively scanned and attacked. Close these ports "
            "or place the device behind a firewall/VPN."))

    # Large attack surface.
    if len(ports) >= 6:
        findings.append(_finding(
            "attack_surface", "low", 2.5,
            f"Large attack surface: {len(ports)} open ports. Every exposed service is a potential "
            "entry point; disable anything not in use."))

    return findings
