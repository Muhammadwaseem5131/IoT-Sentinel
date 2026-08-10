"""TLS / certificate weakness detection for HTTPS services.

Makes a normal TLS handshake (read-only, like a browser) to inspect the
certificate and which protocol versions the device accepts. Fails closed.
"""
import datetime
import logging
import socket
import ssl

from cryptography import x509

logger = logging.getLogger(__name__)

HTTPS_PORTS = {443, 8443, 8843, 9443}


def _finding(severity, weight, description):
    return {"finding_type": "weak_tls", "severity": severity, "weight": weight, "description": description}


def is_tls_port(port: int, service: str | None) -> bool:
    return port in HTTPS_PORTS or (service or "").lower() in ("https", "ssl", "tls", "https-alt")


def check(ip: str, port: int, timeout: float = 5.0) -> list[dict]:
    findings = []
    cert = _get_cert(ip, port, timeout)
    if cert is not None:
        try:
            if cert.issuer == cert.subject:
                findings.append(_finding(
                    "low", 3.0,
                    "Device presents a self-signed TLS certificate. Its identity can't be verified, "
                    "so connections are open to interception. Common on IoT, but means no trusted identity."))
            not_after = _not_after(cert)
            if not_after and not_after < datetime.datetime.now(datetime.timezone.utc):
                findings.append(_finding(
                    "medium", 5.0,
                    f"TLS certificate expired on {not_after.date()}. An expired certificate signals an "
                    "unmaintained device and breaks trust in the connection."))
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cert inspection failed for %s:%s: %s", ip, port, exc)

    legacy = _legacy_protocol(ip, port, timeout)
    if legacy:
        findings.append(_finding(
            "medium", 5.5,
            f"Server negotiates {legacy}, a deprecated protocol vulnerable to downgrade/BEAST/POODLE-class "
            "attacks. Require TLS 1.2 or higher."))
    return findings


def _get_cert(ip: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as tls:
                der = tls.getpeercert(binary_form=True)
        return x509.load_der_x509_certificate(der) if der else None
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        return None


def _not_after(cert):
    # cryptography >=42 exposes tz-aware *_utc; fall back for older versions.
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _legacy_protocol(ip: str, port: int, timeout: float) -> str | None:
    for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            continue  # local OpenSSL won't even allow this legacy version
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=None):
                    return label  # handshake succeeded at a legacy version
        except (ssl.SSLError, socket.timeout, OSError):
            continue
    return None
