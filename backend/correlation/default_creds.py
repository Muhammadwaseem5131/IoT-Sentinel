import logging

import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

DEFAULT_CREDS = {
    "hikvision": [("admin", "12345"), ("admin", "admin")],
    "tp-link": [("admin", "admin"), ("admin", "password")],
    "dlink": [("admin", "admin")],
    "netgear": [("admin", "password"), ("admin", "1234")],
    "busybox": [("root", ""), ("root", "root")],
    "camera": [("admin", "12345"), ("admin", "admin"), ("root", "root")],
    "router": [("admin", "admin"), ("admin", "password")],
}

# Which services are safe to probe with default credentials.
CRED_TEST_SERVICES = {"telnet", "ssh", "ftp", "http", "https"}


def known_default_creds(vendor: str | None, device_type: str | None) -> list[tuple[str, str]]:
    """Returns candidate default credentials for a device, or [] if unknown."""
    creds = []
    if vendor:
        key = vendor.lower()
        for known, pairs in DEFAULT_CREDS.items():
            if known in key:
                creds.extend(pairs)
    if device_type:
        key = device_type.lower()
        for known, pairs in DEFAULT_CREDS.items():
            if known == key:
                creds.extend(pairs)
    seen = set()
    unique = []
    for pair in creds:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    return unique


def cred_test_allowed(service: str | None) -> bool:
    return (service or "").lower() in CRED_TEST_SERVICES


def http_default_cred_check(ip: str, port: int, service: str,
                            candidates: list[tuple[str, str]],
                            timeout: float = 5.0) -> tuple[str, str] | None:
    """Actively tests HTTP Basic-Auth default credentials against a device.

    Only attempts login if the endpoint actually challenges for auth (HTTP 401),
    so we never send credentials to an open page. Returns the first accepted
    (user, pass) pair, or None. Intended to run only under an explicit opt-in.
    """
    scheme = "https" if service.lower() == "https" else "http"
    base = f"{scheme}://{ip}:{port}/"
    try:
        probe = requests.get(base, timeout=timeout, verify=False)  # nosec B501 - IoT devices use self-signed certs
    except requests.RequestException as exc:
        logger.debug("Cred probe unreachable %s: %s", base, exc)
        return None

    if probe.status_code != 401:
        return None  # not Basic-Auth protected; nothing to test here

    for user, password in candidates:
        try:
            resp = requests.get(base, auth=HTTPBasicAuth(user, password),
                                timeout=timeout, verify=False)  # nosec B501
        except requests.RequestException:
            continue
        if resp.status_code in (200, 301, 302, 303):
            logger.info("Default credential accepted on %s (user=%s)", base, user)
            return (user, password)
    return None
