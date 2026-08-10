import ipaddress
import os

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))


class Config:
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    SCAN_SUBNET = os.getenv("SCAN_SUBNET", "192.168.1.0/24")
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8000"))
    SECRETS_ENCRYPTION_KEY_PATH = os.getenv(
        "SECRETS_ENCRYPTION_KEY_PATH",
        os.path.join(os.path.dirname(__file__), ".secrets.key"),
    )


def validate_subnet(subnet: str) -> str:
    subnet = subnet.strip()
    # A bare IP (no CIDR suffix) means "scan this device's /24 network" — the
    # common intent when someone types their router/PC address.
    if subnet and "/" not in subnet and ":" not in subnet:
        subnet = f"{subnet}/24"
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {subnet}") from exc
    if network.num_addresses < 2:
        raise ValueError(f"Subnet too small: {subnet}")
    if network.num_addresses > 4096:
        raise ValueError(f"Subnet too large ({network.num_addresses} hosts); use /20 or smaller: {subnet}")
    return str(network)


config = Config()
