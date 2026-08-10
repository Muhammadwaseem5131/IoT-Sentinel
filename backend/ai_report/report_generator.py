import logging

from ai_report import prompts
from ai_report.providers import PROVIDERS
from db import models
from security import settings_store

logger = logging.getLogger(__name__)


class NoProviderConfiguredError(RuntimeError):
    pass


def _active_provider():
    """Instantiates the currently configured AI provider, or raises."""
    provider_name = settings_store.get_ai_provider().get("provider")
    if not provider_name:
        raise NoProviderConfiguredError("Add a key in Settings to use this.")
    if provider_name == "ollama":
        return provider_name, PROVIDERS["ollama"]()
    api_key = settings_store.get_provider_key(provider_name)
    if not api_key:
        raise NoProviderConfiguredError(f"The saved key for '{provider_name}' is missing. Add it again in Settings.")
    provider_cls = PROVIDERS.get(provider_name)
    if not provider_cls:
        raise ValueError(f"Unknown provider: {provider_name}")
    return provider_name, provider_cls(api_key=api_key)


def generate_report(scan_id: int) -> str:
    """Generates a plain-language report for a scan using the active AI provider."""
    scan_report = models.get_scan_report(scan_id)
    if not scan_report:
        raise ValueError(f"Scan {scan_id} not found.")
    provider_name, provider = _active_provider()
    payload = prompts.build_report_payload(scan_report)
    logger.info("Generating report for scan %s via %s", scan_id, provider_name)
    return provider.generate_report(payload, prompts.SYSTEM_PROMPT)


def generate_device_explanation(device_id: int) -> str:
    """Generates a plain-language explanation + remediation for one device."""
    device = models.get_device_details(device_id)
    if not device:
        raise ValueError(f"Device {device_id} not found.")
    provider_name, provider = _active_provider()
    payload = prompts.build_device_payload(device)
    logger.info("Explaining device %s via %s", device_id, provider_name)
    return provider.generate_report(payload, prompts.DEVICE_SYSTEM_PROMPT)


def generate_wireless_explanation(finding_id: int) -> str:
    """Generates a plain-language explanation + fix for one wireless finding."""
    finding = models.get_wireless_finding(finding_id)
    if not finding:
        raise ValueError(f"Wireless finding {finding_id} not found.")
    provider_name, provider = _active_provider()
    payload = prompts.build_wireless_payload(finding)
    logger.info("Explaining wireless finding %s via %s", finding_id, provider_name)
    return provider.generate_report(payload, prompts.WIRELESS_SYSTEM_PROMPT)
