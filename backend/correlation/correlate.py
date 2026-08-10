import logging

from correlation import (active_probes, cve_match, default_creds, kev, risk_score,
                         service_rules, tls_check)
from db import models

logger = logging.getLogger(__name__)


def run_correlation(scan_id: int, test_creds: bool = False) -> None:
    """Correlates scan results: CVE matching, (optionally) default-cred testing,
    and risk scoring for every device. Reports progress 60->100."""
    devices = models.get_devices_for_scan(scan_id)
    logger.info("Correlating %d devices for scan %s", len(devices), scan_id)

    weak_encryption, partial = _network_encryption_flags(scan_id)
    total = max(len(devices), 1)

    for i, device in enumerate(devices):
        details = models.get_device_details(device["id"])
        highest_cve_score = None
        matched_any = False
        seen_cves = set()

        for port in details.get("open_ports", []):
            for cve in cve_match.match_cves(port.get("service"), port.get("banner")):
                cve_id = cve.get("cve_id")
                if cve_id in seen_cves:
                    continue  # same CVE can match on several ports; record it once
                seen_cves.add(cve_id)
                matched_any = True
                score = cve.get("base_score")
                description = cve.get("description", "") or cve_id or ""

                if kev.is_known_exploited(cve_id):
                    severity = "critical"
                    description = "⚠ ACTIVELY EXPLOITED (CISA KEV). " + description
                    score = max(score or 0, 9.0)  # exploited-in-the-wild overrides a low CVSS
                else:
                    severity = risk_score.cve_severity_label(score)

                models.insert_finding(
                    device["id"], finding_type="cve", severity=severity,
                    description=description, cve_id=cve_id,
                )
                if score is not None and (highest_cve_score is None or score > highest_cve_score):
                    highest_cve_score = score

        # Rule-based checks: insecure services, weak encryption, exposure, attack surface.
        extra_findings = list(service_rules.evaluate(
            details.get("open_ports", []), internet_facing=bool(device.get("internet_facing"))))

        # TLS/cert weaknesses on HTTPS ports (read-only handshake, always run).
        for port in details.get("open_ports", []):
            if tls_check.is_tls_port(port.get("port"), port.get("service")):
                extra_findings += tls_check.check(device["ip_address"], port["port"])

        # Active probes (anon-FTP, SNMP, MQTT, firmware-endpoint) — only with the intrusive opt-in.
        if test_creds:
            extra_findings += active_probes.run(device["ip_address"], details.get("open_ports", []))

        for rf in extra_findings:
            matched_any = True
            models.insert_finding(device["id"], rf["finding_type"], rf["severity"], rf["description"])
            weight = rf.get("weight")
            if weight is not None and (highest_cve_score is None or weight > highest_cve_score):
                highest_cve_score = weight

        default_cred_found = _check_credentials(device, details, test_creds)

        score = risk_score.compute_risk_score(
            internet_facing=bool(device.get("internet_facing")),
            max_cve_score=highest_cve_score,
            default_cred_found=default_cred_found,
            weak_encryption=weak_encryption,
            weak_encryption_partial=partial,
        )
        models.insert_risk_score(device["id"], score)

        if not matched_any and not default_cred_found and not weak_encryption:
            models.insert_finding(
                device["id"], finding_type="info", severity="low",
                description="No known vulnerabilities matched for this device.",
            )
        models.set_scan_progress(scan_id, 60 + int(40 * (i + 1) / total), "Correlating findings")


def _check_credentials(device: dict, details: dict, test_creds: bool) -> bool:
    """Returns True if a device is confirmed (or, when not testing, flagged) as
    using default credentials. Real login attempts only run when test_creds is set."""
    candidates = default_creds.known_default_creds(device.get("vendor"), device.get("device_type"))
    if not candidates:
        return False

    if not test_creds:
        models.insert_finding(
            device["id"], finding_type="default_cred_candidate", severity="medium",
            description="This device's vendor/type ships with known default credentials. "
            "Enable credential testing to verify, or change the password to be safe.",
        )
        return False

    for port in details.get("open_ports", []):
        service = port.get("service")
        if service and service.lower() in ("http", "https"):
            hit = default_creds.http_default_cred_check(
                device["ip_address"], port["port"], service, candidates
            )
            if hit:
                user, _ = hit
                models.insert_finding(
                    device["id"], finding_type="default_cred", severity="critical",
                    description=f"Default credentials accepted over {service.upper()} "
                    f"(username '{user}'). Change this password immediately.",
                )
                return True
    return False


def _network_encryption_flags(scan_id: int) -> tuple[bool, bool]:
    """Weak-WiFi encryption is a property of the network the devices sit on; it
    comes from the wireless module's findings for this scan (empty for core-only
    scans, in which case we assume WPA2-class strength).

    Only considers findings that actually describe encryption. Findings about
    other properties (rogue_ap, wps_enabled, deauth_detected) don't populate
    the encryption field and must not flip the network-wide weak flag."""
    report = models.get_scan_report(scan_id)
    weak, partial = False, False
    for wf in report.get("wireless_findings", []):
        ftype = (wf.get("finding_type") or "").lower()
        enc = (wf.get("encryption") or "").upper()
        if ftype == "weak_encryption":
            weak = True
        elif not enc:
            continue  # non-encryption finding; skip
        elif "WEP" in enc or "OPEN" in enc:
            weak = True
        elif "WPA" in enc and "WPA2" not in enc and "WPA3" not in enc:
            partial = True
    return weak, partial
