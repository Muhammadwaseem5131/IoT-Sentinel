import logging
import threading

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from config import validate_subnet

router = APIRouter(prefix="/api", tags=["scans"])

logger = logging.getLogger(__name__)

# Serializes scan starts; one scan runs at a time (see models.scan_running()).
_start_lock = threading.Lock()


class ScanRequest(BaseModel):
    subnet: str
    test_creds: bool = False


class WirelessFinding(BaseModel):
    ssid: str | None = None
    bssid: str | None = None
    encryption: str | None = None
    finding_type: str
    details: str | None = None


class WirelessRequest(BaseModel):
    findings: list[WirelessFinding]


@router.post("/scans")
def start_scan(req: ScanRequest):
    """Starts a scan. Returns immediately; the scan runs in the background and
    progress is polled via GET /scans/{id}."""
    from db import models

    subnet_input = req.subnet.strip()
    try:
        subnet = validate_subnet(subnet_input)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    with _start_lock:
        if models.scan_running():
            raise HTTPException(status_code=409, detail="A scan is already running.")
        scan_id = models.create_scan(subnet, scan_type="core")

    from core.scan_runner import run_scan_job
    threading.Thread(
        target=run_scan_job, args=(scan_id, subnet, req.test_creds), daemon=True
    ).start()
    return {"scan_id": scan_id, "status": "running"}


@router.get("/scans")
def list_scans(limit: int = Query(50, ge=1, le=200)):
    from db import models
    return models.list_scans(limit=limit)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    from db import models
    report = models.get_scan_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report


@router.get("/scans/{scan_id}/diff")
def get_diff(scan_id: int):
    """Diffs a scan against the previous scan of the same subnet."""
    from core import diff
    from db import models

    current = models.get_scan_report(scan_id)
    if not current:
        raise HTTPException(status_code=404, detail="Scan not found")
    prev_id = models.get_previous_scan(scan_id, current["subnet"])
    previous = models.get_scan_report(prev_id) if prev_id else None
    return diff.compute_diff(current, previous)


@router.get("/scans/{scan_id}/report")
def get_report(scan_id: int):
    """Generates the AI report for a scan."""
    from ai_report.report_generator import NoProviderConfiguredError, generate_report

    try:
        text = generate_report(scan_id)
    except NoProviderConfiguredError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001 - surface provider errors cleanly
        logger.exception("Report generation failed for scan %s", scan_id)
        raise HTTPException(status_code=502, detail="Report generation failed. Check provider settings.")
    return {"report": text}


@router.get("/scans/{scan_id}/devices/{device_id}/explain")
def explain_device(scan_id: int, device_id: int):
    """AI explanation of a single device's vulnerabilities and how to fix them."""
    from ai_report.report_generator import NoProviderConfiguredError, generate_device_explanation

    try:
        text = generate_device_explanation(device_id)
    except NoProviderConfiguredError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001
        logger.exception("Device explanation failed for device %s", device_id)
        raise HTTPException(status_code=502, detail="AI explanation failed. Check provider settings.")
    return {"explanation": text}


@router.get("/scans/{scan_id}/wireless/{finding_id}/explain")
def explain_wireless(scan_id: int, finding_id: int):
    """AI explanation of a single wireless finding and how to fix it."""
    from ai_report.report_generator import NoProviderConfiguredError, generate_wireless_explanation

    try:
        text = generate_wireless_explanation(finding_id)
    except NoProviderConfiguredError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001
        logger.exception("Wireless explanation failed for finding %s", finding_id)
        raise HTTPException(status_code=502, detail="AI explanation failed. Check provider settings.")
    return {"explanation": text}


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def get_report_html(scan_id: int, ai: bool = Query(False, description="Include AI narrative if a provider is set")):
    """Standalone printable HTML report (print-to-PDF ready). Works offline; the
    AI narrative is included only when ai=true and a provider is configured."""
    from ai_report import report_html
    from db import models

    report = models.get_scan_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan not found")

    narrative = None
    if ai:
        try:
            from ai_report.report_generator import generate_report
            narrative = generate_report(scan_id)
        except Exception:  # noqa: BLE001 - export must never fail on provider issues
            logger.warning("AI narrative unavailable for HTML export of scan %s", scan_id)
    return HTMLResponse(report_html.render(report, narrative))


@router.get("/wireless/status")
def wireless_status():
    """Reports whether the wireless module can run on this host."""
    from wireless.monitor_check import list_interfaces, wireless_supported

    supported = wireless_supported()
    return {
        "supported": supported,
        "interfaces": list_interfaces() if supported else [],
        "reason": None if supported else "Requires Linux with a monitor-mode adapter and aircrack-ng.",
    }


@router.get("/wireless/adapters")
def wireless_adapters():
    """Lists WiFi adapters and whether each can do monitor mode."""
    from wireless import adapters
    return adapters.list_adapters()


class MonitorRequest(BaseModel):
    interface: str
    enable: bool = True


@router.post("/wireless/monitor")
def wireless_monitor(req: MonitorRequest):
    """Enables or disables monitor mode on an adapter (Linux + root)."""
    from wireless import adapters

    try:
        if req.enable:
            return adapters.enable_monitor(req.interface)
        return adapters.disable_monitor(req.interface)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class DiscoverRequest(BaseModel):
    interface: str
    duration: int = 15


@router.post("/wireless/discover")
def wireless_discover(req: DiscoverRequest):
    """Standalone passive WiFi survey: lists nearby networks and their weakness
    classification, without attaching anything to a scan. Powers the dedicated
    Wireless page. Requires monitor mode active on this host."""
    from wireless import wifi_scan
    from wireless.monitor_check import wireless_supported

    if not wireless_supported():
        raise HTTPException(status_code=400, detail="Wireless module unavailable on this host.")

    duration = max(5, min(req.duration, 60))
    try:
        findings = wifi_scan.capture_findings(req.interface, duration)
    except wifi_scan.WirelessUnavailableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001
        logger.exception("Wireless discovery failed on %s", req.interface)
        raise HTTPException(status_code=502, detail="Discovery failed. Check the interface is in monitor mode.")
    return {"networks": findings}


class WpsCheckRequest(BaseModel):
    interface: str
    bssid: str
    confirm: bool = False


@router.post("/wireless/wps-check")
def wireless_wps_check(req: WpsCheckRequest):
    """Active WPS vulnerability test against one network: sends WPS probe frames
    to the target BSSID (via wash) to see if PIN-based WPS is enabled and
    unlocked. This transmits to the target, unlike passive discovery, so it
    requires explicit confirm=true, the same opt-in gate as default-cred
    testing. Only test networks you own or are authorized to test."""
    from wireless import wifi_scan
    from wireless.monitor_check import wireless_supported

    if not req.confirm:
        raise HTTPException(status_code=400, detail="This test transmits to the target network. Confirm to proceed.")
    if not wireless_supported():
        raise HTTPException(status_code=400, detail="Wireless module unavailable on this host.")

    try:
        result = wifi_scan.check_wps(req.interface, req.bssid)
    except wifi_scan.WirelessUnavailableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001
        logger.exception("WPS check failed on %s", req.bssid)
        raise HTTPException(status_code=502, detail="WPS check failed. Check the interface is in monitor mode.")
    return result


class PmkidCheckRequest(BaseModel):
    interface: str
    bssid: str
    confirm: bool = False


@router.post("/wireless/pmkid-check")
def wireless_pmkid_check(req: PmkidCheckRequest):
    """Active PMKID capture test: the least-intrusive way to check whether a
    network's WPA2 key is offline-crackable, no client disruption or deauth.
    Still transmits to the target, so it requires explicit confirm=true."""
    from wireless import wifi_scan
    from wireless.monitor_check import wireless_supported

    if not req.confirm:
        raise HTTPException(status_code=400, detail="This test transmits to the target network. Confirm to proceed.")
    if not wireless_supported():
        raise HTTPException(status_code=400, detail="Wireless module unavailable on this host.")

    try:
        result = wifi_scan.pmkid_capture(req.interface, req.bssid)
    except wifi_scan.WirelessUnavailableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001
        logger.exception("PMKID check failed on %s", req.bssid)
        raise HTTPException(status_code=502, detail="PMKID check failed. Check the interface is in monitor mode.")
    return result


class WirelessScanRequest(BaseModel):
    interface: str
    duration: int = 15


@router.post("/scans/{scan_id}/wireless/scan")
def run_wireless_scan(scan_id: int, req: WirelessScanRequest):
    """Runs a short passive capture on this host and attaches findings to the scan.
    Only works when this backend process itself is on Linux with a monitor-mode
    adapter (see GET /wireless/status) — there is no remote-trigger path."""
    from db import models
    from wireless import wifi_scan
    from wireless.monitor_check import wireless_supported

    if not models.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    if not wireless_supported():
        raise HTTPException(status_code=400, detail="Wireless module unavailable on this host.")

    duration = max(5, min(req.duration, 60))
    try:
        findings = wifi_scan.capture_findings(req.interface, duration)
    except wifi_scan.WirelessUnavailableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:  # noqa: BLE001
        logger.exception("Wireless capture failed on %s", req.interface)
        raise HTTPException(status_code=502, detail="Wireless capture failed. Check the interface is in monitor mode.")

    for f in findings:
        models.insert_wireless_finding(
            scan_id, ssid=f.get("ssid"), bssid=f.get("bssid"), encryption=f.get("encryption"),
            finding_type=f.get("finding_type"), details=f.get("details"),
        )
    return {"status": "completed", "count": len(findings)}


@router.post("/scans/{scan_id}/wireless")
def post_wireless_findings(scan_id: int, req: WirelessRequest):
    """Ingests wireless findings (from the Linux wireless module) into the shared DB."""
    from db import models

    if not models.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    for f in req.findings:
        models.insert_wireless_finding(
            scan_id, ssid=f.ssid, bssid=f.bssid, encryption=f.encryption,
            finding_type=f.finding_type, details=f.details,
        )
    return {"status": "recorded", "count": len(req.findings)}


@router.get("/health")
def health():
    return {"status": "ok"}
