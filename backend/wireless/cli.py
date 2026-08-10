"""CLI entrypoint for the wireless module.

Runs on Linux with a monitor-mode adapter and posts findings to the Core backend
(or writes them to a local SQLite DB directly).

Usage:
    python -m wireless.cli --interface wlan0 --duration 30
        [--api-endpoint http://<core-host>:8000 --scan-id 5]
        [--deauth BSSID] [--wps BSSID]
"""
import argparse
import logging
import sys

from wireless import wifi_scan
from wireless.monitor_check import wireless_supported

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="IoT-Sentinel wireless scanner")
    parser.add_argument("--interface", required=True, help="WiFi interface in monitor mode")
    parser.add_argument("--duration", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("--api-endpoint", help="Core backend URL, e.g. http://192.168.1.10:8000")
    parser.add_argument("--scan-id", type=int, help="Scan ID to attach findings to")
    parser.add_argument("--deauth", help="BSSID to watch for deauth floods against")
    parser.add_argument("--wps", help="BSSID to check WPS status on")
    parser.add_argument("--db-path", help="Write findings directly to a local SQLite DB instead")
    args = parser.parse_args()

    if not wireless_supported():
        logger.error("Wireless module unavailable: requires Linux + aircrack-ng + monitor-mode adapter.")
        sys.exit(1)

    logger.info("Capturing wireless environment on %s for %ds...", args.interface, args.duration)
    findings = wifi_scan.capture_findings(args.interface, args.duration)
    logger.info("Captured %d findings", len(findings))

    if args.deauth:
        count = wifi_scan.detect_deauth(args.interface, args.deauth, args.duration)
        if count > 0:
            findings.append({
                "ssid": None, "bssid": args.deauth, "encryption": None,
                "finding_type": "deauth_detected",
                "details": f"Deauth flood detected: {count} frames",
            })
        logger.info("Deauth frames seen: %d", count)

    if args.wps:
        wps = wifi_scan.check_wps(args.interface, args.wps)
        if wps["wps_enabled"]:
            findings.append({
                "ssid": None, "bssid": args.wps, "encryption": None,
                "finding_type": "wps_enabled",
                "details": wps["details"],
            })

    if args.api_endpoint and args.scan_id:
        wifi_scan.push_to_backend(args.api_endpoint, args.scan_id, findings)
        logger.info("Posted %d findings to %s for scan %s", len(findings), args.api_endpoint, args.scan_id)
    elif args.db_path:
        from db import models
        models.init_db()
        for f in findings:
            with models.db_cursor() as cur:
                cur.execute(
                    "INSERT INTO wireless_findings (scan_id, ssid, bssid, encryption, finding_type, details) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (args.scan_id, f.get("ssid"), f.get("bssid"), f.get("encryption"),
                     f.get("finding_type"), f.get("details")),
                )
        logger.info("Wrote %d findings to local DB", len(findings))
    else:
        logger.info("No --api-endpoint/--scan-id or --db-path given; findings were not persisted.")


if __name__ == "__main__":
    main()
