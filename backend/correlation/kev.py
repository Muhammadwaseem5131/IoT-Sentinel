"""CISA Known Exploited Vulnerabilities (KEV) enrichment.

The KEV catalog is the U.S. government's authoritative list of CVEs that are
being *actively exploited in the wild*. Flagging a device's CVE as KEV-listed is
a much stronger signal than a raw CVSS score. Free, no API key.
"""
import json
import logging
import os
import time

import requests

logger = logging.getLogger(__name__)

CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", ".cve_cache")
CACHE_FILE = os.path.join(CACHE_DIR, "kev_cache.json")
CACHE_TTL_SECONDS = 7 * 24 * 3600  # refresh weekly

_KEV_SET: set[str] | None = None  # process-level cache so we load it once


def _load_disk_cache() -> set[str] | None:
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if time.time() - data.get("fetched_at", 0) > CACHE_TTL_SECONDS:
            return None
        return set(data.get("cve_ids", []))
    except (json.JSONDecodeError, OSError):
        return None


def _save_disk_cache(cve_ids: set[str]):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump({"fetched_at": time.time(), "cve_ids": sorted(cve_ids)}, f)


def _fetch_catalog() -> set[str]:
    resp = requests.get(CATALOG_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}


def known_exploited_set() -> set[str]:
    """Returns the set of KEV CVE IDs. Cached in memory + on disk (weekly).
    Returns an empty set (no enrichment) if the catalog can't be reached."""
    global _KEV_SET
    if _KEV_SET is not None:
        return _KEV_SET

    cached = _load_disk_cache()
    if cached is not None:
        _KEV_SET = cached
        return _KEV_SET

    try:
        _KEV_SET = _fetch_catalog()
        _save_disk_cache(_KEV_SET)
        logger.info("Loaded %d CISA KEV entries", len(_KEV_SET))
    except (requests.RequestException, ValueError, KeyError) as exc:
        logger.warning("Could not fetch CISA KEV catalog: %s", exc)
        _KEV_SET = set()
    return _KEV_SET


def is_known_exploited(cve_id: str | None) -> bool:
    return bool(cve_id) and cve_id in known_exploited_set()
