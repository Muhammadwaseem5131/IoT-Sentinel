import json
import logging
import os
import re
import time

import requests

from config import config

logger = logging.getLogger(__name__)

CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", ".cve_cache")
CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cache.json")
CACHE_TTL_SECONDS = 7 * 24 * 3600  # refresh cached CVEs weekly

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Fallback keywords used ONLY when a banner gives no product string. Kept tight
# to limit false positives from generic terms.
SERVICE_QUERY_MAP = {
    "rtsp": "rtsp ip camera",
    "mqtt": "mosquitto mqtt",
    "ssh": "openssh",
    "ftp": "vsftpd ftp",
    "telnet": "busybox telnet",
    "upnp": "upnp",
    "snmp": "net-snmp",
    "modbus": "modbus",
}

_STOPWORDS = {"server", "httpd", "http", "https", "the", "for", "and", "device"}


def _load_cache() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if time.time() - data.get("fetched_at", 0) > CACHE_TTL_SECONDS:
            return {}
        return data.get("cves", {})
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict):
    os.makedirs(CACHE_DIR, exist_ok=True)
    payload = {"fetched_at": time.time(), "cves": cache}
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f)


def _fetch_from_nvd(keyword: str) -> list[dict]:
    params = {"keywordSearch": keyword, "keywordExactMatch": "", "resultsPerPage": 20}
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    resp = requests.get(BASE_URL, params=params, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric_set in metrics.get(key, []):
                score = metric_set.get("cvssData", {}).get("baseScore")
                if score:
                    break
            if score:
                break
        descs = cve.get("descriptions", [])
        description = descs[0].get("value", "") if descs else ""
        cves.append({
            "cve_id": cve.get("id"),
            "base_score": score,
            "description": description[:500],
        })
    return cves


def _query(keyword: str) -> list[dict]:
    cache = _load_cache()
    if keyword not in cache:
        try:
            cache[keyword] = _fetch_from_nvd(keyword)
            _save_cache(cache)
        except (requests.RequestException, ValueError) as exc:
            logger.warning("NVD query failed for '%s': %s", keyword, exc)
            cache[keyword] = []
    return cache.get(keyword, [])


def _parse_banner(product: str | None) -> tuple[str, str | None]:
    """Splits a banner like 'lighttpd 1.4.35' into ('lighttpd', '1.4.35')."""
    if not product:
        return "", None
    text = product.strip()
    version = None
    m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", text)
    if m:
        version = m.group(1)
        text = text[: m.start()].strip()
    name = re.split(r"[\s/]", text)[0] if text else ""
    return name, version


def _relevant(cve: dict, tokens: list[str]) -> bool:
    """A CVE is kept only if its description mentions the product token, which
    cuts the noise a bare keyword search returns."""
    if not tokens:
        return True
    desc = (cve.get("description") or "").lower()
    return any(tok in desc for tok in tokens if len(tok) >= 3 and tok not in _STOPWORDS)


def match_cves(service: str | None, product: str | None, max_results: int = 5) -> list[dict]:
    """Returns CVEs relevant to a service/product, highest-severity first.

    Prefers the product+version from the banner and filters results so they
    actually mention the product; falls back to a conservative service keyword
    only when no product is known. Empty list if NVD is unreachable.
    """
    name, version = _parse_banner(product)
    if name:
        query = f"{name} {version}".strip() if version else name
        tokens = [name.lower()]
    elif service:
        query = SERVICE_QUERY_MAP.get(service.lower())
        if not query:
            return []  # too generic to search without a product banner
        tokens = [t for t in query.split() if t not in _STOPWORDS]
    else:
        return []

    matched = {}
    for cve in _query(query):
        cve_id = cve.get("cve_id")
        if cve_id and cve_id not in matched and _relevant(cve, tokens):
            matched[cve_id] = cve

    ranked = sorted(matched.values(), key=lambda c: c.get("base_score") or 0, reverse=True)
    return ranked[:max_results]
