"""Compares a scan to the previous scan of the same subnet: which devices
appeared or disappeared, and whose risk changed. Pure function, easy to test."""


def compute_diff(current: dict, previous: dict | None) -> dict:
    if not previous:
        return {"has_previous": False}

    cur = {d["ip_address"]: d for d in current.get("devices", [])}
    prev = {d["ip_address"]: d for d in previous.get("devices", [])}

    new_devices = sorted(ip for ip in cur if ip not in prev)
    removed_devices = sorted(ip for ip in prev if ip not in cur)

    risk_changes = []
    for ip in cur:
        if ip in prev:
            old, new = prev[ip].get("risk_score"), cur[ip].get("risk_score")
            if old != new:
                risk_changes.append({"ip": ip, "old": old, "new": new,
                                     "delta": (new or 0) - (old or 0)})
    risk_changes.sort(key=lambda c: abs(c["delta"]), reverse=True)

    return {
        "has_previous": True,
        "previous_scan_id": previous.get("id"),
        "new_devices": new_devices,
        "removed_devices": removed_devices,
        "risk_changes": risk_changes,
    }
