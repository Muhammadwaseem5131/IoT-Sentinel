import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.getenv("IOT_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "iot_sentinel.db"))
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

# Columns added after v1 shipped; init_db backfills them on existing DBs.
_MIGRATIONS = {
    "scans": [
        ("status", "TEXT DEFAULT 'running'"),
        ("progress", "INTEGER DEFAULT 0"),
        ("stage", "TEXT"),
        ("error", "TEXT"),
    ],
    "devices": [
        ("internet_facing", "INTEGER DEFAULT 0"),
    ],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")  # let reads (status polls) run during a scan's writes
    return conn


@contextmanager
def db_cursor():
    conn = get_connection()
    try:
        yield conn.cursor()
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()
    conn = get_connection()
    try:
        conn.executescript(schema)
        _apply_migrations(conn)
    finally:
        conn.close()


def _apply_migrations(conn):
    for table, columns in _MIGRATIONS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    conn.commit()


def create_scan(subnet: str, scan_type: str = "core") -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO scans (started_at, subnet, scan_type, status, progress) "
            "VALUES (?, ?, ?, 'running', 0)",
            (_now(), subnet, scan_type),
        )
        return cur.lastrowid


def set_scan_progress(scan_id: int, progress: int, stage: str = None):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE scans SET progress = ?, stage = COALESCE(?, stage) WHERE id = ?",
            (max(0, min(100, progress)), stage, scan_id),
        )


def finish_scan(scan_id: int):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE scans SET finished_at = ?, status = 'completed', progress = 100 WHERE id = ?",
            (_now(), scan_id),
        )


def fail_scan(scan_id: int, error: str):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE scans SET finished_at = ?, status = 'failed', error = ? WHERE id = ?",
            (_now(), error[:500], scan_id),
        )


def scan_running() -> bool:
    with db_cursor() as cur:
        cur.execute("SELECT 1 FROM scans WHERE status = 'running' LIMIT 1")
        return cur.fetchone() is not None


def insert_device(scan_id: int, ip: str, mac: str = None, vendor: str = None,
                  hostname: str = None, device_type: str = None,
                  internet_facing: bool = False) -> int:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO devices (scan_id, ip_address, mac_address, vendor, hostname, "
            "device_type, internet_facing) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, ip, mac, vendor, hostname, device_type, 1 if internet_facing else 0),
        )
        return cur.lastrowid


def insert_port(device_id: int, port: int, service: str = None, banner: str = None):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO open_ports (device_id, port, service, banner) VALUES (?, ?, ?, ?)",
            (device_id, port, service, banner),
        )


def insert_finding(device_id: int, finding_type: str, severity: str, description: str, cve_id: str = None):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO findings (device_id, finding_type, cve_id, severity, description) "
            "VALUES (?, ?, ?, ?, ?)",
            (device_id, finding_type, cve_id, severity, description),
        )


def insert_risk_score(device_id: int, score: int):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO risk_scores (device_id, score, computed_at) VALUES (?, ?, ?)",
            (device_id, score, _now()),
        )


def insert_wireless_finding(scan_id: int, ssid=None, bssid=None, encryption=None,
                            finding_type="info", details=None):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO wireless_findings (scan_id, ssid, bssid, encryption, finding_type, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, ssid, bssid, encryption, finding_type, details),
        )


def get_wireless_finding(finding_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM wireless_findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_scan(scan_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_previous_scan(scan_id: int, subnet: str):
    """The most recent completed scan of the same subnet before this one."""
    with db_cursor() as cur:
        cur.execute(
            "SELECT id FROM scans WHERE subnet = ? AND id < ? AND status = 'completed' "
            "ORDER BY id DESC LIMIT 1",
            (subnet, scan_id),
        )
        row = cur.fetchone()
        return row["id"] if row else None


def list_scans(limit: int = 50):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]


def get_devices_for_scan(scan_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM devices WHERE scan_id = ? ORDER BY ip_address", (scan_id,))
        return [dict(row) for row in cur.fetchall()]


def get_device_details(device_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        device = cur.fetchone()
        if not device:
            return None
        result = dict(device)
        cur.execute("SELECT * FROM open_ports WHERE device_id = ?", (device_id,))
        result["open_ports"] = [dict(row) for row in cur.fetchall()]
        cur.execute("SELECT * FROM findings WHERE device_id = ?", (device_id,))
        result["findings"] = [dict(row) for row in cur.fetchall()]
        cur.execute("SELECT score FROM risk_scores WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,))
        row = cur.fetchone()
        result["risk_score"] = row["score"] if row else None
        return result


def get_scan_report(scan_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = cur.fetchone()
        if not scan:
            return None
        result = dict(scan)
        result["devices"] = []
        cur.execute("SELECT * FROM devices WHERE scan_id = ? ORDER BY ip_address", (scan_id,))
        for device in cur.fetchall():
            dev = dict(device)
            cur.execute("SELECT * FROM open_ports WHERE device_id = ?", (dev["id"],))
            dev["open_ports"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM findings WHERE device_id = ?", (dev["id"],))
            dev["findings"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT score FROM risk_scores WHERE device_id = ? ORDER BY id DESC LIMIT 1", (dev["id"],))
            score_row = cur.fetchone()
            dev["risk_score"] = score_row["score"] if score_row else None
            result["devices"].append(dev)
        cur.execute("SELECT * FROM wireless_findings WHERE scan_id = ?", (scan_id,))
        result["wireless_findings"] = [dict(r) for r in cur.fetchall()]
        return result
