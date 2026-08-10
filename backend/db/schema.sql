CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    subnet TEXT,
    scan_type TEXT,
    status TEXT DEFAULT 'running',
    progress INTEGER DEFAULT 0,
    stage TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    ip_address TEXT,
    mac_address TEXT,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,
    internet_facing INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS open_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER REFERENCES devices(id),
    port INTEGER,
    service TEXT,
    banner TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER REFERENCES devices(id),
    finding_type TEXT,
    cve_id TEXT,
    severity TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER REFERENCES devices(id),
    score INTEGER,
    computed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wireless_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    ssid TEXT,
    bssid TEXT,
    encryption TEXT,
    finding_type TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_encrypted BLOB,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_device ON open_ports(device_id);
CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id);
CREATE INDEX IF NOT EXISTS idx_risk_device ON risk_scores(device_id);
CREATE INDEX IF NOT EXISTS idx_wireless_scan ON wireless_findings(scan_id);
