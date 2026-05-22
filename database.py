import sqlite3
import json
import os

DB_FILE = "archon_data.db"

def init_db(db_path=DB_FILE):
    """
    Initializes the SQLite database and creates the scan_findings, watcher_ssl_cache, and alerts tables.
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                connector TEXT NOT NULL,
                data TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS watcher_ssl_cache (
                target TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                expiry TEXT NOT NULL,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def save_finding(target, connector, data, db_path=DB_FILE):
    """
    Saves a finding to the scan_findings table. Converts dict data to JSON string if needed.
    """
    if isinstance(data, dict):
        data_str = json.dumps(data)
    else:
        data_str = str(data)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scan_findings (target, connector, data) VALUES (?, ?, ?)",
            (target, connector, data_str)
        )
        conn.commit()

def get_findings(target, db_path=DB_FILE):
    """
    Retrieves all scan findings for a given target.
    """
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target, connector, data, timestamp FROM scan_findings WHERE target = ?",
            (target,)
        )
        rows = cursor.fetchall()
        
    findings = []
    for row in rows:
        try:
            parsed_data = json.loads(row[3])
        except Exception:
            parsed_data = row[3]
        findings.append({
            "id": row[0],
            "target": row[1],
            "connector": row[2],
            "data": parsed_data,
            "timestamp": row[4]
        })
    return findings

def add_alert(alert_type, target, message, db_path=DB_FILE):
    """Adds a system alert (e.g. SSL fingerprint change, new subdomain)."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO alerts (type, target, message) VALUES (?, ?, ?)",
            (alert_type, target, message)
        )
        conn.commit()

def get_alerts(db_path=DB_FILE):
    """Retrieves all active system alerts."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, type, target, message, timestamp FROM alerts ORDER BY timestamp DESC")
        rows = cursor.fetchall()
    return [{
        "id": r[0],
        "type": r[1],
        "target": r[2],
        "message": r[3],
        "timestamp": r[4]
    } for r in rows]

def get_ssl_cache(target, db_path=DB_FILE):
    """Fetches cached SSL credentials for a target."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT fingerprint, expiry FROM watcher_ssl_cache WHERE target = ?", (target,))
        row = cursor.fetchone()
    if row:
        return {"fingerprint": row[0], "expiry": row[1]}
    return None

def update_ssl_cache(target, fingerprint, expiry, db_path=DB_FILE):
    """Updates or replaces the cached SSL fingerprint and expiry."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO watcher_ssl_cache (target, fingerprint, expiry, last_checked) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            (target, fingerprint, expiry)
        )
        conn.commit()
