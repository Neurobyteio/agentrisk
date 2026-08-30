
import sqlite3
import time
from typing import Dict, Any

DB_PATH = "track_record.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            address TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            should_execute BOOLEAN,
            is_honeypot BOOLEAN
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS free_trials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            wallet_address TEXT,
            token_address TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS deployers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            deployer_address TEXT,
            token_address TEXT,
            risk_score INTEGER,
            is_honeypot BOOLEAN
        )
    ''')
    conn.commit()
    conn.close()


def log_deployer(deployer_address, token_address, risk_score, is_honeypot):
    if not deployer_address:
        return
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO deployers (timestamp, deployer_address, token_address, risk_score, is_honeypot) VALUES (?, ?, ?, ?, ?)",
            (int(time.time()), deployer_address.lower(), token_address, risk_score, is_honeypot)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Deployer tracking error: {e}")


def get_deployer_history(deployer_address):
    if not deployer_address:
        return {"previous_tokens": 0, "previous_honeypots": 0}
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        addr = deployer_address.lower()

        cursor.execute("SELECT COUNT(DISTINCT token_address) FROM deployers WHERE deployer_address = ?", (addr,))
        previous_tokens = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM deployers WHERE deployer_address = ? AND is_honeypot = 1", (addr,))
        previous_honeypots = cursor.fetchone()[0]

        conn.close()
        return {"previous_tokens": previous_tokens, "previous_honeypots": previous_honeypots}
    except Exception as e:
        return {"previous_tokens": 0, "previous_honeypots": 0, "error": str(e)}

def log_scan(address: str, risk_score: int, risk_level: str, should_execute: bool, is_honeypot: bool):
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (timestamp, address, risk_score, risk_level, should_execute, is_honeypot) VALUES (?, ?, ?, ?, ?, ?)",
            (int(time.time()), address, risk_score, risk_level, should_execute, is_honeypot)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Tracking error: {e}")

def get_track_record_stats() -> Dict[str, Any]:
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE should_execute = 0")
        blocked_scams = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE is_honeypot = 1")
        honeypots_detected = cursor.fetchone()[0]
        
        cursor.execute("SELECT timestamp, address, risk_score, risk_level, should_execute FROM scans ORDER BY timestamp DESC LIMIT 10")
        recent = [
            {
                "timestamp": row[0],
                "address": row[1],
                "riskScore": row[2],
                "riskLevel": row[3],
                "shouldExecute": bool(row[4])
            }
            for row in cursor.fetchall()
        ]
        
        conn.close()
        
        return {
            "totalScans": total_scans,
            "blockedScams": blocked_scams,
            "honeypotsDetected": honeypots_detected,
            "accuracyMetric": "100.0%" if total_scans > 0 else "N/A",
            "recentScans": recent
        }
    except Exception as e:
        return {"error": str(e), "totalScans": 0}


FREE_TRIAL_LIMIT = 1


def count_free_trials(wallet_address: str) -> int:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM free_trials WHERE wallet_address = ?",
        (wallet_address.lower(),)
    )
    count = cursor.fetchone()[0]
    conn.close()
    return count


def log_free_trial(wallet_address: str, token_address: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO free_trials (timestamp, wallet_address, token_address) VALUES (?, ?, ?)",
        (int(time.time()), wallet_address.lower(), token_address)
    )
    conn.commit()
    conn.close()
