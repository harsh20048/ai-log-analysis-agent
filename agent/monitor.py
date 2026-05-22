import sqlite3
import json
import os
from datetime import datetime
from agent.log_parser import read_existing_logs, tail_log_file, detect_log_type
from agent.analyzer import analyze_logs
from agent.alerter import send_alert
from config import RISK_ALERT_THRESHOLD

SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}


def init_db(db_path: str = "./db/findings.db"):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log_type TEXT,
            severity TEXT,
            summary TEXT,
            findings_json TEXT,
            risk_score INTEGER,
            brute_force INTEGER,
            suspicious_ips TEXT,
            requires_action INTEGER,
            source TEXT
        )
    """)
    # Add source column to existing DBs that predate this field
    try:
        c.execute("ALTER TABLE findings ADD COLUMN source TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()


def store_finding(result: dict, log_type: str, db_path: str = "./db/findings.db", source: str = ""):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "INSERT INTO findings VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now().isoformat(),
            log_type,
            result.get("severity", "INFO"),
            result.get("summary", ""),
            json.dumps(result.get("findings", [])),
            result.get("overall_risk_score", 0),
            1 if result.get("brute_force_detected") else 0,
            json.dumps(result.get("suspicious_ips", [])),
            1 if result.get("requires_immediate_action") else 0,
            source,
        ),
    )
    conn.commit()
    conn.close()


def print_result(result: dict, log_type: str):
    severity = result.get("severity", "INFO")
    risk = result.get("overall_risk_score", 0)
    summary = result.get("summary", "")
    icon = SEVERITY_ICONS.get(severity, "⚪")

    print(f"\n{icon} [{log_type}] [{severity}] Risk: {risk}/100")
    print(f"   {summary}")

    if result.get("brute_force_detected"):
        print(f"   ⚠️  BRUTE FORCE DETECTED — IPs: {result.get('suspicious_ips', [])}")

    for f in result.get("findings", []):
        print(f"   → [{f.get('type')}] {f.get('description')}")
        print(f"     Action: {f.get('recommendation')}")


def run_analysis(log_files: dict, realtime: bool = False):
    init_db()

    mode = "Real-time" if realtime else "Historical"
    print(f"\n🛡️  AI Log Analysis Agent Started — Mode: {mode}")
    print(f"📂 Monitoring {len(log_files)} log sources\n")

    parser = tail_log_file if realtime else read_existing_logs

    for log_type, filepath in log_files.items():
        print(f"📋 Processing: {log_type.upper()} logs from {filepath}")

        for chunk in parser(filepath):
            if not chunk:
                continue

            detected_type = detect_log_type(chunk)
            print(f"   🔍 Analyzing {len(chunk)} lines (detected: {detected_type})...")

            result = analyze_logs(chunk, realtime=realtime)
            store_finding(result, log_type.upper(), source=filepath)
            print_result(result, log_type.upper())

            risk = result.get("overall_risk_score", 0)
            if risk >= RISK_ALERT_THRESHOLD or result.get("requires_immediate_action"):
                send_alert(result)
