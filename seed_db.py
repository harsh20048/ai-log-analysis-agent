"""Seed the database with realistic mock findings for UI development."""
import sqlite3
import json
import os
from datetime import datetime, timedelta

os.makedirs("db", exist_ok=True)
conn = sqlite3.connect("db/findings.db")
c = conn.cursor()
c.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, log_type TEXT, severity TEXT, summary TEXT,
        findings_json TEXT, risk_score INTEGER, brute_force INTEGER,
        suspicious_ips TEXT, requires_action INTEGER
    )
""")
c.execute("DELETE FROM findings")

base = datetime(2025, 5, 17, 9, 0, 0)

records = [
    (base + timedelta(minutes=0), "SECURITY", "CRITICAL",
     "Brute force attack detected — root account targeted from 45.33.32.156 with 5 failed attempts leading to lockout",
     json.dumps([
         {"type": "SECURITY_THREAT", "severity": "CRITICAL",
          "description": "Brute force attack: 5 failed login attempts for root from same IP in 5 seconds",
          "log_line": "2025-05-17 10:03:05 SECURITY FAILED_LOGIN user=root ip=45.33.32.156 attempt=5",
          "timestamp": "2025-05-17 10:03:05", "affected_component": "root / 45.33.32.156",
          "recommendation": "Block IP 45.33.32.156 immediately at the firewall level and audit all sessions since 10:03:00"},
         {"type": "SECURITY_THREAT", "severity": "HIGH",
          "description": "Privilege escalation: guest user attempted sudo command",
          "log_line": "2025-05-17 10:09:45 SECURITY PRIVILEGE_ESCALATION user=guest attempted sudo command",
          "timestamp": "2025-05-17 10:09:45", "affected_component": "guest",
          "recommendation": "Disable guest account immediately and investigate how it was accessed"},
         {"type": "SECURITY_THREAT", "severity": "HIGH",
          "description": "SQL injection attempt detected in API endpoint",
          "log_line": "2025-05-17 10:10:00 SECURITY SQL_INJECTION_ATTEMPT url=/api/users?id=1 OR 1=1 --",
          "timestamp": "2025-05-17 10:10:00", "affected_component": "/api/users",
          "recommendation": "Enable WAF rules and audit /api/users endpoint for successful injections"},
     ]), 95, 1, json.dumps(["45.33.32.156"]), 1),

    (base + timedelta(minutes=5), "APPLICATION", "CRITICAL",
     "Critical application failures — DB connection pool exhausted and unhandled StackOverflowError detected",
     json.dumps([
         {"type": "CRITICAL_ERROR", "severity": "CRITICAL",
          "description": "Database connection pool exhausted — service is degraded and requests are failing",
          "log_line": "2025-05-17 10:04:10 CRITICAL [DBPool] Connection pool exhausted — service degraded",
          "timestamp": "2025-05-17 10:04:10", "affected_component": "DBPool",
          "recommendation": "Increase connection pool size or restart DBPool; check for connection leaks in PaymentService"},
         {"type": "CRITICAL_ERROR", "severity": "HIGH",
          "description": "Unhandled StackOverflowError in RecursionHandler — potential infinite loop",
          "log_line": "2025-05-17 10:06:00 ERROR [RecursionHandler] StackOverflowError unhandled exception",
          "timestamp": "2025-05-17 10:06:00", "affected_component": "RecursionHandler",
          "recommendation": "Deploy hotfix with recursion depth guard and restart the service"},
     ]), 80, 0, json.dumps([]), 1),

    (base + timedelta(minutes=10), "NETWORK", "HIGH",
     "Port scan detected from 198.51.100.0 and suspicious 2.3GB outbound transfer from internal host",
     json.dumps([
         {"type": "SECURITY_THREAT", "severity": "HIGH",
          "description": "Port scan: 500 ports probed in 2 seconds from external IP",
          "log_line": "2025-05-17 10:10:05 NETWORK src=198.51.100.0 PORTSCAN 500 ports in 2 seconds BLOCKED",
          "timestamp": "2025-05-17 10:10:05", "affected_component": "198.51.100.0",
          "recommendation": "Add 198.51.100.0 to permanent block list and review IDS rules"},
         {"type": "ANOMALY", "severity": "HIGH",
          "description": "Unusual 2.3GB outbound transfer from internal host to external destination",
          "log_line": "2025-05-17 10:11:00 NETWORK src=10.0.0.5 dst=external bytes=2.3GB unusual transfer",
          "timestamp": "2025-05-17 10:11:00", "affected_component": "10.0.0.5",
          "recommendation": "Isolate 10.0.0.5 from network and investigate data exfiltration"},
     ]), 72, 0, json.dumps(["198.51.100.0"]), 1),

    (base + timedelta(minutes=15), "SYSTEM", "HIGH",
     "System resources critical — disk at 94%, memory at 91%, nginx stopped, SSL cert expiring in 3 days",
     json.dumps([
         {"type": "WARNING", "severity": "HIGH",
          "description": "Disk usage at 94% on /var/log — approaching full capacity",
          "log_line": "2025-05-17 10:07:15 SYSTEM disk usage=/var/log 94% WARNING threshold=85%",
          "timestamp": "2025-05-17 10:07:15", "affected_component": "/var/log",
          "recommendation": "Run log rotation immediately and set up automated cleanup"},
         {"type": "CRITICAL_ERROR", "severity": "HIGH",
          "description": "nginx service stopped unexpectedly — web traffic may be down",
          "log_line": "2025-05-17 10:07:30 SYSTEM service=nginx STOPPED unexpectedly restarting",
          "timestamp": "2025-05-17 10:07:30", "affected_component": "nginx",
          "recommendation": "Verify nginx restarted successfully; check error logs at /var/log/nginx/error.log"},
         {"type": "WARNING", "severity": "MEDIUM",
          "description": "SSL certificate for api.company.com expires in 3 days",
          "log_line": "2025-05-17 10:08:45 SYSTEM ssl_cert=api.company.com expires_in=3 days WARNING",
          "timestamp": "2025-05-17 10:08:45", "affected_component": "api.company.com",
          "recommendation": "Renew SSL certificate immediately via certbot or CA portal"},
     ]), 65, 0, json.dumps([]), 1),

    (base + timedelta(minutes=20), "AUDIT", "MEDIUM",
     "Suspicious admin actions — contractor given ADMIN role, firewall opened to 0.0.0.0, bulk data export of 50K records",
     json.dumps([
         {"type": "AUDIT_FLAG", "severity": "HIGH",
          "description": "New contractor account created with ADMIN role — over-privileged",
          "log_line": "2025-05-17 09:00:00 AUDIT action=CREATE_USER by=admin target=contractor_xyz role=ADMIN",
          "timestamp": "2025-05-17 09:00:00", "affected_component": "contractor_xyz",
          "recommendation": "Downgrade contractor_xyz to minimum required role immediately"},
         {"type": "AUDIT_FLAG", "severity": "HIGH",
          "description": "Firewall port 22 opened to 0.0.0.0 — SSH exposed to entire internet",
          "log_line": "2025-05-17 09:30:00 AUDIT action=MODIFY_FIREWALL by=devops port=22 change=OPENED to=0.0.0.0",
          "timestamp": "2025-05-17 09:30:00", "affected_component": "devops / firewall",
          "recommendation": "Restrict port 22 to known IP ranges immediately and get change approval"},
         {"type": "ANOMALY", "severity": "MEDIUM",
          "description": "Bulk export of 50,000 records by newly created contractor account",
          "log_line": "2025-05-17 09:50:00 AUDIT action=EXPORT_DATA by=contractor_xyz records=50000 BULK",
          "timestamp": "2025-05-17 09:50:00", "affected_component": "contractor_xyz",
          "recommendation": "Suspend contractor_xyz, review what data was exported and where it went"},
     ]), 58, 0, json.dumps([]), 0),

    (base + timedelta(minutes=30), "APPLICATION", "LOW",
     "Minor performance warnings — token validation slow and Redis cache miss rate elevated",
     json.dumps([
         {"type": "WARNING", "severity": "LOW",
          "description": "Token validation taking 4200ms vs 500ms threshold in AuthService",
          "log_line": "2025-05-17 10:03:12 WARN [AuthService] Token validation took 4200ms threshold=500ms",
          "timestamp": "2025-05-17 10:03:12", "affected_component": "AuthService",
          "recommendation": "Profile AuthService token validation path; check if DB is under load"},
         {"type": "WARNING", "severity": "LOW",
          "description": "Redis cache miss rate at 89% — heavy DB load expected",
          "log_line": "2025-05-17 10:07:00 WARN [CacheService] Redis cache miss rate 89%",
          "timestamp": "2025-05-17 10:07:00", "affected_component": "CacheService",
          "recommendation": "Increase Redis TTL and warm cache for frequent queries"},
     ]), 25, 0, json.dumps([]), 0),

    (base + timedelta(minutes=45), "NETWORK", "INFO",
     "Normal internal traffic observed — no threats detected in this window",
     json.dumps([]), 5, 0, json.dumps([]), 0),
]

for r in records:
    c.execute("INSERT INTO findings VALUES (NULL,?,?,?,?,?,?,?,?,?)",
              (r[0].isoformat(), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]))

conn.commit()
conn.close()
print(f"Seeded {len(records)} findings into db/findings.db")
