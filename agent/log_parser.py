import time
import os


def detect_log_type(lines: list[str]) -> str:
    combined = " ".join(lines).lower()
    if any(k in combined for k in ["failed_login", "privilege", "unauthorized", "brute", "account_locked", "sql_injection"]):
        return "SECURITY"
    if any(k in combined for k in ["portscan", "src=", "dst=", "bytes=", "blocked"]):
        return "NETWORK"
    if any(k in combined for k in ["disk usage", "memory usage", "cpu load", "kernel", "cpu_load", "ssl_cert"]):
        return "SYSTEM"
    if any(k in combined for k in ["audit", "action=", "by=admin", "firewall", "create_user", "delete_user"]):
        return "AUDIT"
    return "APPLICATION"


def read_existing_logs(filepath: str, chunk_size: int = 30):
    if not os.path.exists(filepath):
        print(f"⚠️  Log file not found: {filepath}")
        return
    with open(filepath, "r", errors="ignore") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    for i in range(0, len(lines), chunk_size):
        yield lines[i : i + chunk_size]


def tail_log_file(filepath: str, chunk_size: int = 30):
    if not os.path.exists(filepath):
        print(f"⚠️  Log file not found: {filepath}")
        return
    with open(filepath, "r", errors="ignore") as f:
        f.seek(0, 2)
        buffer = []
        while True:
            line = f.readline()
            if line:
                buffer.append(line.strip())
                if len(buffer) >= chunk_size:
                    yield buffer
                    buffer = []
            else:
                if buffer:
                    yield buffer
                    buffer = []
                time.sleep(2)
