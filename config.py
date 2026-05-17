import os

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "your-key-here")

LOG_FILES = {
    "application": "./logs/app.log",
    "security":    "./logs/security.log",
    "network":     "./logs/network.log",
    "system":      "./logs/system.log",
    "audit":       "./logs/audit.log",
}

CHUNK_SIZE = 30
POLL_INTERVAL = 3
SLACK_WEBHOOK_URL = ""
RISK_ALERT_THRESHOLD = 60
