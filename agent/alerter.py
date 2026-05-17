import requests
from config import SLACK_WEBHOOK_URL


def send_alert(finding: dict):
    severity = finding.get("severity", "UNKNOWN")
    risk = finding.get("overall_risk_score", 0)
    summary = finding.get("summary", "")
    ips = finding.get("suspicious_ips", [])
    brute = finding.get("brute_force_detected", False)

    alert_msg = f"""
🚨 SECURITY ALERT — {severity}
Risk Score: {risk}/100
Summary: {summary}
Brute Force Detected: {"YES ⚠️" if brute else "No"}
Suspicious IPs: {", ".join(ips) if ips else "None"}
Action Required: IMMEDIATE
    """.strip()

    if SLACK_WEBHOOK_URL:
        try:
            requests.post(
                SLACK_WEBHOOK_URL,
                json={"text": alert_msg},
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            print("✅ Slack alert sent")
        except Exception as e:
            print(f"⚠️  Slack alert failed: {e}")
    else:
        print("\n" + "=" * 60)
        print(alert_msg)
        print("=" * 60 + "\n")
