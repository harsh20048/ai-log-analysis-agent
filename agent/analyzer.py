import anthropic
import json
import re
from config import ANTHROPIC_API_KEY

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """You are an expert cybersecurity analyst AI agent embedded inside a Security Operations Center (SSOC).
You will receive batches of raw log entries from multiple log types: Application logs, Security logs, Network logs, System logs, and Audit logs.

Your job is to analyze every line carefully and identify:
1. CRITICAL_ERROR — Application crashes, service failures, database outages, unhandled exceptions
2. SECURITY_THREAT — Brute force attacks, unauthorized access, privilege escalation, suspicious IPs, SQL injection
3. ANOMALY — Unusual behavior: odd login times, unexpected data transfers, TOR/VPN access, geographic anomalies
4. WARNING — Disk/memory/CPU thresholds, repeated timeouts, expiring certificates, high latency
5. AUDIT_FLAG — Admin actions: new privileged users, firewall changes, sensitive data access, bulk deletions

For SECURITY_THREAT detection, watch for:
- Same IP failing login 3+ times = BRUTE FORCE
- Access to /admin, /root, /etc/passwd without authorization = UNAUTHORIZED ACCESS
- Non-admin attempting privileged commands = PRIVILEGE ESCALATION
- SQL keywords in requests (SELECT, UNION, DROP, --) = SQL INJECTION
- TOR exit nodes or blacklisted IPs = SUSPICIOUS SOURCE

Respond ONLY in this exact JSON format, no extra text, no markdown:
{
  "summary": "One clear sentence describing overall findings",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "log_type_detected": ["APPLICATION", "SECURITY", "NETWORK", "SYSTEM", "AUDIT"],
  "findings": [
    {
      "type": "CRITICAL_ERROR | SECURITY_THREAT | ANOMALY | WARNING | AUDIT_FLAG",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "description": "Clear explanation of what happened and why it's a concern",
      "log_line": "The exact log line that triggered this",
      "timestamp": "Timestamp from the log if present",
      "affected_component": "Which service, user, IP, or system is involved",
      "recommendation": "Specific action the analyst should take right now"
    }
  ],
  "overall_risk_score": 0,
  "requires_immediate_action": false,
  "brute_force_detected": false,
  "suspicious_ips": []
}"""


def analyze_logs(log_lines: list[str], realtime: bool = False) -> dict:
    model = "claude-haiku-4-5-20251001" if realtime else "claude-sonnet-4-6"
    log_text = "\n".join(log_lines)
    response = client.messages.create(
        model=model,
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze these log entries and return JSON only:\n\n{log_text}",
            }
        ],
    )
    raw = response.content[0].text.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
        return {
            "summary": "Failed to parse AI response",
            "severity": "INFO",
            "findings": [],
            "overall_risk_score": 0,
            "requires_immediate_action": False,
            "brute_force_detected": False,
            "suspicious_ips": [],
            "parse_error": raw[:200],
        }
