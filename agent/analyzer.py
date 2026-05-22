import subprocess
import json
import re
import os
import shutil

# ── Find claude CLI ────────────────────────────────────────────────────────────
_CLAUDE_CANDIDATES = [
    "claude",                                  # in PATH (npm install -g)
    "/usr/local/bin/claude",
    "/opt/homebrew/bin/claude",
    os.path.expanduser("~/.npm-global/bin/claude"),
    # Claude Desktop bundled binary (Mac)
    os.path.expanduser(
        "~/Library/Application Support/Claude/claude-code/2.1.138/claude.app/Contents/MacOS/claude"
    ),
]

def _find_claude() -> str | None:
    for candidate in _CLAUDE_CANDIDATES:
        if shutil.which(candidate):
            return candidate
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

CLAUDE_BIN = _find_claude()

SYSTEM_PROMPT = """You are an expert cybersecurity analyst AI agent embedded inside a Security Operations Center (SSOC).
You will receive batches of raw log entries from multiple log types: Application logs, Security logs, Network logs, System logs, and Audit logs.

━━━ SEVERITY MAPPING (follow strictly) ━━━
Map the log's OWN level to finding severity — do NOT upgrade:
  FATAL / CRITICAL in log  →  finding severity CRITICAL
  ERROR in log             →  finding severity HIGH
  WARN  in log             →  finding severity MEDIUM
  INFO  in log             →  finding severity LOW or INFO
  (Exception: INFO lines showing brute-force patterns, mass failures, or suspicious behaviour may be raised one level)

━━━ FINDING TYPES ━━━
1. CRITICAL_ERROR — crashes, service failures, unhandled exceptions (log level FATAL/ERROR)
2. SECURITY_THREAT — brute force, unauthorized access, privilege escalation, SQL injection
3. ANOMALY — unusual behaviour: odd login times, unexpected transfers, geographic anomalies
4. WARNING — disk/memory thresholds, timeouts, expiring certs, high latency (log level WARN)
5. AUDIT_FLAG — admin actions, firewall changes, bulk operations, service account activity
6. INFO — normal operations, routine events, healthy heartbeats (log level INFO, no threat)

━━━ BRUTE FORCE RULES ━━━
- Same IP failing login 3+ times = BRUTE FORCE → SECURITY_THREAT CRITICAL
- Invalid/unknown user attempts = username enumeration → SECURITY_THREAT HIGH
- Successful login after many failures = likely compromise → SECURITY_THREAT CRITICAL

━━━ CRITICAL RULE — LOG LINE ACCURACY ━━━
The "log_line" field MUST be copied VERBATIM from the input. Do NOT paraphrase, reconstruct,
or invent log lines. If you cannot find the exact line, use the closest real line from the input.
Copy it character-for-character including timestamps, PIDs, IPs, and block IDs.

━━━ INFO LOGS ━━━
Always include at least one INFO finding describing what normal/routine activity looks like
in this batch, so analysts know the baseline. Use severity "INFO" and type "INFO".

Respond ONLY in this exact JSON format, no extra text, no markdown:
{
  "summary": "One clear sentence describing overall findings",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "log_type_detected": ["APPLICATION", "SECURITY", "NETWORK", "SYSTEM", "AUDIT"],
  "findings": [
    {
      "type": "CRITICAL_ERROR | SECURITY_THREAT | ANOMALY | WARNING | AUDIT_FLAG | INFO",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "description": "Clear explanation of what happened and why it matters",
      "log_line": "EXACT verbatim line copied from the input — no paraphrasing",
      "timestamp": "Timestamp from the log if present",
      "affected_component": "Which service, user, IP, or system is involved",
      "recommendation": "Specific action the analyst should take (or 'No action needed' for INFO)"
    }
  ],
  "overall_risk_score": 0,
  "requires_immediate_action": false,
  "brute_force_detected": false,
  "suspicious_ips": []
}"""


def _parse_json(raw: str) -> dict:
    raw = raw.strip()
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
        "parse_error": raw[:300],
    }


def _verify_and_fix_log_lines(result: dict, log_lines: list[str]) -> dict:
    """
    Post-analysis guard: checks every finding's log_line against the actual
    input lines. If a line was hallucinated, replaces it with the closest
    real line using simple keyword overlap scoring.
    """
    if not result.get("findings"):
        return result

    log_set  = set(log_lines)                        # exact-match lookup
    fixed    = 0

    for finding in result["findings"]:
        claimed = finding.get("log_line", "").strip()
        if not claimed or claimed in log_set:
            continue                                  # ✅ exact match — keep it

        # fuzzy fallback: score each real line by keyword overlap
        claimed_words = set(claimed.lower().split())
        best_line, best_score = "", 0
        for real in log_lines:
            score = len(claimed_words & set(real.lower().split()))
            if score > best_score:
                best_score, best_line = score, real

        if best_score >= 3 and best_line:            # needs ≥3 words in common
            finding["log_line"] = best_line
            finding["_log_line_corrected"] = True    # flag for debugging
            fixed += 1
        else:
            # Cannot find a close match — mark clearly rather than keep a lie
            finding["log_line"] = f"[Could not verify — original claim: {claimed[:120]}]"
            fixed += 1

    if fixed:
        result["_hallucinated_lines_fixed"] = fixed

    return result


def analyze_logs(log_lines: list[str], realtime: bool = False) -> dict:
    model = "claude-haiku-4-5-20251001" if realtime else "claude-sonnet-4-6"
    log_text = "\n".join(log_lines)
    user_message = f"Analyze these log entries and return JSON only:\n\n{log_text}"

    # ── Try claude CLI first (no API key needed) ──────────────────────────────
    if CLAUDE_BIN:
        try:
            result = subprocess.run(
                [
                    CLAUDE_BIN,
                    "--print",
                    "--model", model,
                    "--system-prompt", SYSTEM_PROMPT,
                    "--output-format", "json",
                    "--no-session-persistence",
                ],
                input=user_message,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                outer = json.loads(result.stdout)
                # CLI --output-format json wraps the response in {"result": "..."}
                raw = outer.get("result", result.stdout)
                return _verify_and_fix_log_lines(_parse_json(raw), log_lines)
        except Exception:
            pass

    # ── Claude CLI not found ───────────────────────────────────────────────────
    return {
        "summary": "Claude CLI not found — install with: npm install -g @anthropic-ai/claude-code",
        "severity": "INFO",
        "findings": [],
        "overall_risk_score": 0,
        "requires_immediate_action": False,
        "brute_force_detected": False,
        "suspicious_ips": [],
    }
