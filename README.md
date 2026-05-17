# 🛡️ AI Log Analysis Agent — SSOC Portfolio Project

> An AI-powered Security Operations Center (SSOC) agent that ingests raw logs, detects threats in real time using Claude AI, and displays everything on a professional interactive dashboard.

---

## 📸 Dashboard Preview

| Section | What You See |
|---|---|
| **Dashboard** | KPI cards, Plotly risk timeline, severity bar chart, log-type donut, findings log |
| **Upload Logs** | Drag-and-drop any log file or one-click load real public datasets |
| **Raw Database** | Full SQLite table with export to CSV and clear controls |

---

## 🚀 Quick Start (macOS — One Command)

```bash
git clone https://github.com/harsh20048/ai-log-analysis-agent.git
cd ai-log-analysis-agent

export ANTHROPIC_API_KEY="sk-ant-your-key-here"

chmod +x run.sh
./run.sh
```

The script handles everything: creates the venv, installs dependencies, seeds sample data, and launches the dashboard at **http://localhost:8501**.

---

## 🔍 What The Agent Detects

### 🔴 Security Threats
- **Brute Force Attacks** — same IP failing login 3+ times in rapid succession
- **Privilege Escalation** — non-admin user attempting sudo / admin commands
- **SQL Injection** — SELECT, UNION, DROP, `--` patterns in API requests
- **Unauthorized Access** — access to `/etc/passwd`, `/shadow`, `/admin` without auth
- **Suspicious Sources** — TOR exit nodes, blacklisted IP ranges

### 🔴 Critical Errors
- Application crashes (NullPointerException, StackOverflowError)
- Database connection pool exhaustion
- Service outages and unhandled exceptions

### 🟠 Anomalies
- Login from unusual location or time
- Large data transfers at odd hours (potential exfiltration)
- Port scanning activity
- New device accessing sensitive endpoints

### 🟡 Warnings
- Disk / memory / CPU threshold breaches
- SSL certificate expiring soon
- High latency on critical services
- Deprecated API calls

### 🔵 Audit Flags
- Admin creating high-privilege accounts
- Firewall rules opened to `0.0.0.0`
- Bulk data exports by new users
- User deletions and role changes

---

## 🏗️ Architecture

```
ai-log-agent/
├── run.sh                  ← One-click launcher (macOS)
├── main.py                 ← CLI entry point
├── config.py               ← API key, log paths, settings
├── seed_db.py              ← Sample data seeder for first run
├── verify_dataset.py       ← Accuracy verification pipeline
│
├── agent/
│   ├── analyzer.py         ← Claude AI API calls + JSON parsing
│   ├── log_parser.py       ← File reading, log-type auto-detection, tailing
│   ├── monitor.py          ← Orchestrator — chunking, SQLite storage, alerts
│   └── alerter.py          ← Slack webhook / terminal alerts
│
├── dashboard/
│   └── app.py              ← Streamlit dashboard (3 tabs, Plotly charts)
│
├── logs/
│   ├── app.log             ← Sample application log
│   ├── security.log        ← Sample security log
│   ├── network.log         ← Sample network log
│   ├── system.log          ← Sample system log
│   ├── audit.log           ← Sample audit log
│   ├── bgl_real.log        ← Real: IBM Blue Gene/L supercomputer logs
│   ├── linux_real.log      ← Real: Linux auth.log (SSH brute force)
│   └── hdfs_real.log       ← Real: Hadoop distributed filesystem logs
│
└── db/
    └── findings.db         ← SQLite database (auto-created at runtime)
```

---

## 🧠 How Claude AI Is Used

Every 30 log lines are sent to Claude with a detailed cybersecurity analyst system prompt. Claude returns structured JSON:

```json
{
  "summary": "Brute force attack detected from 45.33.32.156",
  "severity": "CRITICAL",
  "overall_risk_score": 95,
  "brute_force_detected": true,
  "suspicious_ips": ["45.33.32.156"],
  "requires_immediate_action": true,
  "findings": [
    {
      "type": "SECURITY_THREAT",
      "severity": "CRITICAL",
      "description": "5 failed login attempts for root from same IP in 5 seconds",
      "log_line": "2025-05-17 10:03:05 SECURITY FAILED_LOGIN user=root ip=45.33.32.156 attempt=5",
      "timestamp": "2025-05-17 10:03:05",
      "affected_component": "root / 45.33.32.156",
      "recommendation": "Block IP 45.33.32.156 at the firewall and audit all sessions since 10:03:00"
    }
  ]
}
```

**Model switching by mode:**
| Mode | Model | Reason |
|---|---|---|
| `python main.py historical` | `claude-sonnet-4-6` | Thorough, accurate batch analysis |
| `python main.py realtime` | `claude-haiku-4-5` | Low latency, cost-efficient for continuous polling |

---

## 📊 Log Types Supported

| Type | Source | What Claude Looks For |
|---|---|---|
| **Application** | App servers, APIs | Crashes, unhandled exceptions, slow queries |
| **Security** | Auth systems, firewalls | Brute force, privilege escalation, injection |
| **Network** | Firewalls, routers | Port scans, DDoS, unusual traffic volumes |
| **System** | OS, kernel | Resource exhaustion, service crashes, cert expiry |
| **Audit** | Admin panels, IAM | Privileged actions, config changes, data exports |

---

## 📦 Real Public Datasets

All three are available as one-click presets in the **Upload Logs** tab:

| Dataset | Source | Lines | Ground Truth |
|---|---|---|---|
| **BGL Supercomputer** | IBM Blue Gene/L — Lawrence Livermore National Lab | 2,000 | Expert-labeled kernel failures (column 0) |
| **Linux Auth Logs** | Real production Linux server | 2,000 | SSH brute force + ALERT/FATAL events |
| **HDFS Hadoop** | University of Nevada Hadoop cluster | 2,000 | Block-level failures (He et al. 2016) |

---

## ✅ Accuracy Verification

Run the verification pipeline to measure agent performance against ground truth labels:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python verify_dataset.py
```

Outputs **Precision / Recall / F1 / Accuracy** for all three datasets — directly comparable to published academic benchmarks.

---

## ⚙️ Configuration

Edit `config.py`:

```python
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
CHUNK_SIZE = 30           # Lines per Claude API call
POLL_INTERVAL = 3         # Seconds between real-time checks
SLACK_WEBHOOK_URL = ""    # Paste webhook for Slack alerts
RISK_ALERT_THRESHOLD = 60 # Trigger alert above this score
```

---

## 🖥️ Running Manually

```bash
# Historical analysis (Sonnet)
python main.py historical

# Real-time monitoring (Haiku)
python main.py realtime

# Dashboard only
streamlit run dashboard/app.py

# Accuracy verification
python verify_dataset.py

# Seed sample data
python seed_db.py
```

---

## 📋 Requirements

- Python 3.11+
- macOS / Linux
- Anthropic API key (get one at console.anthropic.com)

```
anthropic>=0.40.0
streamlit>=1.35.0
plotly>=5.0.0
pandas>=2.2.0
requests>=2.31.0
watchdog>=4.0.0
```

---

## 🤝 Credits

- **Log datasets**: [logpai/loghub](https://github.com/logpai/loghub) — Shilin He et al.
- **AI engine**: [Anthropic Claude](https://anthropic.com) — `claude-sonnet-4-6` / `claude-haiku-4-5`
- **Dashboard**: [Streamlit](https://streamlit.io) + [Plotly](https://plotly.com)

---

*Built as an SSOC portfolio project demonstrating AI-powered log analysis, real-time threat detection, and security operations automation.*
