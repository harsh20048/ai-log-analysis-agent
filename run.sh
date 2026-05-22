#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# AI Security Log Analyzer — Quick Start
# ─────────────────────────────────────────────────────────────────

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║     🛡️  AI Security Log Analyzer — SSOC          ║${RESET}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
  echo ""
}

step() { echo -e "${CYAN}▶ $1${RESET}"; }
ok()   { echo -e "${GREEN}✓ $1${RESET}"; }
warn() { echo -e "${YELLOW}⚠ $1${RESET}"; }
die()  { echo -e "${RED}✗ $1${RESET}"; exit 1; }

banner

# ── 1. Check Python ────────────────────────────────────────────
step "Checking Python..."
PYTHON=$(command -v python3 || command -v python || die "Python 3 not found — install from python.org")
ok "Found $($PYTHON --version 2>&1)"

# ── 2. Virtual environment ─────────────────────────────────────
if [ ! -d ".venv" ]; then
  step "Creating virtual environment..."
  $PYTHON -m venv .venv
  ok "Virtual environment created"
else
  ok "Virtual environment ready"
fi

source .venv/bin/activate
PYTHON=python

# ── 3. Dependencies ────────────────────────────────────────────
step "Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt 2>/dev/null || \
  pip install -q anthropic streamlit pandas plotly requests watchdog
ok "Dependencies ready"

# ── 4. Folders ────────────────────────────────────────────────
mkdir -p logs db
ok "Directories ready"

# ── 5. AI Engine check ────────────────────────────────────────
echo ""
if command -v claude &>/dev/null; then
  ok "Claude CLI found — AI analysis runs without an API key"
elif [ -n "$ANTHROPIC_API_KEY" ]; then
  ok "Anthropic API key found — using SDK fallback"
else
  warn "No Claude CLI and no ANTHROPIC_API_KEY set."
  echo -e "  ${CYAN}Option A:${RESET} Install Claude CLI   →  npm install -g @anthropic-ai/claude-code"
  echo -e "  ${CYAN}Option B:${RESET} Set API key          →  export ANTHROPIC_API_KEY=\"sk-ant-...\""
  echo -e "  ${CYAN}The dashboard will still open with existing findings.${RESET}"
fi

# ── 6. Seed real dataset findings if DB is empty ─────────────
if [ ! -s "db/findings.db" ]; then
  step "First run — loading real public dataset findings..."
  python seed_db.py 2>/dev/null && ok "Findings loaded (BGL + Linux Auth + HDFS)"
fi

# ── 7. Launch ─────────────────────────────────────────────────
echo ""
step "Starting dashboard..."
echo -e "  ${GREEN}${BOLD}→ http://localhost:8501${RESET}"
echo -e "  ${CYAN}Press Ctrl+C to stop${RESET}"
echo ""

streamlit run dashboard/app.py \
  --server.port 8501 \
  --server.headless false \
  --browser.gatherUsageStats false \
  --theme.base dark
