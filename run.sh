#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# AI Log Analysis Agent — One-click launcher (macOS)
# ─────────────────────────────────────────────────────────────────

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}${BOLD}║   🛡️  AI Log Analysis Agent — SSOC Dashboard     ║${RESET}"
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
PYTHON=$(command -v python3 || command -v python || die "Python 3 not found. Install from python.org")
PY_VER=$($PYTHON --version 2>&1)
ok "Found $PY_VER"

# ── 2. Virtual environment ─────────────────────────────────────
if [ ! -d ".venv" ]; then
  step "Creating virtual environment..."
  $PYTHON -m venv .venv
  ok "Virtual environment created"
else
  ok "Virtual environment already exists"
fi

source .venv/bin/activate
PYTHON=python

# ── 3. Dependencies ────────────────────────────────────────────
step "Installing dependencies..."
pip install -q --upgrade pip
pip install -q anthropic streamlit pandas plotly requests watchdog
ok "All dependencies installed"

# ── 4. Check API key ──────────────────────────────────────────
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo ""
  warn "ANTHROPIC_API_KEY is not set."
  echo -e "  ${YELLOW}Export it first:${RESET}  export ANTHROPIC_API_KEY=\"sk-ant-...\""
  echo -e "  ${YELLOW}Or add it to${RESET}     ~/.zshrc / ~/.bash_profile"
  echo ""
  echo -e "  ${CYAN}The dashboard will still open — but Upload/Analysis features need the key.${RESET}"
  echo ""
fi

# ── 5. Create folders ─────────────────────────────────────────
mkdir -p logs db
ok "Directories ready"

# ── 6. Seed sample data if DB empty ──────────────────────────
if [ ! -f "db/findings.db" ] || [ ! -s "db/findings.db" ]; then
  step "Seeding sample data for first run..."
  python seed_db.py && ok "Sample data seeded"
fi

# ── 7. Optional: run historical analysis ─────────────────────
echo ""
echo -e "${BOLD}Options:${RESET}"
echo -e "  ${CYAN}[1]${RESET} Launch dashboard only (use existing data)"
echo -e "  ${CYAN}[2]${RESET} Run historical analysis on sample logs, then launch dashboard"
echo -e "  ${CYAN}[3]${RESET} Run real-time monitoring (requires API key)"
echo ""
read -rp "$(echo -e "${BOLD}Choose [1/2/3] (default: 1): ${RESET}")" CHOICE
CHOICE="${CHOICE:-1}"

case "$CHOICE" in
  2)
    if [ -z "$ANTHROPIC_API_KEY" ]; then
      die "ANTHROPIC_API_KEY not set. Cannot run analysis."
    fi
    step "Running historical analysis on all log files..."
    python main.py historical
    ok "Analysis complete — results stored in db/findings.db"
    ;;
  3)
    if [ -z "$ANTHROPIC_API_KEY" ]; then
      die "ANTHROPIC_API_KEY not set. Cannot run real-time monitoring."
    fi
    step "Starting real-time monitor in background..."
    python main.py realtime &
    MONITOR_PID=$!
    ok "Monitor running (PID $MONITOR_PID)"
    trap "kill $MONITOR_PID 2>/dev/null" EXIT
    ;;
esac

# ── 8. Launch dashboard ──────────────────────────────────────
echo ""
step "Launching SSOC Dashboard..."
echo -e "  ${GREEN}${BOLD}URL: http://localhost:8501${RESET}"
echo -e "  ${CYAN}Press Ctrl+C to stop${RESET}"
echo ""

streamlit run dashboard/app.py \
  --server.port 8501 \
  --server.headless false \
  --browser.gatherUsageStats false \
  --theme.base dark
