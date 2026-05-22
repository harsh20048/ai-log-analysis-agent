#!/bin/bash
# Double-click this file on Mac to launch the dashboard

cd "$(dirname "$0")"

# Activate venv if exists, else use system python
if [ -d ".venv" ]; then
  source .venv/bin/activate
fi

# Install deps silently if missing
pip install -q anthropic streamlit pandas plotly requests 2>/dev/null

# Seed DB if empty
if [ ! -s "db/findings.db" ]; then
  python3 seed_db.py 2>/dev/null
fi

# Launch
echo "→ Opening http://localhost:8501"
streamlit run dashboard/app.py \
  --server.port 8501 \
  --server.headless false \
  --browser.gatherUsageStats false \
  --theme.base dark
