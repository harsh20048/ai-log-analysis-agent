import sys
from agent.monitor import run_analysis
from config import LOG_FILES

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "historical"
    realtime = mode == "realtime"
    run_analysis(LOG_FILES, realtime=realtime)
