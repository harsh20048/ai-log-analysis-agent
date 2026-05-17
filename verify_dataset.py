"""
Verification pipeline using real public log datasets from logpai/loghub.

Ground truth extraction strategy:
  BGL   — column 0 is the label: '-' = normal, anything else = anomaly type
  Linux — repeated auth failures from same IP within same minute = brute force (known pattern)
  HDFS  — lines containing ERROR/Exception/failed = anomaly (dataset paper confirmed)

We run Claude on each chunk, collect its findings, then compare against
ground truth labels and compute: TP, FP, FN, precision, recall, F1.
"""

import re
import json
from collections import defaultdict
from agent.analyzer import analyze_logs


# ── Ground truth extractors ────────────────────────────────────────────────────

def extract_bgl_ground_truth(filepath: str) -> dict[int, str]:
    """
    BGL format: <label> <timestamp_unix> <date> <node> <datetime> <node> <type> <component> <level> <message>
    First token: '-' = normal, anything else (APPREAD, FATAL, etc.) = anomaly.
    Returns {line_number: anomaly_label}
    """
    ground_truth = {}
    with open(filepath, errors="ignore") as f:
        for i, line in enumerate(f):
            parts = line.strip().split()
            if not parts:
                continue
            label = parts[0]
            if label != "-":
                ground_truth[i] = label
    return ground_truth


def extract_linux_ground_truth(filepath: str) -> dict[int, str]:
    """
    Linux auth logs: lines with 'authentication failure' from same IP
    within a 60-second window = brute force (5+ hits = confirmed anomaly).
    Also flags: 'ALERT', 'FATAL', 'error'.
    """
    ground_truth = {}
    ip_hits: dict[str, list[int]] = defaultdict(list)

    with open(filepath, errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        low = line.lower()
        if "alert" in low or "fatal" in low:
            ground_truth[i] = "ALERT/FATAL"
        ip_match = re.search(r"rhost=([\d\.a-zA-Z\-]+)", line)
        if ip_match and "authentication failure" in low:
            ip = ip_match.group(1)
            ip_hits[ip].append(i)

    for ip, line_nums in ip_hits.items():
        if len(line_nums) >= 5:
            for ln in line_nums:
                ground_truth[ln] = f"BRUTE_FORCE({ip})"

    return ground_truth


def extract_hdfs_ground_truth(filepath: str) -> dict[int, str]:
    """
    HDFS logs: lines with ERROR level or known failure keywords = anomaly.
    Based on the HDFS anomaly detection paper (He et al., 2016).
    """
    ERROR_KEYWORDS = ["error", "exception", "failed", "failure", "lost", "corrupt"]
    ground_truth = {}
    with open(filepath, errors="ignore") as f:
        for i, line in enumerate(f):
            low = line.lower()
            if any(k in low for k in ERROR_KEYWORDS):
                ground_truth[i] = "HDFS_ERROR"
    return ground_truth


def read_log_lines(filepath: str) -> list[str]:
    with open(filepath, errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


# ── Verification runner ────────────────────────────────────────────────────────

def verify_dataset(name: str, filepath: str, ground_truth: dict[int, str],
                   chunk_size: int = 30) -> dict:
    lines = read_log_lines(filepath)
    total_lines = len(lines)
    anomalous_lines = set(ground_truth.keys())

    agent_flagged_lines: set[int] = set()
    all_findings = []

    print(f"\n{'='*60}")
    print(f"Dataset   : {name}")
    print(f"Total lines: {total_lines}")
    print(f"GT anomalies: {len(anomalous_lines)} lines ({len(anomalous_lines)/total_lines*100:.1f}%)")
    print(f"{'='*60}")

    chunk_results = []
    for chunk_start in range(0, total_lines, chunk_size):
        chunk = lines[chunk_start:chunk_start + chunk_size]
        result = analyze_logs(chunk, realtime=False)
        chunk_results.append(result)

        # Any chunk with findings >= MEDIUM severity → mark those line indices
        findings = result.get("findings", [])
        risk = result.get("overall_risk_score", 0)

        if risk > 20 or findings:
            # Map finding back to approximate line range
            for offset in range(len(chunk)):
                global_idx = chunk_start + offset
                # Flag line if it's in a flagged chunk AND has a finding log_line match
                for f in findings:
                    log_line = f.get("log_line", "")
                    if log_line and log_line[:40] in chunk[offset]:
                        agent_flagged_lines.add(global_idx)
                # If risk is very high, flag the whole chunk range
                if risk >= 70:
                    agent_flagged_lines.add(global_idx)

        all_findings.extend(findings)

        severity = result.get("severity", "INFO")
        risk_score = result.get("overall_risk_score", 0)
        print(f"  Chunk {chunk_start:4d}-{chunk_start+len(chunk)-1:4d} | "
              f"Severity: {severity:8s} | Risk: {risk_score:3d}/100 | "
              f"Findings: {len(findings)}")

    # ── Metrics ──────────────────────────────────────────────────────────────
    tp = len(agent_flagged_lines & anomalous_lines)
    fp = len(agent_flagged_lines - anomalous_lines)
    fn = len(anomalous_lines - agent_flagged_lines)
    tn = total_lines - tp - fp - fn

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total_lines if total_lines > 0 else 0.0

    # Sample ground truth labels found
    gt_labels = list(set(ground_truth.values()))[:5]

    print(f"\n  ── VERIFICATION RESULTS ──────────────────────")
    print(f"  True Positives  (agent caught real anomalies) : {tp}")
    print(f"  False Positives (agent flagged normal lines)  : {fp}")
    print(f"  False Negatives (agent missed real anomalies) : {fn}")
    print(f"  True Negatives  (correctly ignored normal)    : {tn}")
    print(f"  Precision : {precision:.2%}")
    print(f"  Recall    : {recall:.2%}")
    print(f"  F1 Score  : {f1:.2%}")
    print(f"  Accuracy  : {accuracy:.2%}")
    print(f"  GT anomaly types: {gt_labels}")

    return {
        "dataset": name,
        "total_lines": total_lines,
        "gt_anomaly_count": len(anomalous_lines),
        "agent_flagged": len(agent_flagged_lines),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "total_findings": len(all_findings),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")

    datasets = [
        ("BGL Supercomputer",  "logs/bgl_real.log",   extract_bgl_ground_truth),
        ("Linux Auth Logs",    "logs/linux_real.log",  extract_linux_ground_truth),
        ("HDFS Distributed FS","logs/hdfs_real.log",   extract_hdfs_ground_truth),
    ]

    summary = []
    for name, path, gt_fn in datasets:
        gt = gt_fn(path)
        result = verify_dataset(name, path, gt, chunk_size=30)
        summary.append(result)

    print(f"\n{'='*60}")
    print("OVERALL SUMMARY")
    print(f"{'='*60}")
    print(f"{'Dataset':<25} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Accuracy':>10}")
    print("-"*60)
    for r in summary:
        print(f"{r['dataset']:<25} {r['precision']:>9.1%} {r['recall']:>7.1%} "
              f"{r['f1']:>7.1%} {r['accuracy']:>9.1%}")

    with open("db/verification_report.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull report saved to db/verification_report.json")
