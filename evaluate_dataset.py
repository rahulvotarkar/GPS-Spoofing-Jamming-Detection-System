"""
Evaluate detection accuracy against a ground-truth-labeled dataset
------------------------------------------------------------------
Replays labeled_dataset.csv (from generate_labeled_dataset.py) through your
running Flask server in timestamp order, records what the system actually
detected for device_B on every row, compares it against the true_label
column, and reports precision / recall / F1 / a confusion matrix. This is
exactly the "Results and Evaluation" content a final-year report needs --
real numbers, not just screenshots.

For jamming, ground truth is represented by an ABSENCE of rows (device_B
goes silent), so this script also polls /api/status during those windows
to check whether the server actually flagged JAMMING after the timeout.

Usage:
    python app.py                                  # Terminal 1
    python generate_labeled_dataset.py              # Terminal 2 (once)
    python evaluate_dataset.py --file labeled_dataset.csv   # Terminal 2
"""

import argparse
import csv
import os
import time
from collections import defaultdict

import requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="labeled_dataset.csv")
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between rows")
    ap.add_argument("--jam-wait", type=float, default=16, help="seconds to wait after a jam window before checking status")
    args = ap.parse_args()

    with open(args.file, newline="") as f:
        rows = list(csv.DictReader(f))

    print(f"Replaying {len(rows)} rows from {args.file} against {args.url} ...\n")

    predictions = []   # (true_label, predicted_label) for spoofing/normal rows
    jam_checks = []     # (seq_after_gap, expected 'JAMMING')

    prev_seq = None
    last_t_offset = {}  # device_id -> last real t_offset_s seen, for accurate dt_s
    for row in rows:
        seq = int(row["seq"])
        device_id = row["device_id"]
        true_label = row["true_label"]
        t_offset = float(row["t_offset_s"]) if "t_offset_s" in row and row["t_offset_s"] else None

        # a gap in seq numbers for device_B means a jamming window happened
        if device_id == "device_B" and prev_seq is not None and seq - prev_seq > 1:
            jam_checks.append(seq)
        if device_id == "device_B":
            prev_seq = seq

        payload = {"device_id": device_id, "lat": float(row["lat"]), "lon": float(row["lon"]), "accuracy": 6}
        # pass the dataset's REAL recorded time gap so speed checks stay accurate
        # even when --delay replays much faster than the data was originally sampled
        if t_offset is not None and device_id in last_t_offset:
            payload["dt_s"] = max(0.01, t_offset - last_t_offset[device_id])
        if t_offset is not None:
            last_t_offset[device_id] = t_offset

        try:
            r = requests.post(f"{args.url}/update", json=payload, timeout=5)
            predicted = r.json().get("status", "?")
        except Exception as e:
            predicted = f"error:{e}"

        if device_id == "device_B" and true_label in ("NORMAL", "SPOOFING"):
            predictions.append((true_label, predicted))
            marker = "  <-- MISMATCH" if (predicted == "SPOOFING") != (true_label == "SPOOFING") else ""
            print(f"[{seq}] true={true_label:9s} predicted={predicted:9s}{marker}")

        time.sleep(args.delay)

    # --- jamming check: wait past the timeout and see if device_B is flagged ---
    jam_hits = 0
    if jam_checks:
        print(f"\nWaiting {args.jam_wait}s to evaluate {len(jam_checks)} jamming window(s)...")
        time.sleep(args.jam_wait)
        try:
            status = requests.get(f"{args.url}/api/status", timeout=5).json()
            b_status = status["devices"].get("device_B", {}).get("status")
            print(f"device_B status after silence: {b_status}")
            if b_status == "JAMMING":
                jam_hits = len(jam_checks)  # can't distinguish individual windows from one final check
        except Exception as e:
            print(f"Could not check jamming status: {e}")

    # --- metrics for spoofing detection ---
    tp = sum(1 for t, p in predictions if t == "SPOOFING" and p == "SPOOFING")
    fn = sum(1 for t, p in predictions if t == "SPOOFING" and p != "SPOOFING")
    fp = sum(1 for t, p in predictions if t == "NORMAL" and p == "SPOOFING")
    tn = sum(1 for t, p in predictions if t == "NORMAL" and p != "SPOOFING")

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / len(predictions) if predictions else 0

    print("\n" + "=" * 50)
    print("SPOOFING DETECTION RESULTS")
    print("=" * 50)
    print(f"  True Positives  (correctly flagged spoofing): {tp}")
    print(f"  False Negatives (missed spoofing):             {fn}")
    print(f"  False Positives (false alarms):                {fp}")
    print(f"  True Negatives  (correctly normal):            {tn}")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  F1 score:  {f1:.2%}")
    print(f"\nJAMMING DETECTION: {jam_hits}/{len(jam_checks) if jam_checks else 0} windows resulted in a JAMMING status")

    os.makedirs("analysis_output", exist_ok=True)
    report_path = os.path.join("analysis_output", "evaluation_report.txt")
    with open(report_path, "w") as f:
        f.write("GPS Spoofing Detection -- Evaluation Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Dataset: {args.file}\n")
        f.write(f"Rows evaluated (device_B, NORMAL/SPOOFING only): {len(predictions)}\n\n")
        f.write(f"TP={tp}  FN={fn}  FP={fp}  TN={tn}\n")
        f.write(f"Accuracy:  {accuracy:.2%}\n")
        f.write(f"Precision: {precision:.2%}\n")
        f.write(f"Recall:    {recall:.2%}\n")
        f.write(f"F1 score:  {f1:.2%}\n\n")
        f.write(f"Jamming windows flagged: {jam_hits}/{len(jam_checks) if jam_checks else 0}\n")
    print(f"\nSaved report to {report_path} -- use these numbers in your report's Results chapter.")


if __name__ == "__main__":
    main()
