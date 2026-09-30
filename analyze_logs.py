"""
Log analysis tool
-------------------
Reads the CSV logs this project generates (data/gps_log.csv and
data/alerts_log.csv) and produces charts you can drop straight into your
project report / viva slides.

Usage:
    python analyze_logs.py
Output (in analysis_output/):
    trajectory_plot.png   -- lat/lon scatter, colored by detection status
    anomaly_over_time.png -- anomaly score timeline with alert markers
    alerts_summary.png    -- bar chart of alert counts by type
"""

import os
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import pandas as pd

DATA_DIR = "data"
OUT_DIR = "analysis_output"


def main():
    print("Starting log analysis...")
    os.makedirs(OUT_DIR, exist_ok=True)

    gps_path = os.path.join(DATA_DIR, "gps_log.csv")
    alerts_path = os.path.join(DATA_DIR, "alerts_log.csv")

    if not os.path.exists(gps_path):
        print(f"No {gps_path} found yet -- run the server and send some GPS "
              f"updates first (or use replay_dataset.py).")
        return

    if os.path.getsize(gps_path) == 0:
        print(f"{gps_path} exists but is empty -- send some fresh data and try again.")
        return

    print(f"Reading and parsing {gps_path}...")
    cleaned_rows = []
    
    # Read and clean CSV in pure Python to avoid datetime C-extension segfaults on Python 3.14
    import csv
    with open(gps_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("timestamp") == "timestamp" or not row.get("timestamp"):
                continue
            try:
                dt = datetime.fromisoformat(row["timestamp"])
                cleaned_row = {
                    "timestamp_epoch": dt.timestamp(),
                    "device_id": row["device_id"],
                    "status": row["status"]
                }
                for col in ["lat", "lon", "anomaly_score", "snr", "cno", "hdop", "vdop", "satellites", "time_drift_ms"]:
                    if col in row and row[col] not in (None, "", "NaN"):
                        cleaned_row[col] = float(row[col])
                    else:
                        cleaned_row[col] = None
                cleaned_rows.append(cleaned_row)
            except Exception:
                continue

    if not cleaned_rows:
        print("No valid rows found in log file.")
        return

    gps = pd.DataFrame(cleaned_rows)
    print(f"Loaded {len(gps)} records successfully.")

    # ---- 1. trajectory plot, colored by status ----
    print("Generating trajectory plot...")
    fig, ax = plt.subplots(figsize=(7, 6))
    colors = {"NORMAL": "#2ecc71", "SPOOFING": "#e74c3c", "JAMMING": "#f39c12"}
    for status, group in gps.groupby("status"):
        ax.scatter(group["lon"], group["lat"], s=18, label=status,
                   color=colors.get(status, "#3498db"), alpha=0.8)
    ax.set_xlabel("Longitude")
    ax.set_ylabel("Latitude")
    ax.set_title("GPS readings by detection status")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "trajectory_plot.png"), dpi=150)
    plt.close(fig)
    print("Trajectory plot saved successfully!")

    # ---- 2. anomaly score over time ----
    if "anomaly_score" in gps.columns:
        print("Generating anomaly timeline plot...")
        fig, ax = plt.subplots(figsize=(9, 4))
        ax.plot(gps["timestamp_epoch"], gps["anomaly_score"], color="#8ea0c2", linewidth=1.2)
        ax.axhline(0.7, color="#e74c3c", linestyle="--", linewidth=1, label="High risk")
        ax.axhline(0.35, color="#f39c12", linestyle="--", linewidth=1, label="Medium risk")
        
        flagged = gps[gps["status"] != "NORMAL"]
        if not flagged.empty:
            ax.scatter(flagged["timestamp_epoch"], flagged["anomaly_score"], color="#e74c3c", s=25, zorder=5)
            
        ax.set_ylim(0, 1)
        ax.set_ylabel("Anomaly score")
        ax.set_title("Anomaly score over time")
        ax.legend()
        
        # Format ticks to human-readable times safely
        def format_date(x, pos):
            try:
                return datetime.fromtimestamp(x).strftime("%H:%M:%S")
            except Exception:
                return ""
        ax.xaxis.set_major_formatter(FuncFormatter(format_date))
        
        fig.autofmt_xdate()
        fig.tight_layout()
        fig.savefig(os.path.join(OUT_DIR, "anomaly_over_time.png"), dpi=150)
        plt.close(fig)
        print("Anomaly timeline plot saved successfully!")

    # ---- 3. alert counts by type ----
    if os.path.exists(alerts_path) and os.path.getsize(alerts_path) > 0:
        print(f"Reading alerts log from {alerts_path}...")
        try:
            alerts = pd.read_csv(alerts_path, encoding="latin-1")
            if not alerts.empty and "type" in alerts.columns:
                print("Generating alert counts plot...")
                counts = alerts["type"].value_counts()
                fig, ax = plt.subplots(figsize=(5, 4))
                counts.plot(kind="bar", ax=ax, color=["#e74c3c", "#f39c12", "#3498db"])
                ax.set_ylabel("Count")
                ax.set_title("Alerts by type")
                fig.tight_layout()
                fig.savefig(os.path.join(OUT_DIR, "alerts_summary.png"), dpi=150)
                plt.close(fig)
                print("Alerts summary plot saved successfully!")
        except Exception as e:
            print(f"Failed to compile alerts chart: {e}")

    print(f"Saved charts to {OUT_DIR}/")


if __name__ == "__main__":
    main()
