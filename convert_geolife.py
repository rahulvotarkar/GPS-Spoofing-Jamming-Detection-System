"""
Geolife .plt -> CSV batch converter
------------------------------------
Removes the ".plt is critical to convert" friction entirely. Point this at
a downloaded "Geolife Trajectories 1.3" folder and it walks every user's
Trajectory subfolder, reads every .plt file (6 header lines, then
lat,lon,0,altitude,days,date,time per row), and writes ONE combined CSV
ready to use with generate_labeled_dataset.py or replay_dataset.py.

Usage:
    python convert_geolife.py --input "Geolife Trajectories 1.3/Data" --out geolife.csv
    python convert_geolife.py --input "Geolife Trajectories 1.3/Data" --out geolife.csv --user 010 --limit 5000

If you downloaded the Kaggle mirror instead (already CSV), you don't need
this script at all -- just use that file directly.
"""

import argparse
import csv
import glob
import os


def parse_plt(path):
    rows = []
    with open(path, "r", errors="ignore") as f:
        lines = f.readlines()[6:]  # first 6 lines are a fixed Geolife header
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) < 7:
            continue
        try:
            lat, lon = float(parts[0]), float(parts[1])
        except ValueError:
            continue
        rows.append((lat, lon))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="path to the Geolife 'Data' folder (contains 000, 001, ... user folders)")
    ap.add_argument("--out", default="geolife.csv")
    ap.add_argument("--user", default=None, help="only convert one user folder, e.g. 010 (default: all users)")
    ap.add_argument("--limit", type=int, default=20000, help="stop after this many rows total")
    args = ap.parse_args()

    pattern = os.path.join(args.input, args.user or "*", "Trajectory", "*.plt")
    files = sorted(glob.glob(pattern))
    if not files:
        print(f"No .plt files found matching {pattern}")
        print("Check --input points at the 'Data' folder inside the extracted Geolife download.")
        return

    print(f"Found {len(files)} .plt files. Converting...")
    total = 0
    with open(args.out, "w", newline="") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(["lat", "lon"])
        for path in files:
            for lat, lon in parse_plt(path):
                writer.writerow([lat, lon])
                total += 1
                if total >= args.limit:
                    break
            if total >= args.limit:
                break

    print(f"Wrote {total} points to {args.out}")
    print(f"\nNext: python generate_labeled_dataset.py --file {args.out} --spoof-min-m 20 --spoof-max-m 50")


if __name__ == "__main__":
    main()
