"""
Porto Taxi Trajectory dataset -> CSV converter
------------------------------------------------
The Kaggle "Taxi Trajectory Data" (ECML/PKDD 15, crailtap/taxi-trajectory)
ships as one huge train.csv where each row is an entire trip, and the GPS
points are packed into a single POLYLINE column as a string like:
    "[[-8.618643,41.141412],[-8.618499,41.141376],...]"
Note the order inside each pair is [LONGITUDE, LATITUDE] -- the opposite of
what this project expects (lat, lon) -- this script handles that swap.

This script pulls out one (or several) real trips and writes a plain
lat,lon CSV ready to use directly with generate_labeled_dataset.py or
replay_dataset.py. The file is large (1.7M+ trips, several GB), so this
reads it as a stream and stops as soon as it has enough usable trips --
it does NOT load the whole file into memory.

Usage:
    # first usable trip in the file -> one CSV
    python convert_porto_taxi.py --file train.csv --out porto_trip.csv

    # a specific trip, and require at least 30 points
    python convert_porto_taxi.py --file train.csv --out porto_trip.csv --trip-index 5 --min-points 30

    # stitch several trips together into one longer path
    python convert_porto_taxi.py --file train.csv --out porto_trip.csv --num-trips 3
"""

import argparse
import ast
import csv


def usable_trips(path, min_points):
    """Yields (trip_id, [(lat, lon), ...]) for each non-missing trip with enough points."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("MISSING_DATA", "False").strip().lower() == "true":
                continue
            raw = row.get("POLYLINE", "")
            if not raw or raw == "[]":
                continue
            try:
                pairs = ast.literal_eval(raw)  # safe: only parses literals, not arbitrary code
            except (ValueError, SyntaxError):
                continue
            if len(pairs) < min_points:
                continue
            points = [(lat, lon) for lon, lat in pairs]  # POLYLINE is [lon, lat] -> swap to (lat, lon)
            yield row.get("TRIP_ID", "?"), points


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="path to the downloaded train.csv")
    ap.add_argument("--out", default="porto_trip.csv")
    ap.add_argument("--trip-index", type=int, default=0, help="which usable trip to pick (0 = first)")
    ap.add_argument("--num-trips", type=int, default=1, help="stitch this many consecutive usable trips together")
    ap.add_argument("--min-points", type=int, default=20, help="skip trips shorter than this many points")
    args = ap.parse_args()

    collected = []
    seen = 0
    for trip_id, points in usable_trips(args.file, args.min_points):
        if seen >= args.trip_index:
            collected.append((trip_id, points))
            if len(collected) >= args.num_trips:
                break
        seen += 1

    if not collected:
        print("No usable trip found -- try lowering --min-points or --trip-index.")
        return

    with open(args.out, "w", newline="") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(["lat", "lon"])
        total = 0
        for trip_id, points in collected:
            for lat, lon in points:
                writer.writerow([lat, lon])
                total += 1
            print(f"  trip {trip_id}: {len(points)} points")

    print(f"\nWrote {total} points from {len(collected)} trip(s) to {args.out}")
    print(f"\nNext: python generate_labeled_dataset.py --file {args.out} --spoof-min-m 20 --spoof-max-m 50")


if __name__ == "__main__":
    main()
