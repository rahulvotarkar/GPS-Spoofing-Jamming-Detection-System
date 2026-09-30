"""
Generate a ground-truth-labeled spoofing/jamming dataset (CSV)
------------------------------------------------------------------
Answers "where do I get a dataset with actual spoofing/jamming labels?"
Public datasets with real spoofing/jamming ground truth at the lat/lon
level essentially don't exist for free download (real spoofing datasets
like TEXBAT are raw RF signal recordings, not CSV coordinates -- see
README Section 3c). The standard, defensible approach -- and what this
script does -- is: take a REAL movement trajectory (downloaded from a
public dataset, or your own logged walk) as the "normal" baseline, then
programmatically inject spoofing jumps and jamming silences on top of it
with known ground-truth labels. This gives you a labeled dataset you can
both demo with AND compute real precision/recall numbers against.

Two devices are generated:
  device_A -- the trusted reference, always close to the real trajectory
  device_B -- normally tracks device_A within a few metres (real GPS
              jitter), but during randomly chosen windows either:
                - jumps SPOOF_MIN_M-SPOOF_MAX_M metres away (SPOOFING), or
                - goes silent for a few seconds (JAMMING)

Usage:
    # use a real downloaded trajectory as the base path
    python generate_labeled_dataset.py --file geolife_trajectory.csv

    # or generate a synthetic walking path if you don't have one yet
    python generate_labeled_dataset.py

    # target exactly the 20-50m range you care about
    python generate_labeled_dataset.py --spoof-min-m 20 --spoof-max-m 50

IMPORTANT when using a real downloaded dataset: --interval-s must match
that dataset's ACTUAL recorded point-to-point time gap, not an arbitrary
value, or the speed-based spoofing check will be wrong. For example, the
Porto Taxi dataset records one point every 15 seconds, so use
--interval-s 15. Geolife is typically 1-5 seconds (check the file). Your
own logged data from this project (data/gps_log.csv) is ~1 second.
evaluate_dataset.py reads this column back out and passes it to the
server as an accurate time-gap override, so replay can run fast
(--delay 0.1) while speed calculations stay physically correct.

Output: labeled_dataset.csv with columns
    seq, t_offset_s, device_id, lat, lon, true_label
"""

import argparse
import csv
import math
import random


def latlon_offset(lat, lon, north_m, east_m):
    dlat = north_m / 111320
    dlon = east_m / (111320 * math.cos(math.radians(lat)))
    return lat + dlat, lon + dlon


def load_base_path(path, lat_col, lon_col, max_points):
    pts = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                pts.append((float(row[lat_col]), float(row[lon_col])))
            except (KeyError, ValueError):
                continue
            if len(pts) >= max_points:
                break
    if not pts:
        raise ValueError(f"No usable {lat_col}/{lon_col} rows found in {path}")
    return pts


def synthetic_path(n, base_lat, base_lon):
    pts = [(base_lat, base_lon)]
    heading = random.uniform(0, 360)
    for _ in range(n - 1):
        heading += random.uniform(-12, 12)
        lat, lon = latlon_offset(*pts[-1], 1.2 * math.cos(math.radians(heading)),
                                  1.2 * math.sin(math.radians(heading)))
        pts.append((lat, lon))
    return pts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=None, help="CSV with a real base trajectory (optional)")
    ap.add_argument("--lat-col", default="lat")
    ap.add_argument("--lon-col", default="lon")
    ap.add_argument("--points", type=int, default=200, help="number of points to generate/use")
    ap.add_argument("--base-lat", type=float, default=22.2500,
                     help="starting latitude for the synthetic path (default: Vadodara, Gujarat, India)")
    ap.add_argument("--base-lon", type=float, default=73.1950,
                     help="starting longitude for the synthetic path (default: Vadodara, Gujarat, India)")
    ap.add_argument("--spoof-min-m", type=float, default=20, help="min spoof jump distance in metres")
    ap.add_argument("--spoof-max-m", type=float, default=50, help="max spoof jump distance in metres")
    ap.add_argument("--num-spoof-events", type=int, default=4)
    ap.add_argument("--spoof-event-len", type=int, default=4, help="points per spoof event")
    ap.add_argument("--num-jam-events", type=int, default=3)
    ap.add_argument("--jam-event-len", type=int, default=4, help="points dropped per jam event")
    ap.add_argument("--interval-s", type=float, default=1.0, help="seconds between points")
    ap.add_argument("--out", default="labeled_dataset.csv")
    args = ap.parse_args()

    base = (load_base_path(args.file, args.lat_col, args.lon_col, args.points)
            if args.file else synthetic_path(args.points, args.base_lat, args.base_lon))
    n = len(base)
    print(f"Base trajectory: {n} points ({'from ' + args.file if args.file else 'synthetic'})")

    # pick non-overlapping windows for spoof and jam events
    all_idx = list(range(5, n - max(args.spoof_event_len, args.jam_event_len) - 1))
    random.shuffle(all_idx)
    spoof_starts, jam_starts, used = [], [], set()

    def free(start, length):
        return all(i not in used for i in range(start, start + length))

    for idx in all_idx:
        if len(spoof_starts) >= args.num_spoof_events:
            break
        if free(idx, args.spoof_event_len):
            spoof_starts.append(idx)
            used.update(range(idx, idx + args.spoof_event_len))

    for idx in all_idx:
        if len(jam_starts) >= args.num_jam_events:
            break
        if free(idx, args.jam_event_len):
            jam_starts.append(idx)
            used.update(range(idx, idx + args.jam_event_len))

    spoof_ranges = {s: s + args.spoof_event_len for s in spoof_starts}
    jam_ranges = {s: s + args.jam_event_len for s in jam_starts}

    def label_for(i):
        for s, e in spoof_ranges.items():
            if s <= i < e:
                return "SPOOFING"
        for s, e in jam_ranges.items():
            if s <= i < e:
                return "JAMMING"
        return "NORMAL"

    rows = []
    dev_b_lat, dev_b_lon = base[0]
    for i, (lat, lon) in enumerate(base):
        label = label_for(i)
        t = round(i * args.interval_s, 2)

        # device_A: trusted reference, always close to the real path (~1-3m GPS jitter)
        a_lat, a_lon = latlon_offset(lat, lon, random.uniform(-2, 2), random.uniform(-2, 2))
        rows.append([i, t, "device_A", round(a_lat, 7), round(a_lon, 7), "NORMAL"])

        if label == "SPOOFING":
            dist = random.uniform(args.spoof_min_m, args.spoof_max_m)
            angle = random.uniform(0, 360)
            b_lat, b_lon = latlon_offset(lat, lon, dist * math.cos(math.radians(angle)),
                                          dist * math.sin(math.radians(angle)))
            rows.append([i, t, "device_B", round(b_lat, 7), round(b_lon, 7), "SPOOFING"])
        elif label == "JAMMING":
            pass  # no row written -> silence, this IS the jamming signature
        else:
            b_lat, b_lon = latlon_offset(lat, lon, random.uniform(-2, 2), random.uniform(-2, 2))
            rows.append([i, t, "device_B", round(b_lat, 7), round(b_lon, 7), "NORMAL"])

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "t_offset_s", "device_id", "lat", "lon", "true_label"])
        w.writerows(rows)

    print(f"Wrote {len(rows)} labeled rows to {args.out}")
    print(f"  Spoof events: {len(spoof_starts)} (jump {args.spoof_min_m}-{args.spoof_max_m} m each, "
          f"{args.spoof_event_len} points long)")
    print(f"  Jam events:   {len(jam_starts)} ({args.jam_event_len} points of silence each)")
    print("\nNext: python evaluate_dataset.py --file " + args.out)


if __name__ == "__main__":
    main()
