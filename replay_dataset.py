"""
Dataset replay tool
--------------------
Feeds an existing GPS trajectory dataset (CSV) into your running server,
point by point, as if it were a live device. Use this to test/validate your
detection logic against real-world trajectories instead of only your own
walking data, and to generate more data for your report's results section.

Works against a LOCAL server (http://127.0.0.1:5000) or your DEPLOYED
server (https://your-app.onrender.com) -- just change --url.

------------------------------------------------------------------
Expected CSV format (minimum): two columns with latitude and longitude.
Common public datasets and how to prep them:

1. Your own logged data (data/gps_log.csv from this project)
   -> already has "lat" and "lon" columns, use as-is.

2. Kaggle "GPS Trajectories" / "Geolife Trajectories" datasets
   -> usually have columns named lat/lon or latitude/longitude; point
      --lat-col / --lon-col at whatever the file actually uses.

3. Microsoft Geolife dataset (.plt files, not CSV)
   Each .plt file has 6 header lines, then rows like:
       39.984702,116.318417,0,492,39744.246,2008-10-23,05:53:06
   Convert one .plt to CSV first:
       python -c "
import pandas as pd
df = pd.read_csv('000/Trajectory/20081023055305.plt', skiprows=6, header=None,
                  names=['lat','lon','zero','alt','days','date','time'])
df.to_csv('geolife_trip.csv', index=False)
"
   Then replay it with --lat-col lat --lon-col lon.
------------------------------------------------------------------

Usage:
    python replay_dataset.py --file data/gps_log.csv --device-id replay_test \
        --url http://127.0.0.1:5000/update --delay 1.0

    # against your deployed server:
    python replay_dataset.py --file geolife_trip.csv --device-id replay_test \
        --url https://your-app.onrender.com/update --lat-col lat --lon-col lon
"""

import argparse
import time

import pandas as pd
import requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="CSV file with a GPS trajectory")
    ap.add_argument("--url", default="http://127.0.0.1:5000/update", help="server /update endpoint")
    ap.add_argument("--device-id", default="replay_device", help="device_id to tag these points with")
    ap.add_argument("--lat-col", default="lat", help="name of the latitude column")
    ap.add_argument("--lon-col", default="lon", help="name of the longitude column")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds to wait between points")
    ap.add_argument("--limit", type=int, default=None, help="only replay the first N points")
    args = ap.parse_args()

    df = pd.read_csv(args.file)
    if args.limit:
        df = df.head(args.limit)

    print(f"Replaying {len(df)} points from {args.file} as device '{args.device_id}' -> {args.url}")
    for i, row in df.iterrows():
        payload = {
            "device_id": args.device_id,
            "lat": float(row[args.lat_col]),
            "lon": float(row[args.lon_col]),
            "accuracy": 6,
        }
        try:
            r = requests.post(args.url, json=payload, timeout=5)
            status = r.json().get("status", "?")
        except Exception as e:
            status = f"error: {e}"
        print(f"[{i+1}/{len(df)}] ({payload['lat']:.5f},{payload['lon']:.5f}) -> {status}")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
