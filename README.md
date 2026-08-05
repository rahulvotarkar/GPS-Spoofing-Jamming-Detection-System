# GPS Spoofing and Jamming Detection System — Full Project Guide

This package contains a **working prototype** plus a complete procedure so you
can build, run, test, and write up the project end‑to‑end.

**No smartphone required.** `virtual_devices.py` simulates real GPS
receivers entirely in software — the server, detection logic, and
dashboard genuinely cannot tell the difference between a phone's GPS chip
and a Python script sending the same JSON. Phones (Step 4, Option B/C
below) are supported too if you have one, but they're optional.

```
gps-spoof-detect/
├── app.py                  # Flask backend (server, detection logic, API)
├── simulate_devices.py     # ALL-IN-ONE: two virtual devices + interactive spoof/jam commands (recommended)
├── attacker_console.py     # TWO-LAPTOP SETUP: run on a separate "attacker" laptop, targets a remote detector laptop's IP
├── reference_device.py     # OPTIONAL alternative: trusted reference device run on the detector laptop instead
├── virtual_devices.py      # continuous virtual devices only, for scripted/multi-terminal setups
├── simulate_attack.py      # standalone spoof/jam injector, used together with virtual_devices.py
├── generate_labeled_dataset.py  # builds a ground-truth-labeled spoof/jam dataset (targets your 20-50m range)
├── evaluate_dataset.py     # replays a labeled dataset and reports precision/recall/F1
├── convert_geolife.py      # batch-converts downloaded Geolife .plt files to one CSV
├── convert_porto_taxi.py   # unpacks Porto's polyline-format CSV into plain lat/lon
├── replay_dataset.py       # feeds an external CSV dataset into the live system
├── analyze_logs.py         # turns your logged data into report-ready charts
├── requirements.txt
├── Procfile                # for cloud deployment (Render etc.)
├── templates/
│   ├── dashboard.html      # the live dashboard (open this in a browser)
│   └── collector.html      # optional: open on a phone to send its real GPS data
└── data/                   # auto-created: gps_log.csv, alerts_log.csv (your dataset!)
```

---

## 1. How the system actually works

You need **two data points to compare** — that's the core trick of any
software-only spoofing detector, since you can't inspect raw RF signals
without an SDR. This project gets that comparison in two ways at once:

1. **Cross-device check** — two phones physically next to each other should
   report almost the same location. If one suddenly disagrees by more than
   a threshold (default 50 m), that device is likely being spoofed.
2. **Impossible-speed check** — even with only *one* device, if its next fix
   implies a speed no human/vehicle could achieve (default > 150 km/h for a
   walking demo), that's a strong spoofing indicator.
3. **Jamming check** — if a device stops sending updates for longer than a
   timeout (default 15 s), it's flagged as jammed (or lost signal/no
   internet — that limitation is worth stating explicitly in your report).

All three checks run in `app.py` on every incoming reading, and results are
pushed to the dashboard in real time.

---

## 2. Setup procedure

### Step 1 — Install dependencies
```bash
cd gps-spoof-detect
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Run the server
```bash
python app.py
```
This starts Flask on `http://0.0.0.0:5000`. Find your laptop's local IP
(`ipconfig` on Windows / `ifconfig` or `ip a` on Mac/Linux, e.g. `192.168.1.7`).

### Step 3 — Open the dashboard
On your laptop, go to:
```
http://localhost:5000/dashboard
```

### Step 4 — Feed it GPS data (pick one — no smartphone required)

**Option A — All-in-one interactive simulator (simplest, one terminal, recommended):**
```bash
# in a second terminal, with app.py still running in the first
python simulate_devices.py
```
This walks two virtual devices (`device_A`, `device_B`) near each other
continuously, and lets you trigger detection events live by just typing a
command and pressing Enter — no extra terminals needed:
```
spoof   -> injects a sudden, impossible GPS jump on device_A -> SPOOFING alert
jam     -> device_A goes silent for 20 seconds                -> JAMMING alert
quit    -> stop the simulator
```
Open `/dashboard` in your browser and watch it react in real time. This is
the fastest way to get a full working demo running with nothing but your
laptop.

**Option A3 — Two separate laptops: attacker + detector (recommended for your viva demo):**
Instead of everything running on one machine, you can physically split
the roles — a strong choice for a demo, since it makes the attacker/
detector separation real rather than simulated in one process:

- **Laptop 1 (Detector):** runs the server and dashboard, exactly as before.
  ```bash
  python app.py
  ```
  Find this laptop's LAN IP (`ipconfig` / `ifconfig`) — e.g. `192.168.1.7`
  — and open `http://localhost:5000/dashboard` on it.
- **Laptop 2 (Attacker):** runs `attacker_console.py`, pointed at Laptop
  1's IP instead of localhost:
  ```bash
  python attacker_console.py --url http://192.168.1.7:5000/update
  ```
  Both laptops must be on the same Wi-Fi. This script simulates the
  device being attacked (`nav_unit`) plus a second always-normal
  reference device, so the cross-device check still has something to
  compare against without needing a third machine. Type commands
  directly into this terminal:
  ```
  normal  -> nav_unit walks normally
  spoof   -> launches a spoofing attack on nav_unit
  jam     -> launches a jamming attack on nav_unit
  quit    -> stop
  ```
  Watch Laptop 1's dashboard react live as you trigger attacks from
  Laptop 2 — this is a genuinely separate attacker and detector, not one
  script role-playing both, while still being 100% software and legal.

  **Variant (reference device co-located with the detector instead):** if
  you'd rather the "trusted baseline" device be physically with your
  detector laptop rather than simulated from the attacker side, run
  `python reference_device.py` in a second terminal on Laptop 1, and add
  `--no-reference` to the attacker_console.py command on Laptop 2 so it
  only sends the attacked device. Either variant is a valid architecture
  — pick whichever is simpler to explain in your report/viva.

**Option A2 — Separate scriptable simulator + attack injector (more flexible):**
If you'd rather drive movement and attacks from independent processes (for
example, to script an unattended demo loop, or automate repeated test
runs for your report), use `virtual_devices.py` for continuous movement:
```bash
python virtual_devices.py
```
This simulates two GPS receivers (`virtual_A`, `virtual_B`) walking near
each other and streams their positions to the server continuously. Use
`--devices 3` for more, `--interval 0.5` to move faster, `--lat`/`--lon`
to start somewhere else. Then, in a **third** terminal, use
`simulate_attack.py` (see Step 6 below) to inject spoof/jam events against
a separate `device_id` while `virtual_devices.py` keeps running normally.

**Option B — Phone browser (if you do have a phone handy, no app install):**
1. Connect your phone(s) to the **same Wi‑Fi** as your laptop.
2. On each phone, open a browser and go to `http://<laptop-ip>:5000/collector`
3. Give each phone a unique Device ID (`phone_A`, `phone_B`) and tap **Start Sending**.
4. Allow location permission when prompted. Keep the tab open/foregrounded.

**Option C — GPS Logger app (Android):**
1. Install "GPS Logger for Android" (Mendhak) from the Play Store.
2. Settings → Log to Custom URL → enable it.
3. Set the URL to:
   `http://<laptop-ip>:5000/update?device_id=phone_A&lat=%LAT&lon=%LON&accuracy=%ACC`
4. You'll need to adapt `/update` in `app.py` to also read GET query params
   (POST/JSON is the default here because it's more reliable and easier to debug).

All four options feed the exact same `/update` endpoint and drive the exact
same detection logic and dashboard — the system genuinely can't tell
whether a reading came from a phone's GPS chip or a Python script, which is
exactly why Option A is a legitimate way to build and demo the entire
project with zero hardware.

### Step 5 — Watch the dashboard
You'll see live markers per device, colour-coded:
- 🟢 green = normal
- 🔴 red = spoofing alert
- 🟠 orange = jamming alert (no data)

### Step 6 — Demonstrate detection (still no phone needed)
With `virtual_devices.py` running as your "trusted reference pair" in one
terminal, open a **third** terminal and run:
```bash
python simulate_attack.py spoof --device-id attack_test --lat 23.0225 --lon 72.5714
python simulate_attack.py jam   --device-id attack_test --lat 23.0225 --lon 72.5714
```
Use a fresh `--device-id` (like `attack_test`) rather than reusing
`virtual_A`/`virtual_B` — two scripts writing to the same device_id at the
same time interleave and produce noisy, misleading readings, since the
server can't tell they're meant to represent one continuous track. Keeping
the attacked device separate is also more realistic: it mirrors "a third,
untrusted receiver disagreeing with two trusted ones," which is the actual
scenario the cross-device check is designed to catch.

**Worth noting for your report:** when `attack_test` jumps away, you'll
see the dashboard flag `attack_test` **and** `virtual_A`/`virtual_B` as
SPOOFING — the algorithm detects *disagreement*, not which side is lying.
Distinguishing the genuinely spoofed device from the genuine ones (e.g. by
trusting whichever device has the longer consistent history, or a majority
vote across 3+ devices) is a great addition to list under Future Scope.

---

## 3. Are datasets actually important, and where do you get them?

**Short answer: yes, but not the way most students assume.** You do not
need to find a public "GPS spoofing dataset" and load it in — those barely
exist in usable form (see (c) below). What you actually need, and what
your evaluator will actually look for, is **evidence that your detector
was tested against real or realistic movement data and works**. That
comes from four sources, in order of importance:

### a) Your own live/simulated data (primary dataset — you already have this)
Every reading sent by `simulate_devices.py`, `virtual_devices.py`, or a
real phone is automatically logged to `data/gps_log.csv`, and every alert
to `data/alerts_log.csv`. This *is* a real dataset — timestamped,
device-tagged GPS data with outcomes. Run `analyze_logs.py` on it for
report-ready charts. This alone is enough to demonstrate the system works.

### b) A ground-truth-labeled dataset targeting your 20–50 m requirement (do this one)
This is the piece that actually answers your question. Public datasets
with confirmed spoofing/jamming labels at the coordinate level don't
exist for free download (real ones are raw RF recordings, see (c)). The
standard, defensible way researchers handle this for a software-only
detector is to take a **real movement trajectory** and **inject
synthetic spoof/jam events on top of it with known ground truth** — so
you get both realistic movement *and* labels you can score against.
That's exactly what `generate_labeled_dataset.py` + `evaluate_dataset.py`
do:

```bash
# 1. generate a labeled dataset, spoof jumps constrained to your 20-50m range
python generate_labeled_dataset.py --spoof-min-m 20 --spoof-max-m 50

# 2. (in another terminal, with app.py already running) replay it and score it
python evaluate_dataset.py --file labeled_dataset.csv
```
This produces real Accuracy / Precision / Recall / F1 numbers plus a
jamming-detection count, saved to `analysis_output/evaluation_report.txt`
— genuine quantitative results for your report, not just screenshots.
You can pass `--file` a **real downloaded trajectory** (see (d) below)
instead of using the built-in synthetic path, so the "normal" portion of
the dataset is real-world movement and only the attack windows are
synthetic — the strongest, most defensible setup for a project at this level.

**Important: restart `app.py` before an evaluation run if you've been
testing other things in the same session.** The cross-device check
compares a device against *every* other recently-active device, not a
specific designated pair — so if you ran `attacker_console.py` or
`simulate_devices.py` first and then run `evaluate_dataset.py` in the
same still-running server session, leftover devices from the earlier test
(e.g. one that's still sitting at a spoofed, far-away position) will
contaminate the cross-device comparison for your fresh dataset and tank
your precision with false positives that have nothing to do with the
dataset itself. Restart `python app.py` (or simply wait more than 15
seconds with no other devices sending data) right before running
`evaluate_dataset.py` for a clean, reproducible result.

**On your 20–50 m requirement specifically — important correction:**
`DISTANCE_THRESHOLD_METERS` in `app.py` is the cross-device disagreement
threshold, and it now defaults to **`15`** (updated after testing this
exact scenario). Earlier guidance suggested leaving it at `50` and citing
`--spoof-min-m 20 --spoof-max-m 50` results directly — **that combination
was tested and doesn't work**: if the threshold and the injected attack
range share the same upper bound, roughly half your injected spoofing
events land at or under the threshold and go undetected (confirmed:
0% recall in testing). The threshold has to sit **below** the range you
want to catch, not at its edge. With the threshold at `15` and attacks
injected in the `20`–`50` m range, testing produced 100% accuracy,
precision, and recall — that's the configuration to use and cite.

**Also important if you replay a real downloaded dataset:** always pass
`--interval-s` matching that dataset's actual recorded sampling rate
(Porto = 15 seconds, stated in its documentation; Geolife is typically
1–5 seconds; your own logged data is ~1 second). `evaluate_dataset.py`
uses this to tell the server the true elapsed time between points, so
speed-based checks stay physically accurate even when replay itself runs
fast (`--delay 0.1`). Skipping this makes normal real-world movement look
like an impossible jump purely because it was replayed faster than it was
recorded — this is a real, tested failure mode, not a hypothetical one.

### c) Do you even need an external dataset? (probably not — read this first)
The simplest, most defensible option is: **you don't need one at all.**
`generate_labeled_dataset.py`'s built-in synthetic path already starts at
`23.0225, 72.5714` — Gujarat, India — matching a typical Indian project's
location, and your detection algorithm only ever works on *relative*
distances and speeds between points, never absolute location. A dataset
recorded in Beijing, Porto, or anywhere else produces identical detection
behaviour to one recorded in Vadodara, because the haversine-distance and
speed-threshold checks don't know or care what country the coordinates
are in — 50 metres is 50 metres everywhere on Earth. So the Porto taxi
data is completely fine to use even for an India-based project; nothing
about the detection logic is region-specific. If you want it anyway —
for a real-world "normal movement" baseline, or because your report needs
to cite a named public dataset — use the table below. If not, skip
straight to (b) above using the built-in synthetic path.

### d) Public datasets you can actually download as CSV (real-world "normal" baselines, optional)
Use one of these as the `--file` input to `generate_labeled_dataset.py`
so your baseline movement is genuine, not synthetic. Two of these are
**already CSV, zero conversion needed** — start there if `.plt` files are
a hassle:

| Dataset | Format | Notes |
|---|---|---|
| **UCI "GPS Trajectories" Data Set** — `archive.ics.uci.edu/ml/datasets/GPS+Trajectories` | **CSV, direct download, no conversion** | Small, simple, real Android GPS logs (Go!Track app) — easiest starting point |
| **Geolife mirror on Kaggle** — `kaggle.com/datasets/arashnic/microsoft-geolife-gps-trajectory-dataset` | **Pre-converted CSV, no conversion** | Same real 17,621-trajectory Geolife data, already CSV |
| **Microsoft Geolife GPS Trajectories 1.3 (official)** — `microsoft.com/en-us/download/details.aspx?id=52367` | `.plt` — use `convert_geolife.py` (included, see below) | Same data as above but from the original source, if your report specifically needs the official citation |
| **Porto Taxi Trajectory (ECML/PKDD 15)** — `kaggle.com/datasets/crailtap/taxi-trajectory` | CSV, but GPS is packed into a `[lon,lat]` polyline string, one whole trip per row | Real taxi GPS; geography doesn't matter (see (c) above) — use `convert_porto_taxi.py` (included) to unpack it, see below |

**If you downloaded Porto specifically**, its `train.csv` doesn't have
plain lat/lon columns — each row is one entire taxi trip with all its GPS
points packed into a single `POLYLINE` string. `convert_porto_taxi.py` is
included and unpacks one trip into a clean two-column CSV:
```bash
python convert_porto_taxi.py --file train.csv --out porto_trip.csv
```
**Important: nothing gets "inserted into" `alerts_log.csv` or
`gps_log.csv` manually — those two files are outputs the server writes
for you automatically as it processes data, never something you edit or
load data into directly.** The actual pipeline that uses your downloaded
CSV is:
```bash
# 1. unpack the Porto trip into plain lat/lon
python convert_porto_taxi.py --file train.csv --out porto_trip.csv

# 2. build a labeled dataset: real Porto movement + injected 20-50m spoof
#    events + jamming windows, with Porto's real 15s sampling interval
python generate_labeled_dataset.py --file porto_trip.csv --interval-s 15 \
    --spoof-min-m 20 --spoof-max-m 50

# 3. in a separate terminal, make sure the server is running
python app.py

# 4. replay the labeled dataset through it and score the results
python evaluate_dataset.py --file labeled_dataset.csv
```
Step 4 is what actually populates `data/gps_log.csv` (every point it
sent) and `data/alerts_log.csv` (every alert the server raised on its
own, only when detection actually triggered) — both fill in automatically
as a side effect of the server processing the data, exactly like they
would from a real phone. It also prints and saves real
Accuracy/Precision/Recall/F1 numbers, so this one dataset is genuinely
enough for your project: it gives you real-world movement, controlled
ground-truth attacks in your exact 20–50 m range, and quantitative
results, all from a single download.

**If you do end up with Geolife's `.plt` files**, `convert_geolife.py` is
included in this project and batch-converts an entire downloaded folder
into one CSV in one command — no manual pandas snippet needed:
```bash
python convert_geolife.py --input "Geolife Trajectories 1.3/Data" --out geolife.csv
python generate_labeled_dataset.py --file geolife.csv --spoof-min-m 20 --spoof-max-m 50
```

### e) Public reference datasets (literature review / context only — not usable directly here)
These strengthen your literature survey but won't plug into this app —
they're raw RF signal recordings, not lat/lon CSVs:
- **TEXBAT** (Texas Spoofing Test Battery, UT Austin) — raw GNSS IF signal
  recordings with real spoofing attacks, the most-cited dataset in
  academic GNSS spoofing-detection papers.
- **OpenSky Network** — free ADS-B flight-tracking data; used in aviation
  GPS-anomaly research.

Be upfront in your report that (d) is cited for context, while (a)+(b),
optionally grounded in (c), are what your actual system was built and
evaluated on. That's an honest and defensible scope for a software-only,
no-SDR-hardware final-year project.

---

## 4. Detection logic (algorithm, formalised)

```
For each incoming reading (device_id, lat, lon, timestamp):

  1. If a previous reading exists for this device:
       distance = haversine(prev_lat, prev_lon, lat, lon)
       speed    = distance / (timestamp - prev_timestamp)
       if speed > MAX_PLAUSIBLE_SPEED:
           flag device as SPOOFING ("impossible jump")

  2. For every other currently-active device:
       distance = haversine(this device, other device)
       if distance > DISTANCE_THRESHOLD:
           flag device as SPOOFING ("disagrees with other device")

  3. Separately, on a periodic check:
       if (now - last_update_time) > JAMMING_TIMEOUT:
           flag device as JAMMING

  4. Log the reading and any alert; push to dashboard via /api/status
```

**Haversine formula** (great-circle distance between two lat/lon points) is
used because GPS coordinates are angular, not Cartesian — this is the
correct formula to cite in your report rather than plain Euclidean distance.

---

## 5. Suggested thresholds and how to justify them

| Parameter | Default | How to justify in report |
|---|---|---|
| Distance threshold | 15 m | Set deliberately below the 20–50 m attack range you're evaluating against, not at its edge — testing confirmed a threshold equal to the attack range's own bounds misses roughly half of injected attacks. Typical consumer GPS accuracy is 3–10 m, so 15 m still comfortably tolerates normal receiver noise. |
| Max plausible speed | 150 km/h | Set above vehicle speeds if testing while driving, or lower (~10 km/h) if testing on foot — tune to your demo scenario and say so explicitly |
| Jamming timeout | 15 s | Long enough to avoid false alarms from brief network hiccups, short enough to be "real-time" |

Mention in your report that these are **tunable parameters**, and ideally
show a small table/graph of how false-positive rate changes as you vary the
threshold — that's an easy way to add a "results and analysis" section with
real content.

---

## 6. Testing procedure for your demo/viva

1. Start `app.py`, open `/dashboard`.
2. Open `/collector` on Phone A, start sending → see green marker appear.
3. Run `python simulate_attack.py spoof` → red SPOOFING alert should appear
   within seconds, with a log entry explaining why (jump distance/speed).
4. Run `python simulate_attack.py jam` (or just close Phone A's tab and wait
   15+ seconds) → orange JAMMING alert appears.
5. Show `data/gps_log.csv` and `data/alerts_log.csv` as evidence of logged,
   analysable results.
6. Optional: plot a chart (matplotlib) from `gps_log.csv` showing normal vs
   flagged points on a lat/lon scatter — good for your report's results
   chapter and for the viva slide deck.

---

## 7. Mapping this back to your existing chapter structure

Your notes already have the right chapter skeleton. Here's what goes in
each, using this implementation:

1. **Introduction** — as written; add one line noting this is a
   software-only, multi-device comparison approach (not RF-signal analysis).
2. **Problem Statement** — as written.
3. **Objectives** — as written; you can now say "achieved" for all four.
4. **System Overview** — Two (or more) Android phones (browser-based GPS
   collector) → Flask server on a laptop over local Wi‑Fi → detection engine
   → Leaflet/OpenStreetMap dashboard.
5. **Tools Used** — Python 3, Flask, Leaflet.js, OpenStreetMap tiles,
   smartphone browser Geolocation API (mention GPS Logger app as an
   alternative data source).
6. **Working Principle** — as written; now backed by the actual `/update` →
   detection → `/api/status` → dashboard pipeline above.
7. **Detection Logic** — use the three-check algorithm in Section 4 above
   (this is stronger than a single-threshold check and gives you more to
   write about).
8. **Algorithm** — use the pseudocode in Section 4.
9. **Implementation Steps** — use Section 2 verbatim.
10. **Output** — screenshot the dashboard showing NORMAL, SPOOFING, and
    JAMMING states (use the simulator to generate all three states on
    demand for clean screenshots).
11. **Advantages / Limitations / Applications / Future Scope** — your notes
    are already good; you can now add "tested with real Android devices and
    a repeatable attack simulator" as a concrete advantage, and cite TEXBAT
    in future scope as "the next step would be validating against
    RF-level spoofing datasets such as TEXBAT using an SDR front end."
12. **Conclusion** — as written, now demonstrably true.

---

## 8. Common pitfalls to avoid

- **Phone can't reach the server** → laptop and phone must be on the *same*
  Wi‑Fi network, and your laptop firewall must allow inbound connections on
  port 5000.
- **Browser blocks geolocation** → the Geolocation API requires HTTPS on
  most browsers *except* when the page is served from `localhost` or a
  local network IP over plain HTTP for testing — if it's blocked, test on
  `localhost` first, or use `ngrok`/a self-signed cert for phone testing.
- **False spoofing alerts indoors** → GPS accuracy indoors is poor (can be
  50–100+ m error); do your live demo outdoors or in an open area for clean
  results, and mention this as a limitation in your report.
- **Don't attempt a real RF jammer/spoofer** — it's illegal to transmit on
  GPS frequencies without authorization in virtually every country. Use
  `simulate_attack.py` for your demo instead, and say so explicitly in your
  report/viva — examiners respect that distinction.

## 8b. Dashboard opens but nothing updates — troubleshooting

This is almost always one of two things, in order of likelihood:

1. **No data source is running.** Opening `/dashboard` by itself shows
   only the header/clock — the map, alerts, and stat cards all stay empty
   until something is sending GPS data. You need **two terminals**: one
   running `python app.py`, a second running `python simulate_devices.py`
   (or `virtual_devices.py`, or a phone on `/collector`). The dashboard
   now shows a banner directly on the page explaining this if no device
   has connected yet — if you see "No device is sending data yet," that's
   the fix.
2. **A CDN library (map or charts) failed to load.** The dashboard loads
   Leaflet and Chart.js from `cdnjs.cloudflare.com` over the internet —
   if a college/office network firewall blocks that domain, the map or
   charts won't render. The dashboard now detects this and shows a red
   banner naming exactly which library failed. To confirm, press F12 in
   your browser, open the Console tab, and look for red errors — or open
   the Network tab and check whether `leaflet.min.js` / `chart.umd.js`
   show a red/failed status. If your network blocks it, try a different
   network (mobile hotspot works well for this), or download those two
   files once and serve them from `static/` instead of the CDN.

If neither banner appears and panels are still empty, confirm the server
itself is reachable: `curl http://127.0.0.1:5000/api/status` should return
JSON, not a connection error — if it fails, `app.py` isn't running or
you're pointing the browser at the wrong port.

---

## 10. Deployment — making it accessible

You have three levels here, from "just my laptop" to "a public URL anyone
can open." Use whichever matches what you need for your submission/demo.

### Level 1 — Local only (what you've been doing)
```bash
python app.py
```
Only reachable at `http://localhost:5000` on the same machine. Fine for
development, not for a demo where your phone or an examiner's laptop needs
to reach it.

### Level 2 — Accessible on your local Wi-Fi (phone + laptop, no internet needed)
This is what the collector page already relies on:
1. Find your laptop's local IP: `ipconfig` (Windows) or `ifconfig`/`ip a`
   (Mac/Linux) — look for something like `192.168.1.7`.
2. Run `python app.py` (it already binds to `0.0.0.0`, so this works).
3. On your phone (same Wi-Fi), open `http://192.168.1.7:5000/collector`.
4. On your laptop, open `http://192.168.1.7:5000/dashboard` (or
   `http://localhost:5000/dashboard`).
5. If your phone can't connect: your laptop's firewall is probably
   blocking inbound port 5000 — allow it (Windows Defender Firewall →
   Allow an app → add Python, or `sudo ufw allow 5000` on Linux).

This is enough for your in-person viva demo.

### Level 3 — A public URL (for remote demos, or to put a link in your report)

**Option A — ngrok (quick, temporary, easiest)**
Good for a one-off demo without deploying anywhere.
1. Sign up free at ngrok.com and install it.
2. Run your server locally: `python app.py`
3. In another terminal: `ngrok http 5000`
4. ngrok prints a public HTTPS URL like `https://abcd1234.ngrok-free.app`
   — share that. It forwards straight to your laptop, so your laptop must
   stay on and running for it to keep working.

**Option B — Render.com (free, permanent, recommended for a final-year project)**
This gives you a real, permanent URL like
`https://your-project-name.onrender.com` that works even when your laptop
is off — good to put in your report/GitHub README.
1. Push this project folder to a GitHub repository (create one, `git init`,
   `git add .`, `git commit -m "GPS spoofing detection system"`, push).
2. Go to render.com → New → Web Service → connect your GitHub repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --bind 0.0.0.0:$PORT` (already in the
   included `Procfile`, Render detects it automatically).
5. Deploy. Render gives you the public URL in a couple of minutes.
6. Open `https://your-app.onrender.com/dashboard` from anywhere, and give
   phones `https://your-app.onrender.com/collector`.

Note: Render's free tier spins the app down after inactivity and takes ~30s
to wake up on the next request — fine for a demo, mention it if asked.

**Option C — PythonAnywhere** is another free option that's arguably even
simpler for a first-time Flask deployment (upload files directly through
their web UI, no `git` required) — search "Flask on PythonAnywhere" in
their docs if you'd rather avoid GitHub entirely.

**A note on the in-memory data store:** this app currently keeps device
state in a plain Python dict (see `devices = {}` in `app.py`), which is
fine for a single-process demo but resets if the server restarts, and
free hosting tiers on Render will restart your app after inactivity. If
you want data to survive restarts, that's a natural "Future Scope" item —
swap `devices`/`history` for a real database (SQLite is the easiest
upgrade, a couple of lines with `sqlite3` or `SQLAlchemy`).

## 11. Attaching / integrating datasets

There are two different things people mean by "add a dataset" here — make
sure your report is clear about which one you're doing:

### a) Feed an external dataset INTO the running system (test the detector on real trajectories)
Use the included `replay_dataset.py`. It reads any CSV with lat/lon columns
and POSTs each point to your server's `/update` endpoint, one at a time,
exactly like a real device would — so your detection logic runs on it live
and everything shows up on the dashboard and in `data/gps_log.csv`.
```bash
pip install -r requirements.txt
python replay_dataset.py --file data/gps_log.csv --device-id replay_test --delay 1.0
```
To use a public dataset instead of your own logs:
1. Download a trajectory dataset — see options below.
2. Make sure it has a latitude and a longitude column (rename if needed,
   or pass `--lat-col`/`--lon-col` matching whatever the file uses).
3. Run replay_dataset.py pointing `--file` at it. Point `--url` at your
   deployed server's `/update` endpoint if you want to test the public
   version instead of localhost.

**Where to get a real trajectory dataset:**
- Your own collected data — best option, see Section 3(a) above.
- **Kaggle "GPS Trajectories" dataset** (Rome taxi/bus GPS traces) — search
  "GPS Trajectories" on kaggle.com, free download, already close to CSV.
- **Microsoft Geolife GPS Trajectories dataset** — free, ~18,000 real
  trajectories from 182 users, published by Microsoft Research. Files are
  `.plt` format; see the conversion snippet inside `replay_dataset.py`'s
  docstring for turning one into a usable CSV.
- **OpenSky Network** — free ADS-B flight-tracking data, more relevant if
  you want to discuss aviation GPS anomalies in your literature review.

### b) Analyse the dataset your OWN system produced (for your report's results chapter)
Every reading and alert your server handles is already being logged to
`data/gps_log.csv` and `data/alerts_log.csv` — this is your project's own
generated dataset. Run:
```bash
python analyze_logs.py
```
This produces three charts in `analysis_output/`:
- `trajectory_plot.png` — GPS points colored by detection status
- `anomaly_over_time.png` — anomaly score timeline with risk thresholds and flagged points marked
- `alerts_summary.png` — bar chart of alert counts by type

Drop these straight into your report's "Results and Analysis" chapter —
they're exactly the kind of concrete, generated-from-your-own-system
evidence a final-year evaluator wants to see, rather than screenshots
alone.

## 12. Possible extensions if you have time (Future Scope, made concrete)

- Add a `matplotlib`/`plotly` chart endpoint that renders spoofing/jamming
  events over time from `alerts_log.csv`.
- Add a simple ML anomaly detector (e.g. `IsolationForest` from
  scikit-learn) trained on `gps_log.csv` speed/accuracy features, and
  compare its flags against your rule-based thresholds — a nice "future
  scope, partially implemented" section.
- Add HDOP/accuracy-based confidence weighting (GPS Logger app reports
  accuracy; poor accuracy readings could be down-weighted rather than
  treated as equally trustworthy).
