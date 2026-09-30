import time
import math
import random
import threading
import argparse
import socket
from flask import Flask, jsonify, request

# Command line configuration
parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:5000/update", help="Flask server update URL")
parser.add_argument("--device", default="device_B", help="Device ID")
parser.add_argument("--port", type=int, default=9999, help="Receiver port listening for attack commands")
parser.add_argument("--lat", type=float, default=None, help="Manual starting Latitude")
parser.add_argument("--lon", type=float, default=None, help="Manual starting Longitude")
args = parser.parse_args()

# Standard Base Coordinates (Vadodara)
BASE_LAT = 22.28875
BASE_LON = 73.36384
RADIUS = 0.00015  # Circle radius in degrees (~16 meters)

def find_working_server_url(primary_url):
    """Scans primary URL and VirtualBox/Host network candidate endpoints to find the active SOC server."""
    import urllib.request
    import socket
    
    candidate_urls = []
    if primary_url:
        candidate_urls.append(primary_url)
    
    # Dynamically query active network adapter IPs on the host
    dynamic_ips = ["192.168.56.1", "10.0.2.2", "127.0.0.1"]
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127.") and ip not in dynamic_ips:
                dynamic_ips.append(ip)
    except Exception:
        pass

    for ip in dynamic_ips:
        candidate_urls.append(f"http://{ip}:5000/update")

    unique_urls = []
    for u in candidate_urls:
        if u not in unique_urls:
            unique_urls.append(u)

    print("[AUTO-DISCOVERY] Scanning active network interfaces for SOC Dashboard...")
    for test_url in unique_urls:
        try:
            base_url = test_url.replace("/update", "")
            status_url = f"{base_url}/api/status"
            req = urllib.request.Request(status_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                if resp.status == 200:
                    print(f"[AUTO-DISCOVERY] Connected to active SOC Dashboard at: {test_url}")
                    return test_url
        except Exception:
            pass
            
    print(f"[WARN] Could not reach active SOC server during auto-discovery. Using: {primary_url}")
    return primary_url

def get_server_operator_location(server_url):
    """Tries to query the host/operator location saved by the dashboard on the server."""
    import urllib.request
    import json
    try:
        base_url = server_url.replace("/update", "")
        url = f"{base_url}/api/operator/location"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            loc = data.get("location")
            if loc and loc.get("lat") and loc.get("lon"):
                lat = float(loc["lat"])
                lon = float(loc["lon"])
                print(f"[SERVER-GEOLOCATION] Successfully resolved host laptop location: {lat}, {lon}")
                return lat, lon
    except Exception as e:
        print(f"[SERVER-GEOLOCATION] Failed to fetch operator location from server: {e}")
    return None

def get_windows_native_location():
    """Tries to query native Windows Location Services using PowerShell .NET bindings."""
    import subprocess
    import json
    try:
        # PowerShell command calling .NET GeoCoordinateWatcher
        ps_cmd = (
            '[Void][System.Reflection.Assembly]::LoadWithPartialName("System.Device"); '
            '$w = New-Object System.Device.Location.GeoCoordinateWatcher; '
            '$w.Start(); '
            'for($i=0; $i -lt 15; $i++) { '
            '  if ($w.Status -eq "Ready" -or $w.Position.Location.IsUnknown -eq $false) { break; }; '
            '  Start-Sleep -Milliseconds 200; '
            '}; '
            '$loc = $w.Position.Location; '
            '@{Latitude=$loc.Latitude; Longitude=$loc.Longitude; Accuracy=$loc.HorizontalAccuracy} | ConvertTo-Json'
        )
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            lat = data.get("Latitude")
            lon = data.get("Longitude")
            if lat and lon and lat != 0.0 and lon != 0.0 and str(lat) != "NaN":
                print(f"[WINDOWS-GEOLOCATION] Native Windows Location Service resolved location: {lat}, {lon}")
                return lat, lon
    except Exception as e:
        print(f"[WINDOWS-GEOLOCATION] Failed to query Windows native location API: {e}")
    return None

def get_ip_location():
    """Tries to find the VM's real location using free IP Geolocation APIs."""
    import urllib.request
    import json
    try:
        url = "http://ip-api.com/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                lat = float(data.get("lat"))
                lon = float(data.get("lon"))
                print(f"[IP-GEOLOCATION] Successfully resolved real current location: {lat}, {lon} ({data.get('city')}, {data.get('country')})")
                return lat, lon
    except Exception as e:
        print(f"[IP-GEOLOCATION] ip-api lookup failed: {e}")
        
    try:
        url = "https://ipinfo.io/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            loc = data.get("loc", "").split(",")
            if len(loc) == 2:
                lat = float(loc[0])
                lon = float(loc[1])
                print(f"[IP-GEOLOCATION] Successfully resolved real current location (backup): {lat}, {lon} ({data.get('city')}, {data.get('country')})")
                return lat, lon
    except Exception as e:
        print(f"[IP-GEOLOCATION] ipinfo lookup failed: {e}")

    print("[IP-GEOLOCATION] Geolocation failed. Using default baseline (Parul University): 22.28875, 73.36384")
    return 22.28875, 73.36384

# GPS state variables (Laptop 1 VM maintains this)
current_mode = "NORMAL"  # "NORMAL", "SPOOF", "JAM"
angle = 0.0

# Telemetry parameters
telemetry = {
    "lat": BASE_LAT,
    "lon": BASE_LON,
    "altitude": 35.0,
    "speed": 5.0,
    "heading": 0.0,
    "accuracy": 5.0,
    "attacker_ip": None
}

app = Flask(__name__)

@app.route("/attack", methods=["POST"])
def set_attack_state():
    """Receives attack simulation payloads from Kali Linux."""
    global current_mode, telemetry
    payload = request.get_json(force=True, silent=True) or {}
    cmd = payload.get("cmd", "normal").upper()
    
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if cmd == "SPOOF":
        current_mode = "SPOOF"
        try:
            telemetry["lat"] = float(payload.get("lat", BASE_LAT + 0.05))
        except (ValueError, TypeError):
            telemetry["lat"] = BASE_LAT + 0.05
            
        try:
            telemetry["lon"] = float(payload.get("lon", BASE_LON + 0.05))
        except (ValueError, TypeError):
            telemetry["lon"] = BASE_LON + 0.05
            
        try:
            telemetry["altitude"] = float(payload.get("altitude", 100.0))
        except (ValueError, TypeError):
            telemetry["altitude"] = 100.0
            
        try:
            telemetry["speed"] = float(payload.get("speed", 180.0))
        except (ValueError, TypeError):
            telemetry["speed"] = 180.0
            
        try:
            telemetry["heading"] = float(payload.get("heading", 180.0))
        except (ValueError, TypeError):
            telemetry["heading"] = 180.0
            
        try:
            telemetry["accuracy"] = float(payload.get("accuracy", 25.0))
        except (ValueError, TypeError):
            telemetry["accuracy"] = 25.0
            
        telemetry["attacker_ip"] = attacker_ip
        print(f"[ATTACK] Spoofed payload received from {attacker_ip}. Mode: SPOOF")
    elif cmd == "JAM":
        current_mode = "JAM"
        telemetry["attacker_ip"] = attacker_ip
        print(f"[ATTACK] Jamming signal command received from {attacker_ip}. Mode: JAM")
    else:
        current_mode = "NORMAL"
        telemetry["attacker_ip"] = None
        print("[OK] Normal operation restored.")

    return jsonify({"success": True, "mode": current_mode})

def telemetry_sender_loop():
    """Continuously runs the telemetry loop, simulating regular GPS changes."""
    global angle, current_mode, telemetry
    
    while True:
        if current_mode == "JAM":
            # Jamming: Stop transmitting updates to simulate complete signal loss
            print("[INFO] Jamming active: Telemetry transmission suspended.")
            time.sleep(2.0)
            continue
            
        if current_mode == "NORMAL":
            # Normal state: smooth circular walk simulation
            angle += 0.1
            telemetry["lat"] = BASE_LAT + RADIUS * math.sin(angle)
            telemetry["lon"] = BASE_LON + RADIUS * math.cos(angle)
            telemetry["altitude"] = 35.0 + random.uniform(-0.5, 0.5)
            telemetry["speed"] = round(random.uniform(4.0, 7.0), 1)
            telemetry["heading"] = round(math.degrees(angle) % 360, 1)
            telemetry["accuracy"] = round(random.uniform(4.0, 8.0), 1)
            print("[OK] Transmitting normal GPS telemetry...")
        else:
            print("[WARNING] Transmitting spoofed GPS telemetry...")

        # Construct standard JSON telemetry payload
        payload = {
            "device_id": args.device,
            "lat": telemetry["lat"],
            "lon": telemetry["lon"],
            "altitude": telemetry["altitude"],
            "speed": telemetry["speed"],
            "heading": telemetry["heading"],
            "accuracy": telemetry["accuracy"],
            "timestamp": time.time(),
            "attack_state": current_mode,
            "attacker_ip": telemetry.get("attacker_ip")
        }

        # Send over HTTP POST to the SOC Server on Laptop 2
        try:
            requests_session = requests_post_telemetry(args.url, payload)
        except Exception as e:
            print(f"\n[CONNECTION ALERT] Cannot reach SOC server at {args.url}")
            print(f"[REASON] {e}")
            print(f"[SOLUTION] Verify python app.py is running on Laptop 2, and specify Laptop 2's IP:")
            print(f"          python gps_client.py --url http://<LAPTOP_2_IP>:5000/update --device {args.device} --port {args.port}\n")

        time.sleep(2.0)

def requests_post_telemetry(url, payload):
    import requests
    r = requests.post(url, json=payload, timeout=2)
    if r.status_code == 200:
        print(f" -> Response: {r.json()}")
    elif r.status_code == 403:
        print(" -> Response: [403 Forbidden] Blacklisted by SOC Firewall quarantine!")
    else:
        print(f" -> Response Code: {r.status_code}")
    return r

if __name__ == "__main__":
    # Auto-scan candidate network interfaces to discover active SOC Dashboard
    args.url = find_working_server_url(args.url)
    
    # Layered location discovery logic
    if args.lat is not None and args.lon is not None:
        BASE_LAT = args.lat
        BASE_LON = args.lon
        print(f"[MANUAL-LOCATION] Using command-line coordinates: {BASE_LAT}, {BASE_LON}")
    else:
        # 1. Try to fetch Host Laptop Location shared by the dashboard
        coords = get_server_operator_location(args.url)
        if coords:
            BASE_LAT, BASE_LON = coords
        else:
            # 2. Try Windows Native Geolocation
            coords = get_windows_native_location()
            if coords:
                BASE_LAT, BASE_LON = coords
            else:
                # 3. Fallback to IP Geolocation
                BASE_LAT, BASE_LON = get_ip_location()
            
    telemetry["lat"] = BASE_LAT
    telemetry["lon"] = BASE_LON

    # Start sender loop in a separate thread
    t = threading.Thread(target=telemetry_sender_loop, daemon=True)
    t.start()
    
    # Run client API server listening on VM port 9999 for attacker commands
    app.run(host="0.0.0.0", port=args.port, debug=False)
