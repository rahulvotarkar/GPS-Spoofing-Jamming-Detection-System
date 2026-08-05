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
args = parser.parse_args()

# Standard Base Coordinates (Vadodara)
BASE_LAT = 22.3072
BASE_LON = 73.1812
RADIUS = 0.00015  # Circle radius in degrees (~16 meters)

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
        telemetry["lat"] = float(payload.get("lat", BASE_LAT + 0.05))
        telemetry["lon"] = float(payload.get("lon", BASE_LON + 0.05))
        telemetry["altitude"] = float(payload.get("altitude", 100.0))
        telemetry["speed"] = float(payload.get("speed", 180.0))
        telemetry["heading"] = float(payload.get("heading", 180.0))
        telemetry["accuracy"] = float(payload.get("accuracy", 25.0))
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
            print(f"[ERROR] Flask server on Laptop 2 unreachable: {e}")

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
    # Start sender loop in a separate thread
    t = threading.Thread(target=telemetry_sender_loop, daemon=True)
    t.start()
    
    # Run client API server listening on VM port 9999 for attacker commands
    app.run(host="0.0.0.0", port=args.port, debug=False)
