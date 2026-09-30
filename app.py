import csv
import math
import os
import random
import time
import threading
import socket
import json
import requests
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_from_directory

# Import modular components
import config
from detector import SingleDeviceDetector

app = Flask(__name__)

# State registries
devices = {}            # device_id -> current state dictionary
detectors = {}          # device_id -> SingleDeviceDetector instance
blocked_devices = set()  # blacklisted device_ids
blocked_ips = set()      # blacklisted client IPs
history = {}            # device_id -> rolling history deque
sky_state = {}          # device_id -> satellite constellation
alert_history = []      # alert logs feed
attack_timeline = []    # Attack History Timeline records
device_registry = {}    # persistent mapping: device_id -> last_known_ip
live_metrics = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}  # session classification stats
operator_location = {"lat": None, "lon": None, "city": None} # stores host operator's coordinates shared by dashboard

ip_geo_cache = {}

def is_private_ip(ip):
    """True for localhost / same-Wi-Fi private addresses -- these have
    no meaningful public geolocation, so we must not fake one for them."""
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    return (a == 10) or (a == 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)


def geolocate_ip(ip):
    """Real IP -> approximate city-level lat/lon via the free ip-api.com
    endpoint (no API key required). Cached per-IP so this runs at most
    once per unique attacker IP, not on every dashboard poll (every 2s)."""
    if ip in ip_geo_cache:
        return ip_geo_cache[ip]
    if is_private_ip(ip):
        ip_geo_cache[ip] = None
        return None
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city,regionName,country",
            timeout=1.5,
        )
        data = r.json()
        if data.get("status") == "success":
            result = {
                "lat": data["lat"], "lon": data["lon"],
                "city": ", ".join(filter(None, [data.get("city"), data.get("regionName"), data.get("country")])),
            }
            ip_geo_cache[ip] = result
            return result
    except Exception:
        pass
    ip_geo_cache[ip] = None
    return None

SERVER_START = time.time()

# Ensure directories exist
os.makedirs("data", exist_ok=True)

def log_row(path, fieldnames, row):
    file_exists = os.path.isfile(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def _rewrite_timeline_log():
    if os.path.exists(config.ATTACK_HISTORY_FILE):
        try:
            os.remove(config.ATTACK_HISTORY_FILE)
        except Exception:
            pass
    for entry in attack_timeline:
        log_row(config.ATTACK_HISTORY_FILE, 
                ["id", "victim_device", "attacker_ip", "type", "pre_lat", "pre_lon", "post_lat", "post_lon", "start_time", "end_time", "duration", "mitigation_status"],
                entry)

def raise_alert(device_id, alert_type, severity, message):
    alert = {
        "device_id": device_id,
        "type": alert_type,
        "severity": severity,
        "message": message,
        "timestamp": datetime.utcnow().isoformat(),
    }
    alert_history.insert(0, alert)
    del alert_history[200:]
    log_row(config.ALERT_LOG_FILE,
            ["timestamp", "device_id", "type", "severity", "message"],
            {k: alert[k] for k in ["timestamp", "device_id", "type", "severity", "message"]})
    print(f"[ALERT] {alert_type} | {device_id} | {message}")
    return alert

@app.route("/")
def home():
    return render_template("dashboard.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/collector")
def collector():
    return render_template("collector.html")

@app.route("/update", methods=["POST"])
def update_telemetry():
    """Receives standard GPS telemetry from victim receivers over HTTP POST."""
    global devices, history, sky_state, detectors, attack_timeline, device_registry, live_metrics
    
    payload = request.get_json(force=True, silent=True) or {}
    device_id = payload.get("device_id")
    if not device_id:
        return jsonify({"error": "Missing device_id"}), 400

    request_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    device_registry[device_id] = request_ip
    attack_state = payload.get("attack_state", "NORMAL")
    attacker_ip = payload.get("attacker_ip")

    # Mitigation Filter: Automatically unblock if recovery command is active
    if device_id in blocked_devices or request_ip in blocked_ips:
        if attack_state == "NORMAL":
            if device_id in blocked_devices:
                blocked_devices.remove(device_id)
            if request_ip in blocked_ips:
                blocked_ips.remove(request_ip)
            if attacker_ip and attacker_ip in blocked_ips:
                blocked_ips.remove(attacker_ip)
            raise_alert(device_id, "MITIGATION", "INFO", f"Threat neutralized: Automatically unblocked {device_id} on recovery command.")
        else:
            return jsonify({"status": "BLOCKED", "messages": ["Source blacklisted by firewall"]}), 403

    lat = float(payload.get("lat", 0.0))
    lon = float(payload.get("lon", 0.0))
    altitude = float(payload.get("altitude", 0.0))
    speed = float(payload.get("speed", 0.0))
    heading = float(payload.get("heading", 0.0))
    accuracy = float(payload.get("accuracy", 0.0))
    client_ts = float(payload.get("timestamp", time.time()))
    
    if device_id not in detectors:
        detectors[device_id] = SingleDeviceDetector(device_id)

    # Process telemetry variables using modular threat engine
    now = time.time()
    prev_status = devices.get(device_id, {}).get("status", "NORMAL")
    
    state, messages = detectors[device_id].update(
        lat, lon, altitude, speed, heading, accuracy, client_ts, attack_state, attacker_ip, now
    )
    state["ip"] = request_ip
    
    devices[device_id] = state
    sky_state[device_id] = detectors[device_id].sky_state

    # Update live session classification metrics
    gt_attack = (attack_state != "NORMAL")
    pred_attack = (state["status"] in ("SPOOFING", "JAMMING"))
    
    if gt_attack and pred_attack:
        live_metrics["tp"] += 1
    elif not gt_attack and not pred_attack:
        live_metrics["tn"] += 1
    elif not gt_attack and pred_attack:
        live_metrics["fp"] += 1
    elif gt_attack and not pred_attack:
        live_metrics["fn"] += 1

    # Trigger alerts
    for msg in messages:
        severity = "CRITICAL" if state["status"] in ("SPOOFING", "JAMMING") else "WARNING"
        raise_alert(device_id, state["status"], severity, msg)

    # Manage Attack Timeline state transitions
    if prev_status == "NORMAL" and state["status"] in ("SPOOFING", "JAMMING"):
        prev_state = devices.get(device_id, {})
        pre_lat = prev_state.get("lat", lat)
        pre_lon = prev_state.get("lon", lon)
        
        timeline_entry = {
            "id": len(attack_timeline) + 1,
            "victim_device": device_id,
            "attacker_ip": attacker_ip or "unknown",
            "type": state["status"],
            "start_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": "—",
            "duration": "—",
            "mitigation_status": "Blocked" if (device_id in blocked_devices) else "Active Attack",
            "pre_lat": round(pre_lat, 5),
            "pre_lon": round(pre_lon, 5),
            "post_lat": round(lat, 5),
            "post_lon": round(lon, 5)
        }
        attack_timeline.append(timeline_entry)
        log_row(config.ATTACK_HISTORY_FILE,
                ["id", "victim_device", "attacker_ip", "type", "pre_lat", "pre_lon", "post_lat", "post_lon", "start_time", "end_time", "duration", "mitigation_status"],
                timeline_entry)
    elif prev_status in ("SPOOFING", "JAMMING") and state["status"] == "NORMAL":
        for entry in reversed(attack_timeline):
            if entry["victim_device"] == device_id and entry["end_time"] == "—":
                entry["end_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    t1 = datetime.strptime(entry["start_time"], "%Y-%m-%d %H:%M:%S")
                    t2 = datetime.strptime(entry["end_time"], "%Y-%m-%d %H:%M:%S")
                    entry["duration"] = f"{int((t2 - t1).total_seconds())}s"
                except Exception:
                    entry["duration"] = "0s"
                entry["mitigation_status"] = "Mitigated (Neutralized)"
                _rewrite_timeline_log()
                break

    # Maintain rolling chart history
    history.setdefault(device_id, deque(maxlen=config.HISTORY_LENGTH)).append({
        "t": datetime.utcnow().strftime("%H:%M:%S"),
        "snr": state["snr"],
        "cno": state["cno"],
        "satellites": state["satellites"],
        "anomaly_score": state["anomaly_score"],
    })

    # Log telemetry row to CSV dataset
    log_row(config.DATA_LOG_FILE,
            ["timestamp", "device_id", "lat", "lon", "accuracy", "heading", "speed_kmh", "status", "ip", "attacker_ip"],
            {
                "timestamp": datetime.utcnow().isoformat(),
                "device_id": device_id,
                "lat": state["lat"],
                "lon": state["lon"],
                "accuracy": state["accuracy"],
                "heading": state["heading"],
                "speed_kmh": state["speed"],
                "status": state["status"],
                "ip": state["ip"],
                "attacker_ip": state.get("attacker_ip", "")
            })

    return jsonify({"received": True, "status": state["status"], "messages": messages})

@app.route("/api/status")
def api_status():
    """Polled by dashboard UI. Evaluates jamming, uptime, and updates coordinates."""
    now = time.time()
    out = {}
    pruned_devices = []

    for device_id, d in list(devices.items()):
        silent_for = now - d["ts"]
        
        if silent_for > 600.0:  # Keep in dashboard for 10 minutes to allow operator mitigation
            pruned_devices.append(device_id)
            continue

        status = d["status"]
        
        # Jamming timeout / Offline transition
        if silent_for > 45.0:
            status = "OFFLINE"
        elif silent_for > config.JAMMING_TIMEOUT_SECONDS:
            if device_id in blocked_devices:
                status = "BLOCKED"
            else:
                status = "JAMMING"
            
            if status == "JAMMING":
                if not (alert_history and alert_history[0]["device_id"] == device_id
                        and alert_history[0]["type"] == "JAMMING"
                        and silent_for < config.JAMMING_TIMEOUT_SECONDS + 3.0):
                    raise_alert(device_id, "JAMMING", "CRITICAL",
                                f"Signal Loss: Device silent for {silent_for:.0f}s (jamming timeout threshold)")

        out[device_id] = {
            "lat": d["lat"], "lon": d["lon"], "altitude": d.get("altitude"),
            "speed": d.get("speed"), "heading": d.get("heading"),
            "accuracy": d.get("accuracy"), "ts": d["ts"],
            "status": status, "threat_level": d.get("threat_level", "Low Risk"),
            "ip": d.get("ip", "unknown"),
            "attacker_ip": d.get("attacker_ip"),
            "last_update_seconds_ago": round(silent_for, 1),
            "original_lat": d.get("original_lat"),
            "original_lon": d.get("original_lon"),
            "original_alt": d.get("original_alt"),
            
            # Mathematical differentials
            "distance_jump": d.get("distance_jump", 0.0),
            "lat_diff": d.get("lat_diff", 0.0),
            "lon_diff": d.get("lon_diff", 0.0),
            "speed_diff": d.get("speed_diff", 0.0),
            "heading_diff": d.get("heading_diff", 0.0),
            "position_drift": d.get("position_drift", 0.0),
            
            # Scores & indicators
            "threat_score": d.get("threat_score", 0.05) if status not in ("JAMMING", "OFFLINE") else (0.9 if status == "JAMMING" else 0.0),
            "anomaly_score": (d.get("anomaly_score", 0.05) if status not in ("JAMMING", "OFFLINE") else (1.0 if status == "JAMMING" else 0.0)),
            "confidence_score": (d.get("confidence_score", 0.0) if status not in ("JAMMING", "OFFLINE") else (95.0 if status == "JAMMING" else 0.0)),
            
            # Signal parameters
            "snr": d.get("snr"), "cno": d.get("cno"),
            "hdop": d.get("hdop"), "vdop": d.get("vdop"),
            "satellites": d.get("satellites"),
            "time_drift_ms": d.get("time_drift_ms"),
            "history": list(history.get(device_id, [])),
            "sky": sky_state.get(device_id, []),
        }

    # Execute pruning
    for device_id in pruned_devices:
        if device_id in devices:
            del devices[device_id]
        if device_id in detectors:
            del detectors[device_id]
        if device_id in history:
            del history[device_id]
        if device_id in sky_state:
            del sky_state[device_id]

    active_threat = None
    attacker_ip = "unknown"
    for device_id, d in out.items():
        if d["status"] in ("SPOOFING", "JAMMING"):
            active_threat = d
            attacker_ip = d.get("attacker_ip") or d.get("ip", "unknown")
            break

    # Compute live session classification metrics
    global live_metrics
    tp = live_metrics["tp"]
    tn = live_metrics["tn"]
    fp = live_metrics["fp"]
    fn = live_metrics["fn"]
    total = tp + tn + fp + fn
    
    if total > 0:
        accuracy = (tp + tn) / total * 100.0
        precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 100.0
        recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 100.0
        f1_score = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 100.0
    else:
        accuracy, precision, recall, f1_score = 100.0, 100.0, 100.0, 100.0

    attacker_loc = None
    if active_threat and attacker_ip and attacker_ip != "unknown":
        geo = geolocate_ip(attacker_ip)
        if geo:
            attacker_loc = {
                "lat": geo["lat"], "lon": geo["lon"],
                "ip": attacker_ip, "city": geo["city"],
            }
        else:
            attacker_loc = {
                "lat": None, "lon": None,
                "ip": attacker_ip, "city": "Local network (same Wi-Fi as victim)",
            }

    return jsonify({
        "devices": out,
        "alerts": alert_history[:25],
        "attack_timeline": attack_timeline[-10:],  # Return last 10 timeline entries
        "blocked_devices": list(blocked_devices),
        "blocked_ips": list(blocked_ips),
        "attacker_location": attacker_loc,
        "live_accuracy": {
            "accuracy": round(accuracy, 1),
            "precision": round(precision, 1),
            "recall": round(recall, 1),
            "f1_score": round(f1_score, 1),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "total_samples": total
        },
        "server": {
            "uptime_seconds": round(now - SERVER_START),
            "update_interval_s": 1,
        },
        "config": {
            "distance_threshold_m": config.SUDDEN_JUMP_THRESHOLD_M,
            "max_speed_kmh": config.MAX_SPEED_KMH,
            "jamming_timeout_s": config.JAMMING_TIMEOUT_SECONDS,
        }
    })

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        payload = request.get_json(force=True, silent=True) or {}
        if "max_speed_kmh" in payload:
            config.MAX_SPEED_KMH = float(payload["max_speed_kmh"])
        if "jamming_timeout_s" in payload:
            config.JAMMING_TIMEOUT_SECONDS = float(payload["jamming_timeout_s"])
        return jsonify({"success": True, "settings": {
            "max_speed_kmh": config.MAX_SPEED_KMH,
            "jamming_timeout_s": config.JAMMING_TIMEOUT_SECONDS,
        }})
    return jsonify({
        "max_speed_kmh": config.MAX_SPEED_KMH,
        "jamming_timeout_s": config.JAMMING_TIMEOUT_SECONDS,
    })

@app.route("/api/devices/reset", methods=["POST"])
def api_devices_reset():
    global devices, history, sky_state, alert_history, detectors, attack_timeline, live_metrics
    devices.clear()
    detectors.clear()
    history.clear()
    sky_state.clear()
    alert_history.clear()
    attack_timeline.clear()
    live_metrics = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    raise_alert("system", "INFO", "INFO", "System state reset by administrator")
    return jsonify({"success": True})

@app.route("/api/devices/block", methods=["POST"])
def api_devices_block():
    global devices, history, sky_state, blocked_devices, blocked_ips, alert_history, detectors, attack_timeline, device_registry
    payload = request.get_json(force=True, silent=True) or {}
    device_id = payload.get("device_id")
    if not device_id:
        return jsonify({"error": "device_id is required"}), 400
    
    blocked_devices.add(device_id)
    ip = payload.get("ip")
    if not ip and device_id in devices:
        ip = devices[device_id].get("attacker_ip") or devices[device_id].get("ip")

    if ip and ip not in ("127.0.0.1", "::1", "localhost"):
        blocked_ips.add(ip)

    # Revert target VM to NORMAL active state upon firewall quarantine
    victim_ip = None
    if device_id in devices:
        victim_ip = devices[device_id].get("ip")
    if not victim_ip:
        victim_ip = device_registry.get(device_id)

    if victim_ip:
        def send_mitigation_cmd(target_ip):
            try:
                requests.post(f"http://{target_ip}:9999/attack", json={"cmd": "normal"}, timeout=2)
                print(f"[MITIGATION] Remote recovery command issued to VM: {target_ip}:9999")
            except Exception as e:
                print(f"[MITIGATION] Connection failed to VM: {target_ip}: {e}")
        threading.Thread(target=send_mitigation_cmd, args=(victim_ip,), daemon=True).start()

    # Update attack timeline block status
    for entry in reversed(attack_timeline):
        if entry["victim_device"] == device_id and entry["end_time"] == "—":
            entry["end_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            entry["duration"] = "Mitigated"
            entry["mitigation_status"] = "Mitigated (Quarantined)"
            _rewrite_timeline_log()
            break

    # Purge telemetry history
    devices_to_delete = [device_id]
    for d_id, dev in list(devices.items()):
        if dev.get("ip") == ip or dev.get("attacker_ip") == ip:
            devices_to_delete.append(d_id)

    for d_id in set(devices_to_delete):
        if d_id in devices:
            del devices[d_id]
        if d_id in detectors:
            del detectors[d_id]
        if d_id in history:
            del history[d_id]
        if d_id in sky_state:
            del sky_state[d_id]
        alert_history = [a for a in alert_history if a.get("device_id") != d_id]

    raise_alert(device_id, "MITIGATION", "WARNING", f"Mitigation active: Blocked source {device_id} (IP: {ip or 'unknown'})")
    return jsonify({"success": True, "blocked_device": device_id, "blocked_ip": ip})

@app.route("/api/devices/unblock", methods=["POST"])
def api_devices_unblock():
    global blocked_devices, blocked_ips
    payload = request.get_json(force=True, silent=True) or {}
    device_id = payload.get("device_id")
    if not device_id:
        return jsonify({"error": "device_id is required"}), 400
        
    if device_id in blocked_devices:
        blocked_devices.remove(device_id)
        
    ip = payload.get("ip")
    if ip and ip in blocked_ips:
        blocked_ips.remove(ip)
        
    if not blocked_devices:
        blocked_ips.clear()
        
    raise_alert(device_id, "MITIGATION", "INFO", f"Mitigation removed: Unblocked source {device_id}")
    return jsonify({"success": True})

@app.route("/api/operator/location", methods=["GET", "POST"])
def api_operator_location():
    global operator_location
    if request.method == "POST":
        payload = request.get_json(force=True, silent=True) or {}
        lat, lon = payload.get("lat"), payload.get("lon")
        if lat is not None and lon is not None:
            operator_location = {"lat": float(lat), "lon": float(lon), "city": payload.get("city")}
            print(f"[OPERATOR-LOCATION] Dashboard reported real location: {operator_location}")
        return jsonify({"success": True, "location": operator_location})
    return jsonify({"location": operator_location})

@app.route("/api/logs/gps")
def api_logs_gps():
    limit = request.args.get("limit", default=100, type=int)
    rows = []
    if os.path.exists(config.DATA_LOG_FILE):
        try:
            with open(config.DATA_LOG_FILE, newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)[-limit:]
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify(rows)

@app.route("/api/logs/alerts")
def api_logs_alerts():
    limit = request.args.get("limit", default=100, type=int)
    rows = []
    if os.path.exists(config.ALERT_LOG_FILE):
        try:
            with open(config.ALERT_LOG_FILE, newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)[-limit:]
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify(rows)

@app.route("/api/reports/evaluation")
def api_reports_evaluation():
    report_path = os.path.join("analysis_output", "evaluation_report.txt")
    if os.path.exists(report_path):
        try:
            with open(report_path, "r") as f:
                content = f.read()
            return jsonify({"success": True, "content": content})
        except Exception as e:
            return jsonify({"success": False, "message": f"Error reading report: {e}"})
    return jsonify({"success": False, "message": "Report file not found. Run 'python evaluate_dataset.py' to generate it."})

@app.route("/api/reports/generate_charts", methods=["POST"])
def api_reports_generate_charts():
    import subprocess
    import sys
    try:
        # Run analyze_logs.py using the current python executable
        result = subprocess.run([sys.executable, "analyze_logs.py"], capture_output=True, text=True, check=True)
        return jsonify({"success": True, "output": result.stdout})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to run analyze_logs.py: {e}"})

@app.route("/analysis_output/<path:filename>")
def serve_analysis_output(filename):
    return send_from_directory("analysis_output", filename)

@app.route("/api/system/metrics")
def api_system_metrics():
    cpu_usage = 12.5
    memory_usage = 45.2
    try:
        import psutil
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
    except Exception:
        pass
    
    uptime = time.time() - SERVER_START
    return jsonify({
        "cpu_percent": cpu_usage,
        "memory_percent": memory_usage,
        "uptime_seconds": round(uptime),
        "status": "Healthy"
    })

def udp_broadcast_listener_loop():
    print(">>> Auto-Discovery UDP broadcast listener active on port 5005...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 5005))
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            payload = json.loads(data.decode('utf-8'))
            device_id = payload.get("device_id")
            lat = payload.get("lat")
            lon = payload.get("lon")
            if device_id is not None and lat is not None and lon is not None:
                with app.test_request_context(environ_base={'REMOTE_ADDR': addr[0]}):
                    process_telemetry_udp(device_id, float(lat), float(lon), payload, addr[0])
        except Exception:
            pass

def process_telemetry_udp(device_id, lat, lon, payload, request_ip):
    global devices, history, sky_state, detectors, attack_timeline
    attack_state = payload.get("attack_state", "NORMAL")
    attacker_ip = payload.get("attacker_ip")

    if device_id in blocked_devices or request_ip in blocked_ips:
        if attack_state == "NORMAL":
            if device_id in blocked_devices:
                blocked_devices.remove(device_id)
            if request_ip in blocked_ips:
                blocked_ips.remove(request_ip)
            if attacker_ip and attacker_ip in blocked_ips:
                blocked_ips.remove(attacker_ip)
            raise_alert(device_id, "MITIGATION", "INFO", f"Threat neutralized: Automatically unblocked {device_id} on recovery command.")
        else:
            return

    altitude = float(payload.get("altitude", 0.0))
    speed = float(payload.get("speed", 0.0))
    heading = float(payload.get("heading", 0.0))
    accuracy = float(payload.get("accuracy", 0.0))
    client_ts = float(payload.get("timestamp", time.time()))

    if device_id not in detectors:
        detectors[device_id] = SingleDeviceDetector(device_id)

    now = time.time()
    prev_status = devices.get(device_id, {}).get("status", "NORMAL")

    state, messages = detectors[device_id].update(
        lat, lon, altitude, speed, heading, accuracy, client_ts, attack_state, attacker_ip, now
    )
    state["ip"] = request_ip
    
    devices[device_id] = state
    sky_state[device_id] = detectors[device_id].sky_state

    for msg in messages:
        severity = "CRITICAL" if state["status"] in ("SPOOFING", "JAMMING") else "WARNING"
        raise_alert(device_id, state["status"], severity, msg)

    if prev_status == "NORMAL" and state["status"] in ("SPOOFING", "JAMMING"):
        timeline_entry = {
            "id": len(attack_timeline) + 1,
            "victim_device": device_id,
            "attacker_ip": attacker_ip or "unknown",
            "type": state["status"],
            "start_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": "—",
            "duration": "—",
            "mitigation_status": "Blocked" if (device_id in blocked_devices) else "Active Attack"
        }
        attack_timeline.append(timeline_entry)
        log_row(config.ATTACK_HISTORY_FILE,
                ["id", "victim_device", "attacker_ip", "type", "start_time", "end_time", "duration", "mitigation_status"],
                timeline_entry)
    elif prev_status in ("SPOOFING", "JAMMING") and state["status"] == "NORMAL":
        for entry in reversed(attack_timeline):
            if entry["victim_device"] == device_id and entry["end_time"] == "—":
                entry["end_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    t1 = datetime.strptime(entry["start_time"], "%Y-%m-%d %H:%M:%S")
                    t2 = datetime.strptime(entry["end_time"], "%Y-%m-%d %H:%M:%S")
                    entry["duration"] = f"{int((t2 - t1).total_seconds())}s"
                except Exception:
                    entry["duration"] = "0s"
                entry["mitigation_status"] = "Mitigated (Neutralized)"
                _rewrite_timeline_log()
                break

    history.setdefault(device_id, deque(maxlen=config.HISTORY_LENGTH)).append({
        "t": datetime.utcnow().strftime("%H:%M:%S"),
        "snr": state["snr"],
        "cno": state["cno"],
        "satellites": state["satellites"],
        "anomaly_score": state["anomaly_score"],
    })

if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        t_udp = threading.Thread(target=udp_broadcast_listener_loop, daemon=True)
        t_udp.start()
        print(">>> UDP Broadcast Auto-Discovery listener started successfully.")

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
