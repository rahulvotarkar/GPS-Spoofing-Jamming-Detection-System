import os
import sys
import argparse
import urllib.request
import json

def fetch_active_sessions(server_url, api_key):
    """Fetches active test sessions from the SOC server."""
    url = f"{server_url.rstrip('/')}/api/attacker/sessions"
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'AttackerConsole/2.0',
            'X-API-Key': api_key
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            res = json.loads(response.read().decode())
            return res.get("sessions", [])
    except Exception as e:
        print(f"[WARN] Unable to list active sessions from {url}: {e}")
        return []

def send_attack_cmd_server(server_url, api_key, payload):
    """Sends authenticated attack command to SOC Server backend."""
    url = f"{server_url.rstrip('/')}/api/attacker/command"
    payload["api_key"] = api_key
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'AttackerConsole/2.0',
            'X-API-Key': api_key
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            res = json.loads(response.read().decode())
            print(f"\n[SUCCESS] Server response: {res}")
    except Exception as e:
        print(f"\n[ERROR] Failed to send attack payload to server at {url}: {e}")

def send_attack_cmd_direct(target_ip, target_port, payload):
    """Sends attack command directly to Victim VM listening on port 9999."""
    url = f"http://{target_ip}:{target_port}/attack"
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, 
        headers={'Content-Type': 'application/json', 'User-Agent': 'AttackerConsole/1.0'}
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            res = json.loads(response.read().decode())
            print(f"\n[SUCCESS] Command sent successfully! VM response: {res}")
    except Exception as e:
        print(f"\n[ERROR] Failed to reach Victim VM on {url}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Authorized GNSS Attacker Simulator Console")
    parser.add_argument("--server", default=os.environ.get("ATTACKER_SERVER_URL"), help="SOC Server URL (e.g. http://localhost:5000 or Render URL)")
    parser.add_argument("--key", default=os.environ.get("ATTACKER_API_KEY", "default-test-key"), help="Attacker Authorization API Key")
    parser.add_argument("--ip", default="127.0.0.1", help="Direct Victim VM IP Address (Mode B)")
    parser.add_argument("--port", type=int, default=9999, help="Direct Victim VM Client Port (Mode B)")
    parser.add_argument("--target", default=None, help="Target Device/Session ID (e.g. USER-8F31A2 or device_B)")
    args = parser.parse_args()

    print("=" * 65)
    print("      AUTHORIZED GNSS ATTACKER SIMULATOR CONSOLE v2.0     ")
    print("=" * 65)
    
    use_server_mode = bool(args.server)
    if use_server_mode:
        print(f"Server Target Mode : {args.server.rstrip('/')}")
        print(f"Authorization Key  : {args.key[:4]}****")
    else:
        print(f"Direct VM Mode     : {args.ip}:{args.port}")
    print("=" * 65 + "\n")

    selected_target = args.target

    while True:
        # If running in server mode, discover and display active target sessions
        if use_server_mode and not selected_target:
            sessions = fetch_active_sessions(args.server, args.key)
            if sessions:
                print("\n[ACTIVE TEST SESSIONS DISCOVERED]")
                for idx, sess in enumerate(sessions, 1):
                    print(f"  {idx}. ID: {sess['device_id']:<14} Status: {sess['status']:<10} Source: {sess['source']}")
                print(f"  {len(sessions) + 1}. Manual Entry / Custom ID")
                
                sel_in = input(f"\nSelect target session (1-{len(sessions) + 1}) [default: 1]: ").strip()
                try:
                    choice_idx = int(sel_in) - 1 if sel_in else 0
                    if 0 <= choice_idx < len(sessions):
                        selected_target = sessions[choice_idx]["device_id"]
                    else:
                        selected_target = input("Enter Target Device/Session ID (e.g. device_B or USER-XXXXXX): ").strip() or "device_B"
                except ValueError:
                    selected_target = "device_B"
            else:
                selected_target = input("Enter Target Device/Session ID [default: device_B]: ").strip() or "device_B"
            print(f"[LOCKED TARGET SESSION] -> {selected_target}\n")

        print(f"\nActive Target Session: {selected_target or 'Default (device_B)'}")
        print("Choose Attack Command:")
        print("1. [NORMAL] Revert Target back to Safe/Normal telemetry")
        print("2. [SPOOF]  Simulate Controlled Fake GPS Spoofing Telemetry")
        print("3. [JAM]    Trigger Controlled RF Signal Jamming (Suppression)")
        if use_server_mode:
            print("4. [TARGET] Change Active Target Session")
            print("5. [EXIT]   Close Attacker Console")
        else:
            print("4. [EXIT]   Close Attacker Console")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == "1":
            payload = {"cmd": "normal", "device_id": selected_target or "device_B"}
            print(f"\nSending NORMAL restore command for target: {payload['device_id']}...")
            if use_server_mode:
                send_attack_cmd_server(args.server, args.key, payload)
            else:
                send_attack_cmd_direct(args.ip, args.port, payload)

        elif choice == "2":
            print("\nEnter Spoofed Telemetry Parameters (or press Enter for defaults):")
            lat_in = input("Fake Latitude [default: 22.33875]: ").strip()
            lon_in = input("Fake Longitude [default: 73.41384]: ").strip()
            alt_in = input("Fake Altitude (m) [default: 120.0]: ").strip()
            spd_in = input("Fake Speed (km/h) [default: 180.0]: ").strip()
            hdg_in = input("Fake Heading (°) [default: 180.0]: ").strip()
            acc_in = input("Fake Accuracy (m) [default: 25.0]: ").strip()

            try: lat = float(lat_in) if lat_in else 22.33875
            except ValueError: lat = 22.33875
            try: lon = float(lon_in) if lon_in else 73.41384
            except ValueError: lon = 73.41384
            try: alt = float(alt_in) if alt_in else 120.0
            except ValueError: alt = 120.0
            try: spd = float(spd_in) if spd_in else 180.0
            except ValueError: spd = 180.0
            try: hdg = float(hdg_in) if hdg_in else 180.0
            except ValueError: hdg = 180.0
            try: acc = float(acc_in) if acc_in else 25.0
            except ValueError: acc = 25.0

            payload = {
                "cmd": "spoof",
                "device_id": selected_target or "device_B",
                "lat": lat, "lon": lon, "altitude": alt,
                "speed": spd, "heading": hdg, "accuracy": acc
            }
            print(f"\nSending SPOOF payload for target {payload['device_id']}...")
            if use_server_mode:
                send_attack_cmd_server(args.server, args.key, payload)
            else:
                send_attack_cmd_direct(args.ip, args.port, payload)

        elif choice == "3":
            payload = {"cmd": "jam", "device_id": selected_target or "device_B"}
            print(f"\nSending JAMMING command for target {payload['device_id']}...")
            if use_server_mode:
                send_attack_cmd_server(args.server, args.key, payload)
            else:
                send_attack_cmd_direct(args.ip, args.port, payload)

        elif choice == "4" and use_server_mode:
            selected_target = None
        elif (choice == "4" and not use_server_mode) or (choice == "5" and use_server_mode):
            print("\nExiting Attacker Console.")
            sys.exit(0)
        else:
            print("\nInvalid choice. Try again.")

if __name__ == "__main__":
    main()

