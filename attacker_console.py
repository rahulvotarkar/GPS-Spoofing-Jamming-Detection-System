import sys
import argparse
import urllib.request
import json

def send_attack_cmd(target_ip, target_port, payload):
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="127.0.0.1", help="Target Windows VM IP Address")
    parser.add_argument("--port", type=int, default=9999, help="Target Windows VM Client Port")
    args = parser.parse_args()

    print("=" * 60)
    print("      GNSS ATTACKER SIMULATOR CONSOLE (KALI LINUX HOST)     ")
    print("=" * 60)
    print(f"Targeting Victim VM: {args.ip}:{args.port}\n")

    while True:
        print("\nChoose Attack Strategy:")
        print("1. [NORMAL] Revert Victim back to Safe circular walk telemetry")
        print("2. [SPOOF] Simulate fake GPS coordinates, altitude, speed, and heading")
        print("3. [JAM] Trigger RF signal jamming simulation (kill VM telemetry)")
        print("4. [EXIT] Close Attacker Console")
        
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice == "1":
            payload = {"cmd": "normal"}
            print("\nSending Normal operation restore command...")
            send_attack_cmd(args.ip, args.port, payload)
        elif choice == "2":
            print("\nEnter Spoofed Telemetry Parameters (or press Enter for defaults):")
            
            # Default coordinates are ~5km away from Vadodara baseline
            lat_in = input("Fake Latitude [default: 22.3572]: ").strip()
            lon_in = input("Fake Longitude [default: 73.2312]: ").strip()
            alt_in = input("Fake Altitude (meters) [default: 120.0]: ").strip()
            spd_in = input("Fake Speed (km/h) [default: 180.0]: ").strip()
            hdg_in = input("Fake Heading (degrees) [default: 180.0]: ").strip()
            acc_in = input("Fake GPS Accuracy (meters) [default: 25.0]: ").strip()

            payload = {
                "cmd": "spoof",
                "lat": float(lat_in) if lat_in else 22.3572,
                "lon": float(lon_in) if lon_in else 73.2312,
                "altitude": float(alt_in) if alt_in else 120.0,
                "speed": float(spd_in) if spd_in else 180.0,
                "heading": float(hdg_in) if hdg_in else 180.0,
                "accuracy": float(acc_in) if acc_in else 25.0
            }
            print(f"\nSending Spoofed GPS payload: {payload}...")
            send_attack_cmd(args.ip, args.port, payload)
        elif choice == "3":
            payload = {"cmd": "jam"}
            print("\nSending Jamming signal commands...")
            send_attack_cmd(args.ip, args.port, payload)
        elif choice == "4":
            print("\nExiting Attacker Console.")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please select 1 to 4.")

if __name__ == "__main__":
    main()
