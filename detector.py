import math
import random
import time
import config

def haversine_distance_m(lat1, lon1, lat2, lon2):
    """Great-circle distance between two coordinates in meters."""
    R = 6371000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    
    a = (math.sin(dphi / 2.0) ** 2.0 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2.0)
    return 2.0 * R * math.asin(math.sqrt(a))

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

class SingleDeviceDetector:
    def __init__(self, device_id):
        self.device_id = device_id
        self.prev = None
        self.packet_count = 0
        self.sky_state = self._init_sky()
        
        # Saved baseline coordinates to calculate position drift
        self.last_safe_lat = None
        self.last_safe_lon = None
        self.last_safe_alt = None

    def _init_sky(self):
        """Build a deterministic set of simulated satellites for this receiver."""
        random.seed(hash(self.device_id) % (2 ** 16))
        sats = []
        for i in range(12):
            sats.append({
                "id": f"{(i * 7 + 2) % 32:02d}",
                "azimuth": random.uniform(0, 360),
                "elevation": random.uniform(15, 85),
                "snr": random.uniform(35, 48),
            })
        random.seed()  # Restore entropy source
        return sats

    def update(self, lat, lon, altitude, speed, heading, accuracy, client_ts, attack_state, attacker_ip, now):
        self.packet_count += 1
        messages = []
        status = "NORMAL"
        
        # 1. Parse client time delta
        dt = now - self.prev["ts"] if self.prev else 0.0
        
        # 2. Calculate differentials
        distance_jump = 0.0
        lat_diff = 0.0
        lon_diff = 0.0
        speed_diff = 0.0
        heading_diff = 0.0
        position_drift = 0.0

        if self.prev:
            distance_jump = haversine_distance_m(self.prev["lat"], self.prev["lon"], lat, lon)
            lat_diff = lat - self.prev["lat"]
            lon_diff = lon - self.prev["lon"]
            speed_diff = speed - self.prev["speed"]
            
            # Heading diff with wrap-around
            heading_diff = abs(heading - self.prev["heading"])
            if heading_diff > 180:
                heading_diff = 360 - heading_diff

        # 3. Setup safe position baselines
        is_recovery = (attack_state == "NORMAL")
        
        if self.prev is None or is_recovery:
            self.last_safe_lat = lat
            self.last_safe_lon = lon
            self.last_safe_alt = altitude
        
        # Calculate Position Drift (cumulative displacement from baseline)
        if self.last_safe_lat is not None and self.last_safe_lon is not None:
            position_drift = haversine_distance_m(self.last_safe_lat, self.last_safe_lon, lat, lon)

        # 4. Security Threat Calculations (impossible speed, sudden jumps, trajectory deviation)
        computed_speed_kmh = 0.0
        if self.prev and dt > 0:
            computed_speed_kmh = (distance_jump / dt) * 3.6

        # Impossible speed check
        if self.prev and computed_speed_kmh > config.MAX_SPEED_KMH and not is_recovery:
            status = "SPOOFING"
            messages.append(
                f"Impossible Speed Alert: {computed_speed_kmh:.1f} km/h exceeds threshold limit."
            )

        # Sudden GPS coordinate jump check
        if self.prev and distance_jump > config.SUDDEN_JUMP_THRESHOLD_M and dt < 5.0 and not is_recovery:
            status = "SPOOFING"
            messages.append(
                f"GPS Jump Alert: Abrupt spatial displacement of {distance_jump:.1f} meters detected."
            )

        # Trajectory deviation turn check
        if self.prev and speed > 10.0 and self.packet_count > 3 and not is_recovery:
            if heading_diff > 120.0 and dt < 3.0:
                status = "SPOOFING"
                messages.append(
                    f"Trajectory Deviation Alert: Impossible sharp turn of {heading_diff:.1f}° detected."
                )

        # Chronological time consistency check
        if self.prev and dt < 0:
            status = "SPOOFING"
            messages.append("Time Consistency Alert: GPS clock regression detected (replay attack signature).")

        # 5. GNSS Signal Noise Metrics (Simulating receiver fluctuations when under attack)
        prev_snr = self.prev.get("snr", 42.0) if self.prev else 42.0
        prev_cno = self.prev.get("cno", 44.0) if self.prev else 44.0
        prev_hdop = self.prev.get("hdop", 0.8) if self.prev else 0.8
        prev_sats = self.prev.get("satellites", 12) if self.prev else 12

        is_jammed = (attack_state == "JAM")
        is_spoofed = (attack_state == "SPOOF") or (status == "SPOOFING")

        if is_jammed:
            status = "JAMMING"
            snr = clamp(prev_snr - 25.0, 5.0, 15.0)
            cno = clamp(prev_cno - 25.0, 5.0, 15.0)
            hdop = clamp(prev_hdop + 3.5, 3.0, 5.0)
            satellites = int(clamp(prev_sats - 9, 0, 3))
            messages.append(f"Jamming Alert: Massive signal loss. Satellites: {satellites}, SNR: {snr:.1f}")
        elif is_spoofed:
            status = "SPOOFING"
            snr = clamp(prev_snr + random.uniform(2.0, 5.0), 38.0, 49.0)
            cno = clamp(prev_cno + random.uniform(2.0, 5.0), 40.0, 54.0)
            hdop = clamp(prev_hdop - 0.2, 0.4, 0.6)  # synthetically optimized low HDOP
            satellites = int(clamp(prev_sats + random.choice([0, 1]), 10, 14))
        else:
            status = "NORMAL"
            snr = clamp(prev_snr + random.uniform(-1.0, 1.0), 32.0, 46.0)
            cno = clamp(prev_cno + random.uniform(-1.0, 1.0), 35.0, 50.0)
            hdop = clamp(prev_hdop + random.uniform(-0.04, 0.04), 0.5, 1.5)
            satellites = int(clamp(prev_sats + random.choice([-1, 0, 0, 1]), 8, 14))

        vdop = round(hdop * 1.35, 2)
        time_drift = round(clamp((self.prev.get("time_drift_ms", 0.2) if self.prev else 0.2) + random.uniform(-0.02, 0.02) + (1.5 if status != "NORMAL" else 0), 0, 5), 2)

        for sat in self.sky_state:
            sat["snr"] = clamp(sat["snr"] + random.uniform(-0.6, 0.6) - (20 if status == "JAMMING" else (0 if status == "NORMAL" else -3)), 5, 50)

        # 6. Threat, Anomaly, and Attack Confidence Scores
        # Threat score calculated based on the raw metrics delta
        threat_score = 0.05
        if status == "SPOOFING":
            threat_score = clamp(0.70 + (computed_speed_kmh / 500.0) + (distance_jump / 1000.0), 0.75, 0.98)
        elif status == "JAMMING":
            threat_score = clamp(0.65 + ((15.0 - snr) / 30.0), 0.70, 0.95)

        anomaly_score = clamp(threat_score + random.uniform(-0.02, 0.02), 0.0, 1.0)
        
        # Confidence Score Calculation (0% to 100%)
        confidence_score = 0.0
        if status == "SPOOFING":
            confidence_score = clamp(50.0 + (distance_jump / 50.0) * 10.0, 60.0, 100.0)
        elif status == "JAMMING":
            confidence_score = clamp(40.0 + (15.0 - snr) * 4.0, 50.0, 95.0)
        else:
            confidence_score = clamp(random.uniform(1.0, 8.0), 0.0, 15.0)

        # Update baseline safe coordinates only on Normal states
        if status == "NORMAL":
            self.last_safe_lat = lat
            self.last_safe_lon = lon
            self.last_safe_alt = altitude

        # Package state update
        state = {
            "lat": lat,
            "lon": lon,
            "altitude": altitude,
            "speed": speed,
            "heading": heading,
            "accuracy": accuracy,
            "client_ts": client_ts,
            "ts": now,
            "status": status,
            "threat_level": "High Risk" if status != "NORMAL" else "Low Risk",
            
            # Mathematical differentials
            "distance_jump": round(distance_jump, 1),
            "lat_diff": round(lat_diff, 6),
            "lon_diff": round(lon_diff, 6),
            "speed_diff": round(speed_diff, 1),
            "heading_diff": round(heading_diff, 1),
            "position_drift": round(position_drift, 1),
            
            # Anomaly indicators
            "threat_score": round(threat_score, 2),
            "anomaly_score": round(anomaly_score, 2),
            "confidence_score": round(confidence_score, 1),
            
            # Signal quality
            "snr": round(snr, 1),
            "cno": round(cno, 1),
            "hdop": round(hdop, 2),
            "vdop": vdop,
            "satellites": satellites,
            "time_drift_ms": time_drift,
            "attacker_ip": attacker_ip,
            "original_lat": self.last_safe_lat,
            "original_lon": self.last_safe_lon,
            "original_alt": self.last_safe_alt
        }
        
        self.prev = state
        return state, messages
