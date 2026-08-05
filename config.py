import os

# ----------------------------- CONFIG ---------------------------------
# GNSS Threat Detection Parameters
MAX_SPEED_KMH = 150.0             # Max plausible civilian vehicle speed (km/h)
SUDDEN_JUMP_THRESHOLD_M = 100.0    # Max allowed distance between updates (meters)
MIN_SATELLITES = 5                 # Minimum satellite count for healthy lock
MIN_SNR = 28.0                     # Minimum signal strength (dB-Hz)
MAX_HDOP = 2.5                     # Maximum dilution of precision for high accuracy
JAMMING_TIMEOUT_SECONDS = 15.0     # Silence interval indicating active jamming (seconds)

# Storage & Logging configurations
HISTORY_LENGTH = 60
DATA_LOG_FILE = os.path.join("data", "gps_log.csv")
ALERT_LOG_FILE = os.path.join("data", "alerts_log.csv")
ATTACK_HISTORY_FILE = os.path.join("data", "attack_history.csv")
