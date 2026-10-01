import sqlite3
import os
import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join("data", "gps_securetrack.db")

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and seed default HOST and USER accounts."""
    conn = get_db()
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            device_id TEXT,
            avatar_url TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    ''')

    # Safely migrate avatar_url column if table already exists
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT;")
    except Exception:
        pass

    # Devices Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT,
            type TEXT DEFAULT 'browser',
            status TEXT DEFAULT 'NORMAL',
            registered_at TEXT
        )
    ''')

    # Activity Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            device_id TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip TEXT,
            timestamp TEXT NOT NULL
        )
    ''')

    # Security Events / Alerts Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            user_message TEXT,
            timestamp TEXT NOT NULL,
            is_read INTEGER DEFAULT 0
        )
    ''')

    conn.commit()

    # Seed Default HOST/SOC Admin if not exists
    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        admin_pass = generate_password_hash("admin123")
        now_str = datetime.utcnow().isoformat()
        cursor.execute('''
            INSERT INTO users (user_id, name, username, email, password_hash, role, device_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ("HOST-001", "SOC Administrator", "admin", "admin@gpssecuretrack.com", admin_pass, "HOST", "SOC-HOST", now_str))
        cursor.execute('''
            INSERT OR IGNORE INTO devices (device_id, user_id, name, type, registered_at)
            VALUES (?, ?, ?, ?, ?)
        ''', ("SOC-HOST", "HOST-001", "SOC Operator Console", "soc", now_str))

    # Seed Default USER Victim if not exists
    cursor.execute("SELECT * FROM users WHERE username = ?", ("user",))
    if not cursor.fetchone():
        user_pass = generate_password_hash("user123")
        now_str = datetime.utcnow().isoformat()
        cursor.execute('''
            INSERT INTO users (user_id, name, username, email, password_hash, role, device_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ("USER-001", "Demo User", "user", "user@gpssecuretrack.com", user_pass, "USER", "USER-001", now_str))
        cursor.execute('''
            INSERT OR IGNORE INTO devices (device_id, user_id, name, type, registered_at)
            VALUES (?, ?, ?, ?, ?)
        ''', ("USER-001", "USER-001", "Demo Receiver Unit", "browser", now_str))

    conn.commit()
    conn.close()

def create_user(name, username, email, password, role="USER", device_id=None):
    """Registers a new user account with hashed password and device association."""
    conn = get_db()
    cursor = conn.cursor()

    # Check for existing email or username
    cursor.execute("SELECT * FROM users WHERE email = ? OR username = ?", (email, username))
    if cursor.fetchone():
        conn.close()
        return False, "Email or Username already registered."

    user_num = int(time.time() * 1000) % 1000000
    user_id = f"USER-{user_num}"
    if not device_id:
        device_id = user_id

    pwd_hash = generate_password_hash(password)
    now_str = datetime.utcnow().isoformat()

    try:
        cursor.execute('''
            INSERT INTO users (user_id, name, username, email, password_hash, role, device_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, name, username, email, pwd_hash, role, device_id, now_str))

        cursor.execute('''
            INSERT OR IGNORE INTO devices (device_id, user_id, name, type, registered_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, user_id, f"{name}'s Device", "browser", now_str))

        conn.commit()
        
        # Fetch newly created user dict
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user_row = cursor.fetchone()
        conn.close()
        return True, dict(user_row)
    except Exception as e:
        conn.close()
        return False, str(e)

def verify_user_credentials(identifier, password):
    """Authenticates username/email and password."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier))
    user_row = cursor.fetchone()
    
    if not user_row:
        conn.close()
        return None, "Invalid username/email or password."

    user_dict = dict(user_row)
    if check_password_hash(user_dict["password_hash"], password):
        now_str = datetime.utcnow().isoformat()
        cursor.execute("UPDATE users SET last_login = ? WHERE user_id = ?", (now_str, user_dict["user_id"]))
        conn.commit()
        conn.close()
        return user_dict, None
    
    conn.close()
    return None, "Invalid username/email or password."

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_user_profile(user_id, name, email, device_id=None):
    conn = get_db()
    cursor = conn.cursor()
    try:
        if device_id:
            cursor.execute("UPDATE users SET name = ?, email = ?, device_id = ? WHERE user_id = ?", (name, email, device_id, user_id))
            cursor.execute("INSERT OR IGNORE INTO devices (device_id, user_id, name, type, registered_at) VALUES (?, ?, ?, ?, ?)",
                           (device_id, user_id, f"{name}'s Device", "browser", datetime.utcnow().isoformat()))
        else:
            cursor.execute("UPDATE users SET name = ?, email = ? WHERE user_id = ?", (name, email, user_id))
        conn.commit()
        conn.close()
        return True, "Profile updated successfully."
    except Exception as e:
        conn.close()
        return False, str(e)

def update_user_avatar(user_id, avatar_url):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET avatar_url = ? WHERE user_id = ?", (avatar_url, user_id))
        conn.commit()
        conn.close()
        return True, "Avatar updated successfully."
    except Exception as e:
        conn.close()
        return False, str(e)

def update_user_password(user_id, old_password, new_password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row or not check_password_hash(row["password_hash"], old_password):
        conn.close()
        return False, "Current password incorrect."
    
    new_hash = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hash, user_id))
    conn.commit()
    conn.close()
    return True, "Password updated successfully."

def log_activity(user_id, device_id, action, details, ip=None):
    conn = get_db()
    cursor = conn.cursor()
    now_str = datetime.utcnow().isoformat()
    cursor.execute('''
        INSERT INTO activity_logs (user_id, device_id, action, details, ip, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, device_id, action, details, ip or "local", now_str))
    conn.commit()
    conn.close()

def get_user_activity_logs(user_id, limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_user_devices(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
