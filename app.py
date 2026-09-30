"""
WiFi Device Dashboard - Home Network Visibility & Anomaly Detection Tool

- Discovers devices on the local network via nmap
- Tracks device history and flags devices seen for the first time
- Pulls DNS-level activity from a local AdGuard Home instance
- Provides a simple network health summary
- Protects the dashboard itself with basic auth
- Exports device history and activity logs as CSV

Scope and limitations (read this before extending the project):
- This tool only discovers devices and reads DNS query metadata (which
  domains were contacted). It does not intercept, decrypt, or inspect
  any traffic content -- that's an intentional boundary, not a gap to
  "fix" later.
- Intended for use on a network you own/administer. Running this
  against a network you don't control, or using it to covertly track
  a specific person without their knowledge, is outside its intended
  and ethical use.
"""

import subprocess
import re
import json
import time
import threading
import sqlite3
import urllib.request
import base64
import csv
import io
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, render_template, request, Response

try:
    import config
except ImportError:
    raise SystemExit(
        "config.py not found. Copy config.example.py to config.py and fill in your values."
    )

app = Flask(__name__)

DB_PATH = "devices.db"
latest_scan = {"last_updated": None, "devices": [], "new_device_macs": []}
scan_lock = threading.Lock()


# ---------------- Basic dashboard auth ----------------

def check_auth(username, password):
    return username == config.DASHBOARD_USERNAME and password == config.DASHBOARD_PASSWORD


def authenticate():
    return Response(
        "Login required.", 401,
        {"WWW-Authenticate": 'Basic realm="WiFi Dashboard"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# ---------------- Database ----------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            custom_name TEXT,
            first_seen TEXT,
            last_seen TEXT,
            last_ip TEXT,
            vendor TEXT
        )
    """)
    conn.commit()
    conn.close()


def upsert_device(mac, ip, vendor, hostname):
    """Returns True if this MAC is being seen for the very first time."""
    if not mac:
        return False
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT mac FROM devices WHERE mac = ?", (mac,))
    row = c.fetchone()
    is_new = row is None
    if row:
        c.execute(
            "UPDATE devices SET last_seen=?, last_ip=?, vendor=? WHERE mac=?",
            (now, ip, vendor, mac)
        )
    else:
        c.execute(
            "INSERT INTO devices (mac, custom_name, first_seen, last_seen, last_ip, vendor) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (mac, hostname if hostname != "Unknown" else None, now, now, ip, vendor)
        )
    conn.commit()
    conn.close()
    return is_new


def get_device_meta(mac):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT custom_name, first_seen, last_seen FROM devices WHERE mac = ?", (mac,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"custom_name": row[0], "first_seen": row[1], "last_seen": row[2]}
    return {"custom_name": None, "first_seen": None, "last_seen": None}


def set_custom_name(mac, name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE devices SET custom_name = ? WHERE mac = ?", (name, mac))
    conn.commit()
    conn.close()


def get_all_devices_from_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT mac, custom_name, first_seen, last_seen, last_ip, vendor FROM devices ORDER BY last_seen DESC")
    rows = c.fetchall()
    conn.close()
    return rows


# ---------------- Nmap scanning ----------------

def run_nmap_scan(network_range):
    try:
        result = subprocess.run(
            ["nmap", "-sn", network_range],
            capture_output=True, text=True, timeout=120
        )
        return parse_nmap_output(result.stdout)
    except FileNotFoundError:
        return {"error": "nmap not found. Make sure Nmap is installed and added to PATH."}
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out."}
    except Exception as e:
        return {"error": str(e)}


def parse_nmap_output(output):
    devices = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        ip_match = re.match(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
        if ip_match:
            if current:
                devices.append(current)
            hostname = ip_match.group(1) if ip_match.group(1) else "Unknown"
            ip = ip_match.group(2)
            current = {"ip": ip, "hostname": hostname, "mac": None, "vendor": "Unknown"}
            continue
        mac_match = re.match(r"MAC Address: ([0-9A-Fa-f:]+)(?:\s+\((.+)\))?", line)
        if mac_match and current:
            current["mac"] = mac_match.group(1)
            current["vendor"] = mac_match.group(2) if mac_match.group(2) else "Unknown"
    if current:
        devices.append(current)
    return devices


def enrich_and_store(devices):
    new_macs = []
    for d in devices:
        is_new = upsert_device(d.get("mac"), d.get("ip"), d.get("vendor"), d.get("hostname"))
        if is_new and d.get("mac"):
            new_macs.append(d.get("mac"))
        meta = get_device_meta(d.get("mac"))
        d["custom_name"] = meta["custom_name"]
        d["first_seen"] = meta["first_seen"]
        d["last_seen"] = meta["last_seen"]
        d["is_new"] = d.get("mac") in new_macs
    return devices, new_macs


def background_scanner():
    while True:
        result = run_nmap_scan(config.NETWORK_RANGE)
        with scan_lock:
            if isinstance(result, dict) and "error" in result:
                latest_scan["error"] = result["error"]
                latest_scan["devices"] = []
                latest_scan["new_device_macs"] = []
            else:
                devices, new_macs = enrich_and_store(result)
                latest_scan["error"] = None
                latest_scan["devices"] = devices
                latest_scan["new_device_macs"] = new_macs
            latest_scan["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        time.sleep(config.SCAN_INTERVAL_SECONDS)


# ---------------- AdGuard Home integration ----------------

def adguard_request(path):
    url = config.ADGUARD_URL.rstrip("/") + path
    req = urllib.request.Request(url)
    if config.ADGUARD_USERNAME and config.ADGUARD_PASSWORD:
        creds = f"{config.ADGUARD_USERNAME}:{config.ADGUARD_PASSWORD}"
        token = base64.b64encode(creds.encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def get_adguard_query_log(limit=100):
    data = adguard_request(f"/control/querylog?limit={limit}")
    if isinstance(data, dict) and "error" in data:
        return data
    entries = data.get("data", [])
    simplified = []
    for e in entries:
        simplified.append({
            "time": e.get("time"),
            "client": e.get("client"),
            "domain": e.get("question", {}).get("name"),
            "blocked": e.get("reason", "").startswith("Filtered")
        })
    return simplified


def get_adguard_stats():
    data = adguard_request("/control/stats")
    if isinstance(data, dict) and "error" in data:
        return {"dns_queries": 0, "blocked": 0}
    return {
        "dns_queries": data.get("num_dns_queries", 0),
        "blocked": data.get("num_blocked_filtering", 0),
    }


# ---------------- Routes ----------------

@app.route("/")
@requires_auth
def index():
    return render_template("index.html")


@app.route("/api/devices")
@requires_auth
def api_devices():
    with scan_lock:
        return jsonify(latest_scan)


@app.route("/api/scan-now")
@requires_auth
def scan_now():
    result = run_nmap_scan(config.NETWORK_RANGE)
    with scan_lock:
        if isinstance(result, dict) and "error" in result:
            latest_scan["error"] = result["error"]
            latest_scan["devices"] = []
            latest_scan["new_device_macs"] = []
        else:
            devices, new_macs = enrich_and_store(result)
            latest_scan["error"] = None
            latest_scan["devices"] = devices
            latest_scan["new_device_macs"] = new_macs
        latest_scan["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(latest_scan)


@app.route("/api/rename", methods=["POST"])
@requires_auth
def rename_device():
    payload = request.get_json()
    mac = payload.get("mac")
    name = payload.get("name")
    if not mac or not name:
        return jsonify({"success": False, "error": "mac and name required"}), 400
    set_custom_name(mac, name)
    return jsonify({"success": True})


@app.route("/api/activity")
@requires_auth
def api_activity():
    logs = get_adguard_query_log(150)
    return jsonify({"logs": logs})


@app.route("/api/summary")
@requires_auth
def api_summary():
    with scan_lock:
        total_known = len(get_all_devices_from_db())
        online_now = len(latest_scan.get("devices", []))
        new_now = len(latest_scan.get("new_device_macs", []))
    stats = get_adguard_stats()
    return jsonify({
        "total_known_devices": total_known,
        "online_now": online_now,
        "new_devices_this_scan": new_now,
        "dns_queries_today": stats["dns_queries"],
        "blocked_today": stats["blocked"],
    })


@app.route("/api/export/devices.csv")
@requires_auth
def export_devices_csv():
    rows = get_all_devices_from_db()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["MAC", "Custom Name", "First Seen", "Last Seen", "Last IP", "Vendor"])
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=device_history.csv"}
    )


@app.route("/api/export/activity.csv")
@requires_auth
def export_activity_csv():
    logs = get_adguard_query_log(500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Time", "Client", "Domain", "Blocked"])
    if isinstance(logs, list):
        for l in logs:
            writer.writerow([l.get("time"), l.get("client"), l.get("domain"), l.get("blocked")])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=activity_log.csv"}
    )


if __name__ == "__main__":
    init_db()
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()
    app.run(host="127.0.0.1", port=5000, debug=False)