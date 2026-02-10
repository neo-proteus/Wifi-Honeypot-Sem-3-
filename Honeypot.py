#!/usr/bin/env python3
"""
honeypot_windows.py

Windows-friendly low-interaction honeypot + LAN discovery + dashboard.

USAGE:
- Run in an activated venv.
- For accurate LAN discovery run Command Prompt or PowerShell as Administrator:
    Right-click -> Run as administrator
  then: python honeypot_windows.py

DEPENDENCIES:
    pip install flask python-dotenv netifaces psutil mac-vendor-lookup

SAFE / ETHICAL:
- Run only on networks/devices you own or have consent to scan.
- Do not capture credentials from unaware users.
"""
import os #environment variables and file paths
import sqlite3 #bundled lightweight database to store connection and device records
import threading #run background tasks
import binascii #convert binary payload bytes to hex strings for DB
import asyncio #run asynchronous TCP servers
import subprocess #run system commands for discorvery
import psutil #cross platform process and network interface
import socket #low level networking utilities
import ipaddress #manage and manipulate IPv4 Networks
import time #sleeps/smmall delays
from datetime import datetime, timedelta #timestamps
from dotenv import load_dotenv 

# Flask / web
from flask import Flask, request, render_template_string, abort, jsonify

def get_connected_devices():
    devices = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            ip = conn.raddr.ip if conn.raddr else None
            port = conn.raddr.port if conn.raddr else None
            if ip:
                devices.append((ip, port))
        except:
            continue
    return devices

print(get_connected_devices())

# Optional vendor lookup (pip install mac-vendor-lookup), if available
try:
    from mac_vendor_lookup import MacLookup
    _MAC_LOOKUP = MacLookup()
    try:
        _MAC_LOOKUP.update_vendors()  # may attempt network call first time
    except Exception:
        pass
except Exception:
    _MAC_LOOKUP = None

# Optional network helpers
try:
    import netifaces
except Exception:
    netifaces = None

try:
    import psutil
except Exception:
    psutil = None

# Load .env if present
load_dotenv()

# -----------------------------
# Config (environment overrides)
# -----------------------------
LISTEN_HOST = os.getenv("HOST", "0.0.0.0")   # honeypot bind
PORTS = list(map(int, os.getenv("PORTS", "21,23,80,8080").split(",")))
DB_FILE = os.getenv("DB_FILE", "honeypot_windows.db")
RECORD_LIMIT = int(os.getenv("RECORD_LIMIT", "1024"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "demo_token")
ADMIN_HOST = os.getenv("ADMIN_HOST", "127.0.0.1")
ADMIN_PORT = int(os.getenv("ADMIN_PORT", "5000"))
DASH_HOURS = int(os.getenv("DASH_HOURS", "48"))

# Discovery settings (Windows-friendly)
DISCOVER_INTERVAL = int(os.getenv("DISCOVER_INTERVAL", "30"))  # seconds
DISCOVER_TIMEOUT = float(os.getenv("DISCOVER_TIMEOUT", "1.0"))  # ping timeout seconds
# If you know your hotspot subnet you can set DISCOVER_NETWORK to e.g. 192.168.43.0/24
DISCOVER_NETWORK = os.getenv("DISCOVER_NETWORK", "")

# Banners
BANNERS = {
    21: "220 FTP-Service Ready\r\n",
    23: "Welcome to Telnet service\r\n",
    80: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 46\r\n\r\n<h1>It works (honeypot)</h1>\n",
    8080: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nExample honeypot page\n",
}

# -----------------------------
# DB helpers
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        remote_ip TEXT,
        remote_port INTEGER,
        server_port INTEGER,
        banner_sent TEXT,
        payload_hex TEXT,
        payload_truncated INTEGER,
        user_agent_hint TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        mac TEXT,
        hostname TEXT,
        vendor TEXT,
        first_seen TEXT,
        last_seen TEXT,
        last_seen_count INTEGER DEFAULT 1
    )
    """)
    conn.commit()
    conn.close()

def save_connection(ts, remote_ip, remote_port, server_port, banner_sent, payload_bytes, truncated, ua_hint=None):
    payload_hex = binascii.hexlify(payload_bytes).decode('ascii') if payload_bytes else ""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO connections (ts, remote_ip, remote_port, server_port, banner_sent, payload_hex, payload_truncated, user_agent_hint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, remote_ip, remote_port, server_port, banner_sent[:200], payload_hex, int(truncated), ua_hint or "")
    )
    conn.commit()
    conn.close()

def upsert_device(ip, mac, hostname=None, vendor=None):
    now = datetime.utcnow().isoformat() + "Z"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE devices SET mac=?, hostname=?, vendor=?, last_seen=?, last_seen_count=last_seen_count+1 WHERE ip=?", (mac, hostname or "", vendor or "", now, ip))
    else:
        cur.execute("INSERT INTO devices (ip, mac, hostname, vendor, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)", (ip, mac, hostname or "", vendor or "", now, now))
    conn.commit()
    conn.close()

def fetch_devices(limit=200):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, ip, mac, hostname, vendor, first_seen, last_seen, last_seen_count FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

# -----------------------------
# Honeypot async server (same as before)
# -----------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, server_port: int):
    peer = writer.get_extra_info('peername')
    remote_ip, remote_port = (peer[0], peer[1]) if peer else ("unknown", 0)
    ts = datetime.utcnow().isoformat() + "Z"

    banner = BANNERS.get(server_port, "")
    try:
        if banner:
            writer.write(banner.encode('utf-8', 'replace'))
            await writer.drain()
    except Exception:
        pass

    payload = b""
    truncated = False
    try:
        total_read = 0
        reader_timeout = 5.0
        while total_read < RECORD_LIMIT:
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=reader_timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            payload += chunk
            total_read += len(chunk)
            if total_read >= RECORD_LIMIT:
                truncated = True
                break
    except Exception:
        pass

    ua_hint = None
    try:
        text = payload.decode('utf-8', errors='ignore')
        if "User-Agent:" in text:
            start = text.find("User-Agent:")
            ua_hint = text[start:text.find("\r\n", start)]
        elif "Mozilla/" in text:
            start = text.find("Mozilla/")
            ua_hint = text[start:start+80]
    except Exception:
        ua_hint = None

    save_connection(ts, remote_ip, remote_port, server_port, banner, payload[:RECORD_LIMIT], truncated, ua_hint)

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    print(f"[{ts}] {remote_ip}:{remote_port} -> {LISTEN_HOST}:{server_port}  payload_len={len(payload)} truncated={truncated}")

async def start_servers(loop):
    servers = []
    for p in PORTS:
        try:
            server = await asyncio.start_server(lambda r, w, p=p: handle_client(r, w, p), host=LISTEN_HOST, port=p)
            addr = server.sockets[0].getsockname()
            print(f"Honeypot listening on {addr}")
            servers.append(server)
        except OSError as e:
            print(f"Could not bind to port {p}: {e}")
    if not servers:
        print("No servers started; exiting.")
        return
    await asyncio.gather(*(s.serve_forever() for s in servers))

# -----------------------------
# Windows-friendly discovery (ping sweep + arp -a parse)
# -----------------------------
def _get_local_network_windows():
    """Try DISCOVER_NETWORK first, else infer local IPv4 and use /24."""
    if DISCOVER_NETWORK:
        try:
            return ipaddress.ip_network(DISCOVER_NETWORK, strict=False)
        except Exception:
            pass
    # Try netifaces or psutil to find active interface IP
    ip = None
    try:
        if netifaces:
            # choose default gateway interface
            gws = netifaces.gateways()
            default = gws.get('default')
            if default:
                gw_iface = default.get(netifaces.AF_INET)[1] if default.get(netifaces.AF_INET) else None
                if gw_iface:
                    addrs = netifaces.ifaddresses(gw_iface).get(netifaces.AF_INET)
                    if addrs:
                        ip = addrs[0].get('addr')
        if not ip and psutil:
            for nic, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        ip = a.address
                        break
                if ip:
                    break
    except Exception:
        ip = None
    if not ip:
        # fallback: socket trick
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = None
    if ip:
        try:
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        except Exception:
            pass
    # final fallback: common hotspot net
    return ipaddress.ip_network("192.168.43.0/24")

def _ping_host_windows(ip_str, timeout_ms=800):
    """
    Windows ping: 'ping -n 1 -w timeout_ms ip'
    Returns True if ping command returns 0 exit code.
    """
    try:
        # use -n 1 (one echo), -w timeout in ms
        res = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), ip_str],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def _arp_parse_windows():
    """
    Parse output of 'arp -a' (Windows format).
    Returns list of (ip, mac) tuples. MAC normalized to colon-separated lower-case.
    """
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, encoding='utf-8', errors='ignore')
    except Exception:
        return []
    results = []
    # Windows arp -a output sections like:
    # Interface: 192.168.43.193 --- 0x3
    #   Internet Address      Physical Address      Type
    #   192.168.43.1         00-11-22-33-44-55     dynamic
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        # typical data rows have 3 parts: ip, mac, type
        if len(parts) >= 3 and parts[0][0].isdigit():
            ip_part = parts[0]
            mac_part = parts[1]
            # skip incomplete entries
            if mac_part.lower() == "<incomplete>":
                continue
            # Normalize MAC - convert '-' to ':' and lower
            mac = mac_part.replace('-', ':').lower()
            results.append((ip_part, mac))
    return results

def discover_once_windows():
    """
    Ping-sweep the network (quick) and parse arp -a to gather IP+MAC.
    Use conservative timing so it completes quickly on typical phone hotspot /24.
    """
    net = _get_local_network_windows()
    # create small list of addresses to ping (hosts())
    # to make it quick, we will ping only addresses .1-.254 but skip our own IP
    hosts = [str(ip) for ip in net.hosts()]
    # Launch pings in background (fire-and-forget) to populate ARP cache
    procs = []
    for ip in hosts:
        # Launch ping but don't wait; use small timeout
        try:
            # For speed, use subprocess.Popen and do not block; system will handle concurrent pings
            subprocess.Popen(["ping", "-n", "1", "-w", str(int(DISCOVER_TIMEOUT*1000)), ip],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    # Wait a short time for ARP table to populate
    time.sleep(1.2)
    # Parse arp table
    found = _arp_parse_windows()
    # Upsert devices into DB
    for ip, mac in found:
        # try reverse DNS (fast enough)
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        vendor = ""
        if _MAC_LOOKUP:
            try:
                vendor = _MAC_LOOKUP.lookup(mac)
            except Exception:
                vendor = ""
        upsert_device(ip, mac, hostname=name, vendor=vendor)
    return found

def discovery_worker_windows(stop_event):
    while not stop_event.is_set():
        try:
            found = discover_once_windows()
            print(f"[discovery] found {len(found)} entries")
        except Exception as e:
            print("Discovery error:", e)
        stop_event.wait(DISCOVER_INTERVAL)

# -----------------------------
# Flask admin + dashboard (same UI concept)
# -----------------------------
admin_app = Flask("honeypot_admin")

ADMIN_TEMPLATE = """
<!doctype html>
<title>Honeypot Admin (Windows)</title>
<h1>Honeypot connections</h1>
<p><a href="/dashboard?token={{ token }}">Open dashboard</a> | <a href="/devices?token={{ token }}">Devices</a></p>
<table border=1 cellpadding=4>
<tr><th>ID</th><th>TS (UTC)</th><th>Remote</th><th>Server Port</th><th>Banner Sent</th><th>Payload (hex)</th><th>UA hint</th></tr>
{% for r in rows %}
  <tr>
    <td>{{ r[0] }}</td>
    <td>{{ r[1] }}</td>
    <td>{{ r[2] }}:{{ r[3] }}</td>
    <td>{{ r[4] }}</td>
    <td><pre style="max-width:300px;white-space:pre-wrap">{{ r[5] }}</pre></td>
    <td style="max-width:420px;word-break:break-all"><small>{{ r[6] }}{% if r[7] %} ... (truncated){% endif %}</small></td>
    <td><pre style="max-width:200px">{{ r[8] }}</pre></td>
  </tr>
{% endfor %}
</table>
"""

@admin_app.route("/admin")
def admin_index():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        abort(401)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, remote_ip, remote_port, server_port, banner_sent, payload_hex, payload_truncated, user_agent_hint FROM connections ORDER BY id DESC LIMIT 200")
    rows = cur.fetchall()
    conn.close()
    return render_template_string(ADMIN_TEMPLATE, rows=rows, token=ADMIN_TOKEN)

# Dashboard endpoints
def fetch_hourly_counts(hours_back=DASH_HOURS):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    hours = []
    for i in range(hours_back-1, -1, -1):
        h = now - timedelta(hours=i)
        hours.append(h.strftime("%Y-%m-%d %H:00:00"))
    cur.execute("""
        SELECT (replace(substr(ts,1,13),'T',' ') || ':00:00') AS hour, COUNT(*) as cnt
        FROM connections
        GROUP BY hour
        ORDER BY hour ASC
    """)
    rows = cur.fetchall()
    conn.close()
    db_map = {r[0]: r[1] for r in rows}
    counts = [db_map.get(h, 0) for h in hours]
    return hours, counts

@admin_app.route("/api/stats")
def api_stats():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    try:
        hours_back = int(request.args.get("hours", DASH_HOURS))
        if hours_back <= 0 or hours_back > 168:
            hours_back = DASH_HOURS
    except Exception:
        hours_back = DASH_HOURS
    labels, data = fetch_hourly_counts(hours_back)
    return jsonify({"labels": labels, "counts": data})

# Dashboard HTML (Chart.js) + devices section
DASH_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Honeypot Dashboard (Windows)</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style> body { font-family: sans-serif; margin: 20px; } .container { max-width: 900px; margin: auto; } .chart-card { background:#fafafa; padding: 12px; border-radius:8px; } table { margin-top: 16px; border-collapse: collapse; width: 100%; } td, th { border: 1px solid #ddd; padding: 6px; font-size: 13px; } </style>
</head>
<body>
  <div class="container">
    <h2>Honeypot — Connections per hour (UTC)</h2>
    <p>Showing last <span id="hoursLabel">{{ hours }}</span> hours.</p>
    <div class="chart-card"><canvas id="connChart" width="800" height="320"></canvas></div>

    <h3>Latest connections</h3><div id="latestWrap">Loading...</div>

    <h3>Known devices on LAN</h3><div id="devicesWrap">Loading...</div>

    <p style="margin-top:12px;"><small>Protected by token.</small></p>
  </div>
<script>
const TOKEN = "{{ token }}", HOURS = {{ hours }};
async function fetchJson(path){ const res = await fetch(path + "?token=" + encodeURIComponent(TOKEN)); if(!res.ok) return null; return await res.json(); }
async function renderChart(){ const d = await fetchJson("/api/stats&hours=" + HOURS) || await fetchJson("/api/stats?hours=" + HOURS); if(!d) return; const ctx=document.getElementById('connChart').getContext('2d'); if(window._hpChart) window._hpChart.destroy(); window._hpChart=new Chart(ctx,{type:'bar',data:{labels:d.labels,datasets:[{label:'Connections',data:d.counts,borderWidth:1}]},options:{responsive:true,scales:{x:{ticks:{maxRotation:90,minRotation:45,autoSkip:true}},y:{beginAtZero:true}}}}); }
async function fetchLatest(){ const res = await fetch("/api/latest?token=" + encodeURIComponent(TOKEN)); if(!res.ok) return null; return await res.json(); }
async function fetchDevices(){ const res = await fetch("/api/devices?token=" + encodeURIComponent(TOKEN)); if(!res.ok) return null; return await res.json(); }
function renderLatest(rows){ if(!rows) { document.getElementById("latestWrap").innerText = "Failed"; return; } let html="<table><tr><th>ID</th><th>TS</th><th>Remote</th><th>Port</th><th>UA</th></tr>"; rows.forEach(r=> html += `<tr><td>${r.id}</td><td>${r.ts}</td><td>${r.remote_ip}:${r.remote_port}</td><td>${r.server_port}</td><td>${r.user_agent_hint||''}</td></tr>`); html += "</table>"; document.getElementById("latestWrap").innerHTML = html; }
function renderDevices(rows){ if(!rows) { document.getElementById("devicesWrap").innerText = "Failed"; return; } let html="<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>First</th><th>Last</th><th>Seen</th></tr>"; rows.forEach(r=> html += `<tr><td>${r.ip}</td><td>${r.mac}</td><td>${r.hostname||''}</td><td>${r.vendor||''}</td><td>${r.first_seen}</td><td>${r.last_seen}</td><td>${r.last_seen_count}</td></tr>`); html += "</table>"; document.getElementById("devicesWrap").innerHTML = html; }
async function refreshAll(){ await renderChart(); const latest = await fetchLatest(); renderLatest(latest); const devs = await fetchDevices(); renderDevices(devs); }
renderChart(); refreshAll(); setInterval(refreshAll, 60000);
</script>
</body></html>
"""

@admin_app.route("/dashboard")
def dashboard():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        abort(401)
    try:
        hours = int(request.args.get("hours", DASH_HOURS))
        if hours <= 0 or hours > 168:
            hours = DASH_HOURS
    except Exception:
        hours = DASH_HOURS
    return render_template_string(DASH_TEMPLATE, token=ADMIN_TOKEN, hours=hours)

# APIs for latest and devices
@admin_app.route("/api/latest")
def api_latest():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    try:
        limit = int(request.args.get("limit", "10"))
        if limit <= 0 or limit > 200:
            limit = 10
    except Exception:
        limit = 10
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, remote_ip, remote_port, server_port, user_agent_hint FROM connections ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    results = [{"id":r[0],"ts":r[1],"remote_ip":r[2],"remote_port":r[3],"server_port":r[4],"user_agent_hint":r[5]} for r in rows]
    return jsonify(results)

@admin_app.route("/api/devices")
def api_devices():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    try:
        limit = int(request.args.get("limit", "50"))
        if limit <= 0 or limit > 500:
            limit = 50
    except Exception:
        limit = 50
    rows = fetch_devices(limit=limit)
    results = []
    for r in rows:
        results.append({
            "id": r[0], "ip": r[1], "mac": r[2], "hostname": r[3], "vendor": r[4],
            "first_seen": r[5], "last_seen": r[6], "last_seen_count": r[7]
        })
    return jsonify(results)

@admin_app.route("/devices")
def devices_html():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        abort(401)
    rows = fetch_devices(limit=200)
    html = "<h1>Known devices on LAN</h1><table border=1 cellpadding=4><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>First</th><th>Last</th><th>Count</th></tr>"
    for r in rows:
        html += f"<tr><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td><td>{r[5]}</td><td>{r[6]}</td><td>{r[7]}</td></tr>"
    html += "</table><p><a href='/dashboard?token=%s'>Back</a></p>" % ADMIN_TOKEN
    return html

# -----------------------------
# Run admin + discovery + honeypot
# -----------------------------
def run_admin():
    admin_app.run(host=ADMIN_HOST, port=ADMIN_PORT, debug=False, use_reloader=False)

def main():
    print("Starting Windows honeypot + LAN discovery (educational).")
    init_db()
    # Start admin UI
    t_admin = threading.Thread(target=run_admin, daemon=True)
    t_admin.start()
    print(f"Admin UI: http://{ADMIN_HOST}:{ADMIN_PORT}/admin?token={ADMIN_TOKEN}")
    print(f"Dashboard: http://{ADMIN_HOST}:{ADMIN_PORT}/dashboard?token={ADMIN_TOKEN}")

    # Start discovery worker
    stop_event = threading.Event()
    t_disc = threading.Thread(target=discovery_worker_windows, args=(stop_event,), daemon=True)
    t_disc.start()
    print(f"Discovery worker started, interval={DISCOVER_INTERVAL}s (Windows mode).")

    # Start honeypot main loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_servers(loop))
    except KeyboardInterrupt:
        print("Shutting down.")
    finally:
        stop_event.set()
        loop.stop()
        loop.close()

if __name__ == "__main__":
    main()
