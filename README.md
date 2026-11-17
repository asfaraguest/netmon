# 🌐 NetMon — Network Monitoring Application

Real-time network monitoring with SNMP auto-discovery, interactive floor plan alerting, zone management, and a live dashboard.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Real Record Bucketing** | Accurate point-to-point raw traffic sampling for Backbone and Router charts without generic averaging |
| **SNMP Auto-Polling** | Automatically polls all SNMP-enabled devices at a configurable interval |
| **Network Discovery** | Scans a CIDR range and discovers SNMP-responsive devices |
| **Interactive Floor Plan** | Drag devices onto a custom background image with real-time status glow |
| **Visual Alerting** | Devices pulse red when down, glow yellow on warnings |
| **Zone Management** | Group devices by area/VLAN/floor, color-coded on the floor plan |
| **UniFi Integration** | One-click sync of devices from a UniFi controller |
| **Alert Log** | Timestamped alert history with severity, acknowledgement, and filtering |
| **Access Log** | Full audit trail of who accessed the dashboard and what actions ran |
| **Real-time Dashboard** | WebSocket-powered live stats, device table, and alert feed |
| **Bandwidth Reports** | Monthly reports on backbone & uplink throughput with AI anomaly filtering and PDF export |
| **Per-Device Muting** | Mute/unmute alerts from individual devices with a single click to prevent alert spam |
| **Double-Check Offline** | Two-step offline validation (SNMP re-poll + ping) to ensure high-accuracy alerts |
| **Split Polling Intervals** | Decouple device status checks (default 30s) and interface traffic polling (default 10s) for high-accuracy bandwidth sampling |
| **Manual WAN Override** | Manually configure router WAN interface mapping via an on-demand dropdown on the Devices page |
| **Time-Weighted Reports** | Monthly bandwidth average calculated via time-weighted algorithms over valid intervals |
| **Context-Aware Rollovers** | Distinguishes 32-bit SNMP counter rollovers from device reboots based on polling delta time (dt) |
| **Responsive Mobile UI** | Fully adaptive interface with an off-canvas sidebar and wrapping filters for smartphone browsers |
| **Router Uplinks Dashboard** | Dedicated multi-chart page for tracking live and historical throughput across all WAN router interfaces |
| **BlackBox Forensics** | AI-like heuristic analysis diagnosing downtime root causes (Thermal shutdown, CPU exhaustion, DDoS, Fiber cuts, etc.) |
| **Dynamic Traffic Retention** | Configurable settings to auto-cleanup historic traffic data and fine-tune anomaly threshold multipliers via the UI |
| **Split Data Retention** | Separate Report Data Retention (min 31 days) and Interface Chart Retention (default 7 days) to save SQLite disk space |
| **Weekly Database Vacuum** | Automatic weekly SQLite `VACUUM` scheduled every Sunday at 03:00 in the background to physically shrink database files |
| **Covering Index & DB Tuning** | Covering index `idx_metrics_name_time` and SQLite connection optimizations (WAL, mmap memory-mapped I/O) to load large queries under 2 seconds |
| **Automated Regression Testing** | Dedicated `test_report_accuracy.py` test suite at root to validate monthly bandwidth calculations, time-weighted average logic, and outlier filtering |

---

## 🏆 Development Milestones & Achievements (Riwayat Capaian)

Here is the progress timeline of the NetMon platform, highlighting the latest enhancements in performance and telemetry accuracy:

* **Phase 1 – 9: Core Platform Foundation**
  - Established multi-threaded SNMP v1/v2c polling engine and real-time dashboard powered by WebSockets.
  - Integrated dynamic interactive Floor Plan, Zone Management, and UniFi Controller API device synchronization.
  - Added Alert & Access Log audit trails, double-check status verification (Ping + SNMP), and per-device alert muting.

* **Phase 10: Telemetry Accuracy & Forensics**
  - **Real Record Bucketing**: Replaced generic averages with point-to-point raw traffic sampling for backbone and router uplinks.
  - **BlackBox Forensics Engine**: Heuristic downtime analysis to identify root causes (e.g. CPU exhaustion, thermal limits, fiber cut, reboot).
  - **Context-Aware Counter Rollovers**: Handled 32-bit and 64-bit SNMP counter rollovers dynamically, preventing traffic chart spikes.

* **Phase 11: SQLite Database Optimization & Performance Tuning**
  - **SQLite Connection Tuning**: Enabled WAL (Write-Ahead Logging) journal mode, `synchronous = NORMAL`, and `mmap_size = 256MB` for simultaneous, non-blocking reads/writes.
  - **Split Data Retention**: Separated detailed interface chart data (default 7 days) from aggregated report metrics (min 31 days) to keep database size under control.
  - **Weekly Background Vacuum**: Scheduled automatic SQLite physical database compression (`VACUUM`) every Sunday at 03:00.
  - **Covering Index**: Implemented `idx_metrics_name_time` covering index to ensure heavy traffic historical queries run in under 2 seconds.
  - **Automated Regression Testing**: Created the `test_report_accuracy.py` suite to validate bandwidth report algorithms, outlier filtering, and rollover calculations.

---

## 📦 Requirements

- Python **3.9+**
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+), macOS 12+, or Windows (manual)
- Network access to SNMP-enabled devices (UDP port 161)
- (Optional) UniFi controller for automatic device import

---

## 🚀 Quick Install (Linux / macOS)

```bash
# 1. Clone or extract the NetMon package
git clone https://github.com/yourorg/netmon.git
cd netmon

# 2. Run the install script (Linux: requires sudo)
sudo bash install.sh

# 3. Open the dashboard
http://<server-ip>:5000
```

The installer will:
- Install system dependencies
- Create a Python virtual environment
- Install all Python packages
- Initialise the SQLite database
- Create a systemd service (Linux) that auto-starts on boot
- Open the firewall port

---

## 🪟 Windows Install (Manual)

```powershell
# 1. Install Python 3.9+ from https://python.org

# 2. Open PowerShell in the netmon directory
cd C:\netmon

# 3. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start the app
python app.py

# 6. Open http://localhost:5000
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT`   | `5000`  | Web server port |
| `HOST`   | `0.0.0.0` | Bind address |
| `DB_PATH`| `netmon.db` | SQLite database path |
| `SECRET_KEY` | (random) | Flask session key |

### In-app Settings (Settings page)

- **Poll Interval**: How often SNMP devices are queried (default 30s)
- **Default Community**: SNMP community string (default `public`)
- **UniFi Credentials**: Host, port, username, password, site
- **Alert Rules**: Toggle alerts on device down/recovery
- **Telegram Bot**: Bot Token, Whitelisted Chat IDs, Down/Up Alerts, Daily Digest schedule

---

## 🤖 Telegram Bot Integration

NetMon dilengkapi modul bot Telegram interaktif 2-arah native (tanpa dependensi eksternal tambahan) yang mendukung pengiriman alert instan, eksekusi perintah monitoring, dan laporan rekap harian otomatis.

### 1. Konfigurasi Bot
1. Buat bot baru melalui [@BotFather](https://t.me/BotFather) di Telegram dengan perintah `/newbot` dan simpan token yang diberikan.
2. Buka dashboard NetMon di browser, navigasi ke menu **Settings** > **Telegram Bot Integration**.
3. Centang opsi **Aktifkan Telegram Bot**.
4. Tempel **Bot Token** pada kolom yang tersedia.
5. Untuk mendapatkan **Chat ID**, kirim `/start` atau `/myid` ke bot Anda di Telegram (atau gunakan `@userinfobot`), lalu masukkan Chat ID tersebut ke kolom **Authorized Chat IDs**.
6. Klik tombol **Test Connection** untuk memverifikasi koneksi, lalu klik **Save All Settings**.

### 2. Fitur & Tombol Interaktif
- **Alert Instan Berfilter AI:** Saat perangkat DOWN atau kembali ONLINE, bot akan mengirimkan notifikasi real-time yang telah divalidasi oleh AI False Warning Detector.
- **Inline Keyboard:** Setiap pesan alert dilengkapi tombol `[✅ Acknowledge]` dan `[🔄 Re-check]`. Mengklik tombol ini akan langsung memperbarui status di Telegram dan mensinkronkan data ke Web Dashboard NetMon via Socket.IO secara langsung.
- **Daily Digest:** Ringkasan kesehatan jaringan otomatis setiap hari sesuai waktu yang dijadwalkan (default 08:00 WIB).

### 3. Daftar Perintah Chat
| Perintah | Deskripsi |
| :--- | :--- |
| `/status` / `/summary` | Ringkasan jumlah perangkat UP, DOWN, Warning, latensi rata-rata, dan alert terbuka |
| `/alerts` | Menampilkan daftar insiden/alert aktif yang belum di-acknowledge |
| `/down` | Daftar seluruh perangkat yang sedang offline (DOWN) |
| `/devices` | Ringkasan sebaran perangkat berdasarkan tipe dan zona |
| `/ack <id>` | Konfirmasi / acknowledge alert berdasarkan ID |
| `/ack_all` | Acknowledge seluruh alert aktif sekaligus |
| `/poll <ip/id>` | Memicu polling ulang seketika untuk perangkat tertentu |
| `/digest` | Meminta pengiriman rekap harian (Daily Digest) saat ini |
| `/myid` | Menampilkan Chat ID dan User ID Telegram Anda |
| `/help` | Menampilkan panduan bantuan dan daftar perintah |

---

## 📡 SNMP Setup

### On Cisco IOS / IOS-XE

```
snmp-server community public RO
snmp-server location "Server Room"
snmp-server contact "admin@company.com"
```

### On MikroTik RouterOS

```
/snmp set enabled=yes contact="admin" location="MDF"
/snmp community set name=public
```

### On Linux (net-snmp)

```bash
sudo apt install snmpd
# Edit /etc/snmp/snmpd.conf:
#   rocommunity public 192.168.0.0/16
sudo systemctl restart snmpd
```

### On UniFi Devices

Enable SNMP in Settings → System → SNMP.

---

## 🗺️ Using the Floor Plan

1. Go to **Floor Plan** → click **Background** → upload a PNG/JPG/SVG floor plan image
2. Click **Edit Mode**
3. Drag devices from the right panel to their physical locations on the map
4. Click **Save** — positions are stored persistently
5. Return to **View Mode** — devices will pulse/glow based on live status

---

## 🔍 Network Discovery

1. Go to **Devices** → **Network Scan**
2. Enter your network CIDR (e.g. `192.168.1.0/24`)
3. Enter the SNMP community string (e.g. `public`)
4. Click **Start Scan**
5. Discovered devices are automatically added to the device list

---

## ☁️ UniFi Sync

1. Go to **Settings** → enter UniFi controller host/credentials
2. Or go to **Devices** → **Sync UniFi** and enter credentials inline
3. Click **Sync Now** — all UniFi devices are imported with correct types and MAC addresses

---

## 🗂️ Zone Management

1. Go to **Settings** → **Zone Management** → **Add Zone**
2. Name the zone (e.g. "Server Room", "Office Floor 1", "DMZ")
3. Assign a color for visual identification on the floor plan
4. Assign devices to zones via **Devices** → Edit → Zone

---

## 📊 SNMP OIDs Polled

| OID | Description |
|-----|-------------|
| `1.3.6.1.2.1.1.1.0` | sysDescr — system description |
| `1.3.6.1.2.1.1.5.0` | sysName — hostname |
| `1.3.6.1.2.1.1.3.0` | sysUpTime — uptime |
| `1.3.6.1.2.1.1.6.0` | sysLocation — physical location |
| `1.3.6.1.2.1.2.2.1.8.*` | ifOperStatus — interface state |
| `1.3.6.1.2.1.2.2.1.2.*` | ifDescr — interface names |

---

## 🛠️ Service Management (Linux)

```bash
# Start
sudo systemctl start netmon

# Stop
sudo systemctl stop netmon

# Restart
sudo systemctl restart netmon

# Check status
sudo systemctl status netmon

# View logs
sudo journalctl -u netmon -f

# View last 100 lines
sudo journalctl -u netmon -n 100
```

---

## 📁 File Structure

```
netmon/
├── app.py                  ← Flask app + SocketIO + API routes
├── database.py             ← SQLite database manager (tuned connection, WAL mode)
├── snmp_worker.py          ← SNMP polling + discovery + BlackBox Forensics
├── unifi_client.py         ← UniFi controller API client
├── test_report_accuracy.py ← Regression testing suite for bandwidth reports
├── verify_backbone.py      ← Verification script for backbone aggregation queries
├── verify_fase11.py        ← Verification script for SQLite connections & WAL mode
├── verify_fase5.py         ← Verification script for timezone and scheduling
├── requirements.txt        ← Python dependencies
├── install.sh              ← System installation script
├── update.sh               ← In-place automatic update script
├── manage_proxy.sh         ← Nginx reverse proxy configuration helper
├── netmon.db               ← SQLite database (auto-created, persistent)
├── templates/
│   ├── base.html           ← Sidebar layout
│   ├── dashboard.html      ← Main dashboard with backbone charts
│   ├── floorplan.html      ← Interactive floor plan alerting map
│   ├── devices.html        ← Device management and manual overrides
│   ├── logs.html           ← Alert and access audit logs
│   └── settings.html       ← Application configuration (retention settings)
└── static/
    ├── css/style.css       ← Glassmorphism dark theme CSS
    ├── js/main.js          ← Real-time dynamic JS frontend orchestration
    └── img/                ← Floor plan uploads
```

---

## 🔒 Security Notes

- The app binds to `0.0.0.0` by default — restrict with `HOST=127.0.0.1` behind a reverse proxy
- No built-in authentication — place behind nginx/Caddy with Basic Auth or OAuth for production
- SNMP v1/v2c use cleartext community strings — restrict SNMP access via ACL on devices

### Nginx reverse proxy example

```nginx
server {
    listen 80;
    server_name netmon.company.internal;
    auth_basic "NetMon";
    auth_basic_user_file /etc/nginx/.htpasswd;
    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_http_version 1.1;
    }
}
```

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| SNMP scan finds nothing | Check firewall allows UDP 161 from NetMon server; verify community string |
| Device always "Unknown" | SNMP not enabled on device, or wrong community string |
| UniFi sync fails | Verify host, port (8443), credentials; check SSL — the app skips cert verification |
| Floor plan image not showing | Upload PNG/JPG under 10MB via the Background button |
| High CPU | Increase poll interval in Settings |
| Port 5000 in use | Set `PORT=5001 ./start.sh` |

---

## 📝 Big Prompt / System Prompt for AI-assisted Development

```text
You are an expert full-stack developer tasked with building "NetMon", an advanced, highly responsive, and lightweight network monitoring application.

### Tech Stack:
- **Backend**: Python 3.9+, Flask, Flask-SocketIO (threading mode), SQLite3, APScheduler, PySNMP
- **Frontend**: HTML5, Vanilla JavaScript, CSS3 (No Tailwind/Bootstrap, pure custom responsive CSS), Chart.js (for graphs), Socket.IO client.
- **Deployment**: Nginx as a reverse proxy, bash scripts for installation and updates.

### Architecture & Design Rules:
1. **Zero-reload UI**: The frontend must be fully dynamic. Use vanilla JS to render DOM elements based on Socket.IO events (`init_data`, `device_status_update`, `stats_update`). Do not reload the page.
2. **Responsive CSS**: The design must use CSS Grid/Flexbox. Use a dark, premium, glassmorphism aesthetic (vibrant accents, dark background `#0b0b0d`, smooth micro-animations). Implement a mobile-first responsive layout (hamburger menus, horizontally scrollable tables, stacked flex-containers).
3. **Robust SQLite Database**: Use `sqlite3` with `check_same_thread=False` and explicit connection locks to prevent concurrency errors since background threads and API endpoints access the DB simultaneously.

### Database Schema (Core Tables):
1. `devices`: id, name, ip, mac, type (e.g., router, switch, ap), zone_id, snmp_enabled, snmp_community, status (up/down/warning/unknown), pos_x, pos_y, is_muted (boolean), wan_interface (string).
2. `zones`: id, name, color, description.
3. `alerts`: id, device_id, severity, message, timestamp, acknowledged (boolean).
4. `access_logs`: id, source_ip, message, log_type, timestamp.
5. `interface_traffic`: id, device_id, timestamp, rx_bytes, tx_bytes.
6. `settings`: key, value (stores report_metrics_retention_hours, interface_chart_retention_hours, poll_interval, anomaly_cap_multiplier, etc.)

### Backend Core Logic (`snmp_worker.py`):
1. **Dual-Interval Polling**: Implement two separate APScheduler jobs. 
   - Job 1: Status Polling (every 30s) -> Uses ping + basic SNMP to check if a device is online. Uses a "double-check" logic (SNMP fails -> Ping fails -> Mark Offline).
   - Job 2: Traffic Polling (every 10s) -> Polls `ifInOctets` and `ifOutOctets` (32-bit & 64-bit counters) for routers.
2. **Bandwidth Calculation**: Calculate delta bytes between polls divided by delta time (`dt`) to get Bps (Bytes per second). Multiply by 8 to get bps.
3. **Rollover Protection**: Differentiate between a 32-bit SNMP counter rollover (happens at 4.29GB) and a device reboot (where uptime decreases). Adjust the math dynamically to prevent false "negative" or "anomalous spike" bandwidth readings.
4. **Data Retention & Disk Optimization**: Run a background cleanup task every hour to delete `interface_traffic` data older than `interface_chart_retention_hours` and `snmp_metrics` data older than `report_metrics_retention_hours`. Run a weekly background job to execute SQLite `VACUUM` every Sunday at 03:00 to optimize disk space.

### Frontend Core Features:
1. **Dashboard (`dashboard.html`)**: Shows summary cards (Total, Up, Down), recent alerts feed, and real-time total backbone throughput graph (Chart.js).
2. **Devices (`devices.html`)**: A searchable, filterable table. Includes a "Device Detail Modal" that allows editing properties (Name, IP, Type, Zone, WAN Interface dropdown).
3. **Floor Plan (`floorplan.html`)**: An interactive HTML5 Canvas. Users can upload a background image, drag-and-drop device icons, and save their coordinates. Devices pulse red when offline.
4. **Router Uplinks (`uplink_traffic.html`)**: Displays real-time bandwidth charts for all devices marked as 'router'. Includes time-filters (1h, 6h, 12h, 24h) fetched via `/api/devices/<id>/traffic_history`.
5. **Logs & Reports**: Includes Alert Logs, Access Logs, and PDF export functionality for monthly bandwidth summaries.

### API Endpoints:
- `GET/POST /api/devices`, `PUT/DELETE /api/devices/<id>`
- `GET/POST /api/zones`, `DELETE /api/zones/<id>`
- `GET /api/alerts`, `POST /api/alerts/<id>/ack`
- `GET /api/devices/<id>/traffic_history?hours=X`
- `POST /api/settings` (to update retention and polling interval)
- `GET /api/stats` (fetches high-level metrics)

### Deployment Constraints:
- Provide an `update.sh` script that stops the service, git pulls, migrates the DB safely (DO NOT OVERWRITE `netmon.db`), installs pip requirements, and restarts the systemd service.
- Implement a `manage_proxy.sh` script to configure Nginx to reverse proxy port 80 to 5000, supporting WebSocket upgrades (`Upgrade $http_upgrade`, `Connection "upgrade"`).

CRITICAL INSTRUCTION: Ensure the code is modular. Separate database interactions into `database.py`, background polling into `snmp_worker.py`, API and Socket routing into `app.py`, and frontend logic into `static/js/main.js`.
```

---

## 📄 License

MIT License — free for personal and commercial use.
