#!/usr/bin/env python3
"""
NetMon - Network Monitoring Application
Automatic SNMP capture, floor plan alerting, zone management, real-time dashboard
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from flask_socketio import SocketIO, emit
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.middleware.proxy_fix import ProxyFix
import hmac
import ipaddress
import logging
import secrets
import threading
import json
import os
from datetime import datetime, timedelta
from database import Database
from snmp_worker import SNMPWorker
from unifi_client import UniFiClient
from telegram_bot import TelegramBot

logger = logging.getLogger('netmon.web')

app = Flask(__name__)
_proxy_fix_mw = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
_raw_wsgi_app = app.wsgi_app


def _trusted_proxy_wsgi(environ, start_response):
    """Apply ProxyFix only when connection originates from local Nginx reverse proxy."""
    if environ.get('REMOTE_ADDR') in ('127.0.0.1', '::1', '::ffff:127.0.0.1'):
        return _proxy_fix_mw(environ, start_response)
    return _raw_wsgi_app(environ, start_response)


app.wsgi_app = _trusted_proxy_wsgi
db = Database()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or db.get_settings().get('app_secret_key') or os.urandom(32).hex()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('HTTPS_PROXY_ENABLED', '').strip().lower() in ('1', 'true', 'yes')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)

ALLOWED_SETTING_KEYS = {
    'poll_interval', 'traffic_poll_interval', 'allowed_cidrs',
    'default_community', 'default_snmp_version',
    'alert_retention_days', 'log_retention_days', 'traffic_retention_hours',
    'report_metrics_retention_hours', 'interface_chart_retention_hours',
    'anomaly_cap_multiplier', 'anomaly_cap_gbps', 'campus_total_bandwidth_mbps',
    'alert_on_down', 'alert_on_up', 'anomaly_alert_enabled',
    'traffic_spike_multiplier', 'traffic_spike_min_mbps', 'traffic_drop_min_mbps',
    'cpu_spike_threshold', 'cpu_jump_threshold', 'memory_spike_threshold',
    'groq_api_key', 'groq_model', 'groq_redact_ips',
    'telegram_enabled', 'telegram_bot_token', 'telegram_chat_ids',
    'telegram_notify_down', 'telegram_notify_up', 'telegram_censor_ips',
    'telegram_daily_digest_enabled', 'telegram_daily_digest_time',
    'unifi_host', 'unifi_port', 'unifi_site', 'unifi_user', 'unifi_pass',
    'theme', 'app_name', 'global_maintenance_until',
}


def _get_csrf_token():
    """Return per-session CSRF token, generating one on first visit."""
    tok = session.get('_csrf_token')
    if not tok:
        tok = secrets.token_hex(24)
        session['_csrf_token'] = tok
    return tok


def _verify_csrf_token(supplied):
    expected = session.get('_csrf_token') or ''
    return bool(expected and supplied and hmac.compare_digest(str(expected), str(supplied)))

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)

# Web process uses TelegramBot only for test_connection(); polling runs in dedicated poller.py daemon
telegram_bot = TelegramBot(db, socketio, start_polling=False)
snmp_worker = SNMPWorker(db, socketio, telegram_bot=None)
telegram_bot.snmp_worker = snmp_worker
scheduler = BackgroundScheduler(daemon=True)


def _sanitize_device(d):
    """Never expose SNMP community string in plaintext over HTTP/WebSocket APIs."""
    if not isinstance(d, dict):
        return d
    out = dict(d)
    if out.get('snmp_community'):
        out['snmp_community'] = '***'
    return out


def _get_current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        return db.get_user(uid)
    except Exception:
        return None


def _parse_allowed_networks(cidr_str):
    """Parse comma-separated CIDR strings into ip_network objects; defaults safely to campus subnet."""
    raw = (cidr_str if cidr_str is not None else '10.122.100.0/24').strip()
    if not raw:
        raw = '10.122.100.0/24'
    nets = []
    for part in raw.split(','):
        tok = part.strip()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return nets or [ipaddress.ip_network('10.122.100.0/24', strict=False)]


def _is_client_ip_allowed(remote_ip, cidr_str=None):
    """Enforce internal LAN subnet allowlist (always permits localhost & emergency env override)."""
    if os.environ.get('NETMON_DISABLE_IP_LOCK', '').strip().lower() in ('1', 'true', 'yes'):
        return True
    if not remote_ip:
        return False
    ip_str = str(remote_ip).split(',')[0].strip()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if getattr(ip_obj, 'ipv4_mapped', None) is not None:
            ip_obj = ip_obj.ipv4_mapped
    except ValueError:
        return False
    if ip_obj.is_loopback:
        return True
    if cidr_str is None:
        try:
            cidr_str = db.get_settings().get('allowed_cidrs', '10.122.100.0/24')
        except Exception:
            cidr_str = '10.122.100.0/24'
    return any(ip_obj in net for net in _parse_allowed_networks(cidr_str))


@app.before_request
def enforce_auth_and_rbac():
    path = request.path or '/'
    if path not in ('/health', '/internal/emit') and not _is_client_ip_allowed(request.remote_addr):
        logger.warning(f"[IP Lock] Blocked request from {request.remote_addr} to {path}")
        if path.startswith('/api/'):
            return jsonify({
                'status': 'error',
                'message': f'Akses ditolak: IP {request.remote_addr} berada di luar subnet yang diizinkan.'
            }), 403
        return (
            '<!doctype html><html><head><meta charset="utf-8"><title>403 Forbidden - TIKWatch</title></head>'
            '<body style="font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:48px;text-align:center;">'
            '<h2>403 — Akses Ditolak</h2>'
            f'<p>Alamat IP Anda (<code>{request.remote_addr}</code>) tidak termasuk dalam subnet jaringan yang diizinkan.</p>'
            '</body></html>',
            403
        )

    if (
        path.startswith('/static/')
        or path.startswith('/socket.io/')
        or path in ('/login', '/logout', '/health', '/internal/emit', '/metrics')
    ):
        return None

    uid = session.get('user_id')
    if not uid:
        if path.startswith('/api/'):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        return redirect(url_for('login_page', next=path))

    # CSRF check for all authenticated mutating requests (exempt Socket.IO polling & internal IPC)
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        supplied_csrf = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') or ''
        if not _verify_csrf_token(supplied_csrf):
            logger.warning(f"[CSRF] Blocked {request.method} {path} from {request.remote_addr}")
            return jsonify({'status': 'error', 'message': 'CSRF token tidak valid. Muat ulang halaman lalu coba lagi.'}), 403

    # Admin RBAC enforcement for mutating & sensitive endpoints
    if request.method in ('POST', 'PUT', 'DELETE'):
        admin_prefixes = (
            '/api/devices', '/api/zones', '/api/settings', '/api/maintenance',
            '/api/scan', '/api/unifi', '/api/reports', '/api/users',
            '/api/ai/test', '/api/telegram/test'
        )
        # Allow viewer only for non-destructive acknowledge or allow all admin routes strictly to admin
        if any(path.startswith(p) for p in admin_prefixes):
            # Self password change allowed for any authenticated user
            if path == '/api/users/password':
                return None
            if session.get('role') != 'admin':
                return jsonify({'status': 'error', 'message': 'Akses ditolak: butuh hak akses Admin'}), 403
    return None


@app.context_processor
def inject_theme():
    try:
        settings = db.get_settings()
        return {
            'theme': settings.get('theme', 'default'),
            'current_user': _get_current_user(),
            'csrf_token': _get_csrf_token(),
        }
    except Exception:
        return {'theme': 'default', 'current_user': None, 'csrf_token': _get_csrf_token()}


# ============================================================
# AUTHENTICATION, HEALTH & INTERNAL BRIDGE ROUTES
# ============================================================

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if session.get('user_id'):
        return redirect('/')
    error = None
    next_url = request.args.get('next') or request.form.get('next') or '/'
    if not str(next_url).startswith('/') or str(next_url).startswith('//'):
        next_url = '/'
    if request.method == 'POST':
        if not _verify_csrf_token(request.form.get('csrf_token') or ''):
            return render_template('login.html', error='Sesi login kadaluarsa (CSRF). Muat ulang halaman lalu coba lagi.', next_url=next_url), 403
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = db.authenticate_user(username, password)
        if user:
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['_csrf_token'] = secrets.token_hex(24)
            db.add_access_log({'source': request.remote_addr, 'message': f"User '{user['username']}' logged in", 'type': 'auth'})
            return redirect(next_url)
        error = 'Username atau password salah.'
        db.add_access_log({'source': request.remote_addr, 'message': f"Failed login attempt for '{username}'", 'type': 'auth'})
    return render_template('login.html', error=error, next_url=next_url)


@app.route('/logout')
def logout_page():
    uname = session.get('username')
    if uname:
        db.add_access_log({'source': request.remote_addr, 'message': f"User '{uname}' logged out", 'type': 'auth'})
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'app': 'TIKWatch'})


@app.route('/internal/emit', methods=['POST'])
def internal_socket_emit():
    """Local-only IPC endpoint so poller.py can push real-time Socket.IO events to Gunicorn."""
    remote = request.remote_addr or ''
    if remote not in ('127.0.0.1', '::1', '::ffff:127.0.0.1'):
        return jsonify({'status': 'error', 'message': 'Forbidden'}), 403
    expected = db.get_settings().get('internal_emit_token', '')
    provided = request.headers.get('X-Internal-Token', '')
    if not expected or not hmac.compare_digest(expected, provided):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    payload = request.json or {}
    ev = payload.get('event')
    if ev:
        socketio.emit(ev, payload.get('data'))
    return jsonify({'status': 'ok'})


@app.route('/api/users', methods=['GET', 'POST'])
def api_users():
    if request.method == 'GET':
        if session.get('role') != 'admin':
            u = _get_current_user()
            return jsonify([u] if u else [])
        return jsonify(db.get_all_users())
    data = request.json or {}
    try:
        uid = db.create_user(
            data.get('username'),
            data.get('password'),
            role=data.get('role', 'viewer'),
            display_name=data.get('display_name', '')
        )
        return jsonify({'status': 'success', 'id': uid})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    if int(user_id) == int(session.get('user_id', 0)):
        return jsonify({'status': 'error', 'message': 'Tidak dapat menghapus akun yang sedang dipakai login.'}), 400
    try:
        db.delete_user(user_id)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/api/users/password', methods=['POST'])
def api_change_own_password():
    data = request.json or {}
    uid = session.get('user_id')
    cur_pw = data.get('current_password') or ''
    new_pw = data.get('new_password') or ''
    user = db.get_user(uid)
    if not user or not db.authenticate_user(user['username'], cur_pw):
        return jsonify({'status': 'error', 'message': 'Password saat ini salah.'}), 400
    try:
        db.update_user_password(uid, new_pw)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ============================================================
# PAGE ROUTES
# ============================================================

@app.route('/')
def dashboard():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Dashboard', 'type': 'access'})
    return render_template('dashboard.html')

@app.route('/floorplan')
def floorplan():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Floor Plan', 'type': 'access'})
    return render_template('floorplan.html')

@app.route('/uplink-traffic')
def uplink_traffic():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Router Uplink Traffic', 'type': 'access'})
    return render_template('uplink_traffic.html')

@app.route('/zones')
def zones_page():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Zones', 'type': 'access'})
    return render_template('zones.html')

@app.route('/devices')
def devices_page():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Devices', 'type': 'access'})
    return render_template('devices.html')

@app.route('/logs')
def logs_page():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Logs', 'type': 'access'})
    return render_template('logs.html')

@app.route('/settings')
def settings_page():
    db.add_access_log({'source': request.remote_addr, 'message': 'Accessed Settings', 'type': 'access'})
    return render_template('settings.html')

# ============================================================
# API – DEVICES
# ============================================================

@app.route('/api/devices', methods=['GET'])
def get_devices():
    return jsonify([_sanitize_device(d) for d in db.get_all_devices()])

@app.route('/api/devices', methods=['POST'])
def add_device():
    import sqlite3
    data = dict(request.json) if request.json else {}
    data['source'] = request.json.get('source', 'manual') if request.json else 'manual'
    try:
        device_id = db.add_device(data)
        dev = _sanitize_device(db.get_device(device_id))
        socketio.emit('device_added', dev)
        return jsonify({'id': device_id, 'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Alamat IP sudah terdaftar atau terdapat kesalahan integritas data.'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/devices/type_counts', methods=['GET'])
def get_device_type_counts():
    """Count per device type, untuk sub-nav di halaman /devices."""
    return jsonify(db.get_device_type_counts())

@app.route('/api/devices/<int:device_id>', methods=['GET'])
def get_device(device_id):
    dev = db.get_device(device_id)
    return jsonify(_sanitize_device(dev) if dev else {})

@app.route('/api/devices/<int:device_id>', methods=['PUT', 'POST'])
def update_device(device_id):
    import sqlite3
    try:
        db.update_device(device_id, request.json)
        dev = _sanitize_device(db.get_device(device_id))
        socketio.emit('device_updated', dev)
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Alamat IP sudah terdaftar atau terdapat kesalahan integritas data.'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/devices/<int:device_id>/delete', methods=['POST'])
@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    db.delete_device(device_id)
    socketio.emit('device_deleted', {'id': device_id})
    return jsonify({'status': 'success'})

@app.route('/api/devices/<int:device_id>/poll', methods=['POST'])
def poll_device_now(device_id):
    device = db.get_device(device_id)
    if device:
        threading.Thread(target=snmp_worker.poll_device, args=(device,), daemon=True).start()
        return jsonify({'status': 'polling'})
    return jsonify({'status': 'error', 'message': 'Device not found'}), 404

@app.route('/api/devices/<int:device_id>/toggle_alerts', methods=['POST'])
def toggle_device_alerts(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'status': 'error', 'message': 'Device not found'}), 404
    new_state = 0 if device.get('alerts_enabled', 1) else 1
    db.update_device(device_id, {'alerts_enabled': new_state})
    dev = db.get_device(device_id)
    socketio.emit('device_updated', dev)
    return jsonify({'status': 'success', 'alerts_enabled': new_state})

@app.route('/api/devices/detect', methods=['POST'])
def detect_device_info():
    import subprocess
    import re
    
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'IP Address is required'}), 400
        
    snmp_community = data.get('snmp_community', 'public') or 'public'
    snmp_version = data.get('snmp_version', '2c') or '2c'
    try:
        snmp_port = int(data.get('snmp_port', 161) or 161)
    except Exception:
        snmp_port = 161
    
    # 1. Resolve MAC address via ARP
    mac = ""
    try:
        # Send a quick ping to populate ARP cache
        ping_cmd = ["ping", "-n", "1", "-w", "500", ip] if os.name == 'nt' else ["ping", "-c", "1", "-W", "1", ip]
        subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Read ARP output
        if os.name == 'nt':
            res = subprocess.run(["arp", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
            out = res.stdout
        else:
            res = subprocess.run(["arp", "-n", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
            out = res.stdout
            if (not out or "No ARP" in out) and os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r") as f:
                    out = f.read()
                    
        mac_re = re.compile(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})')
        for line in out.splitlines():
            if ip in line:
                match = mac_re.search(line)
                if match:
                    mac = match.group(0).upper().replace('-', ':')
                    break
    except Exception as e:
        print(f"[Detect] ARP MAC fetch failed: {e}")

    # 2. Try SNMP Query
    if snmp_worker:
        oids_to_query = [
            '1.3.6.1.2.1.1.1.0',           # sysDescr
            '1.3.6.1.2.1.1.2.0',           # sysObjectID
            '1.3.6.1.2.1.1.5.0',           # sysName
            '1.3.6.1.4.1.14988.1.1.4.1.0',  # MikroTik Model
            '1.3.6.1.4.1.41112.1.4.1.1.1.1', # Ubiquiti Model
            '1.3.6.1.2.1.47.1.1.1.1.13.1',  # Cisco/Standard Model
            '1.3.6.1.4.1.4881.1.1.10.2.1.1.7.0', # Ruijie device model
            '1.3.6.1.4.1.4881.1.1.10.2.1.1.9.0'  # Ruijie software version
        ]
        res = snmp_worker._get(ip, snmp_community, oids_to_query, port=snmp_port, version=snmp_version, timeout=1.5)
        
        # Fallback to SNMP v1 if 2c fails (some APs only support v1)
        if not res and snmp_version == '2c':
            res = snmp_worker._get(ip, snmp_community, oids_to_query, port=snmp_port, version='1', timeout=1.5)
        
        if res:
            descr = res.get('1.3.6.1.2.1.1.1.0', '')
            sys_obj_id = str(res.get('1.3.6.1.2.1.1.2.0', '')).lower()
            name = res.get('1.3.6.1.2.1.1.5.0', '').strip() or ip
            
            # Vendor detection
            vendor = 'Unknown'
            if '14988' in sys_obj_id or 'mikrotik' in descr.lower() or 'routeros' in descr.lower() or 'routerboard' in descr.lower():
                vendor = 'MikroTik'
            elif '4881' in sys_obj_id or 'ruijie' in descr.lower() or 'reyee' in descr.lower() or 'rgos' in descr.lower() or 'rg-rap' in descr.lower():
                vendor = 'Ruijie'
            elif '41112' in sys_obj_id or 'ubiquiti' in descr.lower() or 'unifi' in descr.lower() or 'ubnt' in descr.lower():
                vendor = 'Ubiquiti'
            elif '9.1.' in sys_obj_id or '9.9.' in sys_obj_id or '.9.' in sys_obj_id or 'cisco' in descr.lower():
                vendor = 'Cisco'
            elif 'generic' in descr.lower() or 'linux' in descr.lower() or 'windows' in descr.lower():
                vendor = 'Generic'
                
            # Model extraction
            model = ""
            if vendor == 'Ruijie' and res.get('1.3.6.1.4.1.4881.1.1.10.2.1.1.7.0'):
                model = res['1.3.6.1.4.1.4881.1.1.10.2.1.1.7.0'].strip()
            elif vendor == 'MikroTik' and res.get('1.3.6.1.4.1.14988.1.1.4.1.0'):
                model = res['1.3.6.1.4.1.14988.1.1.4.1.0'].strip()
            elif vendor == 'Ubiquiti' and res.get('1.3.6.1.4.1.41112.1.4.1.1.1.1'):
                model = res['1.3.6.1.4.1.41112.1.4.1.1.1.1'].strip()
            elif res.get('1.3.6.1.2.1.47.1.1.1.1.13.1'):
                model = res['1.3.6.1.2.1.47.1.1.1.1.13.1'].strip()
                
            # Regex fallback
            if not model and descr:
                descr_clean = descr.replace('\r', '').replace('\n', ' ')
                if vendor == 'Ruijie':
                    match = re.search(r'(RG-[A-Za-z0-9().\-]+)', descr_clean)
                    if match: model = match.group(1)
                elif vendor == 'MikroTik':
                    match = re.search(r'(RB\w+|CCR\w+|CRS\w+|CSS\w+|hEX\w+|LDF\w+|LHG\w+|NetMetal\w+|PowerBox\w+|QRT\w+|SXT\w+|wAP\w+)', descr_clean)
                    if match: model = match.group(1)
                elif vendor == 'Ubiquiti':
                    match = re.search(r'(UAP-[A-Za-z0-9\-]+|US-[A-Za-z0-9\-]+|USW-[A-Za-z0-9\-]+|EdgeRouter\s+\S+|EdgeSwitch\s+\S+|NanoStation\s+\S+)', descr_clean)
                    if match: model = match.group(1)
                elif vendor == 'Cisco':
                    match = re.search(r'(WS-C[A-Za-z0-9\-]+|C[0-9]{4}[A-Za-z0-9\-]*|Catalyst\s+[A-Za-z0-9\-]+)', descr_clean)
                    if match: model = match.group(1)
                    
                if not model:
                    model = descr.split('\n')[0][:30].strip()
            
            # Smart Type classification
            device_type = 'unknown'
            model_lower = model.lower()
            descr_lower = descr.lower()
            
            if any(x in model_lower for x in ('nbs', 'es-', 'nps', 's29', 's37', 's57', 's53', 'crs', 'css', 'usw', 'edgeswitch')) or \
               any(x in descr_lower for x in ('switch', 'catalyst', 'nexus', 'ethernet switch')):
                device_type = 'switch'
            elif any(x in model_lower for x in ('rap', 'rg-rap', 'uap', 'ap-', '-ap')) or \
                 any(x in descr_lower for x in ('access point', 'aironet', 'unifi ap', 'wireless ap', 'wlan ap', 'reyee ap', 'rgos')) or \
                 (vendor == 'Ruijie' and 'rg-' in model_lower and not any(x in model_lower for x in ('nbs', 'nps', 's29', 's37', 's57'))):
                device_type = 'access_point'
            elif any(x in model_lower for x in ('eg', 'rsr', 'edgerouter', 'usg', 'udm', 'uxg')) or \
                 any(x in descr_lower for x in ('router', 'routeros', 'gateway', 'security gateway')):
                device_type = 'router'
            elif any(x in descr_lower for x in ('linux', 'ubuntu', 'debian', 'centos', 'redhat', 'windows', 'win32', 'freebsd')):
                device_type = 'server'
            elif any(x in descr_lower for x in ('firewall', 'pfsense', 'fortigate', 'fortinet', 'checkpoint', 'asa')):
                device_type = 'firewall'
            elif any(x in descr_lower for x in ('printer', 'laserjet', 'epson', 'canon', 'hp officejet')):
                device_type = 'printer'
            
            return jsonify({
                'status': 'success',
                'snmp_enabled': True,
                'name': name,
                'mac': mac,
                'vendor': vendor,
                'model': model,
                'type': device_type
            })
            
    # 3. Fallback to Ping to verify if host is reachable
    is_alive = False
    try:
        ping_cmd = ["ping", "-n", "1", "-w", "800", ip] if os.name == 'nt' else ["ping", "-c", "1", "-W", "1", ip]
        res = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        is_alive = (res.returncode == 0)
    except Exception:
        pass
        
    if is_alive:
        detected_vendor = 'Generic'
        detected_model = 'Ping Only'
        detected_type = 'unknown'
        
        if mac:
            mac_clean = mac.replace('-', ':').replace('.', '').lower()
            parts = mac_clean.split(':')
            if len(parts) >= 3:
                oui = ":".join(parts[:3])
                OUI_MAP = {
                    '00:27:22': 'Ubiquiti', '04:18:d6': 'Ubiquiti', '24:a4:3c': 'Ubiquiti',
                    '70:a7:41': 'Ubiquiti', '80:2a:a8': 'Ubiquiti', 'b4:fb:e4': 'Ubiquiti',
                    'fc:ec:da': 'Ubiquiti', 'f0:9f:c2': 'Ubiquiti', 'e0:63:da': 'Ubiquiti',
                    'd8:b3:77': 'Ubiquiti', 'ac:8b:03': 'Ubiquiti', 'ac:3b:77': 'Ubiquiti',
                    '00:1a:8c': 'Ruijie', '00:21:c7': 'Ruijie', '00:26:8a': 'Ruijie',
                    '1c:34:da': 'Ruijie', 'b0:75:d5': 'Ruijie', '00:01:c9': 'Ruijie',
                    '00:0a:f7': 'Ruijie', '00:11:95': 'Ruijie', '00:14:fd': 'Ruijie',
                    '00:0e:3c': 'Ruijie', 'c4:ad:34': 'Ruijie', 'dc:56:e7': 'Ruijie',
                    'e4:38:83': 'Ruijie', 'f8:15:e7': 'Ruijie', '2c:b2:1a': 'Ruijie',
                    '00:0c:42': 'MikroTik', '18:fd:74': 'MikroTik', '2c:c8:1b': 'MikroTik',
                    '4c:5e:0c': 'MikroTik', '64:d1:54': 'MikroTik', '6c:3b:6b': 'MikroTik',
                    '74:4d:28': 'MikroTik', '78:9a:18': 'MikroTik', 'd4:ca:6d': 'MikroTik',
                    'e8:28:c1': 'MikroTik',
                    '00:00:0c': 'Cisco', '00:01:42': 'Cisco', '00:01:43': 'Cisco',
                    '00:01:63': 'Cisco', '00:01:64': 'Cisco', '00:01:96': 'Cisco',
                    '00:01:97': 'Cisco', '00:02:16': 'Cisco', '00:02:17': 'Cisco',
                    '00:02:4a': 'Cisco', '00:02:4b': 'Cisco', '00:02:b9': 'Cisco',
                    '00:14:1c': 'TP-Link', '00:1f:33': 'TP-Link', '00:25:61': 'TP-Link',
                    'f8:1a:67': 'TP-Link', '18:e8:29': 'TP-Link', '50:3e:aa': 'TP-Link',
                    '50:c7:bf': 'TP-Link', '74:da:da': 'TP-Link', '84:16:f9': 'TP-Link',
                    '84:c9:b2': 'TP-Link', '98:de:d0': 'TP-Link', 'b0:48:7a': 'TP-Link',
                    '00:18:82': 'Huawei', '00:25:9e': 'Huawei', '00:46:4b': 'Huawei',
                    '08:19:a6': 'Huawei', '0c:37:dc': 'Huawei', '10:1b:54': 'Huawei',
                    '10:47:80': 'Huawei', '10:c6:1f': 'Huawei', '14:3c:c9': 'Huawei',
                    '00:05:69': 'VMware', '00:0c:29': 'VMware', '00:50:56': 'VMware',
                    '00:15:5d': 'Microsoft',
                }
                detected_vendor = OUI_MAP.get(oui, 'Generic')
                if detected_vendor != 'Generic':
                    detected_model = f'Ping Only ({detected_vendor})'
                    if detected_vendor in ('Ubiquiti', 'Ruijie', 'MikroTik', 'Cisco', 'TP-Link', 'Huawei'):
                        detected_type = 'network_device'
                    elif detected_vendor in ('VMware', 'Microsoft'):
                        detected_type = 'server'
                        
        return jsonify({
            'status': 'success',
            'snmp_enabled': False,
            'name': ip,
            'mac': mac,
            'vendor': detected_vendor,
            'model': detected_model,
            'type': detected_type
        })
        
    return jsonify({'status': 'error', 'message': 'Device is unreachable or offline'}), 400

@app.route('/api/devices/<int:device_id>/traffic_history', methods=['GET'])
def get_traffic_history(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'status':'error','message':'Not found'}), 404
        
    try:
        hours = max(0.25, min(24, float(request.args.get('hours', 1))))
    except:
        hours = 1.0
        
    unifi_id = device.get('unifi_id') or ''
    is_unifi = (device.get('type') == 'unifi') or (unifi_id != '') or ('ubiquiti' in str(device.get('vendor') or '').lower())
    
    # If the device is UniFi and doesn't have SNMP enabled, return client_count history
    if is_unifi and not device.get('snmp_enabled'):
        points = db.get_metric_history(device_id, 'client_count', hours=hours)
        formatted_points = [{'ts': p['ts'], 'rx_bps': p['value'], 'tx_bps': 0} for p in points]
        return jsonify({'status':'success', 'is_client_chart': True, 'hours':hours, 'points':formatted_points})
        
    iface = request.args.get('iface') or None
    points = db.get_interface_traffic(device_id, iface_name=iface, hours=hours)
    return jsonify({'status':'success','iface':iface,'hours':hours,'points':points})

@app.route('/api/devices/<int:device_id>/traffic_interfaces', methods=['GET'])
def get_traffic_interfaces(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'status':'error','message':'Not found'}), 404
    ifaces = db.get_device_interfaces(device_id, hours=24)
    if not ifaces and device.get('snmp_enabled'):
        try:
            ip = device.get('ip', '')
            community = device.get('snmp_community', 'public') or 'public'
            port = int(device.get('snmp_port', 161) or 161)
            version = device.get('snmp_version', '2c') or '2c'
            walked = snmp_worker._walk(ip, community, '1.3.6.1.2.1.2.2.1.2', port, version, timeout=2)
            if walked:
                ifaces = []
                for oid, name in walked.items():
                    idx = int(oid.split('.')[-1])
                    ifaces.append({'name': str(name), 'idx': idx})
                ifaces.sort(key=lambda x: x['idx'])
        except Exception as e:
            print(f"[API] On-demand interface walk failed: {e}")
    return jsonify({'status':'success','interfaces': ifaces})

@app.route('/api/devices/<int:device_id>/realtime_stats', methods=['GET'])
def get_device_realtime_stats(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'status': 'error', 'message': 'Device not found'}), 404
        
    unifi_id = device.get('unifi_id') or ''
    is_unifi = (device.get('type') == 'unifi') or (unifi_id != '') or ('ubiquiti' in str(device.get('vendor') or '').lower())
    
    if is_unifi:
        try:
            settings = db.get_settings()
            host = settings.get('unifi_host', '')
            username = settings.get('unifi_user', '')
            password = settings.get('unifi_pass', '')
            port = int(settings.get('unifi_port', 8443) or 8443)
            site = settings.get('unifi_site', 'default') or 'default'
            
            if host and username and password:
                unifi = UniFiClient(host=host, username=username, password=password, port=port, site=site)
                details = unifi.get_device_details(device.get('ip') or device.get('mac') or device.get('unifi_id'))
                if details:
                    # Fetch all connected clients from controller
                    all_clients = []
                    try:
                        all_clients = unifi.get_clients()
                    except Exception as ce:
                        print(f"[Realtime] Failed to fetch UniFi clients: {ce}")
                    
                    dev_mac = (details.get('mac') or device.get('mac') or '').lower()
                    connected_clients = []
                    for c in all_clients:
                        cap_mac = str(c.get('ap_mac') or '').lower()
                        csw_mac = str(c.get('sw_mac') or '').lower()
                        if dev_mac and (cap_mac == dev_mac or csw_mac == dev_mac):
                            connected_clients.append({
                                'name': c.get('name') or c.get('hostname') or c.get('mac'),
                                'ip': c.get('ip') or '—',
                                'mac': c.get('mac') or '',
                                'essid': c.get('essid') or 'Wired',
                                'signal': c.get('signal') or c.get('rssi') or None
                            })
                            
                    return jsonify({
                        'status': 'success',
                        'source': 'unifi',
                        'sys_name': details.get('name'),
                        'description': f"UniFi {details.get('model')} Device",
                        'uptime': details.get('uptime'),
                        'cpu_usage': details.get('cpu_usage'),
                        'memory_usage': details.get('memory_usage'),
                        'temperature': details.get('temperature'),
                        'latency_ms': device.get('latency_ms'),
                        'packet_loss': device.get('packet_loss', 0.0),
                        'client_count': details.get('client_count'),
                        'interfaces': details.get('interfaces', []),
                        'clients': connected_clients
                    })
        except Exception as e:
            print(f"[Realtime] UniFi fetch failed: {e}")
            
    if device.get('snmp_enabled'):
        try:
            stats = snmp_worker.get_detailed_stats(device)
            return jsonify({
                'status': 'success',
                'source': 'snmp',
                'sys_name': stats.get('sys_name') or device.get('sys_name') or device.get('name'),
                'description': stats.get('description') or device.get('description'),
                'uptime': stats.get('uptime') or device.get('uptime'),
                'cpu_usage': stats.get('cpu_usage') if stats.get('cpu_usage') is not None else device.get('cpu_usage'),
                'memory_usage': stats.get('memory_usage') if stats.get('memory_usage') is not None else device.get('memory_usage'),
                'temperature': stats.get('temperature') if stats.get('temperature') is not None else device.get('temperature'),
                'latency_ms': device.get('latency_ms'),
                'packet_loss': device.get('packet_loss', 0.0),
                'interfaces': stats.get('interfaces', [])
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': f"SNMP Error: {str(e)}"}), 500
            
    return jsonify({
        'status': 'success',
        'source': 'ping',
        'sys_name': device.get('name'),
        'description': device.get('description') or 'No SNMP enabled',
        'uptime': device.get('uptime'),
        'cpu_usage': device.get('cpu_usage'),
        'memory_usage': device.get('memory_usage'),
        'temperature': device.get('temperature'),
        'latency_ms': device.get('latency_ms'),
        'packet_loss': device.get('packet_loss', 0.0),
        'client_count': device.get('client_count'),
        'interfaces': [],
        'clients': []
    })

@app.route('/api/devices/<int:device_id>/latency', methods=['GET'])
def get_device_latency(device_id):
    try:
        hours = max(1, min(168, int(request.args.get('hours', 24))))
    except Exception:
        hours = 24
    points = db.get_device_latency_history(device_id, hours=hours)
    return jsonify(points)

@app.route('/api/devices/<int:device_id>/timeline', methods=['GET'])
def get_device_timeline(device_id):
    try:
        hours = max(1, min(168, int(request.args.get('hours', 24))))
    except Exception:
        hours = 24
    timeline = db.get_device_status_timeline(device_id, hours=hours)
    return jsonify(timeline)

@app.route('/api/dashboard/sparklines', methods=['GET'])
def get_dashboard_sparklines():
    return jsonify(db.get_dashboard_sparklines())

@app.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """Prometheus / OpenMetrics exporter endpoint for TIKWatch (protected: localhost, session, or METRICS_TOKEN)."""
    remote = request.remote_addr or ''
    metrics_token = os.environ.get('METRICS_TOKEN', '')
    auth_hdr = request.headers.get('Authorization', '')
    has_bearer = bool(metrics_token and hmac.compare_digest(auth_hdr, f'Bearer {metrics_token}'))
    if not session.get('user_id') and remote not in ('127.0.0.1', '::1', '::ffff:127.0.0.1') and not has_bearer:
        return jsonify({'status': 'error', 'message': 'Authentication required for /metrics'}), 401
    devices = db.get_all_devices()
    zones = {z['id']: z['name'] for z in db.get_all_zones()}
    lines = []

    def _pe(v):
        return str(v if v is not None else '').replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')
    
    # 1. Device status
    lines.append('# HELP netmon_device_up Device availability (1 = up, 0 = down)')
    lines.append('# TYPE netmon_device_up gauge')
    for d in devices:
        val = 1 if d.get('status') == 'up' else 0
        zname = zones.get(d.get('zone_id'), 'Default')
        lines.append(f'netmon_device_up{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}",type="{_pe(d.get("type","unknown"))}",zone="{_pe(zname)}"}} {val}')

    # 2. Ping Latency
    lines.append('# HELP netmon_ping_latency_ms Device round-trip ping latency in milliseconds')
    lines.append('# TYPE netmon_ping_latency_ms gauge')
    for d in devices:
        lat = d.get('latency_ms')
        if lat is not None:
            lines.append(f'netmon_ping_latency_ms{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {lat}')

    # 3. Packet Loss
    lines.append('# HELP netmon_packet_loss_percent ICMP packet loss percentage')
    lines.append('# TYPE netmon_packet_loss_percent gauge')
    for d in devices:
        loss = d.get('packet_loss')
        if loss is not None:
            lines.append(f'netmon_packet_loss_percent{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {loss}')

    # 4. CPU Usage
    lines.append('# HELP netmon_cpu_usage_percent CPU utilization percentage')
    lines.append('# TYPE netmon_cpu_usage_percent gauge')
    for d in devices:
        cpu = d.get('cpu_usage')
        if cpu is not None:
            lines.append(f'netmon_cpu_usage_percent{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {cpu}')

    # 5. Memory Usage
    lines.append('# HELP netmon_memory_usage_percent Memory utilization percentage')
    lines.append('# TYPE netmon_memory_usage_percent gauge')
    for d in devices:
        mem = d.get('memory_usage')
        if mem is not None:
            lines.append(f'netmon_memory_usage_percent{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {mem}')

    # 6. Temperature
    lines.append('# HELP netmon_temperature_celsius Device temperature in Celsius')
    lines.append('# TYPE netmon_temperature_celsius gauge')
    for d in devices:
        temp = d.get('temperature')
        if temp is not None:
            lines.append(f'netmon_temperature_celsius{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {temp}')

    # 7. Traffic WAN
    lines.append('# HELP netmon_traffic_in_bps Inbound WAN traffic in bits per second')
    lines.append('# TYPE netmon_traffic_in_bps gauge')
    lines.append('# HELP netmon_traffic_out_bps Outbound WAN traffic in bits per second')
    lines.append('# TYPE netmon_traffic_out_bps gauge')
    for d in devices:
        wan_in = d.get('wan_in')
        wan_out = d.get('wan_out')
        if wan_in is not None:
            lines.append(f'netmon_traffic_in_bps{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {wan_in}')
        if wan_out is not None:
            lines.append(f'netmon_traffic_out_bps{{id="{d["id"]}",name="{_pe(d["name"])}",ip="{_pe(d["ip"])}"}} {wan_out}')

    response_text = '\n'.join(lines) + '\n'
    from flask import Response
    return Response(response_text, mimetype='text/plain; version=0.0.4; charset=utf-8')

@app.route('/api/devices/<int:device_id>/downtime_forensics', methods=['GET'])
def get_device_downtime_forensics(device_id):
    device = db.get_device(device_id)
    if not device:
        return jsonify({'status': 'error', 'message': 'Device not found'}), 404
        
    history = db.get_downtime_analysis(device_id, limit=5)
    
    # Check if the device is ONLINE but SNMP is unreachable (tracked live in snmp_worker._snmp_failing)
    is_snmp_unreachable = False
    if device.get('status') == 'up' and device.get('snmp_enabled') == 1:
        if device.get('ip') in snmp_worker._snmp_failing:
            is_snmp_unreachable = True
                           
    if is_snmp_unreachable:
        latest = {
            'device_id': device_id,
            'down_time': datetime.now().isoformat(),
            'up_time': None,
            'duration_sec': 0,
            'ping_pattern': 'normal',
            'snmp_pattern': 'snmp_failed',
            'reboot_detected': 0,
            'justification': "SNMP Unreachable (Protokol SNMP Tidak Merespon) [Sedang Berlangsung]",
            'confidence': 90.0
        }
        history = [latest] + history
    # Check if the device is currently down to show ongoing analysis
    elif device.get('status') == 'down':
        down_time_str = device.get('last_seen')
        if not down_time_str:
            down_time_str = device.get('last_polled') or datetime.now().isoformat()
            
        try:
            down_t = datetime.fromisoformat(down_time_str)
            duration_sec = int((datetime.now() - down_t).total_seconds())
        except Exception:
            duration_sec = 0
            
        ping_pattern = 'instant_drop'
        ping_history = snmp_worker._ping_history.get(device.get('ip'), [])
        if len(ping_history) >= 3:
            live_pings = [p for p in ping_history if p[0]]
            if live_pings:
                rtts = [p[1] for p in live_pings]
                avg_rtt = sum(rtts) / len(rtts)
                spikes = [r for r in rtts if r > avg_rtt * 3.0 and r > 50]
                if len(spikes) > 0 or len(live_pings) < len(ping_history) - 2:
                    ping_pattern = 'gradual_degrade'
                    
        snmp_pattern = 'normal_metrics'
        cpu_trend = []
        ram_trend = []
        with db.conn() as c:
            rows = c.execute('''
                SELECT metric_name, metric_value FROM snmp_metrics
                WHERE device_id = ? AND timestamp <= ? AND timestamp >= datetime(?, '-10 minutes')
                ORDER BY timestamp DESC LIMIT 20
            ''', (device_id, down_time_str, down_time_str)).fetchall()
            for r in rows:
                val = r['metric_value']
                try:
                    val_f = float(val)
                    if r['metric_name'] == 'cpu_usage':
                        cpu_trend.append(val_f)
                    elif r['metric_name'] == 'memory_usage':
                        ram_trend.append(val_f)
                except Exception:
                    pass
                    
        if cpu_trend and max(cpu_trend) > 85.0:
            snmp_pattern = 'resource_overload'
        elif ram_trend and max(ram_trend) > 90.0:
            snmp_pattern = 'resource_overload'
            
        if snmp_pattern == 'resource_overload':
            justification = "Potensi OS Crash / Overload Resource"
            confidence = 80.0
        elif ping_pattern == 'gradual_degrade':
            justification = "Potensi Congestion / Network Loop"
            confidence = 85.0
        else:
            justification = "Perangkat Offline (Mati Lampu atau Kabel Terputus)"
            confidence = 75.0
            
        latest = {
            'device_id': device_id,
            'down_time': down_time_str,
            'up_time': None,
            'duration_sec': duration_sec,
            'ping_pattern': ping_pattern,
            'snmp_pattern': snmp_pattern,
            'reboot_detected': 0,
            'justification': justification + " [Sedang Berlangsung]",
            'confidence': confidence
        }
        history = [latest] + history
    elif history:
        latest = history[0]
    else:
        latest = None
        
    if not latest:
        return jsonify({'status': 'success', 'history': [], 'analysis': None})
        
    settings = db.get_settings()
    api_key = settings.get('groq_api_key', '')
    
    root_cause = latest['justification']
    if is_snmp_unreachable:
        narration = (
            f"Konektivitas fisik ke perangkat {device.get('name')} ({device.get('ip')}) dalam kondisi normal via Ping, "
            f"namun query SNMP mengalami timeout (UDP port 161). Pastikan:\n"
            f"1. Community String di TIKWatch ('{device.get('snmp_community', 'public')}') cocok dengan konfigurasi SNMP di MikroTik.\n"
            f"2. IP TIKWatch telah diizinkan (Allowed Address) di setting SNMP MikroTik.\n"
            f"3. Service SNMP di MikroTik sudah diaktifkan (/ip snmp set enabled=yes)."
        )
    elif latest['up_time'] is None:
        reboot_text = "Status reboot belum dapat divalidasi karena perangkat masih offline."
        ping_text = "Koneksi terputus secara tiba-tiba tanpa penurunan kualitas latency sebelumnya." if latest['ping_pattern'] == 'instant_drop' else "Terjadi penurunan kualitas latensi secara bertahap sebelum koneksi terputus."
        snmp_text = "Metrik sumber daya (CPU/RAM) terpantau normal sebelum kejadian." if latest['snmp_pattern'] != 'resource_overload' else "Terjadi lonjakan pemakaian CPU/RAM sebelum koneksi terputus."
        narration = f"Perangkat saat ini sedang OFFLINE. Analisis sementara menunjukkan kemungkinan {latest['justification']}. {ping_text} {snmp_text} {reboot_text}"
    else:
        reboot_text = "perangkat terdeteksi melakukan booting ulang setelah menyala kembali." if latest['reboot_detected'] else "perangkat tidak restart, melainkan hanya kehilangan konektivitas jaringan."
        ping_text = "Koneksi terputus secara tiba-tiba tanpa penurunan kualitas latency sebelumnya." if latest['ping_pattern'] == 'instant_drop' else "Terjadi penurunan kualitas latensi secara bertahap hingga RTO sebelum koneksi terputus sepenuhnya."
        snmp_text = "Metrik sumber daya (CPU/RAM) terpantau normal sebelum kejadian." if latest['snmp_pattern'] != 'resource_overload' else "Terjadi lonjakan pemakaian CPU/RAM sebelum koneksi terputus."
        narration = f"Berdasarkan analisis BlackBox, {latest['justification']}. {ping_text} {snmp_text} Serta {reboot_text}"
        
    if api_key:
        try:
            if is_snmp_unreachable:
                prompt = (
                    f"Analisa penyebab kegagalan SNMP (SNMP Unreachable) berikut dan berikan rekomendasi perintah RouterOS/MikroTik untuk memperbaikinya dalam bahasa Indonesia (maksimal 3 kalimat).\n\n"
                    f"Detail Perangkat:\n"
                    f"- Nama: {device.get('name')}\n"
                    f"- Tipe: {device.get('type')}\n"
                    f"- IP: {device.get('ip')}\n"
                    f"- SNMP Community di TIKWatch: {device.get('snmp_community', 'public')}\n"
                    f"Kondisi Saat Ini:\n"
                    f"- Koneksi Fisik: ONLINE / PING OK\n"
                    f"- Query SNMP: TIMEOUT / PORT UDP 161 TIDAK MERESPON\n\n"
                    f"Tentukan root cause dan berikan rekomendasi perintah/langkah perbaikan RouterOS. Kembalikan respon JSON dalam format persis seperti ini: "
                    f'{{"root_cause": "analisis singkat penyebab", "narration": "perintah RouterOS dan rekomendasi perbaikan maks 3 kalimat dalam bahasa Indonesia"}}'
                )
            else:
                prompt_status = "Sedang Berlangsung / Offline" if latest['up_time'] is None else "Sudah Kembali Online"
                prompt = (
                    f"Analisa penyebab downtime (perangkat mati/offline) berikut dan berikan narasi/justifikasi dalam bahasa Indonesia (maksimal 3 kalimat).\n\n"
                    f"Detail Perangkat:\n"
                    f"- Nama: {device.get('name')}\n"
                    f"- Tipe: {device.get('type')}\n"
                    f"- Vendor: {device.get('vendor')}\n"
                    f"Detail Kejadian:\n"
                    f"- Status Kejadian: {prompt_status}\n"
                    f"- Waktu Down: {latest['down_time']}\n"
                    f"- Waktu Up: {latest['up_time'] or 'Masih offline'}\n"
                    f"- Durasi Down: {latest['duration_sec']} detik\n"
                    f"- Pola Latensi Ping: {latest['ping_pattern']}\n"
                    f"- Pola Metrik SNMP: {latest['snmp_pattern']}\n"
                    f"- Reboot Terdeteksi: {'Ya' if latest['reboot_detected'] else 'Tidak' if latest['up_time'] else 'Belum dapat dipastikan'}\n"
                    f"- Kesimpulan Heuristik Sistem: {latest['justification']} (Akurasi: {latest['confidence']}%)\n\n"
                    f"Tentukan root cause dan berikan narasi penjelasan detail maks 3 kalimat dalam bahasa Indonesia. Kembalikan respon JSON dalam format persis seperti ini: "
                    f'{{"root_cause": "analisis singkat penyebab", "narration": "narasi penjelasan detail maks 3 kalimat dalam bahasa Indonesia"}}'
                )
            
            import urllib.request
            import json
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            payload = {
                "model": (settings.get('groq_model') or "llama-3.3-70b-versatile").strip(),
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a network analysis assistant. Respond ONLY with a raw JSON object containing \"root_cause\" (string) and \"narration\" (string in Indonesian, max 3 sentences)."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.2
            }
            
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
            with urllib.request.urlopen(req, timeout=8) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                text_resp = res_data['choices'][0]['message']['content'].strip()
                ai_res = json.loads(text_resp)
                
                root_cause = ai_res.get('root_cause', root_cause)
                narration = ai_res.get('narration', narration)
        except Exception as e:
            print(f"[BlackBox AI API] AI call failed, fallback to local narration: {e}")
            
    return jsonify({
        'status': 'success',
        'history': history,
        'analysis': {
            'justification': latest['justification'],
            'confidence': latest['confidence'],
            'root_cause': root_cause,
            'narration': narration
        }
    })

# ============================================================
# API – ZONES
# ============================================================

@app.route('/api/zones', methods=['GET'])
def get_zones():
    return jsonify(db.get_all_zones())

@app.route('/api/zones/devices', methods=['GET'])
def get_zones_with_devices():
    """Zones beserta device-nya, untuk halaman /zones."""
    return jsonify(db.get_zones_with_devices())

@app.route('/api/zones', methods=['POST'])
def add_zone():
    import traceback
    try:
        data = request.json or {}
        zone_id = db.add_zone(data)
        return jsonify({'id': zone_id, 'status': 'success'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/zones/<int:zone_id>', methods=['PUT', 'POST'])
def update_zone(zone_id):
    import traceback
    try:
        data = request.json or {}
        db.update_zone(zone_id, data)
        return jsonify({'status': 'success'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/zones/<int:zone_id>/delete', methods=['POST'])
@app.route('/api/zones/<int:zone_id>', methods=['DELETE'])
def delete_zone(zone_id):
    import traceback
    try:
        db.delete_zone(zone_id)
        return jsonify({'status': 'success'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================
# API – ALERTS & LOGS
# ============================================================

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    severity = request.args.get('severity')
    return jsonify(db.get_alerts(limit=limit, offset=offset, severity=severity))

@app.route('/api/alerts/<int:alert_id>/ack', methods=['POST'])
def ack_alert(alert_id):
    user = request.json.get('user', 'admin') if request.json else 'admin'
    db.acknowledge_alert(alert_id, user)
    socketio.emit('alert_acked', {'id': alert_id})
    return jsonify({'status': 'success'})

@app.route('/api/alerts/ack_all', methods=['POST'])
def ack_all_alerts():
    db.acknowledge_all_alerts()
    socketio.emit('all_alerts_acked', {})
    return jsonify({'status': 'success'})

@app.route('/api/access_logs', methods=['GET'])
def get_access_logs():
    limit = int(request.args.get('limit', 100))
    return jsonify(db.get_access_logs(limit=limit))

# ============================================================
# API – FLOOR PLAN
# ============================================================

@app.route('/api/floorplan', methods=['GET'])
def get_floorplan():
    return jsonify(db.get_floorplan())

@app.route('/api/floorplan', methods=['POST'])
def save_floorplan():
    db.save_floorplan(request.json)
    return jsonify({'status': 'success'})

@app.route('/api/floorplan/upload', methods=['POST'])
def upload_floorplan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('png', 'jpg', 'jpeg', 'gif', 'svg'):
        return jsonify({'error': 'Invalid file type'}), 400
    target_dir = os.path.join(app.root_path, 'static', 'img')
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, f'floorplan.{ext}')
    f.save(path)
    return jsonify({'status': 'success', 'url': f'/static/img/floorplan.{ext}'})

# ============================================================
# API – NETWORK SCAN
# ============================================================

@app.route('/api/scan', methods=['POST'])
def scan_network():
    data = request.json or {}
    network = data.get('network', '192.168.1.0/24')
    community = data.get('community', 'public') or 'public'
    version = data.get('version', '2c') or '2c'
    zone_id = int(data.get('zone_id', 1))
    method = data.get('method', 'snmp')
    
    ping_timeout = data.get('ping_timeout', 1.5)
    snmp_timeout = data.get('snmp_timeout', data.get('timeout', 2.0))
    retries = data.get('retries', 1)
    max_workers = data.get('max_workers', data.get('workers', None))
    
    # Cast variables if present
    if ping_timeout is not None: ping_timeout = float(ping_timeout)
    if snmp_timeout is not None: snmp_timeout = float(snmp_timeout)
    if retries is not None: retries = int(retries)
    if max_workers is not None: max_workers = int(max_workers)
    
    if snmp_worker.get_scan_status()['running']:
        return jsonify({'status': 'already_running'}), 409
        
    t = threading.Thread(
        target=snmp_worker.scan_network,
        args=(network, community, version, zone_id, method),
        kwargs={
            'ping_timeout': ping_timeout,
            'snmp_timeout': snmp_timeout,
            'retries': retries,
            'max_workers': max_workers
        },
        daemon=True
    )
    snmp_worker._scan_future = t
    t.start()
    db.add_access_log({'source': request.remote_addr, 'message': f'Network scan started: {network}', 'type': 'scan'})
    return jsonify({'status': 'started', 'network': network})

@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    return jsonify(snmp_worker.get_scan_status())

@app.route('/api/scan/stop', methods=['POST'])
def scan_stop():
    snmp_worker.stop_scan()
    return jsonify({'status': 'stopped'})

# ============================================================
# API – UNIFI
# ============================================================

@app.route('/api/unifi/sync', methods=['POST'])
def sync_unifi():
    data = request.json or {}
    try:
        settings = db.get_settings()
        host = data.get('host') or settings.get('unifi_host', '')
        username = data.get('username') or settings.get('unifi_user', '')
        password = data.get('password') or settings.get('unifi_pass', '')
        port = int(data.get('port') or settings.get('unifi_port', 8443))
        site = data.get('site') or settings.get('unifi_site', 'default')

        if not host or not username or not password:
            return jsonify({'status': 'error', 'message': 'UniFi credentials not configured'}), 400

        unifi = UniFiClient(host=host, username=username, password=password, port=port, site=site)
        
        # Get SNMP settings from UniFi controller
        snmp_info = unifi.get_snmp_settings() or {}
        snmp_enabled_for_new = snmp_info.get('enabled', False)
        snmp_community = snmp_info.get('community', settings.get('default_community', 'public'))
        snmp_version = settings.get('default_snmp_version', '2c')
        
        devices = unifi.get_devices()
        clients = unifi.get_clients()
        zone_id = int(data.get('zone_id', 1))
        
        added = 0
        for d in devices:
            if db.add_or_update_unifi_device(
                d, 
                zone_id=zone_id,
                snmp_community=snmp_community,
                snmp_version=snmp_version,
                snmp_port=161,
                snmp_enabled_for_new=snmp_enabled_for_new
            ):
                added += 1

        db.add_access_log({
            'source': request.remote_addr,
            'message': f'UniFi sync: {len(devices)} devices, {len(clients)} clients synced',
            'type': 'sync'
        })
        socketio.emit('unifi_sync_complete', {'devices': len(devices), 'clients': len(clients), 'added': added})
        return jsonify({'status': 'success', 'devices': len(devices), 'clients': len(clients), 'added': added})
    except RuntimeError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Unexpected error: {str(e)}"}), 500

# ============================================================
# API – SETTINGS & STATS
# ============================================================

@app.route('/api/settings', methods=['GET'])
def get_settings():
    s = db.get_settings()
    # Never expose internal cryptographic secrets or plaintext tokens
    s.pop('app_secret_key', None)
    s.pop('internal_emit_token', None)
    if 'unifi_pass' in s:
        s['unifi_pass'] = '***' if s['unifi_pass'] else ''
    if 'groq_api_key' in s:
        s['groq_api_key'] = '***' if s['groq_api_key'] else ''
    if 'telegram_bot_token' in s:
        s['telegram_bot_token'] = '***' if s['telegram_bot_token'] else ''
    return jsonify(s)

@app.route('/api/settings', methods=['POST'])
def save_settings():
    raw_data = request.json or {}
    if not isinstance(raw_data, dict):
        return jsonify({'status': 'error', 'message': 'Invalid settings payload'}), 400
    # Strict whitelist prevents mass-assignment of internal/secret keys
    data = {k: v for k, v in raw_data.items() if k in ALLOWED_SETTING_KEYS}
    if data.get('unifi_pass') == '***':
        data.pop('unifi_pass')
    if data.get('groq_api_key') == '***':
        data.pop('groq_api_key')
    if data.get('telegram_bot_token') == '***':
        data.pop('telegram_bot_token')
    if 'allowed_cidrs' in data:
        raw_cidrs = str(data.get('allowed_cidrs') or '').strip()
        if not raw_cidrs:
            raw_cidrs = '10.122.100.0/24'
        cleaned = []
        for part in raw_cidrs.split(','):
            tok = part.strip()
            if not tok:
                continue
            try:
                net = ipaddress.ip_network(tok, strict=False)
                cleaned.append(str(net))
            except ValueError:
                return jsonify({'status': 'error', 'message': f'Format CIDR tidak valid: {tok}'}), 400
        if not cleaned:
            cleaned = ['10.122.100.0/24']
        normalized_cidrs = ', '.join(cleaned)
        if not _is_client_ip_allowed(request.remote_addr, cidr_str=normalized_cidrs):
            return jsonify({
                'status': 'error',
                'message': f'Ditolak untuk mencegah lock-out: IP Anda ({request.remote_addr}) harus masuk di dalam daftar CIDR baru.'
            }), 400
        data['allowed_cidrs'] = normalized_cidrs
    db.save_settings(data)
    if 'poll_interval' in data:
        try:
            scheduler.reschedule_job('snmp_poll', trigger='interval', seconds=max(10, int(data['poll_interval'])))
        except Exception:
            pass
    if 'traffic_poll_interval' in data:
        try:
            scheduler.reschedule_job('traffic_poll', trigger='interval', seconds=max(5, int(data['traffic_poll_interval'])))
        except Exception:
            pass
    if 'telegram_daily_digest_time' in data:
        try:
            d_time = (data.get('telegram_daily_digest_time') or '08:00').strip()
            dh, dm = [int(x) for x in d_time.split(':')]
            scheduler.reschedule_job('telegram_daily_digest', trigger='cron', hour=dh, minute=dm)
        except Exception:
            pass

    # Reload Telegram bot configuration
    try:
        telegram_bot.reload_config()
    except Exception as te:
        print(f"[Telegram] Reload config failed: {te}")

    return jsonify({'status': 'success'})

@app.route('/api/telegram/test', methods=['POST'])
def test_telegram():
    data = request.json or {}
    token = data.get('telegram_bot_token')
    chat_ids = data.get('telegram_chat_ids')
    
    if not token or token == '***':
        settings = db.get_settings()
        token = settings.get('telegram_bot_token', '')

    if not token:
        return jsonify({'status': 'error', 'message': 'Bot Token belum diisi'}), 400

    result = telegram_bot.test_connection(token=token, chat_ids=chat_ids)
    if result.get('status') == 'error':
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/telegram/status', methods=['GET'])
def get_telegram_status():
    live = db.get_poller_state('telegram_status')
    if isinstance(live, dict) and live:
        return jsonify({
            'enabled': live.get('enabled', False),
            'running': live.get('running', False),
            'bot_username': live.get('bot_username'),
            'bot_name': live.get('bot_name'),
            'chat_count': live.get('chat_count', 0),
        })
    return jsonify({
        'enabled': telegram_bot.enabled,
        'running': telegram_bot.is_running,
        'bot_username': telegram_bot.bot_info.get('username'),
        'bot_name': telegram_bot.bot_info.get('first_name'),
        'chat_count': len(telegram_bot.chat_ids),
    })

@app.route('/api/maintenance', methods=['GET', 'POST'])
def api_maintenance():
    """Zabbix-style Maintenance Window API (get status or mute/unmute alerts)."""
    if request.method == 'GET':
        g_active, g_until = db.is_device_in_maintenance(None)
        with db.conn() as c:
            rows = c.execute(
                "SELECT id, name, ip, maintenance_until FROM devices WHERE maintenance_until IS NOT NULL AND maintenance_until > datetime('now', 'localtime')"
            ).fetchall()
        return jsonify({
            'global_active': g_active,
            'global_until': g_until,
            'devices': [dict(r) for r in rows]
        })
    data = request.json or {}
    target = data.get('target', 'all')
    try:
        minutes = int(data.get('minutes', 0))
    except (ValueError, TypeError):
        minutes = 0
    until_str = db.set_maintenance_window(target, minutes)
    return jsonify({'status': 'success', 'target': target, 'maintenance_until': until_str})

@app.route('/api/settings/cleanup-anomalies', methods=['POST'])
def cleanup_traffic_anomalies():
    """Bersihkan (nolkan) traffic historis di atas cap anomali saat ini.
    DESTRUKTIF & TIDAK BISA DIBATALKAN -- sengaja harus dipicu manual dari UI,
    bukan berjalan otomatis, supaya user sadar & bisa cek dulu nilai cap-nya
    sebelum data lama berpotensi terhapus."""
    result = db.cleanup_traffic_anomalies()
    if result.get('error'):
        return jsonify({'status': 'error', 'message': result['error']}), 500
    return jsonify({'status': 'success', 'result': result})

@app.route('/api/ai/test', methods=['POST'])
def test_groq():
    import urllib.request
    data = request.json or {}
    settings = db.get_settings()
    api_key = data.get('groq_api_key')
    if not api_key or api_key == '***':
        api_key = settings.get('groq_api_key', '')
    model_name = (data.get('groq_model') or settings.get('groq_model') or 'llama-3.3-70b-versatile').strip()
        
    if not api_key:
        return jsonify({'status': 'error', 'message': 'API Key is empty'}), 400
        
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        payload = {
            "model": model_name,
            "messages": [
                {"role": "user", "content": "Say 'OK' and nothing else."}
            ],
            "temperature": 0.2
        }
        import urllib.error
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            text = res_data['choices'][0]['message']['content'].strip()
            return jsonify({'status': 'success', 'message': f"Connected ({model_name})! Response: {text}"})
    except urllib.error.HTTPError as he:
        try:
            err_body = he.read().decode('utf-8')
            err_json = json.loads(err_body)
            msg = err_json.get('error', {}).get('message', he.reason)
        except Exception:
            msg = str(he)
        return jsonify({'status': 'error', 'message': f"Groq API Error: {msg}"}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"API connection failed: {str(e)}"}), 400

@app.route('/reports')
def reports_page():
    return render_template('reports.html')

@app.route('/api/reports/monthly', methods=['GET'])
def get_monthly_reports():
    reports = db.get_monthly_reports()
    import json
    parsed_reports = []
    for r in reports:
        try:
            r_data = json.loads(r['report_data'])
        except:
            r_data = {}
        parsed_reports.append({
            'id': r['id'],
            'report_month': r['report_month'],
            'generated_at': r['generated_at'],
            'data': r_data
        })
    return jsonify(parsed_reports)

@app.route('/api/reports/generate', methods=['POST'])
def generate_monthly_report():
    data = request.json or {}
    month_str = data.get('month')
    if not month_str:
        from datetime import datetime
        month_str = datetime.now().strftime('%Y-%m')
    try:
        report = db.generate_and_save_monthly_report(month_str)
        return jsonify({'status': 'success', 'report': report})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/reports/<int:report_id>/delete', methods=['POST'])
@app.route('/api/reports/<int:report_id>', methods=['DELETE'])
def delete_monthly_report(report_id):
    try:
        db.delete_monthly_report(report_id)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(db.get_dashboard_stats())

@app.route('/api/metrics/traffic', methods=['GET'])
def get_network_traffic_history():
    try:
        hours = max(0.25, min(168, float(request.args.get('hours', 1.0))))
    except:
        hours = 1.0

    points = db.get_backbone_traffic_history(hours)
    return jsonify(points)

# ============================================================
# WEBSOCKET EVENTS
# ============================================================

@socketio.on('connect')
def handle_connect():
    if not _is_client_ip_allowed(request.remote_addr):
        return False
    if not session.get('user_id'):
        return False
    emit('init_data', {
        'devices': [_sanitize_device(d) for d in db.get_all_devices()],
        'zones': db.get_all_zones(),
        'stats': db.get_dashboard_stats(),
        'alerts': db.get_alerts(limit=25),
        'floorplan': db.get_floorplan()
    })

# ============================================================
# BACKGROUND POLLING
# ============================================================

def poll_device_status():
    # 1. Sync UniFi telemetries if configured
    try:
        settings = db.get_settings()
        host = settings.get('unifi_host', '')
        username = settings.get('unifi_user', '')
        password = settings.get('unifi_pass', '')
        port = int(settings.get('unifi_port', 8443) or 8443)
        site = settings.get('unifi_site', 'default') or 'default'
        
        if host and username and password:
            from unifi_client import UniFiClient
            unifi = UniFiClient(host=host, username=username, password=password, port=port, site=site)
            
            # Get SNMP settings from UniFi controller
            snmp_info = unifi.get_snmp_settings() or {}
            snmp_enabled_for_new = snmp_info.get('enabled', False)
            snmp_community = snmp_info.get('community', settings.get('default_community', 'public'))
            snmp_version = settings.get('default_snmp_version', '2c')
            
            unifi_devs = unifi.get_devices()
            for ud in unifi_devs:
                db.add_or_update_unifi_device(
                    ud,
                    snmp_community=snmp_community,
                    snmp_version=snmp_version,
                    snmp_port=161,
                    snmp_enabled_for_new=snmp_enabled_for_new
                )
    except Exception as e:
        print(f"[Poll] UniFi auto-poll failed: {e}")

    # 2. Poll SNMP/Ping devices in parallel
    devices = db.get_all_devices()
    from concurrent.futures import ThreadPoolExecutor
    import platform
    is_win = platform.system().lower() == 'windows'
    is_wsl = False
    if not is_win and os.path.exists('/proc/version'):
        try:
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    is_wsl = True
        except:
            pass
    is_restricted = is_win or is_wsl
    
    # Limit parallel workers on Windows/WSL to prevent socket/process collisions
    max_poll_workers = 3 if is_restricted else min(10, len(devices) or 1)
    with ThreadPoolExecutor(max_workers=max_poll_workers) as executor:
        futures = [executor.submit(snmp_worker.poll_device, device) for device in devices]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"[Poll] Parallel device poll failed: {e}")

def poll_traffic():
    devices = db.get_all_devices()
    import platform
    is_win = platform.system().lower() == 'windows'
    is_wsl = False
    if not is_win and os.path.exists('/proc/version'):
        try:
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    is_wsl = True
        except:
            pass
    is_restricted = is_win or is_wsl

    # Kumpulkan traffic per-interface untuk semua device SNMP-enabled in parallel
    snmp_devices = [d for d in devices if d.get('snmp_enabled')]
    if snmp_devices:
        from concurrent.futures import ThreadPoolExecutor
        max_traffic_workers = 2 if is_restricted else min(10, len(snmp_devices))
        with ThreadPoolExecutor(max_workers=max_traffic_workers) as executor:
            futures = [executor.submit(snmp_worker.collect_interface_traffic, device) for device in snmp_devices]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    print(f"[Traffic] Parallel traffic collection failed: {e}")

def run_hourly_cleanup():
    try:
        settings = db.get_settings()
        db.cleanup_interface_traffic(
            interface_retention_hours=int(settings.get('interface_chart_retention_hours', 168)),
            metrics_retention_hours=int(settings.get('report_metrics_retention_hours', 1440))
        )
        db.cleanup_old_records(
            alert_days=int(settings.get('alert_retention_days', 30)),
            log_days=int(settings.get('log_retention_days', 90))
        )
    except Exception as e:
        print(f"[Cleanup] {e}")

# ============================================================
# MAIN
# ============================================================

def run_monthly_report_cron():
    print("[Report Cron] Running monthly report generation...")
    try:
        from datetime import datetime
        month_str = datetime.now().strftime('%Y-%m')
        db.generate_and_save_monthly_report(month_str)
        print(f"[Report Cron] Monthly report for {month_str} generated successfully!")
    except Exception as e:
        print(f"[Report Cron] Failed to generate monthly report: {e}")

def run_weekly_vacuum():
    print("[Vacuum Cron] Running weekly VACUUM...")
    try:
        with db.conn() as c:
            c.execute("VACUUM")
        print("[Vacuum Cron] VACUUM completed successfully!")
    except Exception as e:
        print(f"[Vacuum Cron] Failed: {e}")

def run_telegram_daily_digest():
    print("[Telegram Digest Cron] Running daily digest...")
    try:
        s = db.get_settings()
        if s.get('telegram_enabled', 'false') == 'true' and s.get('telegram_daily_digest_enabled', 'true') == 'true':
            telegram_bot.send_daily_digest()
            print("[Telegram Digest Cron] Daily digest sent successfully!")
    except Exception as e:
        print(f"[Telegram Digest Cron] Failed: {e}")

if __name__ == '__main__':
    settings = db.get_settings()
    poll_interval = max(10, int(settings.get('poll_interval', 30)))
    traffic_poll_interval = max(5, int(settings.get('traffic_poll_interval', 15)))
    scheduler.add_job(poll_device_status, 'interval', seconds=poll_interval, id='snmp_poll', max_instances=1)
    scheduler.add_job(poll_traffic, 'interval', seconds=traffic_poll_interval, id='traffic_poll', max_instances=1)
    scheduler.add_job(run_hourly_cleanup, 'interval', minutes=60, id='hourly_cleanup', max_instances=1)
    # Automatically generate monthly report at 23:50 on the last day of the month before oldest data prunes
    scheduler.add_job(run_monthly_report_cron, 'cron', day='last', hour=23, minute=50, id='monthly_report_cron')
    scheduler.add_job(run_weekly_vacuum, 'cron', day_of_week='sun', hour=3, minute=0, id='weekly_vacuum')
    
    # Telegram daily digest schedule
    digest_time = (settings.get('telegram_daily_digest_time') or '08:00').strip()
    try:
        d_hour, d_min = [int(x) for x in digest_time.split(':')]
    except Exception:
        d_hour, d_min = 8, 0
    scheduler.add_job(run_telegram_daily_digest, 'cron', hour=d_hour, minute=d_min, id='telegram_daily_digest')

    scheduler.start()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    print(f"\n{'='*50}")
    print(f"  TIKWatch starting → http://{host}:{port}")
    print(f"  SNMP poll status every {poll_interval}s")
    print(f"  SNMP poll traffic every {traffic_poll_interval}s")
    print(f"{'='*50}\n")
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
