import json
import re
import urllib.request
import threading
import subprocess
import platform
import os
from datetime import datetime

def _ping_device(ip):
    if not ip:
        return False
    is_win = platform.system().lower() == 'windows'
    param = '-n' if is_win else '-c'
    timeout_param = '-w' if is_win else '-W'
    timeout_val = '1500' if is_win else '2'
    cmd = ['ping', param, '1', timeout_param, timeout_val, ip]
    try:
        startupinfo = None
        if is_win:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        res = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            startupinfo=startupinfo, 
            timeout=3.0
        )
        return res.returncode == 0
    except Exception:
        return False

def _snmp_ping(ip, community='public', version='2c'):
    if not ip:
        return False
    try:
        from puresnmp import Client, PyWrapper, V2C, V1
        creds = V1(community) if version == '1' else V2C(community)
        c = PyWrapper(Client(ip, creds, port=161))
        try:
            c.configure(timeout=1.5, retries=0)
        except Exception:
            pass
        val = c.get('1.3.6.1.2.1.1.2.0')
        return val is not None
    except Exception:
        return False

def evaluate_heuristics(db, alert, device, alert_id):
    """Fast synchronous heuristic evaluation (< 10ms) to prevent alert flapping and false alarms."""
    is_false = 0
    explanation = "Valid Alert"
    new_replica_count = 0
    replicated = False

    # Check for previous alert of the same device to replicate analysis
    previous_alert = None
    with db.conn() as c:
        row = c.execute(
            'SELECT * FROM alerts WHERE device_id = ? AND id < ? ORDER BY id DESC LIMIT 1', 
            (device['id'], alert_id)
        ).fetchone()
        if row:
            previous_alert = dict(row)

    if previous_alert and previous_alert.get('message') == alert.get('message'):
        prev_replica = previous_alert.get('replica_count', 0) or 0
        if prev_replica < 5:
            # Replicate previous analysis without calling AI API
            is_false = previous_alert.get('is_false_alarm', 0)
            explanation = previous_alert.get('ai_analysis', 'Valid Alert')
            new_replica_count = prev_replica + 1
            replicated = True
            print(f"[AI Cache] Replicated previous analysis for alert {alert_id} (replica_count: {new_replica_count})")

    if not replicated:
        # Proactive Live Ping Verification
        currently_pingable = _ping_device(device.get('ip'))

        # Check for concurrent alerts in the last 15 seconds
        concurrent_alerts = 0
        with db.conn() as c:
            row = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-15 seconds') AND id != ?", 
                (alert_id,)
            ).fetchone()
            if row:
                concurrent_alerts = row[0]

        # Check alert flapping history for this device in the last 15 minutes
        alert_history_count = 0
        with db.conn() as c:
            row = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE device_id = ? AND created_at >= datetime('now', '-15 minutes') AND id != ?", 
                (device['id'], alert_id)
            ).fetchone()
            if row:
                alert_history_count = row[0]

        # Check environment: only suspect WSL congestion if running inside WSL
        is_wsl = False
        try:
            if os.path.exists('/proc/version'):
                with open('/proc/version', 'r') as f:
                    if 'microsoft' in f.read().lower():
                        is_wsl = True
        except Exception:
            pass

        # Run advanced local heuristic rules
        alert_msg_lower = alert['message'].lower()
        is_offline_alert = "offline" in alert_msg_lower or "unreachable" in alert_msg_lower or "down" in alert_msg_lower
        is_anomaly_alert = "anomali" in alert_msg_lower or "lonjakan" in alert_msg_lower or "spike" in alert_msg_lower

        if is_anomaly_alert:
            is_false = 0
            if "ddos" in alert_msg_lower or "flood" in alert_msg_lower or "kritis" in alert_msg_lower:
                explanation = "Valid Anomaly: Terdeteksi korelasi lonjakan traffic dan beban CPU tinggi secara simultan. Waspadai serangan DDoS, packet storm, atau loop routing."
            elif "traffic" in alert_msg_lower:
                explanation = "Valid Anomaly: Lonjakan throughput signifikan melebihi ambang batas baseline normal."
            elif "cpu" in alert_msg_lower or "ram" in alert_msg_lower or "resource" in alert_msg_lower:
                explanation = "Valid Anomaly: Kenaikan konsumsi resource komputasi (CPU/RAM) perangkat mendadak."

        elif is_offline_alert:
            # Rule A: Device is responsive via ping right now
            if currently_pingable:
                is_false = 1
                if "snmp" in alert_msg_lower:
                    # Proactively verify if SNMP works now
                    snmp_works = _snmp_ping(device.get('ip'), device.get('snmp_community', 'public'), device.get('snmp_version', '2c'))
                    if snmp_works:
                        explanation = "False Warning: Query SNMP berhasil pulih saat dites ulang. Koneksi perangkat ke SNMP server stabil."
                    else:
                        explanation = "False Warning: Perangkat aktif via Ping, query SNMP mengalami timeout (kemungkinan beban CPU atau delay sementara)."
                else:
                    explanation = "False Warning: Perangkat merespon Ping saat dites ulang. Gangguan sebelumnya bersifat sementara (transient packet loss)."
            
            # Rule B: High concurrent failures ONLY when on WSL
            elif not currently_pingable and concurrent_alerts >= 2 and is_wsl:
                is_false = 1
                explanation = f"False Warning: Potensi kendala WSL network congestion ({concurrent_alerts} perangkat drop serentak). Perangkat mungkin tidak benar-benar mati."

            # Rule C: Flapping detection
            elif alert_history_count >= 2:
                is_false = 1
                explanation = f"False Warning: Terdeteksi Flapping ({alert_history_count} kali alert dalam 15 menit). Konektivitas tidak stabil/jitter."

    return is_false, explanation, replicated, new_replica_count

def _refine_with_groq(db, socketio, alert, device, alert_id, initial_is_false, initial_explanation, api_key):
    """Background AI enhancement using official Groq llama-3.3-70b-versatile model."""
    try:
        other_devs = []
        with db.conn() as c:
            rows = c.execute('SELECT name, status, type FROM devices WHERE zone_id = ? AND id != ?', 
                             (device['zone_id'], device['id'])).fetchall()
            other_devs = [dict(r) for r in rows]

        alert_msg_lower = alert['message'].lower()
        is_anomaly_alert = "anomali" in alert_msg_lower or "lonjakan" in alert_msg_lower or "spike" in alert_msg_lower

        if is_anomaly_alert:
            prompt = (
                f"Analisa anomali performa jaringan dan lonjakan resource berikut:\n"
                f"Perangkat: {device.get('name')} ({device.get('ip')}) | Tipe: {device.get('type')}\n"
                f"Pesan Alert: {alert['message']}\n\n"
                f"Berikan analisa teknis apakah ini pola serangan DDoS/Flood, looping paket, transfer data wajar/backup, atau lonjakan sesaat. "
                f"Kembalikan respon JSON: "
                f'{{"is_false_alarm": 0 atau 1, "explanation": "Diagnosa teknis: apakah ini anomali berbahaya/valid (0) atau aktivitas normal/false alarm (1). Maks 2 kalimat."}}'
            )
        else:
            prompt = (
                f"Analisa apakah alert jaringan berikut merupakan peringatan palsu (false warning/alarm).\n"
                f"Detail Perangkat:\n"
                f"- Nama: {device.get('name')}\n"
                f"- Tipe: {device.get('type')}\n"
                f"- IP: {device.get('ip')}\n"
                f"- SNMP Aktif: {'Ya' if device.get('snmp_enabled') else 'Tidak'}\n"
                f"- Status Terakhir: {device.get('status')}\n"
                f"- Uptime: {device.get('uptime')}\n"
                f"Detail Alert:\n"
                f"- Pesan: {alert['message']}\n"
                f"Analisa Heuristik Awal: {initial_explanation}\n"
                f"Konteks Sekitar (Zona yang Sama):\n"
                f"{json.dumps(other_devs, indent=2)}\n\n"
                f"Tentukan apakah alert ini adalah False Warning. Kembalikan respon JSON dalam format persis seperti ini: "
                f'{{"is_false_alarm": 0 atau 1, "explanation": "Penjelasan singkat maks 2 kalimat dalam bahasa Indonesia"}}'
            )
        
        url = "https://api.groq.com/openai/v1/chat/completions"
        settings = db.get_settings()
        model_name = (settings.get('groq_model') or 'llama-3.3-70b-versatile').strip()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        payload = {
            "model": model_name,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You are a network analysis assistant. Respond ONLY with a raw JSON object containing \"is_false_alarm\" (0 or 1) and \"explanation\" (string in Indonesian, max 2 sentences)."
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
            
            final_is_false = int(ai_res.get('is_false_alarm', initial_is_false))
            final_explanation = ai_res.get('explanation', initial_explanation)

            # Update DB with refined AI insight
            with db.conn() as c:
                c.execute('UPDATE alerts SET is_false_alarm = ?, ai_analysis = ? WHERE id = ?',
                          (final_is_false, final_explanation, alert_id))

            # Broadcast update via Socket.IO
            if socketio:
                socketio.emit('alert_update', {
                    'id': alert_id,
                    'is_false_alarm': final_is_false,
                    'ai_analysis': final_explanation
                })

    except Exception as e:
        print(f"[AI Detector] Groq API refinement failed: {e}")

def analyze_alert(db, socketio, alert_id):
    """Evaluates heuristics synchronously so DB has valid status immediately (eliminating race condition),
    then delegates Groq AI prompt to background thread if API key is configured."""
    try:
        with db.conn() as c:
            alert = c.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
            if not alert:
                return
            alert = dict(alert)
            device = c.execute('SELECT * FROM devices WHERE id = ?', (alert['device_id'],)).fetchone()
            if device:
                device = dict(device)
            else:
                return

        is_false, explanation, replicated, new_replica_count = evaluate_heuristics(db, alert, device, alert_id)

        # Update DB immediately with heuristic classification
        with db.conn() as c:
            c.execute('UPDATE alerts SET is_false_alarm = ?, ai_analysis = ?, replica_count = ? WHERE id = ?',
                      (is_false, explanation, new_replica_count, alert_id))
            
            alert_msg_lower = alert['message'].lower()
            is_offline_alert = "offline" in alert_msg_lower or "unreachable" in alert_msg_lower or "down" in alert_msg_lower
            if is_false == 1 and is_offline_alert:
                c.execute("UPDATE devices SET status='up', last_seen=? WHERE id=?", 
                          (datetime.now().isoformat(), device['id']))

        # Broadcast initial classification via Socket.IO
        if socketio:
            socketio.emit('alert_update', {
                'id': alert_id,
                'is_false_alarm': is_false,
                'ai_analysis': explanation
            })
            if is_false == 1 and is_offline_alert:
                with db.conn() as c:
                    updated = c.execute('SELECT * FROM devices WHERE id = ?', (device['id'],)).fetchone()
                if updated:
                    socketio.emit('device_status_update', dict(updated))
                socketio.emit('stats_update', db.get_dashboard_stats())

        # If Groq API key is present and not replicated, launch background AI refinement
        settings = db.get_settings()
        api_key = settings.get('groq_api_key', '')
        if api_key and not replicated:
            threading.Thread(
                target=_refine_with_groq, 
                args=(db, socketio, alert, device, alert_id, is_false, explanation, api_key), 
                daemon=True
            ).start()

    except Exception as e:
        print(f"[AI Detector] analyze_alert failed: {e}")


def get_groq_config(db):
    """Return (api_key, model_name) from database settings."""
    try:
        s = db.get_settings()
        api_key = (s.get('groq_api_key') or '').strip()
        model = (s.get('groq_model') or 'llama-3.3-70b-versatile').strip()
        return api_key, model
    except Exception:
        return '', 'llama-3.3-70b-versatile'


def build_noc_telemetry_context(db, device=None, alert=None):
    """Build compact live telemetry snapshot of TIKWatch for LLM NOC analysis."""
    ctx = {}
    try:
        stats = db.get_dashboard_stats()
        campus_bw_mbps = db.get_campus_total_bandwidth_mbps()
        routers = db.get_router_traffic_summary()
        agg_routers = [r for r in routers if r.get('include_in_aggregate', 1) == 1]
        tot_in_mbps = round(sum((r.get('wan_in') or 0.0) for r in agg_routers) / 1e6, 2)
        tot_out_mbps = round(sum((r.get('wan_out') or 0.0) for r in agg_routers) / 1e6, 2)
        peak_util_pct = round((max(tot_in_mbps, tot_out_mbps) / campus_bw_mbps * 100.0), 1) if campus_bw_mbps > 0 else 0.0

        ctx['campus_summary'] = {
            'total_devices': stats.get('total', 0),
            'up': stats.get('up', 0),
            'down': stats.get('down', 0),
            'warning': stats.get('warning', 0),
            'online_rate_pct': stats.get('online_rate', 100.0),
            'avg_latency_ms': stats.get('avg_latency'),
            'unacked_alerts': stats.get('unacked_alerts', 0),
            'campus_total_isp_bandwidth_mbps': campus_bw_mbps,
            'backbone_wan_in_mbps': tot_in_mbps,
            'backbone_wan_out_mbps': tot_out_mbps,
            'backbone_utilization_pct': peak_util_pct,
        }

        all_devs = db.get_all_devices()
        ctx['down_or_warning_devices'] = [
            {
                'id': d['id'], 'name': d.get('name'), 'ip': d.get('ip'),
                'type': d.get('type'), 'status': d.get('status'),
                'latency_ms': d.get('latency_ms'), 'last_seen': d.get('last_seen')
            }
            for d in all_devs if d.get('status') in ('down', 'warning')
        ][:15]

        router_devs = [d for d in all_devs if d.get('type') == 'router']
        ctx['top_routers_by_traffic'] = [
            {
                'name': r.get('name'), 'ip': r.get('ip'),
                'wan_in_mbps': round((r.get('wan_in') or 0.0) / 1e6, 2),
                'wan_out_mbps': round((r.get('wan_out') or 0.0) / 1e6, 2),
                'uplink_mbps': r.get('uplink_speed_mbps'),
                'agg': r.get('include_in_aggregate', 1)
            }
            for r in routers[:8]
        ]
        ctx['top_routers_by_cpu'] = [
            {
                'name': d.get('name'), 'ip': d.get('ip'),
                'cpu_pct': d.get('cpu_usage'), 'ram_pct': d.get('memory_usage'),
                'temp_c': d.get('temperature'), 'uptime': d.get('uptime')
            }
            for d in sorted(router_devs, key=lambda x: float(x.get('cpu_usage') or 0), reverse=True)[:6]
        ]

        active_alerts = db.get_alerts(limit=10, unacked_only=True)
        ctx['recent_unacked_alerts'] = [
            {
                'id': a.get('id'), 'device': a.get('device_name'), 'ip': a.get('device_ip'),
                'severity': a.get('severity'), 'message': a.get('message'),
                'created_at': a.get('created_at'), 'is_false_alarm': a.get('is_false_alarm')
            }
            for a in active_alerts
        ]

        with db.conn() as c:
            reboots = c.execute('''
                SELECT d.name, d.ip, da.up_time, da.duration_sec, da.justification
                FROM downtime_analysis da
                JOIN devices d ON da.device_id = d.id
                WHERE da.reboot_detected = 1
                ORDER BY da.id DESC LIMIT 5
            ''').fetchall()
            ctx['recent_reboots'] = [dict(r) for r in reboots]

        if device:
            ctx['target_device'] = {
                'id': device.get('id'), 'name': device.get('name'), 'ip': device.get('ip'),
                'type': device.get('type'), 'vendor': device.get('vendor'), 'model': device.get('model'),
                'status': device.get('status'), 'uptime': device.get('uptime'),
                'cpu_usage': device.get('cpu_usage'), 'memory_usage': device.get('memory_usage'),
                'temperature': device.get('temperature'), 'latency_ms': device.get('latency_ms'),
                'packet_loss': device.get('packet_loss'),
                'wan_in_mbps': round((device.get('wan_in') or 0.0) / 1e6, 2),
                'wan_out_mbps': round((device.get('wan_out') or 0.0) / 1e6, 2),
                'uplink_speed_mbps': device.get('uplink_speed_mbps'),
                'parent_device_id': device.get('parent_device_id'),
                'maintenance_until': device.get('maintenance_until'),
            }
            ctx['target_device_ifaces'] = db.get_latest_device_interface_traffic(device['id'], limit=10, active_only=True)
            with db.conn() as c:
                dt_hist = c.execute(
                    'SELECT down_time, up_time, duration_sec, reboot_detected, justification FROM downtime_analysis WHERE device_id = ? ORDER BY id DESC LIMIT 5',
                    (device['id'],)
                ).fetchall()
                ctx['target_device_downtime_history'] = [dict(r) for r in dt_hist]

        if alert:
            ctx['target_alert'] = {
                'id': alert.get('id'), 'severity': alert.get('severity'),
                'message': alert.get('message'), 'created_at': alert.get('created_at'),
                'ai_analysis': alert.get('ai_analysis'), 'is_false_alarm': alert.get('is_false_alarm')
            }
    except Exception as e:
        ctx['context_error'] = str(e)
    return ctx


def _redact_ips(text):
    """Mask internal IPv4 addresses before sending telemetry to external Groq Cloud API."""
    ip_map = {}
    rev_map = {}
    counter = [0]
    pattern = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')

    def _repl(match):
        ip = match.group(0)
        if ip not in rev_map:
            counter[0] += 1
            alias = f"[HOST-IP-{counter[0]}]"
            rev_map[ip] = alias
            ip_map[alias] = ip
        return rev_map[ip]

    redacted = pattern.sub(_repl, text)
    return redacted, ip_map


def _restore_ips(text, ip_map):
    """Restore masked IP placeholders back to real internal IPs locally."""
    out = text
    for alias, real_ip in ip_map.items():
        out = out.replace(alias, real_ip)
    return out


def ask_groq_noc(db, user_question, device=None, alert=None, max_tokens=750):
    """Query Groq LLM with live TIKWatch telemetry context. Returns (ok: bool, answer: str)."""
    api_key, model_name = get_groq_config(db)
    if not api_key:
        return False, (
            "⚠️ Groq API Key belum dikonfigurasi. "
            "Masukkan API Key di Web Dashboard: <b>Settings &gt; AI False Warning Detector &gt; Groq API Key</b>."
        )

    settings = db.get_settings()
    redact_ips = settings.get('groq_redact_ips', 'true').lower() == 'true'
    campus_bw_gbps = db.get_campus_total_bandwidth_mbps() / 1000.0

    ctx = build_noc_telemetry_context(db, device=device, alert=alert)
    system_prompt = (
        "Kamu adalah asisten AI NOC senior untuk sistem monitoring jaringan TIKWatch "
        "di UPT TIK Politeknik Negeri Jember (POLIJE). "
        f"Kapasitas total seluruh ISP kampus utama adalah {campus_bw_gbps:.1f} Gbps. "
        "Jawablah dalam bahasa Indonesia yang ringkas, teknis, terstruktur, dan akurat. "
        "HANYA gunakan angka, IP/alias host, nama router, dan metrik dari JSON telemetri live yang diberikan; "
        "jika suatu data tidak tersedia di JSON, katakan tidak tersedia (jangan mengarang). "
        "Berikan langkah troubleshooting nyata (termasuk perintah MikroTik RouterOS jika relevan)."
    )
    raw_user_prompt = (
        f"Permintaan/Pertanyaan Operator NOC:\n{user_question}\n\n"
        f"Data Telemetri Live TIKWatch (JSON):\n{json.dumps(ctx, ensure_ascii=False)}"
    )
    ip_map = {}
    if redact_ips:
        user_prompt, ip_map = _redact_ips(raw_user_prompt)
    else:
        user_prompt = raw_user_prompt

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
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.25,
            "max_tokens": max_tokens
        }
        import urllib.error
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=18) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            answer = res_data['choices'][0]['message']['content'].strip()
            if ip_map:
                answer = _restore_ips(answer, ip_map)
            return True, answer
    except urllib.error.HTTPError as he:
        try:
            err_body = he.read().decode('utf-8')
            msg = json.loads(err_body).get('error', {}).get('message', he.reason)
        except Exception:
            msg = str(he)
        return False, f"⚠️ Groq API Error ({model_name}): {msg}"
    except Exception as e:
        return False, f"⚠️ Gagal menghubungi Groq AI: {e}"
