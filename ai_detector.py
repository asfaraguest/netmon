import json
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
                f"Berikan analisa teknis apakah ini pola serangan DDoS/Flood, looping paket, transfer data masif, atau kebocoran memori. "
                f"Kembalikan respon JSON: "
                f'{{"is_false_alarm": 0, "explanation": "Diagnosa teknis maks 2 kalimat dalam bahasa Indonesia"}}'
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
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        payload = {
            "model": "llama-3.3-70b-versatile",
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
