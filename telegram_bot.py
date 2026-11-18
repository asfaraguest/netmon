"""
NetMon — Telegram Bot Integration Module
Provides 2-way interactive Telegram Bot and automated alert notifications.
Uses standard requests library (lightweight, zero dependency conflicts).
"""

import html
import json
import logging
import re
import threading
import time
from datetime import datetime
import requests

logger = logging.getLogger('netmon.telegram')


class TelegramBot:
    """Manages Telegram Bot notifications and 2-way interactive polling."""

    def __init__(self, db, socketio=None, snmp_worker=None):
        self.db = db
        self.socketio = socketio
        self.snmp_worker = snmp_worker

        self.bot_token = ""
        self.chat_ids = []
        self.enabled = False
        self.notify_down = True
        self.notify_up = True
        self.daily_digest_enabled = True
        self.daily_digest_time = "08:00"

        self.bot_info = {}
        self.last_update_id = 0
        self._stop_event = threading.Event()
        self._poll_thread = None
        self.is_running = False

        self.reload_config()

    @property
    def api_url(self):
        return f"https://api.telegram.org/bot{self.bot_token}"

    def reload_config(self):
        """Reload configuration from database settings and start/stop bot thread."""
        try:
            settings = self.db.get_settings()
        except Exception as e:
            logger.error(f"[Telegram] Failed to load settings from DB: {e}")
            return

        self.enabled = settings.get('telegram_enabled', 'false').lower() == 'true'
        self.bot_token = settings.get('telegram_bot_token', '').strip()
        raw_chats = settings.get('telegram_chat_ids', '')
        self.chat_ids = [c.strip() for c in re.split(r'[,;\s]+', raw_chats) if c.strip()]
        self.notify_down = settings.get('telegram_notify_down', 'true').lower() == 'true'
        self.notify_up = settings.get('telegram_notify_up', 'true').lower() == 'true'
        self.daily_digest_enabled = settings.get('telegram_daily_digest_enabled', 'true').lower() == 'true'
        self.daily_digest_time = settings.get('telegram_daily_digest_time', '08:00').strip() or "08:00"

        if self.enabled and self.bot_token:
            if not self.is_running or not (self._poll_thread and self._poll_thread.is_alive()):
                self.is_running = False
                self.start()
            else:
                # Refresh bot info in case token changed
                self._verify_bot_info()
        else:
            if self.is_running:
                self.stop()

    def start(self):
        """Start background polling thread."""
        if self.is_running and self._poll_thread and self._poll_thread.is_alive():
            return
        if not self.bot_token:
            logger.warning("[Telegram] Cannot start bot: Token is empty")
            print("[Telegram] Cannot start bot: Token is empty")
            return

        info = self._verify_bot_info()
        if not info:
            logger.warning("[Telegram] Invalid bot token, polling not started.")
            print("[Telegram] Invalid bot token, polling not started.")
            return

        # Ensure any old webhook is cleared so getUpdates works properly
        try:
            self._send_request("deleteWebhook", {"drop_pending_updates": False})
        except Exception:
            pass

        self._register_bot_commands()

        self._stop_event.clear()
        self.is_running = True
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True, name="TelegramPollThread")
        self._poll_thread.start()
        print(f"[Telegram] Bot @{self.bot_info.get('username','?')} started successfully with {len(self.chat_ids)} authorized chat(s).")

    def stop(self):
        """Stop background polling thread."""
        if not self.is_running:
            return
        self._stop_event.set()
        self.is_running = False
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=2)
        print("[Telegram] Bot polling stopped.")

    def _register_bot_commands(self, token=None):
        """Automatically register bot commands with Telegram so they appear in the Menu button."""
        tok = token or self.bot_token
        if not tok:
            return
        commands = [
            {"command": "status", "description": "Ringkasan kesehatan jaringan"},
            {"command": "down", "description": "Daftar perangkat offline"},
            {"command": "alerts", "description": "Alert aktif yang belum di-ack"},
            {"command": "poll", "description": "Poll seluruh perangkat SNMP sekarang"},
            {"command": "digest", "description": "Kirim rekap harian sekarang"},
            {"command": "myid", "description": "Tampilkan Chat ID & User ID Anda"},
            {"command": "help", "description": "Panduan & bantuan perintah"}
        ]
        try:
            url = f"https://api.telegram.org/bot{tok}/setMyCommands"
            requests.post(url, json={"commands": commands}, timeout=10)
        except Exception as e:
            logger.debug(f"[Telegram] Failed to set bot commands: {e}")

    def _verify_bot_info(self):
        """Verify token with getMe and cache bot identity."""
        try:
            r = requests.get(f"{self.api_url}/getMe", timeout=10)
            data = r.json()
            if data.get('ok'):
                self.bot_info = data.get('result', {})
                return self.bot_info
            else:
                logger.error(f"[Telegram] getMe returned error: {data.get('description')}")
                return None
        except Exception as e:
            logger.error(f"[Telegram] Connection test failed: {e}")
            return None

    def is_authorized(self, chat_id, user_id=None, username=None):
        """Check if chat_id, user_id, or username is in whitelisted chat_ids."""
        if not self.chat_ids:
            return False
        cid_str = str(chat_id).strip()
        uid_str = str(user_id).strip() if user_id else ""
        u_name = str(username).strip().lower().lstrip('@') if username else ""
        
        for allowed in self.chat_ids:
            al_clean = str(allowed).strip().lower().lstrip('@')
            if al_clean and (al_clean == cid_str or al_clean == uid_str or (u_name and al_clean == u_name)):
                return True
        return False

    # ─── Low-level Telegram API calls ────────────────────────────────

    def _send_request(self, method, payload=None, timeout=15):
        if not self.bot_token:
            return None
        try:
            url = f"{self.api_url}/{method}"
            resp = requests.post(url, json=payload or {}, timeout=timeout)
            data = resp.json()
            if not data.get("ok"):
                logger.error(f"[Telegram] API {method} error: {data.get('description')} (code: {data.get('error_code')})")
                print(f"[Telegram Error] {method} failed: {data.get('description')} (code: {data.get('error_code')})")
            return data
        except Exception as e:
            logger.error(f"[Telegram] API call {method} error: {e}")
            print(f"[Telegram Error] API call {method} exception: {e}")
            return None

    def send_message(self, chat_id, text, parse_mode="HTML", reply_markup=None):
        """Send a message to a specific chat with automatic plain-text fallback."""
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        res = self._send_request("sendMessage", payload)
        if not res or not res.get("ok"):
            # Fallback: if HTML parsing failed, strip HTML and send plain text
            logger.warning(f"[Telegram] Send message with HTML failed ({res.get('description') if res else 'None'}), retrying plain text...")
            payload["parse_mode"] = None
            clean_text = re.sub(r'<[^>]+>', '', text)
            payload["text"] = clean_text
            res = self._send_request("sendMessage", payload)
        return res

    def edit_message_text(self, chat_id, message_id, text, parse_mode="HTML", reply_markup=None):
        """Edit an existing message."""
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self._send_request("editMessageText", payload)

    def answer_callback_query(self, callback_query_id, text=None, show_alert=False):
        """Answer an inline button callback query."""
        payload = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text
            payload["show_alert"] = show_alert
        return self._send_request("answerCallbackQuery", payload, timeout=5)

    # ─── Polling Loop ────────────────────────────────────────────────

    def _poll_loop(self):
        """Background long polling loop for 2-way Telegram communication."""
        print(f"[Telegram Poller] Background polling loop active for @{self.bot_info.get('username','?')}")
        while not self._stop_event.is_set():
            try:
                payload = {
                    "offset": self.last_update_id + 1,
                    "timeout": 20,
                    "allowed_updates": ["message", "callback_query"]
                }
                resp = requests.post(f"{self.api_url}/getUpdates", json=payload, timeout=25)
                data = resp.json()

                if not data.get("ok"):
                    desc = data.get("description", "Unknown error")
                    code = data.get("error_code")
                    logger.error(f"[Telegram Polling Error] {desc} (code {code})")
                    print(f"[Telegram Polling Error] {desc} (code {code})")
                    if code == 409 and "webhook" in desc.lower():
                        print("[Telegram] Active webhook conflict detected. Deleting webhook...")
                        self._send_request("deleteWebhook", {"drop_pending_updates": False})
                    time.sleep(3)
                    continue

                updates = data.get("result", [])
                for update in updates:
                    up_id = update.get("update_id")
                    if up_id:
                        self.last_update_id = max(self.last_update_id, up_id)

                    try:
                        if "message" in update:
                            self._handle_message(update["message"])
                        elif "callback_query" in update:
                            self._handle_callback_query(update["callback_query"])
                    except Exception as he:
                        logger.error(f"[Telegram] Error processing update {up_id}: {he}")
                        print(f"[Telegram] Error processing update {up_id}: {he}")

            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException as e:
                logger.warning(f"[Telegram] Network glitch in poll loop: {e}")
                time.sleep(4)
            except Exception as e:
                logger.error(f"[Telegram] Unexpected poll error: {e}")
                print(f"[Telegram] Unexpected poll error: {e}")
                time.sleep(2)
        print("[Telegram Poller] Background polling loop exited.")

    # ─── Message Dispatcher ──────────────────────────────────────────

    def _handle_message(self, msg):
        text = msg.get("text", "").strip()
        chat = msg.get("chat", {})
        chat_id = chat.get("id")
        user = msg.get("from", {})
        user_id = user.get("id")
        username = user.get("username", "")
        first_name = user.get("first_name", "Admin")

        if not text or not chat_id:
            return

        print(f"[Telegram] Incoming command from chat_id={chat_id} (user={username or first_name}/{user_id}): '{text}'")

        # Check authorization
        if not self.is_authorized(chat_id, user_id, username):
            print(f"[Telegram Access Check] DENIED: chat_id={chat_id}, user={username}/{user_id} not in whitelist: {self.chat_ids}")
            # Reply to ANY slash command so the user receives immediate feedback and knows their ID!
            if text.startswith("/"):
                reply = (
                    "🔒 <b>Akses Ditolak / Belum Diotorisasi</b>\n\n"
                    "Akun atau grup Anda belum terdaftar di whitelist NetMon.\n\n"
                    f"• <b>Chat ID Anda:</b> <code>{chat_id}</code>\n"
                    f"• <b>User ID:</b> <code>{user_id}</code>\n"
                    f"• <b>Username:</b> @{username if username else '-'}\n"
                    f"• <b>Nama:</b> {first_name}\n\n"
                    "<i>Untuk memberikan akses, salin <b>Chat ID</b> di atas lalu masukkan ke menu "
                    "<b>Settings &gt; Telegram Bot Integration &gt; Authorized Chat IDs</b> di Web Dashboard NetMon, lalu klik tombol <b>Save All Settings</b>.</i>"
                )
                self.send_message(chat_id, reply)
            return

        cmd_parts = text.split()
        cmd = cmd_parts[0].lower().split('@')[0]  # strip @botname if in group
        args = cmd_parts[1:]

        if cmd in ("/start", "/help"):
            self._cmd_help(chat_id, first_name)
        elif cmd in ("/myid", "/id"):
            self._cmd_myid(chat_id, user_id, first_name, username)
        elif cmd in ("/status", "/summary"):
            self._cmd_status(chat_id)
        elif cmd == "/alerts":
            self._cmd_alerts(chat_id)
        elif cmd == "/down":
            self._cmd_down(chat_id)
        elif cmd == "/devices":
            self._cmd_devices(chat_id)
        elif cmd in ("/ack", "/resolve"):
            self._cmd_ack(chat_id, args, username or first_name)
        elif cmd == "/ack_all":
            self._cmd_ack_all(chat_id, username or first_name)
        elif cmd == "/poll":
            self._cmd_poll(chat_id, args)
        elif cmd == "/digest":
            self.send_daily_digest(target_chat_id=chat_id)
        else:
            if text.startswith("/"):
                clean_cmd = html.escape(cmd)
                self.send_message(
                    chat_id,
                    f"❓ Perintah <code>{clean_cmd}</code> tidak dikenali.\nKetik <code>/help</code> untuk melihat daftar perintah yang tersedia."
                )

    # ─── Callback Query (Inline Buttons) Dispatcher ──────────────────

    def _handle_callback_query(self, cq):
        cq_id = cq.get("id")
        data = cq.get("data", "")
        msg = cq.get("message", {})
        chat_id = msg.get("chat", {}).get("id")
        message_id = msg.get("message_id")
        user = cq.get("from", {})
        user_id = user.get("id")
        username = user.get("username") or user.get("first_name", "Admin")

        if not self.is_authorized(chat_id, user_id, username):
            self.answer_callback_query(cq_id, text="⚠️ Anda tidak memiliki otorisasi untuk aksi ini.", show_alert=True)
            return

        if data.startswith("ack:"):
            try:
                alert_id = int(data.split(":", 1)[1])
                self.db.acknowledge_alert(alert_id, user=f"Telegram (@{username})")
                self.answer_callback_query(cq_id, text=f"✅ Alert #{alert_id} berhasil di-acknowledge!")

                # Live update message to show who acknowledged it
                orig_text = msg.get("text", "")
                now_str = datetime.now().strftime("%H:%M:%S")
                updated_text = orig_text + f"\n\n✅ <i>Di-acknowledge oleh @{username} pukul {now_str} WIB</i>"

                # Keep only re-check button or remove buttons
                new_markup = {
                    "inline_keyboard": [
                        [{"text": "🔄 Re-check Status", "callback_data": f"recheck:{alert_id}"}]
                    ]
                }
                self.edit_message_text(chat_id, message_id, updated_text, reply_markup=new_markup)

                # Emit real-time socketio event to NetMon Web Dashboard
                if self.socketio:
                    self.socketio.emit('alert_ack', {'id': alert_id, 'ack_by': f"Telegram (@{username})"})
                    self.socketio.emit('stats_update', self.db.get_dashboard_stats())
            except Exception as e:
                self.answer_callback_query(cq_id, text=f"Gagal memproses ack: {e}", show_alert=True)

        elif data.startswith("poll:") or data.startswith("recheck:"):
            target_val = data.split(":", 1)[1]
            device = None
            if data.startswith("recheck:"):
                # Lookup device via alert
                try:
                    aid = int(target_val)
                    with self.db.conn() as c:
                        row = c.execute("SELECT device_id FROM alerts WHERE id=?", (aid,)).fetchone()
                        if row and row['device_id']:
                            device = self.db.get_device(row['device_id'])
                except Exception:
                    pass
            else:
                try:
                    dev_id = int(target_val)
                    device = self.db.get_device(dev_id)
                except Exception:
                    pass

            if device and self.snmp_worker:
                self.answer_callback_query(cq_id, text=f"🔄 Memulai polling ulang untuk {device.get('name', device.get('ip'))}...")
                threading.Thread(target=self._run_poll_and_notify, args=(chat_id, device), daemon=True).start()
            else:
                self.answer_callback_query(cq_id, text="⚠️ Perangkat tidak ditemukan atau worker belum siap.")

        elif data.startswith("cmd:"):
            action = data.split(":", 1)[1]
            if action == "down":
                self.answer_callback_query(cq_id)
                self._cmd_down(chat_id)

    def _run_poll_and_notify(self, chat_id, device):
        """Poll device and reply with updated status."""
        try:
            self.snmp_worker.poll_device(device)
            # Fetch fresh status
            updated = self.db.get_device(device['id'])
            status = updated.get('status', 'unknown').upper()
            icon = "🟢" if status == "UP" else ("🔴" if status == "DOWN" else "🟡")
            lat = f"{updated.get('latency_ms', '-')} ms" if updated.get('latency_ms') is not None else "-"
            reply = (
                f"📡 <b>Hasil Re-Check Polling:</b>\n"
                f"• <b>Perangkat:</b> <code>{updated.get('name', updated.get('ip'))}</code> ({updated.get('ip')})\n"
                f"• <b>Status:</b> {icon} <b>{status}</b>\n"
                f"• <b>Latensi:</b> {lat}\n"
                f"• <b>Terakhir Dilihat:</b> {updated.get('last_seen', '-')}"
            )
            self.send_message(chat_id, reply)
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal polling {device.get('ip')}: {e}")

    # ─── Bot Commands ────────────────────────────────────────────────

    def _cmd_help(self, chat_id, name):
        text = (
            f"👋 Halo, <b>{name}</b>!\n\n"
            "🤖 <b>NetMon Telegram Bot</b> siap membantu monitoring jaringan secara real-time.\n\n"
            "<b>Daftar Perintah:</b>\n"
            "• <code>/status</code> atau <code>/summary</code> — Ringkasan status sistem & metrik jaringan\n"
            "• <code>/alerts</code> — Daftar peringatan aktif yang belum di-acknowledge\n"
            "• <code>/down</code> — Menampilkan seluruh perangkat yang sedang offline (DOWN)\n"
            "• <code>/devices</code> — Ringkasan jumlah perangkat per tipe dan zona\n"
            "• <code>/ack &lt;id&gt;</code> — Acknowledge alert berdasarkan ID\n"
            "• <code>/ack_all</code> — Acknowledge semua alert aktif sekaligus\n"
            "• <code>/poll &lt;ip/id&gt;</code> — Poll langsung status perangkat tertentu\n"
            "• <code>/digest</code> — Minta pengiriman Daily Digest sekarang\n"
            "• <code>/myid</code> — Menampilkan informasi Chat ID Anda\n\n"
            f"<b>Chat ID Anda:</b> <code>{chat_id}</code>"
        )
        self.send_message(chat_id, text)

    def _cmd_myid(self, chat_id, user_id, first_name, username):
        text = (
            "🆔 <b>Informasi Identitas Telegram:</b>\n\n"
            f"• <b>Chat ID:</b> <code>{chat_id}</code>\n"
            f"• <b>User ID:</b> <code>{user_id}</code>\n"
            f"• <b>Nama:</b> {first_name}\n"
            f"• <b>Username:</b> @{username if username else '-'}\n"
            "• <b>Status Akses:</b> ✅ <i>Terotorisasi di NetMon</i>"
        )
        self.send_message(chat_id, text)

    def _cmd_status(self, chat_id):
        try:
            stats = self.db.get_dashboard_stats()
            total = stats.get('total', 0)
            up = stats.get('up', 0)
            down = stats.get('down', 0)
            warn = stats.get('warning', 0)
            unknown = stats.get('unknown', 0)
            online_rate = stats.get('online_rate', 100.0)
            avg_lat = stats.get('avg_latency') or '-'
            unacked = stats.get('unacked_alerts', 0)
            crit = stats.get('critical_alerts', 0)
            zones = stats.get('zones', 0)
            now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            status_icon = "🟢" if down == 0 else "🔴"

            text = (
                f"{status_icon} <b>Ringkasan Status Jaringan NetMon</b>\n"
                f"<i>Waktu: {now_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"🖥 <b>Total Perangkat:</b> {total}\n"
                f"🟢 <b>Online (UP):</b> {up} ({online_rate}%)\n"
                f"🔴 <b>Offline (DOWN):</b> {down}\n"
                f"🟡 <b>Warning:</b> {warn}\n"
                f"⚪ <b>Unknown:</b> {unknown}\n"
                f"⚡ <b>Rata-rata Latensi:</b> {avg_lat} ms\n"
                f"🚨 <b>Alert Aktif:</b> {unacked} (Kritis: {crit})\n"
                f"📁 <b>Jumlah Zona:</b> {zones}\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
            )

            # Check if there are down devices and add inline button
            markup = None
            if down > 0:
                markup = {"inline_keyboard": [[{"text": "🔴 Lihat Perangkat DOWN", "callback_data": "cmd:down"}]]}

            self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal mengambil statistik: {e}")

    def _cmd_alerts(self, chat_id):
        try:
            alerts = self.db.get_active_alerts(limit=8)
            if not alerts:
                self.send_message(chat_id, "✅ <b>Semua Bersih!</b> Tidak ada alert aktif atau belum di-acknowledge saat ini.")
                return

            text = f"🚨 <b>Daftar Alert Aktif ({len(alerts)} Terkini):</b>\n\n"
            for a in alerts:
                aid = a.get('id')
                sev = a.get('severity', 'info').upper()
                s_icon = "🔴" if sev == "CRITICAL" else ("🟡" if sev == "WARNING" else "ℹ️")
                dname = a.get('device_name') or a.get('device_ip') or 'Device'
                msg = a.get('message', '-')
                ts = a.get('created_at', '-')
                text += (
                    f"{s_icon} <b>[#{aid}] {sev}</b>\n"
                    f"• <b>Perangkat:</b> <code>{dname}</code> ({a.get('device_ip','')})\n"
                    f"• <b>Pesan:</b> {msg}\n"
                    f"• <b>Waktu:</b> <i>{ts}</i>\n"
                    f"• Aksi: <code>/ack {aid}</code>\n\n"
                )

            text += "<i>Gunakan tombol [✅ Acknowledge] pada pesan notifikasi atau ketik /ack_all untuk menandai semua telah ditangani.</i>"
            self.send_message(chat_id, text)
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal mengambil alert: {e}")

    def _cmd_down(self, chat_id):
        try:
            devices = self.db.get_all_devices()
            down_devs = [d for d in devices if d.get('status') == 'down']

            if not down_devs:
                self.send_message(chat_id, "🟢 <b>Luar Biasa!</b> Tidak ada perangkat yang sedang DOWN saat ini.")
                return

            text = f"🔴 <b>Perangkat DOWN ({len(down_devs)} Perangkat):</b>\n\n"
            for d in down_devs:
                name = d.get('name') or d.get('ip')
                ip = d.get('ip')
                dtype = d.get('type') or 'Unknown'
                last_seen = d.get('last_seen') or 'Belum pernah'
                text += (
                    f"• <b>{name}</b> ({ip})\n"
                    f"  Tipe: {dtype} | Terakhir terlihat: <i>{last_seen}</i>\n"
                    f"  Cek ulang: <code>/poll {ip}</code>\n\n"
                )
            self.send_message(chat_id, text)
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal mengambil daftar down: {e}")

    def _cmd_devices(self, chat_id):
        try:
            counts = self.db.get_device_type_counts()
            devices = self.db.get_all_devices()
            zones = self.db.get_zones_with_devices()

            text = "🖥 <b>Ringkasan Perangkat Terdaftar:</b>\n\n"
            text += "<b>Berdasarkan Tipe:</b>\n"
            total_devs = counts.get('_total', len(devices))
            for t, cnt in counts.items():
                if t.startswith('_'):
                    continue
                text += f"• {t.capitalize()}: <b>{cnt}</b>\n"
            text += f"• <b>Total:</b> <b>{total_devs}</b> perangkat\n"

            text += "\n<b>Berdasarkan Zona:</b>\n"
            for z in zones:
                z_devs = z.get('devices', [])
                z_up = sum(1 for d in z_devs if d.get('status') == 'up')
                text += f"• <b>{z.get('name')}:</b> {len(z_devs)} perangkat (🟢 {z_up}/{len(z_devs)} UP)\n"

            self.send_message(chat_id, text)
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal mengambil ringkasan perangkat: {e}")

    def _cmd_ack(self, chat_id, args, username):
        if not args:
            self.send_message(chat_id, "⚠️ Masukkan ID alert yang ingin di-ack. Contoh: <code>/ack 15</code>")
            return
        try:
            aid = int(args[0])
            self.db.acknowledge_alert(aid, user=f"Telegram (@{username})")
            if self.socketio:
                self.socketio.emit('alert_ack', {'id': aid, 'ack_by': f"Telegram (@{username})"})
                self.socketio.emit('stats_update', self.db.get_dashboard_stats())
            self.send_message(chat_id, f"✅ Alert <b>#{aid}</b> telah berhasil di-acknowledge oleh @{username}.")
        except ValueError:
            self.send_message(chat_id, "⚠️ Format ID salah. Gunakan angka, contoh: <code>/ack 15</code>")
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal ack alert: {e}")

    def _cmd_ack_all(self, chat_id, username):
        try:
            self.db.acknowledge_all_alerts()
            if self.socketio:
                self.socketio.emit('alert_ack_all', {'ack_by': f"Telegram (@{username})"})
                self.socketio.emit('stats_update', self.db.get_dashboard_stats())
            self.send_message(chat_id, f"✅ Seluruh alert aktif berhasil di-acknowledge oleh @{username}.")
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal ack all: {e}")

    def _cmd_poll(self, chat_id, args):
        if not self.snmp_worker:
            self.send_message(chat_id, "⚠️ Worker polling belum aktif atau belum siap.")
            return

        if not args:
            self.send_message(chat_id, "ℹ️ Gunakan: <code>/poll &lt;ip/id&gt;</code> untuk satu perangkat, atau <code>/poll all</code> untuk re-check seluruh perangkat.")
            return

        target = args[0].strip()
        if target.lower() in ("all", "semua"):
            devices = self.db.get_all_devices()
            if not devices:
                self.send_message(chat_id, "ℹ️ Belum ada perangkat yang terdaftar di database.")
                return
            self.send_message(chat_id, f"🔄 Memulai polling re-check untuk <b>{len(devices)} perangkat</b> di latar belakang...")
            def _poll_all():
                done = 0
                for d in devices:
                    try:
                        self.snmp_worker.poll_device(d)
                        done += 1
                    except Exception as pe:
                        logger.warning(f"[Telegram Poll All] Error on {d.get('ip')}: {pe}")
                self.send_message(chat_id, f"✅ Selesai melakukan re-check untuk <b>{done}/{len(devices)} perangkat</b>.")
            threading.Thread(target=_poll_all, daemon=True).start()
            return

        device = None
        if target.isdigit():
            device = self.db.get_device(int(target))
        if not device:
            device = self.db.get_device_by_ip(target)

        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat dengan IP/ID <code>{target}</code> tidak ditemukan di database.")
            return

        self.send_message(chat_id, f"🔄 Memulai polling untuk <b>{device.get('name', target)}</b> ({device.get('ip')})...")
        threading.Thread(target=self._run_poll_and_notify, args=(chat_id, device), daemon=True).start()

    # ─── Alert Push Notification ─────────────────────────────────────

    def send_alert(self, alert_data, device=None, is_recovery=False):
        """Send incident alert to all authorized Telegram chats."""
        if not self.enabled or not self.bot_token or not self.chat_ids:
            return

        severity = alert_data.get('severity', 'info').lower()

        # Check notification filter settings
        if is_recovery:
            if not self.notify_up:
                return
        else:
            if not self.notify_down:
                return

        alert_id = alert_data.get('id')
        dev_id = device.get('id') if device else alert_data.get('device_id')
        dev_name = device.get('name') if device else alert_data.get('device_name', 'Device')
        dev_ip = device.get('ip') if device else alert_data.get('device_ip', '')
        message = alert_data.get('message', '')
        ai_analysis = alert_data.get('ai_analysis')
        now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        is_anomaly = any(w in message.lower() for w in ['anomali', 'lonjakan', 'spike', 'ddos', 'flood'])

        # Determine icon and header
        if is_recovery:
            icon = "🟢"
            title = "PERANGKAT KEMBALI ONLINE (RECOVERY)"
        elif is_anomaly:
            icon = "⚡"
            title = "ANOMALI TRAFFIC & RESOURCE SPIKE" if severity == 'critical' else "PERINGATAN ANOMALI JARINGAN"
        elif severity == 'critical':
            icon = "🚨"
            title = "PERANGKAT OFFLINE (CRITICAL)"
        elif severity == 'warning':
            icon = "⚠️"
            title = "PERINGATAN JARINGAN (WARNING)"
        else:
            icon = "ℹ️"
            title = "INFORMASI JARINGAN (INFO)"

        # Zone info
        zone_str = ""
        if device and device.get('zone_id'):
            try:
                zone = self.db.get_zone(device['zone_id'])
                if zone:
                    zone_str = f"• <b>Zona:</b> {zone.get('name')}\n"
            except Exception:
                pass

        text = (
            f"{icon} <b>[NETMON] {title}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>Perangkat:</b> <code>{dev_name}</code>\n"
            f"• <b>IP Address:</b> <code>{dev_ip}</code>\n"
            f"{zone_str}"
            f"• <b>Pesan:</b> {message}\n"
            f"• <b>Waktu:</b> <i>{now_str} WIB</i>\n"
        )

        if ai_analysis and "valid alert" not in ai_analysis.lower() and "false warning" not in ai_analysis.lower():
            text += f"\n🤖 <b>AI Diagnostic:</b> <i>{ai_analysis}</i>\n"

        # Interactive buttons
        keyboard = []
        btn_row = []
        if alert_id and not is_recovery:
            btn_row.append({"text": "✅ Acknowledge", "callback_data": f"ack:{alert_id}"})
        if dev_id:
            btn_row.append({"text": "🔄 Re-check", "callback_data": f"poll:{dev_id}"})
        if btn_row:
            keyboard.append(btn_row)

        reply_markup = {"inline_keyboard": keyboard} if keyboard else None

        for cid in self.chat_ids:
            try:
                self.send_message(cid, text, reply_markup=reply_markup)
            except Exception as e:
                logger.error(f"[Telegram] Failed to send alert to {cid}: {e}")

    # ─── Scheduled Daily Digest ──────────────────────────────────────

    def send_daily_digest(self, target_chat_id=None):
        """Send 24-hour summary digest to authorized chats."""
        if not self.enabled and not target_chat_id:
            return
        if not self.bot_token:
            return

        try:
            stats = self.db.get_dashboard_stats()
            total = stats.get('total', 0)
            up = stats.get('up', 0)
            down = stats.get('down', 0)
            warn = stats.get('warning', 0)
            online_rate = stats.get('online_rate', 100.0)
            avg_lat = stats.get('avg_latency') or '-'
            unacked = stats.get('unacked_alerts', 0)
            crit = stats.get('critical_alerts', 0)
            today_str = datetime.now().strftime("%A, %d %B %Y - %H:%M")

            status_headline = "🟢 Kondisi Jaringan Normal" if down == 0 else f"🔴 Perhatian: {down} Perangkat Offline"

            text = (
                "📊 <b>NETMON DAILY DIGEST</b>\n"
                f"🗓 <i>{today_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"<b>Status Umum:</b> {status_headline}\n\n"
                f"🖥 <b>Total Terpantau:</b> {total} perangkat\n"
                f"🟢 <b>Online (UP):</b> {up} ({online_rate}%)\n"
                f"🔴 <b>Offline (DOWN):</b> {down}\n"
                f"🟡 <b>Warning:</b> {warn}\n"
                f"⚡ <b>Rata-rata Latensi:</b> {avg_lat} ms\n"
                f"🚨 <b>Alert Terbuka:</b> {unacked} (Kritis: {crit})\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "<i>Gunakan /status atau buka Web Dashboard NetMon untuk detail lengkap.</i>"
            )

            targets = [target_chat_id] if target_chat_id else self.chat_ids
            for cid in targets:
                self.send_message(cid, text)
            print(f"[Telegram] Daily digest sent to {len(targets)} chat(s).")
        except Exception as e:
            logger.error(f"[Telegram] Failed to generate/send daily digest: {e}")

    # ─── Connection & Configuration Test ─────────────────────────────

    def test_connection(self, token=None, chat_ids=None):
        """Test Telegram Bot API connection and deliver test message."""
        test_token = (token or self.bot_token or "").strip()
        if not test_token:
            return {"status": "error", "message": "Bot token tidak boleh kosong."}

        # 1. Test getMe
        try:
            url = f"https://api.telegram.org/bot{test_token}/getMe"
            r = requests.get(url, timeout=10)
            data = r.json()
            if not data.get('ok'):
                return {"status": "error", "message": f"Token tidak valid: {data.get('description')}"}
            bot_user = data.get('result', {})
            # Automatically register commands menu with Telegram
            self._register_bot_commands(token=test_token)
        except Exception as e:
            return {"status": "error", "message": f"Koneksi ke Telegram API gagal: {e}"}

        # 2. Test sending message if chat_ids provided
        target_chats = chat_ids if chat_ids is not None else self.chat_ids
        if isinstance(target_chats, str):
            target_chats = [c.strip() for c in re.split(r'[,;\s]+', target_chats) if c.strip()]

        sent_count = 0
        now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        test_text = (
            "🧪 <b>Uji Coba Integrasi Telegram NetMon</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "✅ <b>Koneksi Berhasil!</b> Bot Telegram telah terhubung dengan server NetMon.\n"
            f"• <b>Bot:</b> @{bot_user.get('username')}\n"
            f"• <b>Waktu Uji:</b> {now_str} WIB\n\n"
            "<i>Notifikasi alert insiden dan perintah interaktif bot kini siap digunakan.</i>"
        )

        for cid in target_chats:
            try:
                payload = {
                    "chat_id": cid,
                    "text": test_text,
                    "parse_mode": "HTML"
                }
                resp = requests.post(f"https://api.telegram.org/bot{test_token}/sendMessage", json=payload, timeout=10)
                if resp.json().get('ok'):
                    sent_count += 1
            except Exception as e:
                logger.error(f"[Telegram Test] Failed sending to {cid}: {e}")

        return {
            "status": "success",
            "bot_username": bot_user.get('username'),
            "bot_name": bot_user.get('first_name'),
            "chats_contacted": sent_count,
            "message": f"Koneksi sukses! Terhubung sebagai @{bot_user.get('username')}. Terkirim ke {sent_count} chat."
        }
