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
from chart_generator import render_traffic_chart_image, is_chart_available

logger = logging.getLogger('netmon.telegram')


def format_speed(bps):
    """Format bits per second into human-readable string."""
    if bps is None:
        return "0.00 bps"
    try:
        val = float(bps)
    except Exception:
        return "0.00 bps"
    if val >= 1_000_000_000:
        return f"{val / 1_000_000_000:.2f} Gbps"
    elif val >= 1_000_000:
        return f"{val / 1_000_000:.2f} Mbps"
    elif val >= 1_000:
        return f"{val / 1_000:.1f} Kbps"
    else:
        return f"{val:.0f} bps"


def format_bar(pct, length=10):
    """Format percentage as ASCII bar."""
    try:
        val = max(0.0, min(100.0, float(pct)))
    except Exception:
        val = 0.0
    filled = int(round(val / 100.0 * length))
    filled = max(0, min(length, filled))
    bar = "█" * filled + "░" * (length - filled)
    return f"[{bar}] {val:.1f}%"


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
            {"command": "traffic", "description": "Traffic: All router / Selected router"},
            {"command": "chart", "description": "Grafik gambar traffic (1h, 6h, 24h, 7d, 30d)"},
            {"command": "top", "description": "Top 10 bandwidth interface tertinggi"},
            {"command": "capture", "description": "Live capture traffic real-time via SNMP"},
            {"command": "down", "description": "Daftar perangkat offline"},
            {"command": "alerts", "description": "Alert aktif yang belum di-ack"},
            {"command": "poll", "description": "Poll ulang perangkat SNMP sekarang"},
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

    def delete_message(self, chat_id, message_id):
        """Delete a message from Telegram chat."""
        if not self.bot_token or not message_id:
            return None
        return self._send_request("deleteMessage", {"chat_id": chat_id, "message_id": message_id}, timeout=5)

    def edit_message_text(self, chat_id, message_id, text, parse_mode="HTML", reply_markup=None):
        """Edit an existing message. If target was a media message (photo), deletes it and sends fresh text."""
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        res = self._send_request("editMessageText", payload)
        if not res or not res.get("ok"):
            desc = str(res.get("description", "") if res else "").lower()
            if "there is no text in the message to edit" in desc:
                # The target was a photo/media message. Clean it up and send fresh text message.
                try:
                    self.delete_message(chat_id, message_id)
                except Exception:
                    pass
                return self.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
            elif "not modified" in desc:
                return res
            elif "entities" in desc:
                # Fallback to plain text on HTML entity parsing error
                payload["parse_mode"] = None
                payload["text"] = re.sub(r'<[^>]+>', '', text)
                res2 = self._send_request("editMessageText", payload)
                if not res2 or not res2.get("ok"):
                    return self.send_message(chat_id, payload["text"], parse_mode=None, reply_markup=reply_markup)
                return res2
        return res

    def answer_callback_query(self, callback_query_id, text=None, show_alert=False):
        """Answer an inline button callback query."""
        if not callback_query_id:
            return None
        payload = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text
            payload["show_alert"] = show_alert
        return self._send_request("answerCallbackQuery", payload, timeout=5)

    def send_photo(self, chat_id, photo_bytes, caption=None, parse_mode="HTML", reply_markup=None):
        """Send a photo image to Telegram chat."""
        if not self.bot_token:
            return None
        try:
            url = f"{self.api_url}/sendPhoto"
            data = {"chat_id": chat_id}
            if caption:
                data["caption"] = caption
            if parse_mode:
                data["parse_mode"] = parse_mode
            if reply_markup:
                data["reply_markup"] = json.dumps(reply_markup) if isinstance(reply_markup, dict) else reply_markup

            files = {"photo": ("chart.png", photo_bytes, "image/png")}
            resp = requests.post(url, data=data, files=files, timeout=30)
            data_res = resp.json()
            if not data_res.get("ok"):
                if caption and "entities" in str(data_res.get("description", "")).lower():
                    data["parse_mode"] = ""
                    data["caption"] = re.sub(r'<[^>]+>', '', caption)
                    resp = requests.post(url, data=data, files={"photo": ("chart.png", photo_bytes, "image/png")}, timeout=30)
                    data_res = resp.json()
                logger.error(f"[Telegram] sendPhoto error: {data_res.get('description')}")
            return data_res
        except Exception as e:
            logger.error(f"[Telegram] sendPhoto exception: {e}")
            return None

    def edit_message_media(self, chat_id, message_id, photo_bytes, caption=None, parse_mode="HTML", reply_markup=None):
        """Edit an existing photo message in-place in Telegram."""
        if not self.bot_token:
            return None
        try:
            url = f"{self.api_url}/editMessageMedia"
            media_obj = {
                "type": "photo",
                "media": "attach://photo"
            }
            if caption:
                media_obj["caption"] = caption
            if parse_mode:
                media_obj["parse_mode"] = parse_mode

            data = {
                "chat_id": chat_id,
                "message_id": message_id,
                "media": json.dumps(media_obj)
            }
            if reply_markup:
                data["reply_markup"] = json.dumps(reply_markup) if isinstance(reply_markup, dict) else reply_markup

            files = {"photo": ("chart.png", photo_bytes, "image/png")}
            resp = requests.post(url, data=data, files=files, timeout=30)
            data_res = resp.json()
            if not data_res.get("ok"):
                desc = str(data_res.get("description", "")).lower()
                if "entities" in desc and caption:
                    # Retry with plain text caption on entity parse error
                    media_obj["parse_mode"] = ""
                    media_obj["caption"] = re.sub(r'<[^>]+>', '', caption)
                    data["media"] = json.dumps(media_obj)
                    resp = requests.post(url, data=data, files={"photo": ("chart.png", photo_bytes, "image/png")}, timeout=30)
                    data_res = resp.json()
                logger.warning(f"[Telegram] editMessageMedia note: {data_res.get('description')}")
            return data_res
        except Exception as e:
            logger.error(f"[Telegram] editMessageMedia exception: {e}")
            return None

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
                    "Akun atau grup Anda belum terdaftar di whitelist TIKWatch.\n\n"
                    f"• <b>Chat ID Anda:</b> <code>{chat_id}</code>\n"
                    f"• <b>User ID:</b> <code>{user_id}</code>\n"
                    f"• <b>Username:</b> @{username if username else '-'}\n"
                    f"• <b>Nama:</b> {first_name}\n\n"
                    "<i>Untuk memberikan akses, salin <b>Chat ID</b> di atas lalu masukkan ke menu "
                    "<b>Settings &gt; Telegram Bot Integration &gt; Authorized Chat IDs</b> di Web Dashboard TIKWatch, lalu klik tombol <b>Save All Settings</b>.</i>"
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
        elif cmd in ("/traffic", "/traffict", "/bandwidth", "/bw"):
            sub = args[0].lower().strip() if args else ""
            if not sub or sub in ("all", "semua", "backbone", "total"):
                self._cmd_traffic_summary(chat_id)
            elif sub in ("select", "pilih", "list", "daftar", "router", "routers"):
                self._cmd_traffic_picker(chat_id)
            elif sub in ("help", "bantuan", "?"):
                self._cmd_traffic_help(chat_id)
            else:
                self._cmd_traffic_device(chat_id, args)
        elif cmd in ("/traffic_all", "/traffict_all"):
            self._cmd_traffic_summary(chat_id)
        elif cmd in ("/traffic_select", "/traffict_select"):
            self._cmd_traffic_picker(chat_id)
        elif cmd in ("/chart", "/grafik", "/graph", "/plot"):
            self._cmd_chart(chat_id, args)
        elif cmd in ("/chart_all", "/chartall"):
            self._cmd_chart(chat_id, ["all"] + args)
        elif cmd in ("/chart_select", "/chartselect"):
            self._cmd_chart_picker(chat_id)
        elif cmd in ("/top", "/toptraffic", "/topbw", "/top_bandwidth"):
            self._cmd_top_bandwidth(chat_id)
        elif cmd in ("/capture", "/torch", "/live"):
            self._cmd_capture(chat_id, args)
        elif cmd in ("/iface", "/interfaces"):
            self._cmd_interfaces(chat_id, args)
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

        elif data.startswith("chart:"):
            # Format: chart:<target_key>:<time_range>
            parts = data.split(":")
            target_key = parts[1] if len(parts) > 1 else "all"
            time_range = parts[2] if len(parts) > 2 else "24h"
            self._send_or_update_chart(chat_id, target_key, time_range, message_id=message_id, cq_id=cq_id)

        elif data.startswith("cmd:"):
            action = data.split(":", 1)[1]
            if action == "down":
                self.answer_callback_query(cq_id)
                self._cmd_down(chat_id)
            elif action == "chart_picker":
                self.answer_callback_query(cq_id, text="📈 Memuat daftar router...")
                self._cmd_chart_picker(chat_id, edit_msg_id=message_id)
            elif action == "traffic_summary":
                self.answer_callback_query(cq_id, text="🔄 Memperbarui data traffic...")
                self._cmd_traffic_summary(chat_id, edit_msg_id=message_id)
            elif action == "traffic_picker":
                self.answer_callback_query(cq_id, text="🔀 Memuat daftar router...")
                self._cmd_traffic_picker(chat_id, edit_msg_id=message_id)
            elif action == "top_bandwidth":
                self.answer_callback_query(cq_id, text="🔄 Mengambil top bandwidth...")
                self._cmd_top_bandwidth(chat_id, edit_msg_id=message_id)
            elif action.startswith("traffic_dev:"):
                dev_id = action.split(":", 1)[1]
                self.answer_callback_query(cq_id, text="🔄 Memuat data traffic...")
                self._cmd_traffic_device(chat_id, [dev_id], edit_msg_id=message_id)
            elif action.startswith("capture:"):
                dev_id = action.split(":", 1)[1]
                self.answer_callback_query(cq_id, text="⏱️ Memulai live traffic capture (3s)...")
                self._cmd_capture(chat_id, [dev_id])

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
            "🏛️ <b>TIKWatch Bot</b> siap membantu monitoring utilisasi & kesehatan router kampus Politeknik Negeri Jember secara real-time.\n\n"
            "<b>📊 Monitoring Bandwidth & Traffic:</b>\n"
            "• <code>/traffic all</code> — Agregat bandwidth seluruh router (Hanya Uplink WAN)\n"
            "• <code>/traffic select</code> — Menu interaktif memilih router untuk melihat Active Ports\n"
            "• <code>/traffic &lt;nama/ip/id&gt;</code> — Detail uplink & active ports router spesifik\n"
            "• <code>/top</code> — Top 10 router dengan traffic uplink tertinggi\n"
            "• <code>/capture &lt;ip/id&gt;</code> — Live active capture traffic real-time via SNMP (3 detik)\n"
            "• <code>/iface &lt;ip/id&gt;</code> — Cek status & daftar interface perangkat\n\n"
            "<b>📈 Visualisasi Grafik Gambar (Charts):</b>\n"
            "• <code>/chart</code> — Grafik Total Backbone 24 Jam terakhir (PNG)\n"
            "• <code>/chart [1h|6h|24h|7d|30d]</code> — Grafik throughput dengan rentang waktu TIKWatch\n"
            "• <code>/chart &lt;nama/ip/id&gt;</code> — Grafik traffic router tertentu (contoh: <code>/chart core 7d</code>)\n"
            "• <code>/chart select</code> — Menu interaktif memilih router untuk digambar grafiknya\n\n"
            "<b>🖥️ Status Jaringan & Kontrol:</b>\n"
            "• <code>/status</code> atau <code>/summary</code> — Ringkasan kesehatan sistem & metrik perangkat\n"
            "• <code>/down</code> — Menampilkan seluruh perangkat yang sedang offline (DOWN)\n"
            "• <code>/alerts</code> — Daftar peringatan aktif yang belum di-acknowledge\n"
            "• <code>/devices</code> — Ringkasan jumlah perangkat per tipe dan zona\n"
            "• <code>/poll [all|ip]</code> — Polling ulang status perangkat sekarang\n"
            "• <code>/ack &lt;id&gt;</code> — Acknowledge alert berdasarkan ID\n"
            "• <code>/ack_all</code> — Acknowledge semua alert aktif sekaligus\n"
            "• <code>/digest</code> — Minta pengiriman Daily Digest sekarang\n"
            "• <code>/myid</code> — Menampilkan informasi Chat ID & User ID Anda\n\n"
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
            "• <b>Status Akses:</b> ✅ <i>Terotorisasi di TIKWatch</i>"
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
                f"{status_icon} <b>Ringkasan Status Jaringan TIKWatch</b>\n"
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

            buttons = []
            if down > 0:
                buttons.append([{"text": "🔴 Lihat Perangkat DOWN", "callback_data": "cmd:down"}])
            buttons.append([
                {"text": "📊 Traffic & Bandwidth", "callback_data": "cmd:traffic_summary"},
                {"text": "📈 Grafik 24 Jam", "callback_data": "chart:all:24h"}
            ])
            buttons.append([
                {"text": "🔝 Top Bandwidth", "callback_data": "cmd:top_bandwidth"}
            ])
            markup = {"inline_keyboard": buttons}

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

    def _cmd_traffic_summary(self, chat_id, edit_msg_id=None):
        try:
            routers = self.db.get_router_traffic_summary()
            now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            # Strictly separate routers with include_in_aggregate = 1 for the backbone aggregate calculation
            agg_routers = [r for r in routers if r.get('include_in_aggregate', 1) == 1]

            total_in = sum(r.get('wan_in') or 0.0 for r in agg_routers)
            total_out = sum(r.get('wan_out') or 0.0 for r in agg_routers)
            total_all = total_in + total_out

            total_uplink_mbps = sum(r.get('uplink_speed_mbps') or 1000 for r in agg_routers)
            total_uplink_bps = total_uplink_mbps * 1_000_000.0

            util_in = (total_in / total_uplink_bps * 100.0) if total_uplink_bps > 0 else 0.0
            util_out = (total_out / total_uplink_bps * 100.0) if total_uplink_bps > 0 else 0.0
            peak_util = max(util_in, util_out)
            headroom_mbps = max(0.0, total_uplink_mbps - (max(total_in, total_out) / 1_000_000.0))

            uplink_str = f"{total_uplink_mbps} Mbps" if total_uplink_mbps < 1000 else f"{total_uplink_mbps/1000:.1f} Gbps"

            text = (
                "🌐 <b>Ringkasan Backbone TIKWatch (Hanya Uplink WAN)</b>\n"
                f"<i>Waktu: {now_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"🌊 <b>THROUGHPUT BACKBONE ({len(agg_routers)} Router Agregasi ON):</b>\n"
                f"  📥 <b>Inbound (WAN IN):</b>  <b>{format_speed(total_in)}</b>\n"
                f"  📤 <b>Outbound (WAN OUT):</b> <b>{format_speed(total_out)}</b>\n"
                f"  ⚡ <b>Total Agregat:</b> <b>{format_speed(total_all)}</b>\n\n"
                "📈 <b>BANDWIDTH USAGE (Utilisasi Kapasitas Uplink):</b>\n"
                f"  🔌 <b>Kapasitas Backbone:</b> {uplink_str}\n"
                f"  📥 <b>Inbound Usage:</b>  <code>{format_bar(util_in, 8)}</code> {util_in:.1f}%\n"
                f"  📤 <b>Outbound Usage:</b> <code>{format_bar(util_out, 8)}</code> {util_out:.1f}%\n"
                f"  ⚡ <b>Utilisasi Tertinggi:</b> <b>{peak_util:.1f}%</b> (Sisa Headroom: {headroom_mbps:.1f} Mbps)\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
            )

            if routers:
                text += "🛰️ <b>Status Uplink Tiap Router (Agregasi ON):</b>\n\n"
                for r in routers[:8]:
                    rname = r.get('name') or r.get('ip')
                    rip = r.get('ip')
                    win = r.get('wan_in') or 0.0
                    wout = r.get('wan_out') or 0.0
                    uplink_mbps = r.get('uplink_speed_mbps') or 1000
                    uplink_bps = uplink_mbps * 1_000_000.0

                    peak_traffic = max(win, wout)
                    util_pct = (peak_traffic / uplink_bps * 100.0) if uplink_bps > 0 else 0.0
                    status_icon = "🟢" if r.get('status') == 'up' else "🔴"
                    warn_tag = " ⚠️ <i>(Saturasi)</i>" if util_pct >= 85 else ""

                    is_agg = r.get('include_in_aggregate', 1) == 1
                    is_bgp = 'bgp' in (r.get('name') or '').lower()
                    badge = "[Agg ON]" if is_agg else "[Agg OFF]"
                    if is_bgp:
                        badge = "[BGP / Agg ON]" if is_agg else "[BGP / Agg OFF]"

                    text += (
                        f"🔹 <b>{rname}</b> ({rip}) {status_icon} <code>{badge}</code>\n"
                        f"  📥 Uplink IN: <b>{format_speed(win)}</b> | 📤 Uplink OUT: <b>{format_speed(wout)}</b>\n"
                        f"  📊 Utilisasi: <code>{format_bar(util_pct, 8)}</code> {util_pct:.1f}% ({uplink_mbps}M){warn_tag}\n\n"
                    )
            else:
                text += "<i>Belum ada router atau perangkat dengan metrik WAN terdeteksi.</i>\n\n"

            text += (
                "💡 <i>Tampilan Semua Router hanya menampilkan traffic Uplink. "
                "Untuk melihat rincian <b>Active Port</b> tiap interface, pilih router via tombol di bawah.</i>"
            )

            markup = {
                "inline_keyboard": [
                    [
                        {"text": "📈 Grafik Backbone (24h)", "callback_data": "chart:all:24h"},
                        {"text": "📊 Grafik 7 Hari", "callback_data": "chart:all:7d"}
                    ],
                    [
                        {"text": "🔄 Refresh All (Uplink)", "callback_data": "cmd:traffic_summary"},
                        {"text": "🔝 Top 10 Uplink", "callback_data": "cmd:top_bandwidth"}
                    ],
                    [
                        {"text": "🔀 Pilih Router (Lihat Active Ports)", "callback_data": "cmd:traffic_picker"}
                    ]
                ]
            }

            if edit_msg_id:
                self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            logger.error(f"[Telegram] Error in traffic summary: {e}")
            self.send_message(chat_id, f"⚠️ Gagal mengambil ringkasan traffic: {e}")

    def _cmd_traffic_picker(self, chat_id, edit_msg_id=None):
        """Interactive router selector menu."""
        try:
            routers = self.db.get_router_traffic_summary()
            if not routers:
                all_devs = self.db.get_all_devices()
                routers = [d for d in all_devs if d.get('snmp_enabled')] or all_devs

            if not routers:
                self.send_message(chat_id, "ℹ️ Belum ada perangkat atau router yang terdaftar di database.")
                return

            text = (
                "🔀 <b>Pilih Router untuk Melihat Active Ports:</b>\n\n"
                "Pilih router spesifik di bawah untuk melihat rincian traffic <b>Active Ports</b> tiap interface, "
                "atau pilih <b>Semua Router</b> untuk ringkasan Uplink saja:\n"
            )

            buttons = []
            row = []
            for r in routers[:16]:
                rname = (r.get('name') or r.get('ip') or '')[:14]
                status_icon = "🟢" if r.get('status') == 'up' else "🔴"
                is_agg = r.get('include_in_aggregate', 1) == 1
                is_bgp = 'bgp' in (r.get('name') or '').lower()
                badge = "[Agg]" if is_agg else ""
                if is_bgp:
                    badge = "[BGP]"
                label = f"{status_icon} {rname} {badge}".strip()
                row.append({"text": label, "callback_data": f"cmd:traffic_dev:{r['id']}"})
                if len(row) == 2:
                    buttons.append(row)
                    row = []
            if row:
                buttons.append(row)

            buttons.append([
                {"text": "🌐 Semua Router (Hanya Uplink)", "callback_data": "cmd:traffic_summary"},
                {"text": "🔝 Top 10 Uplink", "callback_data": "cmd:top_bandwidth"}
            ])

            markup = {"inline_keyboard": buttons}

            if edit_msg_id:
                self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            logger.error(f"[Telegram] Error in traffic picker: {e}")
            self.send_message(chat_id, f"⚠️ Gagal memuat daftar router: {e}")

    def _cmd_traffic_help(self, chat_id):
        """Show guide for traffic subcommands."""
        text = (
            "ℹ️ <b>Panduan Perintah Traffic & Bandwidth:</b>\n\n"
            "• <code>/traffic all</code> — Pantau ringkasan bandwidth seluruh router (Hanya Uplink WAN)\n"
            "• <code>/traffic select</code> — Menu interaktif memilih router untuk melihat rincian Active Ports\n"
            "• <code>/traffic &lt;nama/ip/id&gt;</code> — Langsung pilih router (tampilkan Uplink & Active Ports)\n"
            "• <code>/top</code> — Top 10 router dengan traffic uplink tertinggi\n"
            "• <code>/capture &lt;ip/id&gt;</code> — Live active capture traffic real-time via SNMP (3 detik)"
        )
        markup = {
            "inline_keyboard": [
                [
                    {"text": "🌐 Semua Router (Uplink)", "callback_data": "cmd:traffic_summary"},
                    {"text": "🔀 Pilih Router (Active Ports)", "callback_data": "cmd:traffic_picker"}
                ]
            ]
        }
        self.send_message(chat_id, text, reply_markup=markup)
        markup = {
            "inline_keyboard": [
                [
                    {"text": "🌐 Semua Router (All)", "callback_data": "cmd:traffic_summary"},
                    {"text": "🔀 Pilih Router (Select)", "callback_data": "cmd:traffic_picker"}
                ]
            ]
        }
        self.send_message(chat_id, text, reply_markup=markup)

    def _find_device_by_target(self, target):
        """Find a device by ID, IP, exact name, or partial name."""
        if not target:
            return None
        t = str(target).strip()
        if t.isdigit():
            dev = self.db.get_device(int(t))
            if dev:
                return dev
        dev = self.db.get_device_by_ip(t)
        if dev:
            return dev
        all_devs = self.db.get_all_devices()
        t_low = t.lower()
        for d in all_devs:
            if (d.get('name') or '').strip().lower() == t_low:
                return d
        for d in all_devs:
            if t_low in (d.get('name') or '').lower():
                return d
        # Helpful match for common router role keywords (e.g. bgp, core, gateway)
        if t_low in ("bgp", "router bgp", "router_bgp", "edge", "gateway", "core"):
            for d in all_devs:
                if d.get('type') == 'router' and d.get('include_in_aggregate', 1) == 1:
                    return d
        return None

    def _cmd_chart(self, chat_id, args):
        """Handle /chart command for generating traffic PNG images."""
        if not is_chart_available():
            self.send_message(
                chat_id,
                "⚠️ <b>Fitur Grafik Membutuhkan Modul Matplotlib</b>\n\n"
                "Modul visualisasi <code>matplotlib</code> belum terpasang di virtual environment server.\n"
                "Silakan jalankan update di server Linux:\n"
                "<code>sudo ./update.sh</code>\n"
                "untuk memasang dependensi grafik secara otomatis tanpa merusak database."
            )
            return

        target_id = "all"
        time_range = "24h"

        if not args:
            self._send_or_update_chart(chat_id, "all", "24h")
            return

        first_arg = args[0].lower().strip()
        if first_arg in ("select", "pilih", "list", "daftar", "router", "routers"):
            tr = args[1].lower().strip() if len(args) > 1 else "24h"
            self._cmd_chart_picker(chat_id, time_range=tr)
            return
        elif first_arg in ("help", "bantuan", "?"):
            self._cmd_chart_help(chat_id)
            return
        elif first_arg in ("all", "semua", "backbone", "total"):
            target_id = "all"
            if len(args) > 1:
                time_range = args[1].lower().strip()
            self._send_or_update_chart(chat_id, target_id, time_range)
            return

        # Check if first argument is a time range like "1h", "6h", "24h", "7d", "30d"
        valid_ranges = ("1h", "6h", "24h", "7d", "30d", "1m", "1hour", "6hours", "24hours", "7days", "30days", "1month")
        if first_arg in valid_ranges:
            target_id = "all"
            time_range = first_arg
            self._send_or_update_chart(chat_id, target_id, time_range)
            return

        # Target is a router / device
        device = self._find_device_by_target(args[0])
        if not device:
            self.send_message(
                chat_id,
                f"⚠️ Router / perangkat <code>{html.escape(args[0])}</code> tidak ditemukan.\n\n"
                "Ketik <code>/chart select</code> untuk memilih router dari daftar interaktif."
            )
            return

        target_id = str(device['id'])
        if len(args) > 1:
            time_range = args[1].lower().strip()

        self._send_or_update_chart(chat_id, target_id, time_range)

    def _cmd_chart_picker(self, chat_id, time_range='24h', edit_msg_id=None):
        """Interactive router selector menu specifically for charts."""
        try:
            routers = self.db.get_router_traffic_summary()
            if not routers:
                all_devs = self.db.get_all_devices()
                routers = [d for d in all_devs if d.get('snmp_enabled')] or all_devs

            text = (
                f"📈 <b>Pilih Target Grafik Traffic (Rentang: {time_range}):</b>\n\n"
                "Pilih <b>Total Backbone</b> untuk agregasi seluruh router (Agregasi ON), "
                "atau pilih <b>Router Tunggal / BGP</b> di bawah:\n"
            )

            buttons = []
            row = []
            for r in routers[:16]:
                rname = (r.get('name') or r.get('ip') or '')[:14]
                status_icon = "🟢" if r.get('status') == 'up' else "🔴"
                is_agg = r.get('include_in_aggregate', 1) == 1
                is_bgp = 'bgp' in (r.get('name') or '').lower()
                badge = "[Agg]" if is_agg else ""
                if is_bgp:
                    badge = "[BGP]"
                label = f"{status_icon} {rname} {badge}".strip()
                row.append({"text": label, "callback_data": f"chart:{r['id']}:{time_range}"})
                if len(row) == 2:
                    buttons.append(row)
                    row = []
            if row:
                buttons.append(row)

            buttons.append([
                {"text": "🌐 Total Backbone (Agregasi ON)", "callback_data": f"chart:all:{time_range}"},
                {"text": "📋 Teks Traffic", "callback_data": "cmd:traffic_summary"}
            ])

            markup = {"inline_keyboard": buttons}
            if edit_msg_id:
                self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            logger.error(f"[Telegram] Error in chart picker: {e}")
            self.send_message(chat_id, f"⚠️ Gagal memuat pemilih router: {e}")

    def _cmd_chart_help(self, chat_id):
        text = (
            "📊 <b>Panduan Perintah Grafik Traffic (/chart):</b>\n\n"
            "• <code>/chart</code> — Grafik Total Backbone 24 Jam terakhir (PNG)\n"
            "• <code>/chart &lt;rentang&gt;</code> — Grafik Total Backbone dengan rentang waktu:\n"
            "   ▫️ <code>/chart 1h</code> — 1 Jam terakhir\n"
            "   ▫️ <code>/chart 6h</code> — 6 Jam terakhir\n"
            "   ▫️ <code>/chart 24h</code> — 24 Jam terakhir (default)\n"
            "   ▫️ <code>/chart 7d</code> — 7 Hari terakhir\n"
            "   ▫️ <code>/chart 30d</code> — 30 Hari / 1 Bulan terakhir\n"
            "• <code>/chart &lt;router&gt;</code> — Grafik router spesifik (contoh: <code>/chart core</code> atau <code>/chart 192.168.1.1</code>)\n"
            "• <code>/chart &lt;router&gt; &lt;rentang&gt;</code> — Contoh: <code>/chart core 7d</code>\n"
            "• <code>/chart select</code> — Menu interaktif memilih router untuk digambar grafiknya\n\n"
            "<i>💡 Setiap gambar grafik dilengkapi tombol interaktif di bawahnya untuk beralih rentang waktu secara instan!</i>"
        )
        markup = {
            "inline_keyboard": [
                [
                    {"text": "📈 Grafik Backbone (24h)", "callback_data": "chart:all:24h"},
                    {"text": "📊 Grafik 7 Hari", "callback_data": "chart:all:7d"},
                ],
                [
                    {"text": "🔀 Pilih Router", "callback_data": "cmd:chart_picker"},
                    {"text": "📋 Teks Traffic", "callback_data": "cmd:traffic_summary"}
                ]
            ]
        }
        self.send_message(chat_id, text, reply_markup=markup)

    def _send_or_update_chart(self, chat_id, target_id, time_range='24h', message_id=None, cq_id=None):
        """Fetch data, render chart PNG, and send or edit photo with interactive buttons."""
        if not is_chart_available():
            if cq_id:
                self.answer_callback_query(cq_id, text="⚠️ Modul matplotlib belum terpasang di server.", show_alert=True)
            else:
                self.send_message(chat_id, "⚠️ Modul matplotlib belum terpasang. Jalankan <code>sudo ./update.sh</code> di server.")
            return

        if cq_id:
            self.answer_callback_query(cq_id, text=f"📊 Menyiapkan grafik {time_range}...")

        # Fetch chart data from database
        dev_arg = None if str(target_id).lower() in ('all', 'backbone', 'total', '0') else target_id
        data = self.db.get_chart_traffic_data(device_id=dev_arg, time_range=time_range)

        # Render PNG image
        img_bytes = render_traffic_chart_image(data)
        if not img_bytes:
            self.send_message(chat_id, "⚠️ Gagal me-render gambar grafik.")
            return

        target_key = "all" if str(target_id).lower() in ('all', 'backbone', 'total', '0') else str(data['target_id'])
        target_name = data.get('target_name', 'Backbone Traffic')
        safe_target_name = html.escape(target_name)
        time_label = data.get('time_label', '24 Jam')
        cur_code = data.get('time_range', '24h')
        peak_rx = data.get('peak_rx', 0.0)
        peak_tx = data.get('peak_tx', 0.0)
        avg_rx = data.get('avg_rx', 0.0)
        avg_tx = data.get('avg_tx', 0.0)
        cur_rx = data.get('cur_rx', 0.0)
        cur_tx = data.get('cur_tx', 0.0)
        uplink_mbps = float(data.get('uplink_mbps') or 1000.0)
        sample_count = len(data.get('points', []))
        now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        # Bandwidth utilization metrics
        cur_rx_util = (cur_rx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
        cur_tx_util = (cur_tx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
        peak_rx_util = (peak_rx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
        peak_tx_util = (peak_tx / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0
        cur_peak_rate = max(cur_rx, cur_tx)
        cur_max_util = max(cur_rx_util, cur_tx_util)
        peak_max_util = max(peak_rx_util, peak_tx_util)
        headroom_mbps = max(0.0, uplink_mbps - cur_peak_rate)

        is_agg = data.get('is_aggregate', False)
        if is_agg:
            scope_badge = "🌐 <b>Scope:</b> Total Backbone Agregat (Router include_in_aggregate = ON)"
        else:
            agg_flag = "ON" if data.get('include_in_aggregate', 1) == 1 else "OFF"
            scope_badge = f"🛰️ <b>Scope:</b> Router Tunggal (BGP/Core, Agregasi: {agg_flag})"

        uplink_str = f"{int(uplink_mbps)} Mbps" if uplink_mbps < 1000 else f"{uplink_mbps/1000:.1f} Gbps"
        sat_warn = " ⚠️ <i>(Saturasi Tinggi &gt; 85%)</i>" if cur_max_util >= 85 else ""

        caption = (
            f"📊 <b>Grafik Throughput & Bandwidth — {safe_target_name}</b>\n"
            f"{scope_badge}\n"
            f"⏱️ <b>Rentang Waktu:</b> {time_label} ({sample_count} sampel)\n"
            f"🔌 <b>Kapasitas Link (Uplink):</b> <b>{uplink_str}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "🌊 <b>TRAFFIC THROUGHPUT (Laju Aliran):</b>\n"
            f"  📥 <b>WAN IN (Download):</b>\n"
            f"     • Terkini: <b>{cur_rx:.2f} Mbps</b>\n"
            f"     • Puncak: <b>{peak_rx:.2f} Mbps</b> | Rata-rata: {avg_rx:.2f} Mbps\n"
            f"  📤 <b>WAN OUT (Upload):</b>\n"
            f"     • Terkini: <b>{cur_tx:.2f} Mbps</b>\n"
            f"     • Puncak: <b>{peak_tx:.2f} Mbps</b> | Rata-rata: {avg_tx:.2f} Mbps\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "📈 <b>BANDWIDTH USAGE (Utilisasi Kapasitas):</b>\n"
            f"  📥 <b>Inbound:</b>  <code>{format_bar(cur_rx_util, 8)}</code> {cur_rx_util:.1f}%\n"
            f"  📤 <b>Outbound:</b> <code>{format_bar(cur_tx_util, 8)}</code> {cur_tx_util:.1f}%\n"
            f"  ⚡ <b>Beban Puncak Terkini:</b> <b>{cur_max_util:.1f}%</b> (Puncak: {peak_max_util:.1f}%){sat_warn}\n"
            f"  💡 <b>Headroom Bebas:</b> {headroom_mbps:.1f} Mbps ({max(0.0, 100.0 - cur_max_util):.1f}%)\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"<i>Waktu generate: {now_str} WIB</i>"
        )

        def b_lbl(label, code):
            return f"▶ {label}" if code == cur_code else label

        markup = {
            "inline_keyboard": [
                [
                    {"text": b_lbl("1 Jam", "1h"), "callback_data": f"chart:{target_key}:1h"},
                    {"text": b_lbl("6 Jam", "6h"), "callback_data": f"chart:{target_key}:6h"},
                    {"text": b_lbl("24 Jam", "24h"), "callback_data": f"chart:{target_key}:24h"},
                ],
                [
                    {"text": b_lbl("7 Hari", "7d"), "callback_data": f"chart:{target_key}:7d"},
                    {"text": b_lbl("30 Hari", "30d"), "callback_data": f"chart:{target_key}:30d"},
                    {"text": "🔄 Refresh", "callback_data": f"chart:{target_key}:{cur_code}"},
                ],
                [
                    {"text": "🔀 Pilih Router Lain", "callback_data": "cmd:chart_picker"},
                    {"text": "🌐 Total Backbone", "callback_data": f"chart:all:{cur_code}"},
                ],
                [
                    {"text": "📋 Teks Traffic", "callback_data": f"cmd:traffic_dev:{target_key}" if target_key != "all" else "cmd:traffic_summary"}
                ]
            ]
        }

        # If editing an existing photo message, attempt editMessageMedia
        if message_id:
            res = self.edit_message_media(chat_id, message_id, img_bytes, caption=caption, reply_markup=markup)
            if res and res.get('ok'):
                return
            if res and not res.get('ok'):
                desc = str(res.get('description', '')).lower()
                if "not modified" in desc:
                    return
                if "there is no media in the message to edit" in desc:
                    try:
                        self.delete_message(chat_id, message_id)
                    except Exception:
                        pass

        # Otherwise send fresh photo
        self.send_photo(chat_id, img_bytes, caption=caption, reply_markup=markup)

    def _cmd_traffic_device(self, chat_id, args, edit_msg_id=None):
        if not args:
            self._cmd_traffic_summary(chat_id, edit_msg_id=edit_msg_id)
            return

        target = str(args[0]).strip()
        device = self._find_device_by_target(target)

        if not device:
            self.send_message(
                chat_id,
                f"⚠️ Perangkat atau router dengan nama/IP/ID <code>{html.escape(target)}</code> tidak ditemukan.\n\n"
                "Ketik <code>/traffic select</code> untuk melihat daftar router yang tersedia."
            )
            return

        did = device.get('id')
        dname = device.get('name') or device.get('ip')
        dip = device.get('ip')
        dtype = device.get('type', 'device').capitalize()
        status = (device.get('status') or 'unknown').upper()
        status_icon = "🟢" if status == "UP" else ("🔴" if status == "DOWN" else "🟡")
        uplink_mbps = device.get('uplink_speed_mbps') or 1000
        uplink_bps = uplink_mbps * 1_000_000.0
        win = device.get('wan_in')
        wout = device.get('wan_out')

        now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        is_agg = device.get('include_in_aggregate', 1) == 1
        agg_label = "Aktif (ON)" if is_agg else "Non-Aktif (OFF)"

        text = (
            f"📡 <b>Monitoring Traffic & Bandwidth: {dname}</b>\n"
            f"• <b>IP:</b> <code>{dip}</code> | <b>Tipe:</b> {dtype}\n"
            f"• <b>Status:</b> {status_icon} <b>{status}</b> | <b>Agregasi:</b> {agg_label}\n"
            f"• <b>Kapasitas Link:</b> {uplink_mbps} Mbps\n"
        )

        if win is not None or wout is not None:
            win_val = win or 0.0
            wout_val = wout or 0.0
            pct_in = (win_val / uplink_bps * 100.0) if uplink_bps > 0 else 0.0
            pct_out = (wout_val / uplink_bps * 100.0) if uplink_bps > 0 else 0.0
            peak = max(win_val, wout_val)
            pct_peak = (peak / uplink_bps * 100.0) if uplink_bps > 0 else 0.0
            headroom_mbps = max(0.0, uplink_mbps - (peak / 1_000_000.0))

            text += (
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "🌊 <b>TRAFFIC THROUGHPUT:</b>\n"
                f"  📥 <b>WAN IN (Download):</b>  <b>{format_speed(win_val)}</b>\n"
                f"  📤 <b>WAN OUT (Upload):</b> <b>{format_speed(wout_val)}</b>\n"
                "📈 <b>BANDWIDTH USAGE:</b>\n"
                f"  📥 <b>Inbound:</b>  <code>{format_bar(pct_in, 8)}</code> {pct_in:.1f}%\n"
                f"  📤 <b>Outbound:</b> <code>{format_bar(pct_out, 8)}</code> {pct_out:.1f}%\n"
                f"  ⚡ <b>Utilisasi Tertinggi:</b> <b>{pct_peak:.1f}%</b> (Sisa Headroom: {headroom_mbps:.1f} Mbps)\n"
            )

        text += "━━━━━━━━━━━━━━━━━━━━━\n"
        text += "🔌 <b>ACTIVE PORTS TRAFFIC (Port Aktif):</b>\n\n"

        # Tampilkan HANYA interface aktif yang memiliki traffic (rx_bps + tx_bps > 0)
        active_ifaces = self.db.get_latest_device_interface_traffic(did, limit=15, active_only=True)
        if active_ifaces:
            for ifc in active_ifaces:
                iname = ifc.get('name')
                i_idx = str(ifc.get('idx') or '')
                rx = ifc.get('rx_bps') or 0.0
                tx = ifc.get('tx_bps') or 0.0
                total = ifc.get('total_bps') or (rx + tx)

                # Tandai jika active port ini adalah port Uplink WAN
                is_uplink_port = False
                if wan_idx and i_idx == wan_idx:
                    is_uplink_port = True
                elif any(k in iname.lower() for k in ('wan', 'sfp', 'sfpplus', 'ether1', 'pppoe')):
                    is_uplink_port = True

                tag = " <code>[Uplink WAN]</code>" if is_uplink_port else ""

                text += (
                    f"• <b>{iname}</b>{tag} (Total: <b>{format_speed(total)}</b>)\n"
                    f"  📥 RX: <b>{format_speed(rx)}</b> | 📤 TX: <b>{format_speed(tx)}</b>\n"
                )
        else:
            text += "<i>ℹ️ Tidak ada port yang sedang aktif mengalirkan traffic saat ini (seluruh port idle atau 0 bps).</i>\n"

        text += f"\n<i>Waktu: {now_str} WIB</i>"

        markup = {
            "inline_keyboard": [
                [
                    {"text": "📈 Grafik 24 Jam", "callback_data": f"chart:{did}:24h"},
                    {"text": "📊 Grafik 7 Hari", "callback_data": f"chart:{did}:7d"}
                ],
                [
                    {"text": "⚡ Live Capture (3s)", "callback_data": f"cmd:capture:{did}"},
                    {"text": "🔄 Refresh", "callback_data": f"cmd:traffic_dev:{did}"}
                ],
                [
                    {"text": "🔀 Pilih Router Lain", "callback_data": "cmd:traffic_picker"},
                    {"text": "🌐 Semua Router (Hanya Uplink)", "callback_data": "cmd:traffic_summary"}
                ]
            ]
        }

        if edit_msg_id:
            self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def _cmd_top_bandwidth(self, chat_id, edit_msg_id=None):
        try:
            top_uplinks = self.db.get_top_bandwidth_interfaces(limit=10)
            now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            text = (
                "🔝 <b>Top 10 Uplink Bandwidth (Hanya Uplink WAN):</b>\n"
                f"<i>Waktu: {now_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "<i>Daftar 10 router/perangkat dengan beban traffic uplink tertinggi:</i>\n\n"
            )

            if not top_uplinks:
                text += "<i>Belum ada data traffic uplink yang terekam atau seluruh router idle.</i>\n"
            else:
                medals = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]
                for i, row in enumerate(top_uplinks):
                    rank_icon = medals[i] if i < len(medals) else f"{i+1}."
                    dname = row.get('device_name') or row.get('device_ip')
                    dip = row.get('device_ip')
                    iname = row.get('iface_name', 'Uplink WAN')
                    rx = row.get('rx_bps') or 0.0
                    tx = row.get('tx_bps') or 0.0
                    tot = row.get('total_bps') or (rx + tx)
                    uplink_mbps = row.get('uplink_speed_mbps', 1000)
                    util_pct = row.get('util_pct', 0.0)

                    is_agg = row.get('include_in_aggregate', 1) == 1
                    is_bgp = 'bgp' in dname.lower()
                    badge = "[Agg ON]" if is_agg else "[Agg OFF]"
                    if is_bgp:
                        badge = "[BGP / Agg ON]" if is_agg else "[BGP]"

                    text += (
                        f"{rank_icon} <b>{dname}</b> (<code>{dip}</code>) {badge}\n"
                        f"   🔌 <b>Port:</b> <code>{iname}</code>\n"
                        f"   📥 In: <b>{format_speed(rx)}</b> | 📤 Out: <b>{format_speed(tx)}</b>\n"
                        f"   ⚡ <b>Total: {format_speed(tot)}</b>\n"
                        f"   📊 <b>Utilisasi:</b> <code>{format_bar(util_pct, 8)}</code> {util_pct:.1f}% ({uplink_mbps} Mbps)\n\n"
                    )

            markup = {
                "inline_keyboard": [
                    [
                        {"text": "🔄 Refresh Top Uplink", "callback_data": "cmd:top_bandwidth"},
                        {"text": "🔀 Pilih Router (Active Ports)", "callback_data": "cmd:traffic_picker"}
                    ],
                    [
                        {"text": "🌐 Pantau Semua Router (Uplink)", "callback_data": "cmd:traffic_summary"}
                    ]
                ]
            }

            if edit_msg_id:
                self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            logger.error(f"[Telegram] Error in top bandwidth: {e}")
            self.send_message(chat_id, f"⚠️ Gagal mengambil top bandwidth: {e}")

    def _cmd_capture(self, chat_id, args):
        if not args:
            self.send_message(
                chat_id,
                "ℹ️ Gunakan format: <code>/capture &lt;ip/id&gt;</code>\n"
                "Contoh: <code>/capture 192.168.1.1</code> atau <code>/capture 1</code>\n\n"
                "<i>Bot akan mengambil 2 sampel SNMP berjarak 3 detik secara langsung untuk menghitung throughput real-time tiap interface.</i>"
            )
            return

        target = str(args[0]).strip()
        device = None
        if target.isdigit():
            device = self.db.get_device(int(target))
        if not device:
            device = self.db.get_device_by_ip(target)

        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat dengan IP/ID <code>{target}</code> tidak ditemukan di database.")
            return

        if not device.get('snmp_enabled'):
            self.send_message(
                chat_id,
                f"⚠️ Perangkat <b>{device.get('name', target)}</b> ({device.get('ip')}) belum mengaktifkan SNMP.\n"
                "Aktifkan SNMP pada perangkat dan di menu Settings/Device TIKWatch untuk menggunakan fitur Live Capture."
            )
            return

        if not self.snmp_worker:
            self.send_message(chat_id, "⚠️ Worker SNMP belum siap.")
            return

        dname = device.get('name', target)
        dip = device.get('ip')
        did = device.get('id')

        # Send initial progress notice
        init_res = self.send_message(
            chat_id,
            f"⏱️ <i>Sedang melakukan <b>Live Traffic Capture (3 detik)</b> via SNMP pada <b>{dname}</b> ({dip})...\nMohon tunggu sebentar.</i>"
        )
        msg_id = init_res.get("result", {}).get("message_id") if init_res and init_res.get("ok") else None

        def _do_capture():
            results, err = self.snmp_worker.capture_live_traffic(device, sample_seconds=3)
            now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            if err or results is None:
                err_text = f"⚠️ Gagal melakukan live capture pada <b>{dname}</b> ({dip}):\n<i>{err or 'Unknown error'}</i>"
                if msg_id:
                    self.edit_message_text(chat_id, msg_id, err_text)
                else:
                    self.send_message(chat_id, err_text)
                return

            text = (
                f"⚡ <b>Hasil Live Traffic Capture (3 Detik):</b>\n"
                f"• <b>Perangkat:</b> <code>{dname}</code> ({dip})\n"
                f"• <b>Waktu Capture:</b> {now_str} WIB\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "🔌 <b>Throughput Interface Real-Time:</b>\n\n"
            )

            active_count = 0
            for r in results[:12]:
                rx = r.get('rx_bps', 0.0)
                tx = r.get('tx_bps', 0.0)
                tot = r.get('total_bps', 0.0)
                if tot > 0:
                    active_count += 1
                text += (
                    f"• <b>{r.get('name')}</b> (Total: <b>{format_speed(tot)}</b>)\n"
                    f"  📥 RX: {format_speed(rx)} | 📤 TX: {format_speed(tx)}\n"
                )

            if not results:
                text += "<i>Tidak ada interface yang merespons counter traffic.</i>\n"

            text += f"\n✅ <i>Capture selesai. Terdeteksi {len(results)} interface ({active_count} aktif).</i>"

            markup = {
                "inline_keyboard": [
                    [
                        {"text": "⚡ Capture Ulang (3s)", "callback_data": f"cmd:capture:{did}"},
                        {"text": "📊 Detail Traffic", "callback_data": f"cmd:traffic_dev:{did}"}
                    ]
                ]
            }

            if msg_id:
                self.edit_message_text(chat_id, msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)

        threading.Thread(target=_do_capture, daemon=True).start()

    def _cmd_interfaces(self, chat_id, args):
        if not args:
            self.send_message(chat_id, "ℹ️ Masukkan IP atau ID perangkat. Contoh: <code>/iface 192.168.1.1</code>")
            return
        target = str(args[0]).strip()
        device = None
        if target.isdigit():
            device = self.db.get_device(int(target))
        if not device:
            device = self.db.get_device_by_ip(target)

        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat dengan IP/ID <code>{target}</code> tidak ditemukan.")
            return

        self._cmd_traffic_device(chat_id, [device['id']])

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
            f"{icon} <b>[TIKWatch] {title}</b>\n"
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
                "📊 <b>TIKWatch DAILY DIGEST</b>\n"
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
                "<i>Gunakan /status atau buka Web Dashboard TIKWatch untuk detail lengkap.</i>"
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
            "🧪 <b>Uji Coba Integrasi Telegram TIKWatch</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "✅ <b>Koneksi Berhasil!</b> Bot Telegram telah terhubung dengan server TIKWatch.\n"
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
