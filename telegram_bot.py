"""
NetMon — Telegram Bot Integration Module
Provides 2-way interactive Telegram Bot and automated alert notifications.
Uses standard requests library (lightweight, zero dependency conflicts).
"""

import html
import json
import logging
import os
import platform
import re
import shutil
import socket
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

    def __init__(self, db, socketio=None, snmp_worker=None, start_polling=True):
        self.db = db
        self.socketio = socketio
        self.snmp_worker = snmp_worker
        self.start_polling = start_polling

        self.bot_token = ""
        self.chat_ids = []
        self.enabled = False
        self.notify_down = True
        self.notify_up = True
        self.censor_ips = True
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
        self.censor_ips = settings.get('telegram_censor_ips', 'true').lower() != 'false'
        self.daily_digest_enabled = settings.get('telegram_daily_digest_enabled', 'true').lower() == 'true'
        self.daily_digest_time = settings.get('telegram_daily_digest_time', '08:00').strip() or "08:00"

        if self.enabled and self.bot_token:
            if not self.start_polling:
                return
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
            {"command": "ai", "description": "Tanya AI NOC tentang kondisi jaringan live"},
            {"command": "diagnosa", "description": "Diagnosa mendalam router dengan AI"},
            {"command": "traffic", "description": "Traffic: All router / Selected router"},
            {"command": "resource", "description": "Resource usage: Server / All router / Selected"},
            {"command": "server", "description": "Resource usage server TIKWatch (CPU/RAM/Disk)"},
            {"command": "chart", "description": "Grafik gambar traffic (1h, 6h, 24h, 7d, 30d)"},
            {"command": "top", "description": "Top 10 bandwidth interface tertinggi"},
            {"command": "capture", "description": "Live capture traffic real-time via SNMP"},
            {"command": "down", "description": "Daftar perangkat offline"},
            {"command": "reboots", "description": "Riwayat perangkat yang mengalami reboot"},
            {"command": "mute", "description": "Maintenance mode: bisukan alert (/mute <target> <menit>)"},
            {"command": "unmute", "description": "Matikan maintenance mode (/unmute <target>)"},
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

    _IPV4_RE = re.compile(
        r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?(?![\d.])'
    )
    _HTML_TOKEN_RE = re.compile(
        r'(<tg-spoiler>.*?</tg-spoiler>|<code\b[^>]*>.*?</code>|<pre\b[^>]*>.*?</pre>|<[^>]+>)',
        re.IGNORECASE | re.DOTALL
    )

    def _censor_ips_html(self, text):
        """Wrap IPv4 addresses in Telegram native <tg-spoiler> (click/tap to reveal)."""
        if not getattr(self, 'censor_ips', True) or not text:
            return text
        parts = self._HTML_TOKEN_RE.split(str(text))
        out = []
        for part in parts:
            if not part:
                continue
            low = part.lower()
            if low.startswith('<tg-spoiler>'):
                out.append(part)
            elif low.startswith('<code'):
                m = re.match(r'^<code\b[^>]*>(.*)</code>$', part, re.IGNORECASE | re.DOTALL)
                if m:
                    inner = m.group(1)
                    if self._IPV4_RE.fullmatch(inner.strip()):
                        out.append(f'<tg-spoiler>{inner.strip()}</tg-spoiler>')
                    else:
                        replaced = self._IPV4_RE.sub(r'</code><tg-spoiler>\g<0></tg-spoiler><code>', inner)
                        out.append(f'<code>{replaced}</code>'.replace('<code></code>', ''))
                else:
                    out.append(part)
            elif low.startswith('<pre'):
                m = re.match(r'^<pre\b[^>]*>(.*)</pre>$', part, re.IGNORECASE | re.DOTALL)
                if m:
                    replaced = self._IPV4_RE.sub(r'</pre><tg-spoiler>\g<0></tg-spoiler><pre>', m.group(1))
                    out.append(f'<pre>{replaced}</pre>'.replace('<pre></pre>', ''))
                else:
                    out.append(part)
            elif part.startswith('<'):
                out.append(part)
            else:
                out.append(self._IPV4_RE.sub(r'<tg-spoiler>\g<0></tg-spoiler>', part))
        return ''.join(out)

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
        if parse_mode == "HTML":
            text = self._censor_ips_html(text)
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
        if parse_mode == "HTML":
            text = self._censor_ips_html(text)
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
            if caption and parse_mode == "HTML":
                caption = self._censor_ips_html(caption)
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
            if caption and parse_mode == "HTML":
                caption = self._censor_ips_html(caption)
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
                    f"• <b>Username:</b> @{html.escape(str(username)) if username else '-'}\n"
                    f"• <b>Nama:</b> {html.escape(str(first_name))}\n\n"
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
        elif cmd in ("/server", "/server_resource", "/host"):
            self._cmd_resource_server(chat_id)
        elif cmd in ("/resource", "/resources", "/res"):
            sub = args[0].lower().strip() if args else ""
            if not sub or sub in ("all", "semua", "router", "routers"):
                self._cmd_resource_all(chat_id)
            elif sub in ("server", "host", "netmon", "tikwatch"):
                self._cmd_resource_server(chat_id)
            elif sub in ("select", "pilih", "list", "daftar"):
                self._cmd_resource_picker(chat_id)
            else:
                self._cmd_resource_device(chat_id, args)
        elif cmd in ("/resource_all", "/res_all"):
            self._cmd_resource_all(chat_id)
        elif cmd in ("/resource_select", "/res_select"):
            self._cmd_resource_picker(chat_id)
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
        elif cmd in ("/reboots", "/reboot"):
            self._cmd_reboots(chat_id)
        elif cmd in ("/mute", "/maintenance", "/maint"):
            self._cmd_mute(chat_id, args)
        elif cmd in ("/unmute", "/unmaint"):
            self._cmd_unmute(chat_id, args)
        elif cmd in ("/ai", "/tanya", "/ask"):
            self._cmd_ai(chat_id, args)
        elif cmd in ("/diagnosa", "/analisa", "/diagnose"):
            self._cmd_diagnosa(chat_id, args)
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

                # Live update message to show who acknowledged it (escape original plain text & preserve IP spoiler)
                orig_text = html.escape(str(msg.get("text", "")))
                now_str = datetime.now().strftime("%H:%M:%S")
                updated_text = orig_text + f"\n\n✅ <i>Di-acknowledge oleh @{html.escape(str(username))} pukul {now_str} WIB</i>"

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
            elif action == "resource_server":
                self.answer_callback_query(cq_id, text="🔄 Memperbarui resource server...")
                self._cmd_resource_server(chat_id, edit_msg_id=message_id)
            elif action == "resource_all":
                self.answer_callback_query(cq_id, text="🔄 Memperbarui resource semua router...")
                self._cmd_resource_all(chat_id, edit_msg_id=message_id)
            elif action == "resource_picker":
                self.answer_callback_query(cq_id, text="🔀 Memuat daftar router...")
                self._cmd_resource_picker(chat_id, edit_msg_id=message_id)
            elif action.startswith("resource_dev:"):
                dev_id = action.split(":", 1)[1]
                self.answer_callback_query(cq_id, text="🔄 Memuat resource router...")
                self._cmd_resource_device(chat_id, [dev_id], edit_msg_id=message_id)
            elif action.startswith("mute:"):
                # Format: cmd:mute:<target>:<minutes>
                parts = action.split(":")
                m_target = parts[1] if len(parts) > 1 else "all"
                m_mins = int(parts[2]) if len(parts) > 2 and parts[2].lstrip('-').isdigit() else 60
                until_str = self.db.set_maintenance_window(m_target, m_mins)
                if until_str:
                    self.answer_callback_query(cq_id, text=f"🔕 Maintenance aktif s/d {until_str} WIB")
                    self.send_message(chat_id, f"🔕 <b>Maintenance Mode Diaktifkan</b> untuk ID/Target <code>{m_target}</code> hingga <b>{until_str} WIB</b>.")
                else:
                    self.answer_callback_query(cq_id, text="🔔 Maintenance mode dimatikan")
                    self.send_message(chat_id, f"🔔 <b>Maintenance Mode Dimatikan</b> untuk ID/Target <code>{m_target}</code>.")
            elif action.startswith("ai_alert:"):
                aid = action.split(":", 1)[1]
                self.answer_callback_query(cq_id, text="🤖 Menganalisa alert dengan Groq AI...")
                threading.Thread(target=self._run_ai_alert_analysis, args=(chat_id, aid), daemon=True).start()
            elif action.startswith("ai_dev:"):
                did = action.split(":", 1)[1]
                self.answer_callback_query(cq_id, text="🤖 Menganalisa perangkat dengan Groq AI...")
                self._cmd_diagnosa(chat_id, [did])

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
                f"• <b>Perangkat:</b> <code>{html.escape(str(updated.get('name') or updated.get('ip')))}</code> ({updated.get('ip')})\n"
                f"• <b>Status:</b> {icon} <b>{status}</b>\n"
                f"• <b>Latensi:</b> {lat}\n"
                f"• <b>Terakhir Dilihat:</b> {html.escape(str(updated.get('last_seen') or '-'))}"
            )
            self.send_message(chat_id, reply)
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal polling {device.get('ip')}: {html.escape(str(e))}")

    # ─── Bot Commands ────────────────────────────────────────────────

    def _cmd_help(self, chat_id, name):
        text = (
            f"👋 Halo, <b>{html.escape(str(name))}</b>!\n\n"
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
            "<b>🤖 AI NOC Assistant (Groq LLM):</b>\n"
            "• <code>/ai &lt;pertanyaan&gt;</code> — Tanya AI tentang kondisi jaringan, bottleneck 6 Gbps, atau alert aktif\n"
            "• <code>/diagnosa &lt;nama/ip/id&gt;</code> — Diagnosa AI kesehatan perangkat & rekomendasi RouterOS\n\n"
            "<b>🖥️ Status Jaringan, Resource & Kontrol:</b>\n"
            "• <code>/server</code> atau <code>/resource server</code> — Resource usage server TIKWatch (CPU, RAM, Disk, Uptime)\n"
            "• <code>/resource all</code> — Resource usage (CPU, RAM, Temp) seluruh router\n"
            "• <code>/resource select</code> — Menu interaktif memilih router untuk cek resource\n"
            "• <code>/resource &lt;nama/ip/id&gt;</code> — Detail resource usage router spesifik\n"
            "• <code>/status</code> atau <code>/summary</code> — Ringkasan kesehatan sistem & metrik perangkat\n"
            "• <code>/down</code> — Menampilkan seluruh perangkat yang sedang offline (DOWN)\n"
            "• <code>/reboots</code> — Riwayat perangkat yang terdeteksi reboot\n"
            "• <code>/mute &lt;nama/ip/all&gt; [menit]</code> — Maintenance window (bisukan alert sementara, default 60m)\n"
            "• <code>/unmute [nama/ip/all]</code> — Akhiri maintenance window\n"
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
            f"• <b>Nama:</b> {html.escape(str(first_name))}\n"
            f"• <b>Username:</b> @{html.escape(str(username)) if username else '-'}\n"
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
                dname = html.escape(str(a.get('device_name') or a.get('device_ip') or 'Device'))
                msg = html.escape(str(a.get('message') or '-'))
                ts = html.escape(str(a.get('created_at') or '-'))
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

    def _cmd_reboots(self, chat_id):
        """Show recent device reboot events from downtime_analysis."""
        try:
            with self.db.conn() as c:
                rows = c.execute('''
                    SELECT d.name, d.ip, da.down_time, da.up_time, da.duration_sec, da.justification
                    FROM downtime_analysis da
                    JOIN devices d ON da.device_id = d.id
                    WHERE da.reboot_detected = 1
                    ORDER BY da.id DESC
                    LIMIT 15
                ''').fetchall()
            if not rows:
                self.send_message(chat_id, "✅ Belum ada riwayat perangkat yang terdeteksi reboot.")
                return
            lines = [f"🔄 <b>Riwayat Perangkat Reboot ({len(rows)} Terbaru):</b>\n"]
            for i, r in enumerate(rows, start=1):
                name = html.escape(str(r['name'] or r['ip']))
                ip = r['ip'] or '-'
                ts = (r['up_time'] or r['down_time'] or '-')[:19].replace('T', ' ')
                dur = int(r['duration_sec'] or 0)
                dur_str = f"{dur}s" if dur < 60 else f"{dur // 60}m {dur % 60}s"
                just = html.escape(str(r['justification'] or '-'))
                lines.append(
                    f"{i}. <b>{name}</b> (<code>{ip}</code>)\n"
                    f"   🕒 {ts} (Durasi: {dur_str})\n"
                    f"   📝 <i>{just}</i>\n"
                )
            self.send_message(chat_id, "\n".join(lines))
        except Exception as e:
            logger.error(f"[Telegram] Error in _cmd_reboots: {e}")
            self.send_message(chat_id, f"⚠️ Gagal mengambil riwayat reboot: {e}")

    def _cmd_down(self, chat_id):
        try:
            devices = self.db.get_all_devices()
            down_devs = [d for d in devices if d.get('status') == 'down']

            if not down_devs:
                self.send_message(chat_id, "🟢 <b>Luar Biasa!</b> Tidak ada perangkat yang sedang DOWN saat ini.")
                return

            text = f"🔴 <b>Perangkat DOWN ({len(down_devs)} Perangkat):</b>\n\n"
            for d in down_devs:
                name = html.escape(str(d.get('name') or d.get('ip')))
                ip = d.get('ip')
                dtype = html.escape(str(d.get('type') or 'Unknown'))
                last_seen = html.escape(str(d.get('last_seen') or 'Belum pernah'))
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
                text += f"• <b>{html.escape(str(z.get('name') or '-'))}:</b> {len(z_devs)} perangkat (🟢 {z_up}/{len(z_devs)} UP)\n"

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
            self.send_message(chat_id, f"✅ Alert <b>#{aid}</b> telah berhasil di-acknowledge oleh @{html.escape(str(username))}.")
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
            self.send_message(chat_id, f"✅ Seluruh alert aktif berhasil di-acknowledge oleh @{html.escape(str(username))}.")
        except Exception as e:
            self.send_message(chat_id, f"⚠️ Gagal ack all: {e}")

    def _cmd_poll(self, chat_id, args):
        if not self.snmp_worker:
            self.send_message(chat_id, "⚠️ Worker polling belum aktif atau belum siap.")
            return

        if not args:
            self.send_message(chat_id, "ℹ️ Gunakan: <code>/poll &lt;nama/ip/id&gt;</code> untuk satu perangkat, atau <code>/poll all</code> untuk re-check seluruh perangkat.")
            return

        target = " ".join(args).strip()
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

        device = self._find_device_by_target(target)
        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat <code>{html.escape(target)}</code> tidak ditemukan di database.")
            return

        dname = html.escape(str(device.get('name') or target))
        self.send_message(chat_id, f"🔄 Memulai polling untuk <b>{dname}</b> ({device.get('ip')})...")
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

            total_uplink_mbps = self.db.get_campus_total_bandwidth_mbps()
            total_uplink_bps = total_uplink_mbps * 1_000_000.0

            util_in = (total_in / total_uplink_bps * 100.0) if total_uplink_bps > 0 else 0.0
            util_out = (total_out / total_uplink_bps * 100.0) if total_uplink_bps > 0 else 0.0
            peak_util = max(util_in, util_out)
            headroom_mbps = max(0.0, total_uplink_mbps - (max(total_in, total_out) / 1_000_000.0))

            uplink_str = f"{int(total_uplink_mbps)} Mbps" if total_uplink_mbps < 1000 else f"{total_uplink_mbps/1000:.1f} Gbps"

            header = (
                "🌐 <b>Ringkasan Backbone TIKWatch (Hanya Uplink WAN)</b>\n"
                f"<i>Waktu: {now_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"🌊 <b>THROUGHPUT BACKBONE ({len(agg_routers)} Router Agregasi ON):</b>\n"
                f"  📥 <b>Inbound (WAN IN):</b>  <b>{format_speed(total_in)}</b>\n"
                f"  📤 <b>Outbound (WAN OUT):</b> <b>{format_speed(total_out)}</b>\n"
                f"  ⚡ <b>Total Agregat:</b> <b>{format_speed(total_all)}</b>\n\n"
                "📈 <b>BANDWIDTH USAGE (Kapasitas Total ISP Kampus):</b>\n"
                f"  🔌 <b>Kapasitas ISP Kampus:</b> {uplink_str}\n"
                f"  📥 <b>Inbound Usage:</b>  <code>{format_bar(util_in, 8)}</code> {util_in:.1f}%\n"
                f"  📤 <b>Outbound Usage:</b> <code>{format_bar(util_out, 8)}</code> {util_out:.1f}%\n"
                f"  ⚡ <b>Utilisasi Tertinggi:</b> <b>{peak_util:.1f}%</b> (Sisa Headroom: {headroom_mbps:.1f} Mbps)\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
            )

            footer = (
                "💡 <i>Tampilan Semua Router hanya menampilkan traffic Uplink. "
                "Untuk melihat rincian <b>Active Port</b> tiap interface, pilih router via tombol di bawah.</i>"
            )

            messages = []
            if routers:
                current_msg = header + f"🛰️ <b>Status Uplink Semua Router ({len(routers)}):</b>\n\n"
                for idx, r in enumerate(routers, start=1):
                    rname = html.escape(str(r.get('name') or r.get('ip') or '-'))
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

                    block = (
                        f"{idx}. 🔹 <b>{rname}</b> ({rip}) {status_icon} <code>{badge}</code>\n"
                        f"  📥 IN: <b>{format_speed(win)}</b> | 📤 OUT: <b>{format_speed(wout)}</b>\n"
                        f"  📊 Util: <code>{format_bar(util_pct, 8)}</code> {util_pct:.1f}% ({uplink_mbps}M){warn_tag}\n\n"
                    )
                    if len(current_msg) + len(block) > 3600:
                        messages.append(current_msg)
                        current_msg = f"🛰️ <b>Lanjutan Status Uplink Router ({idx}-{len(routers)}):</b>\n\n"
                    current_msg += block

                if len(current_msg) + len(footer) > 3950:
                    messages.append(current_msg)
                    messages.append(footer)
                else:
                    messages.append(current_msg + footer)
            else:
                messages.append(header + "<i>Belum ada router atau perangkat dengan metrik WAN terdeteksi.</i>\n\n" + footer)

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

            for i, msg_text in enumerate(messages):
                is_last = (i == len(messages) - 1)
                rm = markup if is_last else None
                if i == 0 and edit_msg_id:
                    self.edit_message_text(chat_id, edit_msg_id, msg_text, reply_markup=rm)
                else:
                    self.send_message(chat_id, msg_text, reply_markup=rm)
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
            for r in routers[:90]:
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

    # ─── Server & Router Resource Usage Commands ────────────────────

    def _get_server_resource_metrics(self):
        """Collect Linux host CPU, RAM, Swap, Disk, Load Average, Uptime, and DB size."""
        metrics = {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "cpu_cores": os.cpu_count() or 1,
            "cpu_pct": None,
            "load_avg": None,
            "mem_total_mb": None,
            "mem_used_mb": None,
            "mem_pct": None,
            "swap_total_mb": 0.0,
            "swap_used_mb": 0.0,
            "swap_pct": 0.0,
            "disk_total_gb": None,
            "disk_used_gb": None,
            "disk_pct": None,
            "uptime_str": "-",
            "proc_rss_mb": None,
            "db_size_mb": None,
        }

        # CPU % via /proc/stat (200ms delta)
        try:
            def _read_proc_stat():
                with open("/proc/stat", "r") as f:
                    parts = f.readline().split()
                vals = [int(x) for x in parts[1:]]
                idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                total = sum(vals)
                return idle, total

            idle1, total1 = _read_proc_stat()
            time.sleep(0.2)
            idle2, total2 = _read_proc_stat()
            total_delta = total2 - total1
            idle_delta = idle2 - idle1
            if total_delta > 0:
                metrics["cpu_pct"] = max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0))
        except Exception:
            pass

        # Load average
        try:
            l1, l5, l15 = os.getloadavg()
            metrics["load_avg"] = f"{l1:.2f}, {l5:.2f}, {l15:.2f}"
        except Exception:
            pass

        # RAM & Swap via /proc/meminfo
        try:
            meminfo = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        meminfo[k.strip()] = int(v.strip().split()[0])  # kB
            if "MemTotal" in meminfo:
                tot_kb = meminfo["MemTotal"]
                avail_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
                used_kb = max(0, tot_kb - avail_kb)
                metrics["mem_total_mb"] = tot_kb / 1024.0
                metrics["mem_used_mb"] = used_kb / 1024.0
                metrics["mem_pct"] = (used_kb / tot_kb * 100.0) if tot_kb > 0 else 0.0
            if meminfo.get("SwapTotal", 0) > 0:
                st_kb = meminfo["SwapTotal"]
                sf_kb = meminfo.get("SwapFree", 0)
                su_kb = max(0, st_kb - sf_kb)
                metrics["swap_total_mb"] = st_kb / 1024.0
                metrics["swap_used_mb"] = su_kb / 1024.0
                metrics["swap_pct"] = (su_kb / st_kb * 100.0) if st_kb > 0 else 0.0
        except Exception:
            pass

        # Disk usage (root / or app dir)
        try:
            disk_path = os.path.dirname(os.path.abspath(__file__)) or "/"
            du = shutil.disk_usage(disk_path)
            metrics["disk_total_gb"] = du.total / (1024 ** 3)
            metrics["disk_used_gb"] = du.used / (1024 ** 3)
            metrics["disk_pct"] = (du.used / du.total * 100.0) if du.total > 0 else 0.0
        except Exception:
            pass

        # Uptime via /proc/uptime
        try:
            with open("/proc/uptime", "r") as f:
                secs = int(float(f.read().split()[0]))
            days, rem = divmod(secs, 86400)
            hours, rem = divmod(rem, 3600)
            mins, _ = divmod(rem, 60)
            metrics["uptime_str"] = f"{days}d {hours}h {mins}m" if days > 0 else f"{hours}h {mins}m"
        except Exception:
            pass

        # Current Python process RSS
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        metrics["proc_rss_mb"] = rss_kb / 1024.0
                        break
        except Exception:
            pass

        # SQLite database size (main + wal)
        try:
            db_path = getattr(self.db, "db_path", None)
            if db_path and os.path.exists(db_path):
                total_bytes = os.path.getsize(db_path)
                for ext in ("-wal", "-shm"):
                    if os.path.exists(db_path + ext):
                        total_bytes += os.path.getsize(db_path + ext)
                metrics["db_size_mb"] = total_bytes / (1024 ** 2)
        except Exception:
            pass

        return metrics

    @staticmethod
    def _fmt_mem_mb(mb):
        if mb is None:
            return "-"
        if mb >= 1024:
            return f"{mb / 1024:.2f} GB"
        return f"{mb:.0f} MB"

    def _cmd_resource_server(self, chat_id, edit_msg_id=None):
        """Show TIKWatch Linux host server resource usage."""
        try:
            m = self._get_server_resource_metrics()
            now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            cpu_str = (
                f"<code>{format_bar(m['cpu_pct'], 10)}</code> <b>{m['cpu_pct']:.1f}%</b>"
                if m["cpu_pct"] is not None else "<i>N/A</i>"
            )
            mem_str = (
                f"<code>{format_bar(m['mem_pct'], 10)}</code> <b>{m['mem_pct']:.1f}%</b> "
                f"({self._fmt_mem_mb(m['mem_used_mb'])} / {self._fmt_mem_mb(m['mem_total_mb'])})"
                if m["mem_pct"] is not None else "<i>N/A</i>"
            )
            disk_str = (
                f"<code>{format_bar(m['disk_pct'], 10)}</code> <b>{m['disk_pct']:.1f}%</b> "
                f"({m['disk_used_gb']:.1f} GB / {m['disk_total_gb']:.1f} GB)"
                if m["disk_pct"] is not None else "<i>N/A</i>"
            )

            swap_line = ""
            if m["swap_total_mb"] > 0:
                swap_line = (
                    f"🔁 <b>Swap:</b> <code>{format_bar(m['swap_pct'], 10)}</code> <b>{m['swap_pct']:.1f}%</b> "
                    f"({self._fmt_mem_mb(m['swap_used_mb'])} / {self._fmt_mem_mb(m['swap_total_mb'])})\n"
                )

            proc_line = f"🐍 <b>Proses TIKWatch (RAM):</b> {self._fmt_mem_mb(m['proc_rss_mb'])}\n" if m["proc_rss_mb"] is not None else ""
            db_line = f"🗄️ <b>Ukuran Database:</b> {m['db_size_mb']:.2f} MB\n" if m["db_size_mb"] is not None else ""
            load_line = f"📈 <b>Load Average (1m/5m/15m):</b> <code>{m['load_avg']}</code>\n" if m["load_avg"] else ""

            text = (
                "🖥️ <b>Resource Usage Server TIKWatch</b>\n"
                f"<i>Waktu: {now_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"🏷️ <b>Hostname:</b> <code>{html.escape(str(m['hostname']))}</code>\n"
                f"🐧 <b>OS:</b> <code>{html.escape(str(m['os']))}</code>\n"
                f"⏱️ <b>Uptime Server:</b> <b>{m['uptime_str']}</b>\n\n"
                f"⚙️ <b>CPU ({m['cpu_cores']} Core):</b>\n  {cpu_str}\n"
                f"{load_line}\n"
                f"🧠 <b>RAM Memory:</b>\n  {mem_str}\n"
                f"{swap_line}\n"
                f"💾 <b>Disk Storage (/):</b>\n  {disk_str}\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"{proc_line}{db_line}"
            )

            markup = {
                "inline_keyboard": [
                    [
                        {"text": "🔄 Refresh Server", "callback_data": "cmd:resource_server"},
                        {"text": "🛰️ Resource All Router", "callback_data": "cmd:resource_all"}
                    ],
                    [
                        {"text": "🔀 Pilih Router (Detail)", "callback_data": "cmd:resource_picker"}
                    ]
                ]
            }

            if edit_msg_id:
                self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            logger.error(f"[Telegram] Error in resource server: {e}")
            self.send_message(chat_id, f"⚠️ Gagal mengambil resource server: {e}")

    def _get_router_devices(self):
        """Return all router devices (matching /traffic all router set)."""
        routers = self.db.get_router_traffic_summary()
        if not routers:
            all_devs = self.db.get_all_devices()
            routers = [d for d in all_devs if d.get('type') == 'router' or d.get('snmp_enabled')]
        return routers

    def _cmd_resource_all(self, chat_id, edit_msg_id=None):
        """Show CPU, RAM, Temperature, and Uptime for all routers (with auto-split)."""
        try:
            routers = self._get_router_devices()
            # Enrich with full device fields (cpu_usage, memory_usage, temperature, uptime, latency_ms)
            all_devs_map = {d['id']: d for d in self.db.get_all_devices()}
            enriched = [all_devs_map.get(r['id'], r) for r in routers]

            now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            online_cnt = sum(1 for d in enriched if d.get('status') == 'up')
            cpus = [float(d['cpu_usage']) for d in enriched if d.get('cpu_usage') is not None]
            mems = [float(d['memory_usage']) for d in enriched if d.get('memory_usage') is not None]
            avg_cpu = (sum(cpus) / len(cpus)) if cpus else 0.0
            avg_mem = (sum(mems) / len(mems)) if mems else 0.0
            high_cpu = sum(1 for c in cpus if c >= 80.0)
            high_mem = sum(1 for m in mems if m >= 80.0)

            header = (
                "🛰️ <b>Resource Usage Semua Router (TIKWatch)</b>\n"
                f"<i>Waktu: {now_str} WIB</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"📊 <b>Ringkasan ({len(enriched)} Router | {online_cnt} Online):</b>\n"
                f"  ⚙️ <b>Rata-rata CPU:</b> <b>{avg_cpu:.1f}%</b> (≥80%: {high_cpu})\n"
                f"  🧠 <b>Rata-rata RAM:</b> <b>{avg_mem:.1f}%</b> (≥80%: {high_mem})\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
            )
            footer = (
                "💡 <i>Pilih router spesifik via tombol di bawah untuk melihat detail lengkap "
                "(CPU, RAM, Suhu, Latensi, Packet Loss, Uptime).</i>"
            )

            messages = []
            if enriched:
                current_msg = header
                for idx, d in enumerate(enriched, start=1):
                    rname = html.escape(str(d.get('name') or d.get('ip') or '-'))
                    rip = d.get('ip') or '-'
                    status_icon = "🟢" if d.get('status') == 'up' else ("🔴" if d.get('status') == 'down' else "🟡")

                    cpu_val = d.get('cpu_usage')
                    mem_val = d.get('memory_usage')
                    temp_val = d.get('temperature')
                    lat_val = d.get('latency_ms')

                    cpu_txt = f"<code>{format_bar(cpu_val, 6)}</code> <b>{float(cpu_val):.0f}%</b>" if cpu_val is not None else "<i>-</i>"
                    mem_txt = f"<code>{format_bar(mem_val, 6)}</code> <b>{float(mem_val):.0f}%</b>" if mem_val is not None else "<i>-</i>"
                    warn_flag = " ⚠️" if ((cpu_val is not None and float(cpu_val) >= 85) or (mem_val is not None and float(mem_val) >= 85)) else ""

                    extras = []
                    if temp_val is not None:
                        extras.append(f"🌡️{float(temp_val):.0f}°C")
                    if lat_val is not None:
                        extras.append(f"⚡{float(lat_val):.1f}ms")
                    if d.get('uptime'):
                        extras.append(f"⏱️{html.escape(str(d.get('uptime'))[:18])}")
                    extra_line = f"\n  {' | '.join(extras)}" if extras else ""

                    block = (
                        f"{idx}. 🔹 <b>{rname}</b> ({rip}) {status_icon}{warn_flag}\n"
                        f"  ⚙️ CPU: {cpu_txt} | 🧠 RAM: {mem_txt}{extra_line}\n\n"
                    )
                    if len(current_msg) + len(block) > 3600:
                        messages.append(current_msg)
                        current_msg = f"🛰️ <b>Lanjutan Resource Router ({idx}-{len(enriched)}):</b>\n\n"
                    current_msg += block

                if len(current_msg) + len(footer) > 3950:
                    messages.append(current_msg)
                    messages.append(footer)
                else:
                    messages.append(current_msg + footer)
            else:
                messages.append(header + "<i>Belum ada router yang terdaftar di database.</i>\n\n" + footer)

            markup = {
                "inline_keyboard": [
                    [
                        {"text": "🔄 Refresh All", "callback_data": "cmd:resource_all"},
                        {"text": "🖥️ Resource Server", "callback_data": "cmd:resource_server"}
                    ],
                    [
                        {"text": "🔀 Pilih Router (Detail)", "callback_data": "cmd:resource_picker"}
                    ]
                ]
            }

            for i, msg_text in enumerate(messages):
                is_last = (i == len(messages) - 1)
                rm = markup if is_last else None
                if i == 0 and edit_msg_id:
                    self.edit_message_text(chat_id, edit_msg_id, msg_text, reply_markup=rm)
                else:
                    self.send_message(chat_id, msg_text, reply_markup=rm)
        except Exception as e:
            logger.error(f"[Telegram] Error in resource all: {e}")
            self.send_message(chat_id, f"⚠️ Gagal mengambil resource semua router: {e}")

    def _cmd_resource_picker(self, chat_id, edit_msg_id=None):
        """Interactive router selector menu for resource usage."""
        try:
            routers = self._get_router_devices()
            if not routers:
                self.send_message(chat_id, "ℹ️ Belum ada router atau perangkat yang terdaftar di database.")
                return

            text = (
                "🔀 <b>Pilih Router untuk Melihat Resource Usage:</b>\n\n"
                "Pilih router spesifik di bawah untuk melihat detail CPU, RAM, Suhu, Latensi, dan Uptime:\n"
            )

            buttons = []
            row = []
            for r in routers[:90]:
                rname = (r.get('name') or r.get('ip') or '')[:16]
                status_icon = "🟢" if r.get('status') == 'up' else "🔴"
                row.append({"text": f"{status_icon} {rname}", "callback_data": f"cmd:resource_dev:{r['id']}"})
                if len(row) == 2:
                    buttons.append(row)
                    row = []
            if row:
                buttons.append(row)

            buttons.append([
                {"text": "🛰️ Semua Router (All)", "callback_data": "cmd:resource_all"},
                {"text": "🖥️ Resource Server", "callback_data": "cmd:resource_server"}
            ])

            markup = {"inline_keyboard": buttons}
            if edit_msg_id:
                self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
            else:
                self.send_message(chat_id, text, reply_markup=markup)
        except Exception as e:
            logger.error(f"[Telegram] Error in resource picker: {e}")
            self.send_message(chat_id, f"⚠️ Gagal memuat daftar router: {e}")

    def _cmd_resource_device(self, chat_id, args, edit_msg_id=None):
        """Show detailed resource usage for a specific selected router/device."""
        if not args:
            self._cmd_resource_picker(chat_id, edit_msg_id=edit_msg_id)
            return

        target = " ".join(args).strip()
        device = self._find_device_by_target(target)
        if not device:
            self.send_message(
                chat_id,
                f"⚠️ Router/perangkat <code>{html.escape(target)}</code> tidak ditemukan.\n"
                "Gunakan <code>/resource select</code> untuk memilih dari daftar."
            )
            return

        now_str = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        dname = html.escape(str(device.get('name') or device.get('ip')))
        dip = device.get('ip') or '-'
        status = (device.get('status') or 'unknown').upper()
        status_icon = "🟢" if status == "UP" else ("🔴" if status == "DOWN" else "🟡")

        cpu = device.get('cpu_usage')
        mem = device.get('memory_usage')
        temp = device.get('temperature')
        lat = device.get('latency_ms')
        loss = device.get('packet_loss')
        uptime = device.get('uptime') or '-'
        last_polled = device.get('last_polled') or '-'
        vendor = device.get('vendor') or ''
        model = device.get('model') or ''
        hw_info = " ".join(x for x in (vendor, model) if x).strip()

        cpu_line = (
            f"⚙️ <b>CPU Usage:</b>  <code>{format_bar(cpu, 10)}</code> <b>{float(cpu):.1f}%</b>"
            + (" ⚠️ <i>(Tinggi)</i>" if float(cpu) >= 80 else "")
            if cpu is not None else "⚙️ <b>CPU Usage:</b> <i>Tidak tersedia</i>"
        )
        mem_line = (
            f"🧠 <b>RAM Usage:</b>  <code>{format_bar(mem, 10)}</code> <b>{float(mem):.1f}%</b>"
            + (" ⚠️ <i>(Tinggi)</i>" if float(mem) >= 80 else "")
            if mem is not None else "🧠 <b>RAM Usage:</b> <i>Tidak tersedia</i>"
        )
        temp_line = f"🌡️ <b>Temperature:</b> <b>{float(temp):.1f} °C</b>" if temp is not None else "🌡️ <b>Temperature:</b> <i>-</i>"
        lat_line = f"⚡ <b>Latency:</b> <b>{float(lat):.2f} ms</b>" if lat is not None else "⚡ <b>Latency:</b> <i>-</i>"
        loss_line = f"📉 <b>Packet Loss:</b> <b>{float(loss):.1f}%</b>" if loss is not None else "📉 <b>Packet Loss:</b> <i>-</i>"
        hw_line = f"🏷️ <b>Perangkat:</b> {html.escape(hw_info)}\n" if hw_info else ""

        text = (
            f"🖥️ <b>Detail Resource Router: {dname}</b>\n"
            f"<i>Waktu: {now_str} WIB</i>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🌐 <b>IP Address:</b> <code>{dip}</code>\n"
            f"{hw_line}"
            f"📡 <b>Status:</b> {status_icon} <b>{status}</b>\n"
            f"⏱️ <b>Uptime:</b> {html.escape(str(uptime))}\n\n"
            f"{cpu_line}\n"
            f"{mem_line}\n"
            f"{temp_line}\n"
            f"{lat_line} | {loss_line}\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕒 <i>Last Polled: {last_polled}</i>"
        )

        markup = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Refresh", "callback_data": f"cmd:resource_dev:{device['id']}"},
                    {"text": "📡 Poll Sekarang", "callback_data": f"poll:{device['id']}"}
                ],
                [
                    {"text": "📊 Traffic Port", "callback_data": f"cmd:traffic_dev:{device['id']}"},
                    {"text": "📈 Grafik 24h", "callback_data": f"chart:{device['id']}:24h"}
                ],
                [
                    {"text": "🤖 Diagnosa AI", "callback_data": f"cmd:ai_dev:{device['id']}"},
                    {"text": "🔀 Pilih Router Lain", "callback_data": "cmd:resource_picker"}
                ],
                [
                    {"text": "🛰️ Semua Router", "callback_data": "cmd:resource_all"}
                ]
            ]
        }

        if edit_msg_id:
            self.edit_message_text(chat_id, edit_msg_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

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

        # Target is a router / device (supports multi-word name + optional trailing time_range)
        if len(args) > 1 and args[-1].lower().strip() in valid_ranges:
            time_range = args[-1].lower().strip()
            target_query = " ".join(args[:-1]).strip()
        else:
            target_query = " ".join(args).strip()

        device = self._find_device_by_target(target_query)
        if not device:
            self.send_message(
                chat_id,
                f"⚠️ Router / perangkat <code>{html.escape(target_query)}</code> tidak ditemukan.\n\n"
                "Ketik <code>/chart select</code> untuk memilih router dari daftar interaktif."
            )
            return

        target_id = str(device['id'])
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
            for r in routers[:90]:
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

        p95_rx = data.get('p95_rx', 0.0)
        p95_tx = data.get('p95_tx', 0.0)
        total_rx_gb = data.get('total_rx_gb', 0.0)
        total_tx_gb = data.get('total_tx_gb', 0.0)
        p95_max = max(p95_rx, p95_tx)
        p95_util = (p95_max / uplink_mbps * 100.0) if uplink_mbps > 0 else 0.0

        caption = (
            f"📊 <b>Grafik Throughput & Bandwidth — {safe_target_name}</b>\n"
            f"{scope_badge}\n"
            f"⏱️ <b>Rentang Waktu:</b> {time_label} ({sample_count} sampel)\n"
            f"🔌 <b>Kapasitas Link (Uplink):</b> <b>{uplink_str}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "🌊 <b>TRAFFIC THROUGHPUT (Laju Aliran):</b>\n"
            f"  📥 <b>WAN IN (Download):</b>\n"
            f"     • Terkini: <b>{cur_rx:.2f} Mbps</b> | Avg: {avg_rx:.2f} Mbps\n"
            f"     • P95: <b>{p95_rx:.2f} Mbps</b> | Peak: <b>{peak_rx:.2f} Mbps</b>\n"
            f"     • Volume: <b>{total_rx_gb:.2f} GB</b>\n"
            f"  📤 <b>WAN OUT (Upload):</b>\n"
            f"     • Terkini: <b>{cur_tx:.2f} Mbps</b> | Avg: {avg_tx:.2f} Mbps\n"
            f"     • P95: <b>{p95_tx:.2f} Mbps</b> | Peak: <b>{peak_tx:.2f} Mbps</b>\n"
            f"     • Volume: <b>{total_tx_gb:.2f} GB</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "📈 <b>BANDWIDTH USAGE & CACTI P95:</b>\n"
            f"  📥 <b>Inbound:</b>  <code>{format_bar(cur_rx_util, 8)}</code> {cur_rx_util:.1f}%\n"
            f"  📤 <b>Outbound:</b> <code>{format_bar(cur_tx_util, 8)}</code> {cur_tx_util:.1f}%\n"
            f"  🎯 <b>95th Percentile (P95):</b> <b>{p95_max:.2f} Mbps</b> ({p95_util:.1f}% kapasitas)\n"
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

        target = " ".join(args).strip()
        device = self._find_device_by_target(target)

        if not device:
            self.send_message(
                chat_id,
                f"⚠️ Perangkat atau router dengan nama/IP/ID <code>{html.escape(target)}</code> tidak ditemukan.\n\n"
                "Ketik <code>/traffic select</code> untuk melihat daftar router yang tersedia."
            )
            return

        did = device.get('id')
        dname = html.escape(str(device.get('name') or device.get('ip')))
        dip = device.get('ip')
        wan_idx = str(device.get('wan_iface_idx') or '').strip()
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
                raw_iname = str(ifc.get('name') or '-')
                iname = html.escape(raw_iname)
                i_idx = str(ifc.get('idx') or '')
                rx = ifc.get('rx_bps') or 0.0
                tx = ifc.get('tx_bps') or 0.0
                total = ifc.get('total_bps') or (rx + tx)

                # Tandai jika active port ini adalah port Uplink WAN
                is_uplink_port = False
                if wan_idx and i_idx == wan_idx:
                    is_uplink_port = True
                elif any(k in raw_iname.lower() for k in ('wan', 'sfp', 'sfpplus', 'ether1', 'pppoe')):
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
                    raw_dname = str(row.get('device_name') or row.get('device_ip') or '-')
                    dname = html.escape(raw_dname)
                    dip = row.get('device_ip')
                    iname = html.escape(str(row.get('iface_name') or 'Uplink WAN'))
                    rx = row.get('rx_bps') or 0.0
                    tx = row.get('tx_bps') or 0.0
                    tot = row.get('total_bps') or (rx + tx)
                    uplink_mbps = row.get('uplink_speed_mbps', 1000)
                    util_pct = row.get('util_pct', 0.0)

                    is_agg = row.get('include_in_aggregate', 1) == 1
                    is_bgp = 'bgp' in raw_dname.lower()
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
                "ℹ️ Gunakan format: <code>/capture &lt;nama/ip/id&gt;</code>\n"
                "Contoh: <code>/capture core</code> atau <code>/capture 192.168.1.1</code>\n\n"
                "<i>Bot akan mengambil 2 sampel SNMP berjarak 3 detik secara langsung untuk menghitung throughput real-time tiap interface.</i>"
            )
            return

        target = " ".join(args).strip()
        device = self._find_device_by_target(target)

        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat <code>{html.escape(target)}</code> tidak ditemukan di database.")
            return

        if not device.get('snmp_enabled'):
            self.send_message(
                chat_id,
                f"⚠️ Perangkat <b>{html.escape(str(device.get('name') or target))}</b> ({device.get('ip')}) belum mengaktifkan SNMP.\n"
                "Aktifkan SNMP pada perangkat dan di menu Settings/Device TIKWatch untuk menggunakan fitur Live Capture."
            )
            return

        if not self.snmp_worker:
            self.send_message(chat_id, "⚠️ Worker SNMP belum siap.")
            return

        dname = html.escape(str(device.get('name') or target))
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
                err_text = f"⚠️ Gagal melakukan live capture pada <b>{dname}</b> ({dip}):\n<i>{html.escape(str(err or 'Unknown error'))}</i>"
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
                    f"• <b>{html.escape(str(r.get('name') or '-'))}</b> (Total: <b>{format_speed(tot)}</b>)\n"
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

    def _cmd_mute(self, chat_id, args):
        """Set Zabbix-style maintenance window for 'all' or a specific device."""
        if not args:
            g_active, g_until = self.db.is_device_in_maintenance(None)
            with self.db.conn() as c:
                m_rows = c.execute(
                    "SELECT id, name, ip, maintenance_until FROM devices WHERE maintenance_until IS NOT NULL AND maintenance_until > datetime('now', 'localtime')"
                ).fetchall()
            lines = ["🔕 <b>Status Maintenance Window (Zabbix Mute):</b>\n"]
            lines.append(f"• <b>Global Mute:</b> {'🟢 Aktif s/d ' + g_until if g_active else '⚪ Tidak aktif'}")
            if m_rows:
                lines.append("\n<b>Perangkat dalam Maintenance:</b>")
                for r in m_rows:
                    lines.append(f"• <b>{html.escape(str(r['name'] or r['ip']))}</b> (<code>{r['ip']}</code>) s/d <b>{r['maintenance_until']}</b>")
            else:
                lines.append("• <i>Tidak ada perangkat spesifik dalam mode maintenance.</i>")
            lines.append(
                "\n<b>Cara Penggunaan:</b>\n"
                "• <code>/mute &lt;nama/ip/id&gt; [menit]</code> — Bisukan alert perangkat (default 60 menit)\n"
                "• <code>/mute all [menit]</code> — Bisukan seluruh alert global\n"
                "• <code>/unmute [nama/ip/all]</code> — Aktifkan kembali notifikasi alert"
            )
            self.send_message(chat_id, "\n".join(lines))
            return

        minutes = 60
        if len(args) >= 2 and args[-1].isdigit():
            minutes = max(1, min(10080, int(args[-1])))
            target_str = " ".join(args[:-1]).strip()
        else:
            target_str = " ".join(args).strip()

        if target_str.lower() in ("all", "global", "semua"):
            until_str = self.db.set_maintenance_window("all", minutes)
            self.send_message(
                chat_id,
                f"🔕 <b>Global Maintenance Mode Aktif!</b>\n"
                f"Seluruh notifikasi alert Telegram dibisukan selama <b>{minutes} menit</b> (hingga <b>{until_str} WIB</b>).\n"
                f"Ketik <code>/unmute all</code> untuk mengaktifkan kembali lebih awal."
            )
            return

        dev = self._find_device_by_target(target_str)
        if not dev:
            self.send_message(chat_id, f"⚠️ Perangkat <code>{html.escape(target_str)}</code> tidak ditemukan.")
            return

        until_str = self.db.set_maintenance_window(dev['id'], minutes)
        dname = html.escape(str(dev.get('name') or dev.get('ip')))
        self.send_message(
            chat_id,
            f"🔕 <b>Maintenance Mode Aktif: {dname}</b> (<code>{dev.get('ip')}</code>)\n"
            f"Notifikasi alert Telegram untuk perangkat ini dibisukan selama <b>{minutes} menit</b> (hingga <b>{until_str} WIB</b>).\n"
            f"Ketik <code>/unmute {dev['id']}</code> untuk mengakhiri maintenance."
        )

    def _cmd_unmute(self, chat_id, args):
        """Clear maintenance window for 'all' or a specific device."""
        target_str = " ".join(args).strip() if args else "all"
        if target_str.lower() in ("all", "global", "semua"):
            self.db.set_maintenance_window("all", 0)
            self.send_message(chat_id, "🔔 <b>Maintenance Mode Dimatikan (Global & Semua Perangkat).</b> Notifikasi alert kembali normal.")
            return
        dev = self._find_device_by_target(target_str)
        if not dev:
            self.send_message(chat_id, f"⚠️ Perangkat <code>{html.escape(target_str)}</code> tidak ditemukan.")
            return
        self.db.set_maintenance_window(dev['id'], 0)
        dname = html.escape(str(dev.get('name') or dev.get('ip')))
        self.send_message(chat_id, f"🔔 <b>Maintenance Mode Dimatikan</b> untuk <b>{dname}</b> (<code>{dev.get('ip')}</code>).")

    def _cmd_interfaces(self, chat_id, args):
        if not args:
            self.send_message(chat_id, "ℹ️ Masukkan nama, IP, atau ID perangkat. Contoh: <code>/iface 192.168.1.1</code>")
            return
        target = " ".join(args).strip()
        device = self._find_device_by_target(target)
        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat <code>{html.escape(target)}</code> tidak ditemukan.")
            return

        if self.snmp_worker and device.get('snmp_enabled'):
            try:
                stats = self.snmp_worker.get_detailed_stats(device)
                ifaces = stats.get('interfaces', []) if stats else []
                if ifaces:
                    dname = html.escape(str(device.get('name') or device.get('ip')))
                    lines = [
                        f"🔌 <b>Status & Kesehatan Interface (Cacti Diagnostics)</b>",
                        f"🛰️ <b>{dname}</b> (<code>{device.get('ip')}</code>)\n━━━━━━━━━━━━━━━━━━━━━"
                    ]
                    for ifc in ifaces[:25]:
                        st_icon = "🟢" if ifc.get('status') == 'up' else "⚪"
                        iname = html.escape(str(ifc.get('name', '-')))
                        spd = int((ifc.get('speed') or 0) / 1e6)
                        spd_str = f"{spd}M" if spd < 1000 else f"{spd/1000:.0f}G"
                        in_err = int(ifc.get('in_errors') or 0)
                        out_err = int(ifc.get('out_errors') or 0)
                        in_disc = int(ifc.get('in_discards') or 0)
                        out_disc = int(ifc.get('out_discards') or 0)
                        health_tag = "✅ OK"
                        if (in_err + out_err) > 0 or (in_disc + out_disc) > 0:
                            health_tag = f"⚠️ Err:{in_err}/{out_err} Disc:{in_disc}/{out_disc}"
                        lines.append(f"{st_icon} <b>{iname}</b> ({spd_str}) — {health_tag}")
                    self.send_message(chat_id, "\n".join(lines))
                    return
            except Exception as e:
                logger.warning(f"[Telegram] Detailed iface check fallback: {e}")

        self._cmd_traffic_device(chat_id, [str(device['id'])])

    # ─── Groq AI NOC Assistant Commands ─────────────────────────────

    @staticmethod
    def _format_ai_html(raw_text):
        """Safely convert basic Markdown from LLM output to Telegram HTML."""
        escaped = html.escape(str(raw_text or "").strip())
        escaped = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', escaped)
        escaped = re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped)
        return escaped

    def _cmd_ai(self, chat_id, args):
        """Handle /ai <question> using Groq LLM with live TIKWatch telemetry."""
        question = " ".join(args).strip() if args else ""
        if not question:
            self.send_message(
                chat_id,
                "🤖 <b>AI NOC Assistant (Groq LLM)</b>\n\n"
                "Ajukan pertanyaan apa saja seputar kondisi jaringan kampus (kapasitas ISP 6 Gbps, alert aktif, atau troubleshooting).\n\n"
                "<b>Contoh penggunaan:</b>\n"
                "• <code>/ai bagaimana kondisi jaringan dan utilisasi 6 Gbps saat ini?</code>\n"
                "• <code>/ai analisa alert aktif dan cara perbaikannya</code>\n"
                "• <code>/ai router mana yang CPU atau trafiknya paling tinggi?</code>\n"
                "• <code>/diagnosa &lt;nama/ip&gt;</code> — Diagnosa mendalam 1 perangkat"
            )
            return

        def _worker():
            try:
                import ai_detector
                ok, answer = ai_detector.ask_groq_noc(self.db, question)
                if not ok:
                    self.send_message(chat_id, answer)
                    return
                formatted = self._format_ai_html(answer)
                _, model_name = ai_detector.get_groq_config(self.db)
                reply = (
                    f"🤖 <b>TIKWatch AI NOC Assistant</b> (<code>{html.escape(model_name)}</code>)\n"
                    "━━━━━━━━━━━━━━━━━━━━━\n"
                    f"{formatted}"
                )
                if len(reply) > 3950:
                    reply = reply[:3940] + "\n<i>…(terpotong)</i>"
                self.send_message(chat_id, reply)
            except Exception as e:
                logger.error(f"[Telegram AI] /ai error: {e}")
                self.send_message(chat_id, f"⚠️ Gagal memproses AI: {e}")

        self.send_message(chat_id, "🤖 <i>Menganalisa telemetri live TIKWatch…</i>")
        threading.Thread(target=_worker, daemon=True).start()

    def _cmd_diagnosa(self, chat_id, args):
        """Handle /diagnosa <nama/ip/id> for deep AI analysis of a specific device."""
        if not args:
            self.send_message(chat_id, "ℹ️ Masukkan nama, IP, atau ID router. Contoh: <code>/diagnosa core</code>")
            return
        target = " ".join(args).strip()
        device = self._find_device_by_target(target)
        if not device:
            self.send_message(chat_id, f"⚠️ Perangkat <code>{html.escape(target)}</code> tidak ditemukan.")
            return

        def _worker():
            try:
                import ai_detector
                question = (
                    f"Lakukan diagnosa kesehatan dan performa mendalam untuk perangkat target "
                    f"{device.get('name')} ({device.get('ip')}). Sertakan analisa CPU/RAM/suhu/latency/uptime, "
                    f"trafik port aktif, riwayat downtime/reboot, dan rekomendasi konkret (termasuk perintah RouterOS jika perlu)."
                )
                ok, answer = ai_detector.ask_groq_noc(self.db, question, device=device)
                if not ok:
                    self.send_message(chat_id, answer)
                    return
                formatted = self._format_ai_html(answer)
                _, model_name = ai_detector.get_groq_config(self.db)
                dname = html.escape(str(device.get('name') or device.get('ip')))
                reply = (
                    f"🩺 <b>AI Diagnosa: {dname}</b> (<code>{device.get('ip')}</code>)\n"
                    f"<i>Model: {html.escape(model_name)}</i>\n"
                    "━━━━━━━━━━━━━━━━━━━━━\n"
                    f"{formatted}"
                )
                if len(reply) > 3950:
                    reply = reply[:3940] + "\n<i>…(terpotong)</i>"
                self.send_message(chat_id, reply)
            except Exception as e:
                logger.error(f"[Telegram AI] /diagnosa error: {e}")
                self.send_message(chat_id, f"⚠️ Gagal diagnosa AI: {e}")

        self.send_message(chat_id, f"🩺 <i>Menjalankan AI diagnosa untuk <b>{html.escape(str(device.get('name') or device.get('ip')))}</b>…</i>")
        threading.Thread(target=_worker, daemon=True).start()

    def _run_ai_alert_analysis(self, chat_id, alert_id):
        """Run AI root-cause analysis when the user clicks 'Analisa AI' on an alert message."""
        try:
            import ai_detector
            alert_row = None
            device = None
            with self.db.conn() as c:
                row = c.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
                if row:
                    alert_row = dict(row)
                    if alert_row.get('device_id'):
                        device = self.db.get_device(alert_row['device_id'])
            if not alert_row:
                self.send_message(chat_id, f"⚠️ Alert #{alert_id} tidak ditemukan.")
                return
            question = (
                f"Analisa insiden alert #{alert_id}: '{alert_row.get('message')}'. "
                f"Jelaskan kemungkinan root cause, dampak ke jaringan kampus, dan langkah verifikasi/perbaikan cepat untuk teknisi NOC."
            )
            ok, answer = ai_detector.ask_groq_noc(self.db, question, device=device, alert=alert_row)
            if not ok:
                self.send_message(chat_id, answer)
                return
            formatted = self._format_ai_html(answer)
            reply = (
                f"🤖 <b>Analisa AI — Alert #{alert_id}</b>\n"
                f"🛰️ <b>{html.escape(str(alert_row.get('device_name') or '-'))}</b> (<code>{alert_row.get('device_ip') or '-'}</code>)\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"{formatted}"
            )
            if len(reply) > 3950:
                reply = reply[:3940] + "\n<i>…(terpotong)</i>"
            self.send_message(chat_id, reply)
        except Exception as e:
            logger.error(f"[Telegram AI] alert analysis error: {e}")
            self.send_message(chat_id, f"⚠️ Gagal analisa alert AI: {e}")

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
                    zone_str = f"• <b>Zona:</b> {html.escape(str(zone.get('name') or '-'))}\n"
            except Exception:
                pass

        text = (
            f"{icon} <b>[TIKWatch] {title}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>Perangkat:</b> <code>{html.escape(str(dev_name or '-'))}</code>\n"
            f"• <b>IP Address:</b> <code>{dev_ip}</code>\n"
            f"{zone_str}"
            f"• <b>Pesan:</b> {html.escape(str(message or '-'))}\n"
            f"• <b>Waktu:</b> <i>{now_str} WIB</i>\n"
        )

        if ai_analysis and "valid alert" not in ai_analysis.lower() and "false warning" not in ai_analysis.lower():
            text += f"\n🤖 <b>AI Diagnostic:</b> <i>{html.escape(str(ai_analysis))}</i>\n"

        # Interactive buttons
        keyboard = []
        btn_row = []
        if alert_id and not is_recovery:
            btn_row.append({"text": "✅ Acknowledge", "callback_data": f"ack:{alert_id}"})
        if dev_id:
            btn_row.append({"text": "🔄 Re-check", "callback_data": f"poll:{dev_id}"})
        if btn_row:
            keyboard.append(btn_row)

        btn_row2 = []
        if alert_id and not is_recovery:
            btn_row2.append({"text": "🤖 Analisa AI", "callback_data": f"cmd:ai_alert:{alert_id}"})
        elif dev_id and not is_recovery:
            btn_row2.append({"text": "🤖 Analisa AI", "callback_data": f"cmd:ai_dev:{dev_id}"})
        if dev_id and not is_recovery:
            btn_row2.append({"text": "🔕 Mute 1h", "callback_data": f"cmd:mute:{dev_id}:60"})
        if btn_row2:
            keyboard.append(btn_row2)

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

            campus_gbps = self.db.get_campus_total_bandwidth_mbps() / 1000.0
            ai_insight_block = ""
            try:
                import ai_detector
                api_key, _ = ai_detector.get_groq_config(self.db)
                if api_key:
                    ok, ai_summary = ai_detector.ask_groq_noc(
                        self.db,
                        "Berikan ringkasan eksekutif NOC harian singkat (maksimal 3 kalimat) mengenai kesehatan router, alert terbuka, dan utilisasi terhadap kapasitas ISP 6 Gbps.",
                        max_tokens=260
                    )
                    if ok and ai_summary:
                        ai_insight_block = f"\n🤖 <b>AI Daily Insight:</b>\n{self._format_ai_html(ai_summary)}\n"
            except Exception as aie:
                logger.debug(f"[Telegram Digest AI] skipped: {aie}")

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
                f"🌐 <b>Kapasitas ISP Kampus:</b> {campus_gbps:.1f} Gbps\n"
                f"🚨 <b>Alert Terbuka:</b> {unacked} (Kritis: {crit})\n"
                f"{ai_insight_block}"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "<i>Gunakan /status, /ai, atau buka Web Dashboard TIKWatch untuk detail lengkap.</i>"
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
