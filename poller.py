#!/usr/bin/env python3
"""
TIKWatch - Dedicated Background Poller & Telegram Bot Daemon
Runs independently from the Gunicorn Web Server so SNMP/ICMP polling,
retention cleanup, and Telegram Bot never block HTTP/WebSocket workers.
"""

import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime

import requests
from apscheduler.schedulers.background import BackgroundScheduler

from database import Database
from snmp_worker import SNMPWorker
from telegram_bot import TelegramBot
from unifi_client import UniFiClient

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('netmon.poller')


class InternalSocketBridge:
    """Forwards real-time Socket.IO events from poller process to local Gunicorn web process."""

    def __init__(self, db, port=None):
        self.db = db
        self.port = int(port or os.environ.get('PORT', 5000))
        self.url = f"http://127.0.0.1:{self.port}/internal/emit"
        self._token = None
        self._token_ts = 0

    def _get_token(self):
        now = time.time()
        if not self._token or (now - self._token_ts) > 60:
            try:
                self._token = self.db.get_settings().get('internal_emit_token', '')
                self._token_ts = now
            except Exception as e:
                logger.warning(f"[SocketBridge] Failed reading token: {e}")
        return self._token or ''

    def emit(self, event, data=None, **kwargs):
        token = self._get_token()
        if not token:
            return

        def _post():
            try:
                requests.post(
                    self.url,
                    json={'event': event, 'data': data},
                    headers={'X-Internal-Token': token},
                    timeout=1.5
                )
            except Exception:
                # Web server may be restarting during update; non-fatal
                pass

        threading.Thread(target=_post, daemon=True).start()


db = Database()
socket_bridge = InternalSocketBridge(db)
telegram_bot = TelegramBot(db, socket_bridge)
snmp_worker = SNMPWorker(db, socket_bridge, telegram_bot=telegram_bot)
telegram_bot.snmp_worker = snmp_worker
scheduler = BackgroundScheduler(daemon=True)

_last_cfg_sig = None


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
            unifi = UniFiClient(host=host, username=username, password=password, port=port, site=site)
            snmp_info = unifi.get_snmp_settings() or {}
            snmp_comm = snmp_info.get('community') or settings.get('default_community', 'public')
            snmp_en = bool(snmp_info.get('enabled', False))

            unifi_devs = unifi.get_devices()
            for ud in unifi_devs:
                db.add_or_update_unifi_device(
                    ud,
                    snmp_community=snmp_comm,
                    snmp_version='2c',
                    snmp_port=161,
                    snmp_enabled_for_new=snmp_en
                )
            socket_bridge.emit('stats_update', db.get_dashboard_stats())
    except Exception as ue:
        logger.warning(f"[UniFi Background Sync] Error: {ue}")

    # 2. Poll all devices via ICMP/SNMP in parallel
    devices = db.get_all_devices()
    if not devices:
        return
    from concurrent.futures import ThreadPoolExecutor
    max_poll_workers = min(12, len(devices) or 1)
    with ThreadPoolExecutor(max_workers=max_poll_workers) as executor:
        futures = [executor.submit(snmp_worker.poll_device, device) for device in devices]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.warning(f"[Poll] Parallel device poll failed: {e}")


def poll_traffic():
    devices = db.get_all_devices()
    snmp_devices = [d for d in devices if d.get('snmp_enabled')]
    if not snmp_devices:
        return
    from concurrent.futures import ThreadPoolExecutor
    max_traffic_workers = min(12, len(snmp_devices))
    with ThreadPoolExecutor(max_workers=max_traffic_workers) as executor:
        futures = [executor.submit(snmp_worker.collect_interface_traffic, device) for device in snmp_devices]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.warning(f"[Traffic] Parallel traffic collection failed: {e}")


def run_hourly_cleanup():
    """Run retention cleanup once per hour instead of every 10 seconds."""
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
        logger.warning(f"[Cleanup Cron] Error: {e}")


def run_monthly_report_cron():
    logger.info("[Report Cron] Running monthly report generation...")
    try:
        month_str = datetime.now().strftime('%Y-%m')
        db.generate_and_save_monthly_report(month_str)
        logger.info(f"[Report Cron] Monthly report for {month_str} generated successfully!")
    except Exception as e:
        logger.error(f"[Report Cron] Failed to generate monthly report: {e}")


def run_weekly_vacuum():
    logger.info("[Vacuum Cron] Running weekly VACUUM...")
    try:
        with db.conn() as c:
            c.execute("VACUUM")
        logger.info("[Vacuum Cron] VACUUM completed successfully!")
    except Exception as e:
        logger.error(f"[Vacuum Cron] Failed: {e}")


def run_telegram_daily_digest():
    try:
        s = db.get_settings()
        if s.get('telegram_enabled', 'false') == 'true' and s.get('telegram_daily_digest_enabled', 'true') == 'true':
            telegram_bot.send_daily_digest()
            logger.info("[Telegram Digest Cron] Daily digest sent successfully!")
    except Exception as e:
        logger.error(f"[Telegram Digest Cron] Failed: {e}")


def _publish_telegram_status():
    try:
        db.set_poller_state('telegram_status', {
            'enabled': telegram_bot.enabled,
            'running': bool(telegram_bot.is_running and telegram_bot._poll_thread and telegram_bot._poll_thread.is_alive()),
            'bot_username': telegram_bot.bot_info.get('username'),
            'bot_name': telegram_bot.bot_info.get('first_name'),
            'chat_count': len(telegram_bot.chat_ids),
            'updated_at': datetime.now().isoformat()
        })
    except Exception as e:
        logger.warning(f"[Poller] Publish telegram status failed: {e}")


def sync_dynamic_settings():
    """Detect settings changes saved from Gunicorn web UI and hot-reload bot/schedules."""
    global _last_cfg_sig
    try:
        s = db.get_settings()
        sig = (
            s.get('poll_interval', '30'),
            s.get('traffic_poll_interval', '15'),
            s.get('telegram_enabled', 'false'),
            s.get('telegram_bot_token', ''),
            s.get('telegram_chat_ids', ''),
            s.get('telegram_notify_down', 'true'),
            s.get('telegram_notify_up', 'true'),
            s.get('telegram_censor_ips', 'true'),
            s.get('telegram_daily_digest_time', '08:00'),
        )
        if _last_cfg_sig is None:
            _last_cfg_sig = sig
            _publish_telegram_status()
            return
        if sig != _last_cfg_sig:
            old_sig = _last_cfg_sig
            _last_cfg_sig = sig
            if sig[0] != old_sig[0]:
                scheduler.reschedule_job('snmp_poll', trigger='interval', seconds=max(10, int(sig[0])))
            if sig[1] != old_sig[1]:
                scheduler.reschedule_job('traffic_poll', trigger='interval', seconds=max(5, int(sig[1])))
            if sig[8] != old_sig[8]:
                try:
                    dh, dm = [int(x) for x in sig[8].split(':')]
                    scheduler.reschedule_job('telegram_daily_digest', trigger='cron', hour=dh, minute=dm)
                except Exception:
                    pass
            if sig[2:8] != old_sig[2:8]:
                telegram_bot.reload_config()
            logger.info("[Poller] Hot-reloaded updated configuration from database.")
        _publish_telegram_status()
    except Exception as e:
        logger.warning(f"[Poller] Config sync check failed: {e}")


def main():
    settings = db.get_settings()
    poll_interval = max(10, int(settings.get('poll_interval', 30)))
    traffic_poll_interval = max(5, int(settings.get('traffic_poll_interval', 15)))
    digest_time = (settings.get('telegram_daily_digest_time') or '08:00').strip()
    try:
        d_hour, d_min = [int(x) for x in digest_time.split(':')]
    except Exception:
        d_hour, d_min = 8, 0

    scheduler.add_job(poll_device_status, 'interval', seconds=poll_interval, id='snmp_poll', max_instances=1)
    scheduler.add_job(poll_traffic, 'interval', seconds=traffic_poll_interval, id='traffic_poll', max_instances=1)
    scheduler.add_job(run_hourly_cleanup, 'interval', minutes=60, id='hourly_cleanup', max_instances=1)
    scheduler.add_job(run_monthly_report_cron, 'cron', day='last', hour=23, minute=50, id='monthly_report_cron')
    scheduler.add_job(run_weekly_vacuum, 'cron', day_of_week='sun', hour=3, minute=0, id='weekly_vacuum')
    scheduler.add_job(run_telegram_daily_digest, 'cron', hour=d_hour, minute=d_min, id='telegram_daily_digest')
    scheduler.add_job(sync_dynamic_settings, 'interval', seconds=30, id='config_sync', max_instances=1)

    sync_dynamic_settings()
    scheduler.start()
    telegram_bot.start()

    print(f"\n{'='*50}")
    print("  TIKWatch Poller & Telegram Daemon started")
    print(f"  SNMP poll status every {poll_interval}s")
    print(f"  SNMP poll traffic every {traffic_poll_interval}s")
    print("  Retention cleanup every 60m")
    print(f"{'='*50}\n")

    stop_event = threading.Event()

    def _shutdown(signum, _frame):
        logger.info(f"[Poller] Received signal {signum}, shutting down gracefully...")
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while not stop_event.is_set():
        stop_event.wait(1.0)

    try:
        scheduler.shutdown(wait=False)
        telegram_bot.stop()
    except Exception:
        pass
    sys.exit(0)


if __name__ == '__main__':
    main()
