#!/usr/bin/env python3
"""
NetMon - Database Manager
SQLite-based persistent storage
"""

import sqlite3
import json
import logging
import os
import random
import secrets
import threading
import time
from datetime import datetime
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger('netmon.database')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(BASE_DIR, 'netmon.db')
DB_PATH = os.environ.get('DB_PATH', DEFAULT_DB)


class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self._write_lock = threading.RLock()
        self._init_db()

    @staticmethod
    def _is_locked_error(exc):
        msg = str(exc).lower()
        return 'locked' in msg or 'busy' in msg

    def _run_with_retry(self, fn, max_retries=6):
        """Execute a DB operation with jittered exponential backoff on transient SQLite lock/busy errors."""
        last_exc = None
        for attempt in range(max_retries + 1):
            try:
                return fn()
            except sqlite3.OperationalError as e:
                if not self._is_locked_error(e) or attempt >= max_retries:
                    raise
                last_exc = e
                delay = min(2.5, 0.12 * (2 ** attempt)) + random.uniform(0.02, 0.12)
                logger.warning(f"[DB] SQLite busy/locked (attempt {attempt + 1}/{max_retries + 1}), retrying in {delay:.2f}s...")
                time.sleep(delay)
        if last_exc:
            raise last_exc

    @contextmanager
    def conn(self, read_only=False):
        c = sqlite3.connect(self.db_path, check_same_thread=False, timeout=45.0)
        c.row_factory = sqlite3.Row
        for pragma in (
            "PRAGMA busy_timeout=45000",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA cache_size=-8000",
            "PRAGMA temp_store=MEMORY"
        ):
            try:
                c.execute(pragma)
            except sqlite3.OperationalError:
                pass
        try:
            c.execute("PRAGMA mmap_size=268435456")
        except sqlite3.OperationalError:
            try:
                c.execute("PRAGMA mmap_size=0")
            except Exception:
                pass
        try:
            yield c
            if not read_only and c.in_transaction:
                for attempt in range(5):
                    try:
                        c.commit()
                        break
                    except sqlite3.OperationalError as e:
                        if not self._is_locked_error(e) or attempt >= 4:
                            raise
                        time.sleep(0.08 * (attempt + 1) + random.uniform(0.01, 0.05))
            elif read_only and c.in_transaction:
                c.rollback()
        except Exception:
            try:
                c.rollback()
            except Exception:
                pass
            raise
        finally:
            c.close()

    def _init_db(self):
        def _enable_wal():
            with self.conn() as c:
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("PRAGMA wal_autocheckpoint=1000")
        self._run_with_retry(_enable_wal)

        with self.conn() as c:
            try:
                c.execute("DROP INDEX IF EXISTS idx_metrics_device")
            except Exception:
                pass
            c.executescript('''
                CREATE TABLE IF NOT EXISTS devices (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    name          TEXT NOT NULL,
                    ip            TEXT NOT NULL UNIQUE,
                    mac           TEXT DEFAULT '',
                    type          TEXT DEFAULT 'unknown',
                    vendor        TEXT DEFAULT '',
                    model         TEXT DEFAULT '',
                    zone_id       INTEGER DEFAULT 1,
                    snmp_enabled  INTEGER DEFAULT 0,
                    snmp_community TEXT DEFAULT 'public',
                    snmp_version  TEXT DEFAULT '2c',
                    snmp_port     INTEGER DEFAULT 161,
                    status        TEXT DEFAULT 'unknown',
                    last_seen     TEXT,
                    last_polled   TEXT,
                    uptime        TEXT DEFAULT '',
                    description   TEXT DEFAULT '',
                    sys_name      TEXT DEFAULT '',
                    pos_x         REAL DEFAULT 100,
                    pos_y         REAL DEFAULT 100,
                    icon          TEXT DEFAULT 'router',
                    unifi_id      TEXT DEFAULT '',
                    cpu_usage     REAL DEFAULT NULL,
                    memory_usage  REAL DEFAULT NULL,
                    temperature   REAL DEFAULT NULL,
                    wan_in        REAL DEFAULT NULL,
                    wan_out       REAL DEFAULT NULL,
                    client_count  INTEGER DEFAULT NULL,
                    uplink_speed_mbps INTEGER DEFAULT 1000,
                    alerts_enabled INTEGER DEFAULT 1,
                    latency_ms    REAL DEFAULT NULL,
                    packet_loss   REAL DEFAULT 0,
                    created_at    TEXT DEFAULT (datetime('now')),
                    updated_at    TEXT DEFAULT (datetime('now')),
                    source        TEXT DEFAULT 'manual'
                );

                CREATE TABLE IF NOT EXISTS zones (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    color       TEXT DEFAULT '#00d4ff',
                    created_at  TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id      INTEGER,
                    device_name    TEXT DEFAULT '',
                    device_ip      TEXT DEFAULT '',
                    severity       TEXT DEFAULT 'info',
                    message        TEXT NOT NULL,
                    details        TEXT DEFAULT '{}',
                    acknowledged   INTEGER DEFAULT 0,
                    ack_by         TEXT DEFAULT '',
                    ack_at         TEXT,
                    is_false_alarm INTEGER DEFAULT 0,
                    ai_analysis    TEXT DEFAULT '',
                    replica_count  INTEGER DEFAULT 0,
                    created_at     TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS access_logs (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    source     TEXT DEFAULT '',
                    message    TEXT DEFAULT '',
                    type       TEXT DEFAULT 'info',
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS floorplans (
                    id             INTEGER PRIMARY KEY,
                    name           TEXT DEFAULT 'Main Floor',
                    background_url TEXT DEFAULT '',
                    canvas_data    TEXT DEFAULT NULL,
                    updated_at     TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS monthly_reports (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_month   TEXT UNIQUE,
                    generated_at   TEXT DEFAULT (datetime('now')),
                    report_data    TEXT
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key        TEXT PRIMARY KEY,
                    value      TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS snmp_metrics (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id    INTEGER,
                    metric_name  TEXT,
                    metric_value TEXT,
                    timestamp    TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS interface_traffic (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id   INTEGER NOT NULL,
                    iface_name  TEXT NOT NULL,
                    iface_idx   INTEGER DEFAULT 0,
                    rx_bps      REAL DEFAULT 0,
                    tx_bps      REAL DEFAULT 0,
                    sampled_at  TEXT DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS downtime_analysis (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id      INTEGER,
                    down_time      TEXT NOT NULL,
                    up_time        TEXT,
                    duration_sec   INTEGER,
                    ping_pattern   TEXT,
                    snmp_pattern   TEXT,
                    reboot_detected INTEGER DEFAULT 0,
                    justification  TEXT,
                    confidence     REAL,
                    created_at     TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS users (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    username             TEXT UNIQUE NOT NULL,
                    password_hash        TEXT NOT NULL,
                    role                 TEXT DEFAULT 'viewer',
                    display_name         TEXT DEFAULT '',
                    must_change_password INTEGER DEFAULT 0,
                    created_at           TEXT DEFAULT (datetime('now')),
                    last_login           TEXT
                );

                CREATE TABLE IF NOT EXISTS poller_state (
                    key        TEXT PRIMARY KEY,
                    value      TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
                CREATE INDEX IF NOT EXISTS idx_access_logs_created ON access_logs(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_metrics_device ON snmp_metrics(device_id, metric_name, timestamp);
                CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON snmp_metrics(metric_name, timestamp, device_id, metric_value);
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON snmp_metrics(timestamp);
                CREATE INDEX IF NOT EXISTS idx_if_traffic ON interface_traffic(device_id, iface_name, sampled_at DESC);
                CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON interface_traffic(sampled_at);
                CREATE INDEX IF NOT EXISTS idx_downtime_device ON downtime_analysis(device_id);
            ''')

            # Migration: Add any missing fields to devices table if they don't exist (preserving DB state)
            columns_definitions = {
                'mac': "TEXT DEFAULT ''",
                'type': "TEXT DEFAULT 'unknown'",
                'vendor': "TEXT DEFAULT ''",
                'model': "TEXT DEFAULT ''",
                'zone_id': "INTEGER DEFAULT 1",
                'snmp_enabled': "INTEGER DEFAULT 0",
                'snmp_community': "TEXT DEFAULT 'public'",
                'snmp_version': "TEXT DEFAULT '2c'",
                'snmp_port': "INTEGER DEFAULT 161",
                'status': "TEXT DEFAULT 'unknown'",
                'last_seen': "TEXT",
                'last_polled': "TEXT",
                'uptime': "TEXT DEFAULT ''",
                'description': "TEXT DEFAULT ''",
                'sys_name': "TEXT DEFAULT ''",
                'pos_x': "REAL DEFAULT 100",
                'pos_y': "REAL DEFAULT 100",
                'icon': "TEXT DEFAULT 'router'",
                'unifi_id': "TEXT DEFAULT ''",
                'cpu_usage': "REAL DEFAULT NULL",
                'memory_usage': "REAL DEFAULT NULL",
                'temperature': "REAL DEFAULT NULL",
                'wan_in': "REAL DEFAULT NULL",
                'wan_out': "REAL DEFAULT NULL",
                'client_count': "INTEGER DEFAULT NULL",
                'uplink_speed_mbps': "INTEGER DEFAULT 1000",
                'alerts_enabled': "INTEGER DEFAULT 1",
                'created_at': "TEXT DEFAULT (datetime('now'))",
                'updated_at': "TEXT DEFAULT (datetime('now'))",
                'source': "TEXT DEFAULT 'manual'",
                'wan_iface_idx': "TEXT DEFAULT ''",
                'include_in_aggregate': "INTEGER DEFAULT 1",
                'latency_ms': "REAL DEFAULT NULL",
                'packet_loss': "REAL DEFAULT 0",
                'parent_device_id': "INTEGER DEFAULT NULL",
                'maintenance_until': "TEXT DEFAULT NULL"
            }
            for col, defn in columns_definitions.items():
                try:
                    c.execute(f"ALTER TABLE devices ADD COLUMN {col} {defn}")
                except sqlite3.OperationalError:
                    pass # Column already exists
            
            # Run alerts migrations for AI false warning detection
            alerts_cols = {r['name']: r['type'] for r in c.execute("PRAGMA table_info(alerts)").fetchall()}
            if 'is_false_alarm' not in alerts_cols:
                try:
                    c.execute("ALTER TABLE alerts ADD COLUMN is_false_alarm INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
            if 'ai_analysis' not in alerts_cols:
                try:
                    c.execute("ALTER TABLE alerts ADD COLUMN ai_analysis TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass
            if 'replica_count' not in alerts_cols:
                try:
                    c.execute("ALTER TABLE alerts ADD COLUMN replica_count INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass

            # Update source for existing unifi devices
            c.execute("UPDATE devices SET source='unifi' WHERE (unifi_id IS NOT NULL AND unifi_id != '') AND source = 'manual'")

            # Default settings
            defaults = {
                'poll_interval': '30',
                'traffic_poll_interval': '15',
                'allowed_cidrs': '10.122.100.0/24',
                'ai_provider': 'auto',
                'groq_api_key': '',
                'groq_model': 'llama-3.3-70b-versatile',
                'groq_redact_ips': 'true',
                'campus_total_bandwidth_mbps': '6000',
                'campus_isp_list': '[{"name":"ISP 1 (Utama)","mbps":6000,"enabled":true},{"name":"ISP 2","mbps":0,"enabled":false},{"name":"ISP 3","mbps":0,"enabled":false},{"name":"ISP 4","mbps":0,"enabled":false}]',
                'alert_on_down': 'true',
                'alert_on_up': 'true',
                'default_community': 'public',
                'default_snmp_version': '2c',
                'unifi_host': '',
                'unifi_user': '',
                'unifi_pass': '',
                'unifi_port': '8443',
                'unifi_site': 'default',
                'app_name': 'TIKWatch',
                'alert_retention_days': '30',
                'log_retention_days': '90',
                'traffic_retention_hours': '720',
                'report_metrics_retention_hours': '1440',
                'interface_chart_retention_hours': '168',
                'anomaly_cap_multiplier': '1.05',
                'anomaly_cap_gbps': '5.0',
                'telegram_enabled': 'false',
                'telegram_bot_token': '',
                'telegram_chat_ids': '',
                'telegram_notify_down': 'true',
                'telegram_notify_up': 'true',
                'telegram_censor_ips': 'true',
                'telegram_daily_digest_enabled': 'true',
                'telegram_daily_digest_time': '08:00',
                'anomaly_alert_enabled': 'true',
                'traffic_spike_multiplier': '4.0',
                'traffic_spike_min_mbps': '80.0',
                'cpu_spike_threshold': '92.0',
                'cpu_jump_threshold': '65.0',
                'memory_spike_threshold': '95.0',
            }
            for k, v in defaults.items():
                c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

            # Auto-generate strong cryptographic secrets if missing
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                      ('app_secret_key', secrets.token_hex(32)))
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                      ('internal_emit_token', secrets.token_hex(24)))

            # Seed initial admin account if no users exist yet
            user_cnt = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            if user_cnt == 0:
                init_pw = os.environ.get('NETMON_ADMIN_PASS', 'tikwatch2026')
                c.execute('''
                    INSERT INTO users (username, password_hash, role, display_name, must_change_password)
                    VALUES (?, ?, 'admin', 'NOC Administrator', ?)
                ''', ('admin', generate_password_hash(init_pw), 1 if init_pw == 'tikwatch2026' else 0))
                print("[Auth] Initialized default admin account (username: admin). Please change password in Settings!")

            # Migrate old overly aggressive default settings to conservative non-spam defaults
            old_aggressive_defaults = {
                'traffic_spike_multiplier': ('2.5', '4.0'),
                'traffic_spike_min_mbps': ('20.0', '80.0'),
                'cpu_spike_threshold': ('85.0', '92.0'),
                'cpu_jump_threshold': ('40.0', '65.0'),
                'memory_spike_threshold': ('90.0', '95.0'),
            }
            for key, (old_val, new_val) in old_aggressive_defaults.items():
                c.execute('UPDATE settings SET value=? WHERE key=? AND value=?', (new_val, key, old_val))

            # Strictly enforce the SFP / ISP anomaly link cap (1.05x tolerance, 5.0 Gbps ceiling)
            c.execute("UPDATE settings SET value='1.05' WHERE key='anomaly_cap_multiplier' AND value='1.25'")
            c.execute("UPDATE settings SET value='5.0' WHERE key='anomaly_cap_gbps' AND value='10.0'")

            # Automatically purge any nonsensical traffic spikes (> SFP / link cap) that may have been recorded
            try:
                mult_row = c.execute("SELECT value FROM settings WHERE key='anomaly_cap_multiplier'").fetchone()
                cap_row = c.execute("SELECT value FROM settings WHERE key='anomaly_cap_gbps'").fetchone()
                clean_mult = float(mult_row[0]) if mult_row else 1.05
                clean_cap_bps = float(cap_row[0]) * 1e9 if cap_row else 5e9

                c.execute('''
                    UPDATE snmp_metrics 
                    SET metric_value = '0' 
                    WHERE metric_name IN ('wan_in', 'wan_out') 
                    AND CAST(metric_value AS REAL) > (
                        SELECT MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?) 
                        FROM devices WHERE devices.id = snmp_metrics.device_id
                    )
                ''', (clean_mult, clean_cap_bps))

                c.execute('''
                    UPDATE devices 
                    SET wan_in = 0
                    WHERE wan_in > MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                ''', (clean_mult, clean_cap_bps))

                c.execute('''
                    UPDATE devices 
                    SET wan_out = 0
                    WHERE wan_out > MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                ''', (clean_mult, clean_cap_bps))

                c.execute('''
                    UPDATE interface_traffic 
                    SET rx_bps = 0
                    WHERE rx_bps > (
                        SELECT MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?) 
                        FROM devices WHERE devices.id = interface_traffic.device_id
                    )
                ''', (clean_mult, clean_cap_bps))

                c.execute('''
                    UPDATE interface_traffic 
                    SET tx_bps = 0
                    WHERE tx_bps > (
                        SELECT MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?) 
                        FROM devices WHERE devices.id = interface_traffic.device_id
                    )
                ''', (clean_mult, clean_cap_bps))
            except Exception as e:
                print(f"[DB init] Auto-clean traffic spikes note: {e}")

            c.execute('INSERT OR IGNORE INTO zones (id, name, color, description) VALUES (1, "Default Zone", "#00d4ff", "Default network zone")')
            c.execute('INSERT OR IGNORE INTO floorplans (id) VALUES (1)')

    def cleanup_traffic_anomalies(self):
        """Hapus (nolkan) traffic historis yang melebihi cap anomali saat ini.
        DESTRUKTIF & TIDAK BISA DIBATALKAN -- sengaja HANYA dipanggil manual (lewat tombol
        di Settings), BUKAN otomatis tiap startup, supaya data lama tidak diam-diam
        terhapus setiap kali aplikasi restart hanya karena nilai cap/uplink_speed_mbps
        kebetulan berubah sejak data itu direkam.
        Return dict jumlah baris yang kena di tiap tabel, supaya hasilnya bisa diaudit."""
        result = {'snmp_metrics': 0, 'devices_wan_in': 0, 'devices_wan_out': 0,
                  'interface_rx': 0, 'interface_tx': 0, 'error': None}
        try:
            with self.conn() as c:
                mult_row = c.execute("SELECT value FROM settings WHERE key='anomaly_cap_multiplier'").fetchone()
                cap_row = c.execute("SELECT value FROM settings WHERE key='anomaly_cap_gbps'").fetchone()
                mult = float(mult_row[0]) if mult_row else 1.05
                cap_bps = float(cap_row[0]) * 1000000000.0 if cap_row else 5000000000.0

                cur = c.execute('''
                    UPDATE snmp_metrics
                    SET metric_value = '0'
                    WHERE metric_name IN ('wan_in', 'wan_out')
                    AND CAST(metric_value AS REAL) > (
                        SELECT MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                        FROM devices WHERE devices.id = snmp_metrics.device_id
                    )
                ''', (mult, cap_bps))
                result['snmp_metrics'] = cur.rowcount

                cur = c.execute('''
                    UPDATE devices
                    SET wan_in = 0
                    WHERE wan_in > MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                ''', (mult, cap_bps))
                result['devices_wan_in'] = cur.rowcount

                cur = c.execute('''
                    UPDATE devices
                    SET wan_out = 0
                    WHERE wan_out > MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                ''', (mult, cap_bps))
                result['devices_wan_out'] = cur.rowcount

                cur = c.execute('''
                    UPDATE interface_traffic
                    SET rx_bps = 0
                    WHERE rx_bps > (
                        SELECT MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                        FROM devices WHERE devices.id = interface_traffic.device_id
                    )
                ''', (mult, cap_bps))
                result['interface_rx'] = cur.rowcount

                cur = c.execute('''
                    UPDATE interface_traffic
                    SET tx_bps = 0
                    WHERE tx_bps > (
                        SELECT MIN(IFNULL(uplink_speed_mbps, 1000) * 1000000.0 * ?, ?)
                        FROM devices WHERE devices.id = interface_traffic.device_id
                    )
                ''', (mult, cap_bps))
                result['interface_tx'] = cur.rowcount
        except Exception as e:
            result['error'] = str(e)
        return result

    # ============================================================
    # DEVICES
    # ============================================================

    def get_all_devices(self):
        with self.conn() as c:
            rows = c.execute('''
                SELECT d.*, z.name AS zone_name, z.color AS zone_color
                FROM devices d
                LEFT JOIN zones z ON d.zone_id = z.id
                ORDER BY d.name COLLATE NOCASE
            ''').fetchall()
            return [dict(r) for r in rows]

    def get_device(self, device_id):
        with self.conn() as c:
            row = c.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
            return dict(row) if row else None

    def get_device_by_ip(self, ip):
        with self.conn() as c:
            row = c.execute('SELECT * FROM devices WHERE ip = ?', (ip,)).fetchone()
            return dict(row) if row else None


    def add_device(self, data):
        parent_id = data.get('parent_device_id')
        try:
            parent_id = int(parent_id) if parent_id not in (None, '', 0, '0') else None
        except (ValueError, TypeError):
            parent_id = None
        with self.conn() as c:
            cur = c.execute('''
                INSERT INTO devices
                    (name, ip, mac, type, vendor, model, zone_id,
                     snmp_enabled, snmp_community, snmp_version, snmp_port,
                     icon, pos_x, pos_y, description, status, source, uplink_speed_mbps, alerts_enabled, wan_iface_idx, include_in_aggregate, parent_device_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                data.get('name') or data.get('ip', 'Unknown'),
                data.get('ip', ''),
                data.get('mac', ''),
                data.get('type', 'unknown'),
                data.get('vendor', ''),
                data.get('model', ''),
                data.get('zone_id', 1),
                1 if data.get('snmp_enabled') else 0,
                data.get('snmp_community', 'public'),
                data.get('snmp_version', '2c'),
                data.get('snmp_port', 161),
                data.get('icon', 'router'),
                data.get('pos_x', 100),
                data.get('pos_y', 100),
                data.get('description', ''),
                data.get('status', 'unknown'),
                data.get('source', 'manual'),
                data.get('uplink_speed_mbps', 1000),
                1 if data.get('alerts_enabled', True) else 0,
                data.get('wan_iface_idx', ''),
                1 if data.get('include_in_aggregate', True) else 0,
                parent_id,
            ))
            return cur.lastrowid

    def update_device(self, device_id, data):
        allowed = ['name', 'ip', 'mac', 'type', 'vendor', 'model', 'zone_id',
                   'snmp_enabled', 'snmp_community', 'snmp_version', 'snmp_port',
                   'icon', 'pos_x', 'pos_y', 'description', 'status',
                   'last_seen', 'last_polled', 'uptime', 'sys_name',
                   'cpu_usage', 'memory_usage', 'temperature', 'wan_in', 'wan_out',
                   'uplink_speed_mbps', 'alerts_enabled', 'wan_iface_idx', 'include_in_aggregate',
                   'latency_ms', 'packet_loss', 'parent_device_id', 'maintenance_until']
        if 'snmp_community' in data and data['snmp_community'] in ('***', '', None):
            data = dict(data)
            data.pop('snmp_community', None)
        if 'parent_device_id' in data:
            pid = data['parent_device_id']
            try:
                pid = int(pid) if pid not in (None, '', 0, '0') and str(pid) != str(device_id) else None
            except (ValueError, TypeError):
                pid = None
            data = dict(data)
            data['parent_device_id'] = pid
        fields, values = [], []
        for f in allowed:
            if f in data:
                fields.append(f'{f} = ?')
                values.append(data[f])
        if not fields:
            return
        fields.append('updated_at = ?')
        values.append(datetime.now().isoformat())
        values.append(device_id)
        def _do_update():
            with self._write_lock:
                with self.conn() as c:
                    c.execute(f'UPDATE devices SET {", ".join(fields)} WHERE id = ?', tuple(values))
        self._run_with_retry(_do_update)

    def delete_device(self, device_id):
        with self.conn() as c:
            c.execute('UPDATE devices SET parent_device_id = NULL WHERE parent_device_id = ?', (device_id,))
            c.execute('DELETE FROM devices WHERE id = ?', (device_id,))

    def is_upstream_parent_down(self, device_id):
        """Return (True, parent_dict) if any upstream parent in chain (up to 5 hops) is currently DOWN."""
        if not device_id:
            return False, None
        visited = {int(device_id)}
        cur_id = int(device_id)
        with self.conn() as c:
            for _ in range(5):
                row = c.execute('SELECT parent_device_id FROM devices WHERE id = ?', (cur_id,)).fetchone()
                if not row or not row['parent_device_id']:
                    break
                pid = int(row['parent_device_id'])
                if pid in visited:
                    break
                visited.add(pid)
                prow = c.execute('SELECT id, name, ip, status FROM devices WHERE id = ?', (pid,)).fetchone()
                if not prow:
                    break
                if prow['status'] == 'down':
                    return True, dict(prow)
                cur_id = pid
        return False, None

    def is_device_in_maintenance(self, device_id=None):
        """Return (True, until_str) if global or per-device maintenance window is currently active."""
        now_iso = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            settings = self.get_settings()
            g_until = (settings.get('global_maintenance_until') or '').strip()
            if g_until and g_until > now_iso:
                return True, g_until
        except Exception:
            pass
        if device_id:
            try:
                with self.conn() as c:
                    row = c.execute('SELECT maintenance_until FROM devices WHERE id = ?', (device_id,)).fetchone()
                    if row and row['maintenance_until']:
                        d_until = str(row['maintenance_until']).strip()
                        if d_until > now_iso:
                            return True, d_until
            except Exception:
                pass
        return False, None

    def set_maintenance_window(self, target='all', minutes=0):
        """Set or clear (minutes <= 0) maintenance window for 'all' or a specific device_id."""
        until_str = None
        if minutes and int(minutes) > 0:
            until_dt = datetime.now() + timedelta(minutes=int(minutes))
            until_str = until_dt.strftime('%Y-%m-%d %H:%M:%S')
        if str(target).lower() in ('all', 'global', 'semua'):
            self.save_settings({'global_maintenance_until': until_str or ''})
            if not until_str:
                with self.conn() as c:
                    c.execute('UPDATE devices SET maintenance_until = NULL')
            return until_str
        with self.conn() as c:
            c.execute('UPDATE devices SET maintenance_until = ? WHERE id = ?', (until_str, int(target)))
        return until_str

    def get_campus_total_bandwidth_mbps(self):
        """Return configured total campus ISP bandwidth capacity in Mbps (default 6000 = 6 Gbps)."""
        try:
            val = float(self.get_settings().get('campus_total_bandwidth_mbps', 6000) or 6000)
            return val if val > 0 else 6000.0
        except Exception:
            return 6000.0

    # ============================================================
    # USER AUTHENTICATION & RBAC
    # ============================================================

    def authenticate_user(self, username, password):
        if not username or not password:
            return None
        with self.conn() as c:
            row = c.execute('SELECT * FROM users WHERE username = ?', (username.strip(),)).fetchone()
            if row and check_password_hash(row['password_hash'], password):
                c.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), row['id']))
                u = dict(row)
                u.pop('password_hash', None)
                return u
        return None

    def get_user(self, user_id):
        with self.conn() as c:
            row = c.execute(
                'SELECT id, username, role, display_name, must_change_password, created_at, last_login FROM users WHERE id = ?',
                (user_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_all_users(self):
        with self.conn() as c:
            rows = c.execute(
                'SELECT id, username, role, display_name, must_change_password, created_at, last_login FROM users ORDER BY id ASC'
            ).fetchall()
            return [dict(r) for r in rows]

    def create_user(self, username, password, role='viewer', display_name=''):
        uname = (username or '').strip()
        if not uname or not password or len(password) < 6:
            raise ValueError("Username wajib diisi dan password minimal 6 karakter.")
        role_val = 'admin' if role == 'admin' else 'viewer'
        with self.conn() as c:
            cur = c.execute(
                'INSERT INTO users (username, password_hash, role, display_name, must_change_password) VALUES (?, ?, ?, ?, 0)',
                (uname, generate_password_hash(password), role_val, (display_name or uname).strip())
            )
            return cur.lastrowid

    def update_user_password(self, user_id, new_password):
        if not new_password or len(new_password) < 6:
            raise ValueError("Password baru minimal 6 karakter.")
        with self.conn() as c:
            c.execute(
                'UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
                (generate_password_hash(new_password), int(user_id))
            )

    def delete_user(self, user_id):
        with self.conn() as c:
            admins = c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?", (int(user_id),)).fetchone()[0]
            target = c.execute("SELECT role FROM users WHERE id = ?", (int(user_id),)).fetchone()
            if target and target['role'] == 'admin' and admins == 0:
                raise ValueError("Tidak dapat menghapus satu-satunya akun Admin.")
            c.execute('DELETE FROM users WHERE id = ?', (int(user_id),))

    # ============================================================
    # POLLER STATE PERSISTENCE & LOG RETENTION
    # ============================================================

    def get_poller_state(self, key, default=None):
        try:
            with self.conn() as c:
                row = c.execute('SELECT value FROM poller_state WHERE key = ?', (key,)).fetchone()
                return json.loads(row['value']) if row and row['value'] else default
        except Exception as e:
            logger.warning(f"[DB] get_poller_state({key}) failed: {e}")
            return default

    def set_poller_state(self, key, value):
        try:
            def _do_set():
                with self._write_lock:
                    with self.conn() as c:
                        c.execute(
                            'INSERT OR REPLACE INTO poller_state (key, value, updated_at) VALUES (?, ?, ?)',
                            (key, json.dumps(value), datetime.now().isoformat())
                        )
            self._run_with_retry(_do_set)
        except Exception as e:
            logger.warning(f"[DB] set_poller_state({key}) failed: {e}")

    def cleanup_old_records(self, alert_days=30, log_days=90):
        """Prune old acknowledged alerts and access logs periodically."""
        try:
            def _do_cleanup():
                with self._write_lock:
                    with self.conn() as c:
                        c.execute("DELETE FROM alerts WHERE acknowledged = 1 AND created_at < datetime('now', ? || ' days')",
                                  (f'-{int(alert_days)}',))
                        c.execute("DELETE FROM access_logs WHERE created_at < datetime('now', ? || ' days')",
                                  (f'-{int(log_days)}',))
            self._run_with_retry(_do_cleanup)
        except Exception as e:
            logger.warning(f"[DB] cleanup_old_records failed: {e}")

    @staticmethod
    def calc_percentile(values, pct=95):
        """Calculate the N-th percentile (Cacti 95th percentile standard) from a list of numeric samples."""
        clean = sorted(float(v) for v in values if v is not None)
        if not clean:
            return 0.0
        idx = int(round((pct / 100.0) * (len(clean) - 1)))
        idx = max(0, min(len(clean) - 1, idx))
        return round(clean[idx], 2)

    def add_or_update_unifi_device(self, data, zone_id=1, snmp_community='public', snmp_version='2c', snmp_port=161, snmp_enabled_for_new=False):
        ip = str(data.get('ip', '') or '').strip()
        if not ip:
            return False
        try:
            with self.conn() as c:
                existing = c.execute(
                    'SELECT id, client_count FROM devices WHERE ip = ? OR (unifi_id != "" AND unifi_id = ?)',
                    (ip, data.get('unifi_id', ''))
                ).fetchone()
                if existing:
                    now_str = datetime.now().isoformat()
                    c.execute('''
                        UPDATE devices SET name=?, mac=?, vendor=?, model=?, unifi_id=?, zone_id=?, updated_at=?,
                                           type = CASE WHEN ? NOT IN ('','unifi','unknown') THEN ? ELSE type END,
                                           cpu_usage=?, memory_usage=?, temperature=?, status=?, uptime=?, last_polled=?,
                                           last_seen=CASE WHEN ? = 'up' THEN ? ELSE last_seen END,
                                           wan_in=?, wan_out=?, client_count=?, source='unifi'
                        WHERE id=?
                    ''', (data.get('name',''), data.get('mac',''), data.get('vendor','Ubiquiti'),
                          data.get('model',''), data.get('unifi_id',''), zone_id,
                          now_str,
                          data.get('type',''), data.get('type',''),
                          data.get('cpu_usage'), data.get('memory_usage'), data.get('temperature'),
                          data.get('status','unknown'), data.get('uptime',''), now_str,
                          data.get('status','unknown'), now_str,
                          data.get('wan_in'), data.get('wan_out'), data.get('client_count'), existing['id']))
                    
                    device_id = existing['id']
                    if data.get('cpu_usage') is not None:
                        c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'cpu_usage', str(data['cpu_usage'])))
                    if data.get('memory_usage') is not None:
                        c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'memory_usage', str(data['memory_usage'])))
                    if data.get('temperature') is not None:
                        c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'temperature', str(data['temperature'])))
                    if data.get('client_count') is not None:
                        new_count = data['client_count']
                        old_count = existing['client_count']
                        if old_count is None or new_count != old_count:
                            c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'client_count', str(new_count)))
                    return False
                else:
                    now_str = datetime.now().isoformat()
                    c.execute('''
                        INSERT INTO devices (name, ip, mac, type, vendor, model, unifi_id, zone_id, snmp_enabled, snmp_community, snmp_version, snmp_port, status,
                                             cpu_usage, memory_usage, temperature, uptime, last_polled, last_seen,
                                             wan_in, wan_out, client_count, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unifi')
                    ''', (data.get('name', ip), ip,
                          data.get('mac',''), data.get('type','unifi'),
                          data.get('vendor','Ubiquiti'), data.get('model',''),
                          data.get('unifi_id',''), zone_id, 1 if snmp_enabled_for_new else 0, snmp_community, snmp_version, snmp_port, data.get('status','unknown'),
                          data.get('cpu_usage'), data.get('memory_usage'), data.get('temperature'),
                          data.get('uptime',''), now_str, 
                          now_str if data.get('status') == 'up' else None,
                          data.get('wan_in'), data.get('wan_out'), data.get('client_count')))
                    
                    new_id = c.execute('SELECT id FROM devices WHERE ip = ?', (ip,)).fetchone()
                    if new_id:
                        device_id = new_id['id']
                        if data.get('cpu_usage') is not None:
                            c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'cpu_usage', str(data['cpu_usage'])))
                        if data.get('memory_usage') is not None:
                            c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'memory_usage', str(data['memory_usage'])))
                        if data.get('temperature') is not None:
                            c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'temperature', str(data['temperature'])))
                        if data.get('client_count') is not None:
                            c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)', (device_id, 'client_count', str(data['client_count'])))
                    return True

        except sqlite3.IntegrityError:
            return False

    def get_zones_with_devices(self):
        with self.conn() as c:
            zones_rows = c.execute('''
                SELECT z.id, z.name, z.description, z.color,
                       COUNT(d.id) AS total,
                       SUM(CASE WHEN d.status='up' THEN 1 ELSE 0 END) AS up_count,
                       SUM(CASE WHEN d.status='down' THEN 1 ELSE 0 END) AS down_count,
                       SUM(CASE WHEN d.status='warning' THEN 1 ELSE 0 END) AS warn_count
                FROM zones z LEFT JOIN devices d ON d.zone_id = z.id
                GROUP BY z.id ORDER BY z.name COLLATE NOCASE
            ''').fetchall()
            
            zones = [dict(r) for r in zones_rows]
            for z in zones:
                z['devices'] = []
                # Ensure counts are integers even if NULL
                z['total'] = z['total'] or 0
                z['up_count'] = z['up_count'] or 0
                z['down_count'] = z['down_count'] or 0
                z['warn_count'] = z['warn_count'] or 0
                
            for z in zones:
                devs = c.execute('''
                    SELECT d.*, z.name AS zone_name, z.color AS zone_color
                    FROM devices d LEFT JOIN zones z ON z.id = d.zone_id
                    WHERE d.zone_id = ? ORDER BY d.name COLLATE NOCASE
                ''', (z['id'],)).fetchall()
                z['devices'] = [dict(d) for d in devs]
            return zones

    def get_device_type_counts(self):
        with self.conn() as c:
            rows = c.execute('SELECT type, COUNT(*) as cnt FROM devices GROUP BY type').fetchall()
            counts = {r['type']: r['cnt'] for r in rows}
            counts['_total'] = sum(counts.values())
            return counts

    # ============================================================
    # ZONES
    # ============================================================

    def get_all_zones(self):
        with self.conn() as c:
            rows = c.execute('''
                SELECT z.*, COUNT(d.id) AS device_count
                FROM zones z
                LEFT JOIN devices d ON z.id = d.zone_id
                GROUP BY z.id ORDER BY z.name COLLATE NOCASE
            ''').fetchall()
            return [dict(r) for r in rows]

    def get_zone(self, zone_id):
        with self.conn() as c:
            row = c.execute('SELECT * FROM zones WHERE id = ?', (zone_id,)).fetchone()
            return dict(row) if row else None

    def add_zone(self, data):
        with self.conn() as c:
            cur = c.execute(
                'INSERT INTO zones (name, description, color) VALUES (?, ?, ?)',
                (data.get('name','New Zone'), data.get('description',''), data.get('color','#00d4ff'))
            )
            return cur.lastrowid

    def update_zone(self, zone_id, data):
        with self.conn() as c:
            c.execute('UPDATE zones SET name=?, description=?, color=? WHERE id=?',
                      (data.get('name'), data.get('description',''), data.get('color','#00d4ff'), zone_id))

    def delete_zone(self, zone_id):
        with self.conn() as c:
            c.execute('UPDATE devices SET zone_id=1 WHERE zone_id=?', (zone_id,))
            if zone_id != 1:
                c.execute('DELETE FROM zones WHERE id=?', (zone_id,))

    # ============================================================
    # ALERTS
    # ============================================================

    def get_alerts(self, limit=50, offset=0, severity=None):
        with self.conn() as c:
            if severity:
                rows = c.execute(
                    '''SELECT id, device_id, device_name, device_ip, severity, message, details, 
                              acknowledged, ack_by, ack_at, is_false_alarm, ai_analysis, replica_count, 
                              strftime('%Y-%m-%dT%H:%M:%SZ', created_at) AS created_at 
                       FROM alerts WHERE severity=? ORDER BY created_at DESC LIMIT ? OFFSET ?''',
                    (severity, limit, offset)
                ).fetchall()
            else:
                rows = c.execute(
                    '''SELECT id, device_id, device_name, device_ip, severity, message, details, 
                              acknowledged, ack_by, ack_at, is_false_alarm, ai_analysis, replica_count, 
                              strftime('%Y-%m-%dT%H:%M:%SZ', created_at) AS created_at 
                       FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?''',
                    (limit, offset)
                ).fetchall()
            return [dict(r) for r in rows]

    def add_alert(self, data):
        with self.conn() as c:
            details = data.get('details', {})
            if isinstance(details, dict):
                details = json.dumps(details)
            cur = c.execute('''
                INSERT INTO alerts (device_id, device_name, device_ip, severity, message, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (data.get('device_id'), data.get('device_name',''), data.get('device_ip',''),
                  data.get('severity','info'), data.get('message',''), details))
            return cur.lastrowid

    def acknowledge_alert(self, alert_id, user='admin'):
        with self.conn() as c:
            c.execute('UPDATE alerts SET acknowledged=1, ack_by=?, ack_at=? WHERE id=?',
                      (user, datetime.now().isoformat(), alert_id))

    def acknowledge_all_alerts(self):
        with self.conn() as c:
            c.execute("UPDATE alerts SET acknowledged=1, ack_by='admin', ack_at=? WHERE acknowledged=0",
                      (datetime.now().isoformat(),))

    def get_unack_count(self):
        with self.conn() as c:
            return c.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND is_false_alarm=0').fetchone()[0]

    def get_active_alerts(self, limit=10):
        with self.conn(read_only=True) as c:
            rows = c.execute('''
                SELECT id, device_id, device_name, device_ip, severity, message, details,
                       acknowledged, ack_by, ack_at, is_false_alarm, ai_analysis, replica_count,
                       strftime('%Y-%m-%d %H:%M:%S', created_at) AS created_at
                FROM alerts
                WHERE acknowledged = 0 AND is_false_alarm = 0
                ORDER BY created_at DESC LIMIT ?
            ''', (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ============================================================
    # ACCESS LOGS
    # ============================================================

    def add_access_log(self, data):
        with self.conn() as c:
            c.execute('INSERT INTO access_logs (source, message, type) VALUES (?, ?, ?)',
                      (data.get('source',''), data.get('message',''), data.get('type','info')))

    def get_access_logs(self, limit=100):
        with self.conn() as c:
            rows = c.execute(
                '''SELECT id, source, message, type, 
                          strftime('%Y-%m-%dT%H:%M:%SZ', created_at) AS created_at 
                   FROM access_logs ORDER BY created_at DESC LIMIT ?''', 
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ============================================================
    # FLOOR PLAN
    # ============================================================

    def get_floorplan(self, fp_id=1):
        with self.conn() as c:
            row = c.execute('SELECT * FROM floorplans WHERE id=?', (fp_id,)).fetchone()
            if row:
                result = dict(row)
                if result.get('canvas_data'):
                    try:
                        result['canvas_data'] = json.loads(result['canvas_data'])
                    except Exception:
                        pass
                return result
            return {'id': 1, 'name': 'Main Floor', 'background_url': '', 'canvas_data': None}

    def save_floorplan(self, data, fp_id=1):
        canvas_data = data.get('canvas_data')
        if isinstance(canvas_data, (dict, list)):
            canvas_data = json.dumps(canvas_data)
        with self.conn() as c:
            c.execute('''
                UPDATE floorplans SET name=?, background_url=?, canvas_data=?, updated_at=?
                WHERE id=?
            ''', (data.get('name','Main Floor'), data.get('background_url',''),
                  canvas_data, datetime.now().isoformat(), fp_id))

    # ============================================================
    # SETTINGS
    # ============================================================

    def get_settings(self):
        with self.conn(read_only=True) as c:
            rows = c.execute('SELECT key, value FROM settings').fetchall()
            return {r['key']: r['value'] for r in rows}

    def save_settings(self, data):
        with self.conn() as c:
            for k, v in data.items():
                c.execute('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)',
                          (k, str(v), datetime.now().isoformat()))

    # ============================================================
    # SNMP METRICS
    # ============================================================

    def save_metric(self, device_id, name, value):
        def _do_save():
            with self._write_lock:
                with self.conn() as c:
                    c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)',
                              (device_id, name, str(value)))
        self._run_with_retry(_do_save)

    def save_metrics_batch(self, metric_rows):
        """Batch-insert [(device_id, metric_name, value), ...] in a single transaction."""
        if not metric_rows:
            return
        rows = [(did, name, str(val)) for did, name, val in metric_rows]
        def _do_batch():
            with self._write_lock:
                with self.conn() as c:
                    c.executemany(
                        'INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)',
                        rows
                    )
        self._run_with_retry(_do_batch)

    def save_interface_traffic(self, device_id, iface_name, iface_idx, rx_bps, tx_bps):
        def _do_save():
            with self._write_lock:
                with self.conn() as c:
                    c.execute('INSERT INTO interface_traffic (device_id,iface_name,iface_idx,rx_bps,tx_bps) VALUES (?,?,?,?,?)',
                              (device_id, iface_name, iface_idx, rx_bps, tx_bps))
        self._run_with_retry(_do_save)

    def save_interface_traffic_batch(self, traffic_rows):
        """Batch-insert [(device_id, iface_name, iface_idx, rx_bps, tx_bps), ...] in one transaction."""
        if not traffic_rows:
            return
        def _do_batch():
            with self._write_lock:
                with self.conn() as c:
                    c.executemany(
                        'INSERT INTO interface_traffic (device_id,iface_name,iface_idx,rx_bps,tx_bps) VALUES (?,?,?,?,?)',
                        traffic_rows
                    )
        self._run_with_retry(_do_batch)

    def get_interface_traffic(self, device_id, iface_name=None, hours=1):
        try:
            poll_interval = max(5, int(self.get_settings().get('traffic_poll_interval', 15)))
        except Exception:
            poll_interval = 15
        # Limit utk baris mentah (single iface) harus ngikutin traffic_poll_interval AKTUAL,
        # bukan asumsi tetap 30 detik/sample -- kalau tidak, view rentang lebar bisa kepotong
        # dan kehilangan data TERBARU (LIMIT ambil yg paling lama dulu krn ORDER BY ASC).
        raw_limit = min(int(hours * 3600 / poll_interval) + 50, 20000)
        bucket_limit = min(int(hours * 120) + 10, 3000)
        with self.conn() as c:
            if iface_name:
                rows = c.execute('''
                    SELECT strftime('%Y-%m-%dT%H:%M:%SZ', sampled_at) AS ts, rx_bps, tx_bps FROM interface_traffic
                    WHERE device_id=? AND iface_name=?
                      AND sampled_at >= datetime('now', ? || ' hours')
                    ORDER BY sampled_at ASC LIMIT ?
                ''', (device_id, iface_name, f'-{int(hours)}', raw_limit)).fetchall()
            else:
                rows = c.execute('''
                    WITH iface_bucket AS (
                        SELECT
                            iface_name,
                            CASE
                                WHEN CAST(strftime('%S', sampled_at) AS INTEGER) < 30 THEN strftime('%Y-%m-%dT%H:%M:00Z', sampled_at)
                                ELSE strftime('%Y-%m-%dT%H:%M:30Z', sampled_at)
                            END AS bucket,
                            AVG(rx_bps) AS avg_rx,
                            AVG(tx_bps) AS avg_tx
                        FROM interface_traffic
                        WHERE device_id=?
                          AND sampled_at >= datetime('now', ? || ' hours')
                        GROUP BY iface_name, bucket
                    )
                    SELECT bucket, SUM(avg_rx), SUM(avg_tx)
                    FROM iface_bucket
                    GROUP BY bucket
                    ORDER BY bucket ASC LIMIT ?
                ''', (device_id, f'-{int(hours)}', bucket_limit)).fetchall()
            return [{'ts': r[0], 'rx_bps': r[1], 'tx_bps': r[2]} for r in rows]

    def get_backbone_traffic_history(self, hours):
        """Riwayat throughput backbone (wan_in/wan_out gabungan semua router) untuk chart dashboard.
        - Rentang <= 2h (1h view): memakai real peak per-device per-menit lalu dijumlahkan lintas router.
        - Rentang > 2h (24h/3d/7d): memakai rata-rata (AVG) per-device per-bucket agar tren tidak
          bias oleh spike sesaat, sambil tetap menyertakan nilai peak (in_peak/out_peak).
        """
        is_short_range = (hours <= 2)
        if is_short_range:
            bucket_sql = "strftime('%Y-%m-%d %H:%M', m.timestamp, 'localtime')"
            label_idx = 11  # 'HH:MM'
            limit = 130
        elif hours <= 24:
            bucket_sql = ("strftime('%Y-%m-%d %H:', m.timestamp, 'localtime') || "
                          "(CASE WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 15 THEN '00' "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 30 THEN '15' "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 45 THEN '30' ELSE '45' END)")
            label_idx = 11  # 'HH:MM'
            limit = 100
        else:
            bucket_sql = "strftime('%Y-%m-%d %H:00', m.timestamp, 'localtime')"
            label_idx = 5   # 'MM-DD HH:00'
            limit = 200

        with self.conn() as c:
            rows = c.execute(f'''
                WITH per_device_bucket AS (
                    SELECT
                        m.device_id,
                        {bucket_sql} AS bucket,
                        COALESCE(MAX(CASE WHEN m.metric_name = 'wan_in' THEN CAST(m.metric_value AS REAL) END), 0) AS rx_peak,
                        COALESCE(MAX(CASE WHEN m.metric_name = 'wan_out' THEN CAST(m.metric_value AS REAL) END), 0) AS tx_peak,
                        COALESCE(AVG(CASE WHEN m.metric_name = 'wan_in' THEN CAST(m.metric_value AS REAL) END), 0) AS rx_avg,
                        COALESCE(AVG(CASE WHEN m.metric_name = 'wan_out' THEN CAST(m.metric_value AS REAL) END), 0) AS tx_avg
                    FROM snmp_metrics m
                    JOIN devices d ON m.device_id = d.id
                    WHERE d.type = 'router'
                      AND d.include_in_aggregate = 1
                      AND m.metric_name IN ('wan_in', 'wan_out')
                      AND m.timestamp >= datetime('now', ? || ' hours')
                    GROUP BY m.device_id, bucket
                )
                SELECT
                    bucket,
                    SUM(rx_peak) AS rx_peak_sum,
                    SUM(tx_peak) AS tx_peak_sum,
                    SUM(rx_avg)  AS rx_avg_sum,
                    SUM(tx_avg)  AS tx_avg_sum
                FROM per_device_bucket
                GROUP BY bucket
                ORDER BY bucket ASC
                LIMIT ?
            ''', (f'-{hours}', limit)).fetchall()

        campus_bw_mbps = float(self.get_campus_total_bandwidth_mbps() or 5000)
        points = []
        for r in rows:
            b_str = str(r['bucket'] or '')
            t_label = b_str[label_idx:] if len(b_str) > label_idx else b_str
            # Clamping to campus total ISP capacity (RRDtool DS MAX rule)
            rx_peak_mbps = min(round((r['rx_peak_sum'] or 0) / 1000000.0, 2), campus_bw_mbps)
            tx_peak_mbps = min(round((r['tx_peak_sum'] or 0) / 1000000.0, 2), campus_bw_mbps)
            rx_avg_mbps = min(round((r['rx_avg_sum'] or 0) / 1000000.0, 2), campus_bw_mbps)
            tx_avg_mbps = min(round((r['tx_avg_sum'] or 0) / 1000000.0, 2), campus_bw_mbps)
            points.append({
                't': t_label,
                'in': rx_peak_mbps if is_short_range else rx_avg_mbps,
                'out': tx_peak_mbps if is_short_range else tx_avg_mbps,
                'in_avg': rx_avg_mbps,
                'out_avg': tx_avg_mbps,
                'in_peak': rx_peak_mbps,
                'out_peak': tx_peak_mbps,
            })
        return points

    def get_chart_traffic_data(self, device_id=None, time_range='24h'):
        """Ambil data time-series throughput untuk rendering chart grafik (PNG) sesuai rentang waktu NetMon.
        Mendukung target:
          - None / 'all': Backbone total (semua router dengan include_in_aggregate = 1)
          - int / device_id: Router / perangkat spesifik
        Mendukung rentang waktu:
          - '1h' (1 jam, interval ~1 mnt)
          - '6h' (6 jam, interval ~5 mnt)
          - '24h' (24 jam, interval ~15 mnt, default)
          - '7d' (7 hari, interval ~2 jam)
          - '30d' (30 hari, interval ~6 jam)
        """
        tr = str(time_range).lower().strip()
        if tr in ('1h', '1hour', '1jam'):
            code = '1h'
            hours = 1
            label = '1 Jam Terakhir'
            bucket_sql = "strftime('%Y-%m-%d %H:%M', m.timestamp, 'localtime')"
            bucket_it_sql = "strftime('%Y-%m-%d %H:%M', sampled_at, 'localtime')"
            limit = 70
        elif tr in ('6h', '6hours', '6jam'):
            code = '6h'
            hours = 6
            label = '6 Jam Terakhir'
            bucket_sql = ("strftime('%Y-%m-%d %H:', m.timestamp, 'localtime') || "
                          "substr('0' || ((CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) / 5) * 5), -2)")
            bucket_it_sql = ("strftime('%Y-%m-%d %H:', sampled_at, 'localtime') || "
                             "substr('0' || ((CAST(strftime('%M', sampled_at, 'localtime') AS INTEGER) / 5) * 5), -2)")
            limit = 80
        elif tr in ('7d', '7days', '7hari', '1week'):
            code = '7d'
            hours = 168
            label = '7 Hari Terakhir'
            bucket_sql = ("strftime('%Y-%m-%d ', m.timestamp, 'localtime') || "
                          "substr('0' || ((CAST(strftime('%H', m.timestamp, 'localtime') AS INTEGER) / 2) * 2), -2) || ':00'")
            bucket_it_sql = ("strftime('%Y-%m-%d ', sampled_at, 'localtime') || "
                             "substr('0' || ((CAST(strftime('%H', sampled_at, 'localtime') AS INTEGER) / 2) * 2), -2) || ':00'")
            limit = 90
        elif tr in ('30d', '30days', '30hari', '1m', '1month'):
            code = '30d'
            hours = 720
            label = '30 Hari Terakhir'
            bucket_sql = ("strftime('%Y-%m-%d ', m.timestamp, 'localtime') || "
                          "substr('0' || ((CAST(strftime('%H', m.timestamp, 'localtime') AS INTEGER) / 6) * 6), -2) || ':00'")
            bucket_it_sql = ("strftime('%Y-%m-%d ', sampled_at, 'localtime') || "
                             "substr('0' || ((CAST(strftime('%H', sampled_at, 'localtime') AS INTEGER) / 6) * 6), -2) || ':00'")
            limit = 130
        else: # default 24h
            code = '24h'
            hours = 24
            label = '24 Jam Terakhir'
            bucket_sql = ("strftime('%Y-%m-%d %H:', m.timestamp, 'localtime') || "
                          "(CASE "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 15 THEN '00' "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 30 THEN '15' "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 45 THEN '30' ELSE '45' END)")
            bucket_it_sql = ("strftime('%Y-%m-%d %H:', sampled_at, 'localtime') || "
                             "(CASE "
                             "WHEN CAST(strftime('%M', sampled_at, 'localtime') AS INTEGER) < 15 THEN '00' "
                             "WHEN CAST(strftime('%M', sampled_at, 'localtime') AS INTEGER) < 30 THEN '15' "
                             "WHEN CAST(strftime('%M', sampled_at, 'localtime') AS INTEGER) < 45 THEN '30' ELSE '45' END)")
            limit = 100

        target_id = 'all'
        target_name = 'Total Backbone (Agregasi ON)'
        target_ip = ''
        uplink_mbps = 1000
        is_aggregate = True
        device_agg_status = 1

        with self.conn() as c:
            if device_id and str(device_id).lower() not in ('all', 'backbone', 'total', '0'):
                try:
                    dev_id_int = int(device_id)
                except ValueError:
                    dev_id_int = None

                dev = None
                if dev_id_int:
                    dev = c.execute("SELECT id, name, ip, uplink_speed_mbps, COALESCE(include_in_aggregate, 1) AS include_in_aggregate FROM devices WHERE id=?", (dev_id_int,)).fetchone()
                if not dev and isinstance(device_id, str):
                    dev = c.execute("SELECT id, name, ip, uplink_speed_mbps, COALESCE(include_in_aggregate, 1) AS include_in_aggregate FROM devices WHERE ip=? OR name=?", (device_id, device_id)).fetchone()

                if dev:
                    target_id = dev['id']
                    target_name = dev['name'] or dev['ip']
                    target_ip = dev['ip']
                    uplink_mbps = dev['uplink_speed_mbps'] or 1000
                    device_agg_status = dev['include_in_aggregate']
                    is_aggregate = False

                    # 1. Query snmp_metrics
                    rows = c.execute(f'''
                        SELECT {bucket_sql} AS bucket,
                               MAX(CASE WHEN m.metric_name = 'wan_in' THEN CAST(m.metric_value AS REAL) ELSE 0 END) AS rx_bps,
                               MAX(CASE WHEN m.metric_name = 'wan_out' THEN CAST(m.metric_value AS REAL) ELSE 0 END) AS tx_bps
                        FROM snmp_metrics m
                        WHERE m.device_id = ?
                          AND m.metric_name IN ('wan_in', 'wan_out')
                          AND m.timestamp >= datetime('now', ? || ' hours')
                        GROUP BY bucket
                        ORDER BY bucket ASC
                        LIMIT ?
                    ''', (target_id, f'-{hours}', limit)).fetchall()

                    # Fallback to interface_traffic if snmp_metrics empty
                    if not rows:
                        rows = c.execute(f'''
                            SELECT {bucket_it_sql} AS bucket,
                                   SUM(rx_bps) AS rx_bps,
                                   SUM(tx_bps) AS tx_bps
                            FROM interface_traffic
                            WHERE device_id = ?
                              AND sampled_at >= datetime('now', ? || ' hours')
                            GROUP BY bucket
                            ORDER BY bucket ASC
                            LIMIT ?
                        ''', (target_id, f'-{hours}', limit)).fetchall()
                else:
                    rows = []
            else:
                # Target: All aggregate routers (strictly include_in_aggregate = 1)
                target_id = 'all'
                target_name = 'Total Backbone (Agregasi ON)'
                target_ip = 'Backbone WAN'
                is_aggregate = True
                device_agg_status = 1

                # Use configured total campus ISP bandwidth capacity (default 6000 Mbps = 6 Gbps)
                uplink_mbps = int(self.get_campus_total_bandwidth_mbps())

                rows = c.execute(f'''
                    WITH per_device_bucket AS (
                        SELECT
                            m.device_id,
                            {bucket_sql} AS bucket,
                            MAX(CASE WHEN m.metric_name = 'wan_in' THEN CAST(m.metric_value AS REAL) ELSE 0 END) AS rx_peak,
                            MAX(CASE WHEN m.metric_name = 'wan_out' THEN CAST(m.metric_value AS REAL) ELSE 0 END) AS tx_peak
                        FROM snmp_metrics m
                        JOIN devices d ON m.device_id = d.id
                        WHERE d.type = 'router'
                          AND COALESCE(d.include_in_aggregate, 1) = 1
                          AND m.metric_name IN ('wan_in', 'wan_out')
                          AND m.timestamp >= datetime('now', ? || ' hours')
                        GROUP BY m.device_id, bucket
                    )
                    SELECT bucket, SUM(rx_peak) AS rx_bps, SUM(tx_peak) AS tx_bps
                    FROM per_device_bucket
                    GROUP BY bucket
                    ORDER BY bucket ASC
                    LIMIT ?
                ''', (f'-{hours}', limit)).fetchall()

                # Fallback to interface_traffic if snmp_metrics empty
                if not rows:
                    rows = c.execute(f'''
                        WITH iface_bucket AS (
                            SELECT
                                it.device_id,
                                {bucket_it_sql} AS bucket,
                                SUM(it.rx_bps) AS rx_sum,
                                SUM(it.tx_bps) AS tx_sum
                            FROM interface_traffic it
                            JOIN devices d ON it.device_id = d.id
                            WHERE d.type = 'router'
                              AND COALESCE(d.include_in_aggregate, 1) = 1
                              AND it.sampled_at >= datetime('now', ? || ' hours')
                            GROUP BY it.device_id, bucket
                        )
                        SELECT bucket, SUM(rx_sum) AS rx_bps, SUM(tx_sum) AS tx_bps
                        FROM iface_bucket
                        GROUP BY bucket
                        ORDER BY bucket ASC
                        LIMIT ?
                    ''', (f'-{hours}', limit)).fetchall()

        campus_bw_mbps = float(self.get_campus_total_bandwidth_mbps() or 5000)
        is_core_dev = any(k in str(target_name).lower() for k in ('bgp', 'core'))
        max_allowed_mbps = campus_bw_mbps if (is_aggregate or is_core_dev) else min(float(uplink_mbps or 1000), campus_bw_mbps)

        # Parse points into list
        points = []
        rx_vals = []
        tx_vals = []
        for r in rows:
            b_str = r['bucket']
            # Physical Link Clamping (RRDtool DS MAX rule): filter past historical glitches
            rx_m = min(round((r['rx_bps'] or 0.0) / 1_000_000.0, 2), max_allowed_mbps)
            tx_m = min(round((r['tx_bps'] or 0.0) / 1_000_000.0, 2), max_allowed_mbps)
            points.append({
                'bucket': b_str,
                'rx_mbps': rx_m,
                'tx_mbps': tx_m
            })
            rx_vals.append(rx_m)
            tx_vals.append(tx_m)

        peak_rx = max(rx_vals) if rx_vals else 0.0
        peak_tx = max(tx_vals) if tx_vals else 0.0
        avg_rx = round(sum(rx_vals) / len(rx_vals), 2) if rx_vals else 0.0
        avg_tx = round(sum(tx_vals) / len(tx_vals), 2) if tx_vals else 0.0
        cur_rx = rx_vals[-1] if rx_vals else 0.0
        cur_tx = tx_vals[-1] if tx_vals else 0.0
        p95_rx = self.calc_percentile(rx_vals, 95)
        p95_tx = self.calc_percentile(tx_vals, 95)
        # Estimate total transferred volume over the window (avg_mbps * hours * 3600 / 8 / 1000 -> GB)
        span_sec = hours * 3600.0
        total_rx_gb = round((avg_rx * span_sec) / 8000.0, 2) if rx_vals else 0.0
        total_tx_gb = round((avg_tx * span_sec) / 8000.0, 2) if tx_vals else 0.0

        return {
            'target_id': target_id,
            'target_name': target_name,
            'target_ip': target_ip,
            'uplink_mbps': uplink_mbps,
            'is_aggregate': is_aggregate,
            'include_in_aggregate': device_agg_status,
            'time_range': code,
            'time_label': label,
            'hours': hours,
            'points': points,
            'peak_rx': peak_rx,
            'peak_tx': peak_tx,
            'avg_rx': avg_rx,
            'avg_tx': avg_tx,
            'cur_rx': cur_rx,
            'cur_tx': cur_tx,
            'p95_rx': p95_rx,
            'p95_tx': p95_tx,
            'total_rx_gb': total_rx_gb,
            'total_tx_gb': total_tx_gb
        }

    def get_device_interfaces(self, device_id, hours=24):
        with self.conn() as c:
            rows = c.execute('''
                SELECT DISTINCT iface_name, iface_idx FROM interface_traffic
                WHERE device_id=? AND sampled_at >= datetime('now', ? || ' hours')
                ORDER BY iface_idx ASC
            ''', (device_id, f'-{int(hours)}')).fetchall()
            return [{'name': r[0], 'idx': r[1]} for r in rows]

    def get_latest_device_interface_traffic(self, device_id, limit=15, active_only=False):
        """Ambil data traffic interface terbaru untuk suatu perangkat (diambil dari sampel terkini).
        Jika active_only=True, hanya mengembalikan interface yang memiliki traffic aktif (rx_bps + tx_bps > 0)."""
        with self.conn() as c:
            where_active = "AND (COALESCE(it.rx_bps, 0) > 0 OR COALESCE(it.tx_bps, 0) > 0)" if active_only else ""
            rows = c.execute(f'''
                WITH latest_sample AS (
                    SELECT iface_name, MAX(sampled_at) AS max_sampled
                    FROM interface_traffic
                    WHERE device_id = ? AND sampled_at >= datetime('now', '-24 hours')
                    GROUP BY iface_name
                )
                SELECT it.iface_name, it.iface_idx, it.rx_bps, it.tx_bps, it.sampled_at
                FROM latest_sample ls
                JOIN interface_traffic it
                  ON ls.iface_name = it.iface_name
                 AND ls.max_sampled = it.sampled_at
                WHERE it.device_id = ?
                  {where_active}
                ORDER BY (COALESCE(it.rx_bps, 0) + COALESCE(it.tx_bps, 0)) DESC
                LIMIT ?
            ''', (device_id, device_id, limit)).fetchall()
            return [{
                'name': r[0],
                'idx': r[1],
                'rx_bps': float(r[2] or 0.0),
                'tx_bps': float(r[3] or 0.0),
                'total_bps': float(r[2] or 0.0) + float(r[3] or 0.0),
                'sampled_at': r[4]
            } for r in rows]

    def get_top_bandwidth_interfaces(self, limit=10):
        """Ambil daftar traffic uplink (WAN In + Out) tertinggi lintas router/perangkat (Hanya Uplink)."""
        with self.conn() as c:
            # Ambil router atau perangkat dengan traffic uplink aktif
            rows = c.execute('''
                SELECT d.id, d.name, d.ip, d.type, d.wan_in, d.wan_out,
                       (COALESCE(d.wan_in, 0) + COALESCE(d.wan_out, 0)) AS total_bps,
                       d.uplink_speed_mbps, d.wan_iface_idx, d.status,
                       COALESCE(d.include_in_aggregate, 1) AS include_in_aggregate
                FROM devices d
                WHERE (d.type = 'router' OR d.wan_in IS NOT NULL OR d.wan_out IS NOT NULL)
                  AND (COALESCE(d.wan_in, 0) + COALESCE(d.wan_out, 0)) > 0
                ORDER BY (COALESCE(d.wan_in, 0) + COALESCE(d.wan_out, 0)) DESC
                LIMIT ?
            ''', (limit,)).fetchall()

            results = []
            for r in rows:
                did = r['id']
                wan_idx = r['wan_iface_idx']
                iface_name = "Uplink WAN"
                if wan_idx:
                    it_row = c.execute("SELECT iface_name FROM interface_traffic WHERE device_id=? AND iface_idx=? ORDER BY sampled_at DESC LIMIT 1", (did, str(wan_idx))).fetchone()
                    if it_row and it_row[0]:
                        iface_name = it_row[0]
                else:
                    it_row = c.execute('''
                        SELECT iface_name FROM interface_traffic
                        WHERE device_id=? AND (
                            LOWER(iface_name) LIKE '%wan%' OR
                            LOWER(iface_name) LIKE '%sfp%' OR
                            LOWER(iface_name) LIKE '%ether1%' OR
                            LOWER(iface_name) LIKE '%pppoe%'
                        )
                        ORDER BY sampled_at DESC LIMIT 1
                    ''', (did,)).fetchone()
                    if it_row and it_row[0]:
                        iface_name = it_row[0]

                win = float(r['wan_in'] or 0.0)
                wout = float(r['wan_out'] or 0.0)
                tot = win + wout
                uplink_mbps = int(r['uplink_speed_mbps'] or 1000)
                uplink_bps = uplink_mbps * 1_000_000.0
                util_pct = (max(win, wout) / uplink_bps * 100.0) if uplink_bps > 0 else 0.0

                results.append({
                    'device_id': did,
                    'device_name': r['name'] or r['ip'],
                    'device_ip': r['ip'],
                    'device_type': r['type'],
                    'iface_name': iface_name,
                    'rx_bps': win,
                    'tx_bps': wout,
                    'total_bps': tot,
                    'uplink_speed_mbps': uplink_mbps,
                    'util_pct': util_pct,
                    'include_in_aggregate': r['include_in_aggregate'],
                    'status': r['status']
                })

            # Jika devices belum memiliki nilai wan_in/wan_out di tabel devices, fallback cari dari interface_traffic khusus uplink
            if not results:
                rows_it = c.execute('''
                    WITH latest_sample AS (
                        SELECT device_id, iface_name, MAX(sampled_at) AS max_sampled
                        FROM interface_traffic
                        WHERE sampled_at >= datetime('now', '-24 hours')
                          AND (
                              LOWER(iface_name) LIKE '%wan%' OR
                              LOWER(iface_name) LIKE '%sfp%' OR
                              LOWER(iface_name) LIKE '%ether1%' OR
                              LOWER(iface_name) LIKE '%pppoe%' OR
                              LOWER(iface_name) LIKE '%uplink%'
                          )
                        GROUP BY device_id, iface_name
                    )
                    SELECT d.id, d.name, d.ip, it.iface_name, it.rx_bps, it.tx_bps, it.sampled_at,
                           d.uplink_speed_mbps, COALESCE(d.include_in_aggregate, 1) AS include_in_aggregate, d.status
                    FROM latest_sample ls
                    JOIN interface_traffic it
                      ON ls.device_id = it.device_id
                     AND ls.iface_name = it.iface_name
                     AND ls.max_sampled = it.sampled_at
                    JOIN devices d ON d.id = it.device_id
                    WHERE (COALESCE(it.rx_bps, 0) + COALESCE(it.tx_bps, 0)) > 0
                    ORDER BY (COALESCE(it.rx_bps, 0) + COALESCE(it.tx_bps, 0)) DESC
                    LIMIT ?
                ''', (limit,)).fetchall()
                for r in rows_it:
                    win = float(r['rx_bps'] or 0.0)
                    wout = float(r['tx_bps'] or 0.0)
                    uplink_mbps = int(r['uplink_speed_mbps'] or 1000)
                    uplink_bps = uplink_mbps * 1_000_000.0
                    util_pct = (max(win, wout) / uplink_bps * 100.0) if uplink_bps > 0 else 0.0
                    results.append({
                        'device_id': r['id'],
                        'device_name': r['name'] or r['ip'],
                        'device_ip': r['ip'],
                        'device_type': 'router',
                        'iface_name': r['iface_name'],
                        'rx_bps': win,
                        'tx_bps': wout,
                        'total_bps': win + wout,
                        'uplink_speed_mbps': uplink_mbps,
                        'util_pct': util_pct,
                        'include_in_aggregate': r['include_in_aggregate'],
                        'status': r['status']
                    })

            return results

    def get_router_traffic_summary(self):
        """Ambil data utilisasi bandwidth WAN seluruh router yang terdaftar,
        dilengkapi sanitasi anomali/spike yang melebihi threshold link atau total ISP kampus."""
        with self.conn(read_only=True) as c:
            rows = c.execute('''
                SELECT id, name, ip, type, wan_in, wan_out, uplink_speed_mbps, status, last_polled,
                       COALESCE(include_in_aggregate, 1) AS include_in_aggregate
                FROM devices
                WHERE type = 'router' OR wan_in IS NOT NULL OR wan_out IS NOT NULL
                ORDER BY COALESCE(include_in_aggregate, 1) DESC, (COALESCE(wan_in, 0) + COALESCE(wan_out, 0)) DESC
            ''').fetchall()

            try:
                campus_bw_mbps = float(self.get_campus_total_bandwidth_mbps() or 5000)
            except Exception:
                campus_bw_mbps = 5000.0
            max_isp_bps = (campus_bw_mbps * 1e6) * 1.05

            clean_rows = []
            for r in rows:
                d = dict(r)
                uplink_mbps = float(d.get('uplink_speed_mbps') or 1000)
                link_cap_bps = (uplink_mbps * 1e6) * 1.05
                max_allowed = min(link_cap_bps, max_isp_bps)

                win = d.get('wan_in')
                wout = d.get('wan_out')
                if win is not None and win > max_allowed:
                    d['wan_in'] = 0.0
                if wout is not None and wout > max_allowed:
                    d['wan_out'] = 0.0
                clean_rows.append(d)
            return clean_rows

    def cleanup_interface_traffic(self, interface_retention_hours=168, metrics_retention_hours=None):
        # metrics_retention_hours default None -> pakai interface_retention_hours (kompatibel mundur
        # kalau caller lama cuma kirim 1 parameter). snmp_metrics itu sumber data laporan bulanan,
        # jadi dikasih retensi jauh lebih panjang dp interface_traffic (yang cuma buat chart recent).
        if metrics_retention_hours is None:
            metrics_retention_hours = interface_retention_hours
        def _do_cleanup():
            with self._write_lock:
                with self.conn() as c:
                    c.execute("DELETE FROM interface_traffic WHERE sampled_at < datetime('now', ? || ' hours')",
                              (f'-{int(interface_retention_hours)}',))
                    c.execute("DELETE FROM snmp_metrics WHERE timestamp < datetime('now', ? || ' hours')",
                              (f'-{int(metrics_retention_hours)}',))
        self._run_with_retry(_do_cleanup)


    def get_metric_history(self, device_id, name, hours=1):
        with self.conn() as c:
            rows = c.execute('''
                SELECT strftime('%Y-%m-%dT%H:%M:%SZ', timestamp) AS ts, metric_value FROM snmp_metrics
                WHERE device_id = ? AND metric_name = ?
                  AND timestamp >= datetime('now', ? || ' hours')
                ORDER BY timestamp ASC
            ''', (device_id, name, f'-{float(hours)}')).fetchall()
            return [{'ts': r[0], 'value': float(r[1]) if r[1] is not None and r[1] != 'None' else 0.0} for r in rows]

    # ============================================================
    # DASHBOARD STATS
    # ============================================================

    def get_dashboard_stats(self):
        with self.conn(read_only=True) as c:
            total    = c.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
            up       = c.execute("SELECT COUNT(*) FROM devices WHERE status='up'").fetchone()[0]
            down     = c.execute("SELECT COUNT(*) FROM devices WHERE status='down'").fetchone()[0]
            warning  = c.execute("SELECT COUNT(*) FROM devices WHERE status='warning'").fetchone()[0]
            unknown  = c.execute("SELECT COUNT(*) FROM devices WHERE status='unknown'").fetchone()[0]
            snmp_en  = c.execute("SELECT COUNT(*) FROM devices WHERE snmp_enabled=1").fetchone()[0]
            unacked  = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND is_false_alarm=0").fetchone()[0]
            critical = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND severity='critical' AND is_false_alarm=0").fetchone()[0]
            zones    = c.execute('SELECT COUNT(*) FROM zones').fetchone()[0]
            
            avg_lat_row = c.execute("SELECT AVG(latency_ms) FROM devices WHERE status='up' AND latency_ms IS NOT NULL").fetchone()
            avg_latency = round(avg_lat_row[0], 1) if (avg_lat_row and avg_lat_row[0] is not None) else None
            online_rate = round((up / total) * 100, 1) if total > 0 else 100.0

            return {
                'total': total, 'up': up, 'down': down, 'warning': warning,
                'unknown': unknown, 'snmp_enabled': snmp_en,
                'unacked_alerts': unacked, 'critical_alerts': critical, 'zones': zones,
                'avg_latency': avg_latency, 'online_rate': online_rate,
                'campus_total_bandwidth_mbps': self.get_campus_total_bandwidth_mbps()
            }

    def get_device_latency_history(self, device_id, hours=24):
        with self.conn() as c:
            rows = c.execute('''
                SELECT strftime('%Y-%m-%dT%H:%M:%SZ', timestamp) AS ts,
                       CAST(metric_value AS REAL) AS latency_ms
                FROM snmp_metrics
                WHERE device_id = ? AND metric_name = 'ping_latency'
                  AND timestamp >= datetime('now', ? || ' hours')
                ORDER BY timestamp ASC LIMIT 500
            ''', (device_id, f'-{int(hours)}')).fetchall()
            return [dict(r) for r in rows]

    def get_device_status_timeline(self, device_id, hours=24, buckets=24):
        import datetime as dt
        with self.conn() as c:
            dev = c.execute('SELECT id, name, status, created_at FROM devices WHERE id = ?', (device_id,)).fetchone()
            if not dev:
                return []
            
            # Fetch downtime events in this window
            downtimes = c.execute('''
                SELECT down_time, up_time FROM downtime_analysis
                WHERE device_id = ? AND down_time >= datetime('now', ? || ' hours')
            ''', (device_id, f'-{int(hours)}')).fetchall()
            
            # Fetch alerts in this window
            alerts = c.execute('''
                SELECT severity, created_at FROM alerts
                WHERE device_id = ? AND created_at >= datetime('now', ? || ' hours')
            ''', (device_id, f'-{int(hours)}')).fetchall()

            now = dt.datetime.now()
            interval_sec = (hours * 3600) / buckets
            timeline = []

            for i in range(buckets):
                b_start = now - dt.timedelta(seconds=(buckets - i) * interval_sec)
                b_end = now - dt.timedelta(seconds=(buckets - i - 1) * interval_sec)
                b_label = b_start.strftime('%H:%M')
                
                # Check downtime overlap
                b_status = 'up'
                tooltip = 'Online / Operational'
                
                for dt_row in downtimes:
                    try:
                        down_dt = dt.datetime.fromisoformat(dt_row['down_time'].replace('Z', ''))
                        up_dt = dt.datetime.fromisoformat(dt_row['up_time'].replace('Z', '')) if dt_row['up_time'] else now
                        if max(b_start, down_dt) <= min(b_end, up_dt):
                            b_status = 'down'
                            tooltip = 'Downtime Detected'
                            break
                    except Exception:
                        pass
                
                if b_status == 'up':
                    for a_row in alerts:
                        try:
                            a_dt = dt.datetime.fromisoformat(a_row['created_at'].replace('Z', ''))
                            if b_start <= a_dt <= b_end:
                                if a_row['severity'] == 'critical':
                                    b_status = 'down'
                                    tooltip = 'Critical Alert Incident'
                                    break
                                elif a_row['severity'] == 'warning':
                                    b_status = 'warning'
                                    tooltip = 'Warning / High Latency'
                        except Exception:
                            pass
                
                # If current time bucket and device is down right now
                if i == buckets - 1 and dev['status'] == 'down':
                    b_status = 'down'
                    tooltip = 'Currently Offline'
                elif i == buckets - 1 and dev['status'] == 'warning':
                    b_status = 'warning'
                    tooltip = 'Warning / Degraded'

                timeline.append({
                    'time': b_label,
                    'timestamp': b_start.isoformat(),
                    'status': b_status,
                    'tooltip': f"{b_label}: {tooltip}"
                })
            
            return timeline

    def get_dashboard_sparklines(self):
        with self.conn() as c:
            # 1. Throughput points (last 12 hours, 1 point per hour)
            tp_rows = c.execute('''
                SELECT strftime('%H:00', sampled_at) as hr,
                       AVG(rx_bps + tx_bps) as avg_bps
                FROM interface_traffic
                WHERE sampled_at >= datetime('now', '-12 hours')
                GROUP BY hr ORDER BY sampled_at ASC
            ''').fetchall()
            tp_data = [round(float(r['avg_bps'] or 0) / 1e6, 2) for r in tp_rows]
            if len(tp_data) < 2:
                tp_data = [0.0, 0.0, 0.0, 0.0]

            # 2. Latency points (last 12 hours)
            lat_rows = c.execute('''
                SELECT strftime('%H:00', timestamp) as hr,
                       AVG(CAST(metric_value AS REAL)) as avg_lat
                FROM snmp_metrics
                WHERE metric_name = 'ping_latency' AND timestamp >= datetime('now', '-12 hours')
                GROUP BY hr ORDER BY timestamp ASC
            ''').fetchall()
            lat_data = [round(float(r['avg_lat'] or 0), 1) for r in lat_rows]
            if len(lat_data) < 2:
                lat_data = [1.0, 1.2, 1.1, 1.0]

            # 3. Online rate trend (simulated over last 12 hours based on uptime/downtime)
            stats = self.get_dashboard_stats()
            curr_rate = stats.get('online_rate', 100.0)
            rate_data = [curr_rate] * 6

            return {
                'throughput': tp_data,
                'latency': lat_data,
                'online_rate': rate_data
            }

    def generate_and_save_monthly_report(self, month_str):
        import json
        from datetime import datetime, timedelta
        from collections import defaultdict
        
        # 1. Fetch all routers
        settings = self.get_settings()
        api_key = settings.get('groq_api_key', '')

        with self.conn() as c:
            rows = c.execute("SELECT id, name, ip, uplink_speed_mbps, include_in_aggregate FROM devices WHERE type = 'router'").fetchall()
            routers = [dict(r) for r in rows]
            
        report = {
            'month': month_str,
            'generated_at': datetime.now().isoformat(),
            'routers': [],
            'backbone': {
                'total_in_gb': 0.0,
                'total_out_gb': 0.0,
                'peak_in_mbps': 0.0,
                'peak_out_mbps': 0.0,
                'avg_in_mbps': 0.0,
                'avg_out_mbps': 0.0
            }
        }
        
        if not routers:
            def _save_empty_report():
                with self._write_lock:
                    with self.conn() as c:
                        c.execute('INSERT OR REPLACE INTO monthly_reports (report_month, report_data, generated_at) VALUES (?, ?, datetime("now"))',
                                  (month_str, json.dumps(report)))
            self._run_with_retry(_save_empty_report)
            return report
            
        # Parse month_str to calendar month bounds
        year, mon = month_str.split('-')
        year, mon = int(year), int(mon)
        month_start = f"{year:04d}-{mon:02d}-01 00:00:00"
        next_year, next_mon = (year + 1, 1) if mon == 12 else (year, mon + 1)
        month_end = f"{next_year:04d}-{next_mon:02d}-01 00:00:00"

        # 2. Query metrics for the specified calendar month
        def _read_traffic_metrics():
            with self.conn() as c:
                return c.execute('''
                    SELECT device_id, metric_name, timestamp, CAST(metric_value AS REAL) as val
                    FROM snmp_metrics
                    WHERE metric_name IN ('wan_in', 'wan_out')
                      AND timestamp >= ? AND timestamp < ?
                    ORDER BY timestamp ASC
                ''', (month_start, month_end)).fetchall()
        rows = self._run_with_retry(_read_traffic_metrics)

            
        # Build lookup: device_id -> uplink_speed in bps
        device_uplink_bps = {}
        for router in routers:
            speed_mbps = router.get('uplink_speed_mbps') or 1000
            device_uplink_bps[router['id']] = speed_mbps * 1e6  # convert to bps

        # Helper functions for median and MAD
        def calc_median(values):
            if not values:
                return 0.0
            s = sorted(values)
            n = len(s)
            if n % 2 == 1:
                return s[n // 2]
            return (s[n // 2 - 1] + s[n // 2]) / 2.0

        def calc_mad(values, med):
            if not values:
                return 0.0
            devs = [abs(x - med) for x in values]
            return calc_median(devs)

        # Calculate median and MAD per (device_id, metric_name)
        device_metric_vals = defaultdict(list)
        for r in rows:
            val = r['val'] or 0.0
            device_metric_vals[(r['device_id'], r['metric_name'])].append(val)

        device_stats = {}
        for key, vals in device_metric_vals.items():
            if vals:
                med = calc_median(vals)
                mad = calc_mad(vals, med)
                device_stats[key] = {'median': med, 'mad': mad}
            else:
                device_stats[key] = {'median': 0.0, 'mad': 0.0}

        discard_timestamps = set()
        candidates = []
        for r in rows:
            val = r['val'] or 0.0
            did = r['device_id']
            mname = r['metric_name']
            uplink_bps = device_uplink_bps.get(did, 1e9)  # default 1 Gbps

            # Hard cap: anything exceeding the device uplink capacity is anomalous
            if val > uplink_bps:
                discard_timestamps.add((did, mname, r['timestamp']))
                continue

            # Statistical filter: median + (6 * MAD)
            stats = device_stats.get((did, mname), {'median': 0.0, 'mad': 0.0})
            threshold = stats['median'] + (6 * stats['mad'])

            # Only flag as candidate if it exceeds the statistical threshold
            if val > threshold:
                candidates.append({
                    'timestamp': r['timestamp'],
                    'device_id': did,
                    'metric_name': mname,
                    'value_gbps': round(val / 1e9, 3),
                    'uplink_gbps': round(uplink_bps / 1e9, 3)
                })

        if candidates:
            candidate_by_ts = defaultdict(list)
            for cnd in candidates:
                candidate_by_ts[cnd['timestamp']].append((cnd['device_id'], cnd['metric_name']))

            if api_key:
                try:
                    import ai_detector
                    api_key, provider, model_name = ai_detector._resolve_ai_creds(self)
                    sub_candidates = candidates[:50]
                    prompt = (
                        f"Analisis log telemetri traffic jaringan berikut.\n"
                        f"Setiap record memiliki 'value_gbps' (throughput tercatat) dan 'uplink_gbps' (kapasitas uplink fisik perangkat).\n"
                        f"Tentukan timestamp mana yang merupakan lonjakan anomali/palsu (spike akibat error SNMP / counter rollover) sehingga harus DIHAPUS.\n"
                        f"Traffic yang wajar dan di bawah kapasitas uplink JANGAN dihapus.\n"
                        f"Data:\n{json.dumps(sub_candidates, indent=2)}\n\n"
                        f"Kembalikan respon JSON dalam format persis seperti ini:\n"
                        f'{{"discard_timestamps": ["YYYY-MM-DD HH:MM:SS", ...]}}'
                    )

                    text_resp = ai_detector._call_llm_completion(
                        provider=provider,
                        api_key=api_key,
                        model_name=model_name,
                        system_prompt='You are a network traffic analyst. Respond ONLY with a raw JSON object containing "discard_timestamps" as a list of strings.',
                        user_prompt=prompt,
                        temperature=0.1,
                        max_tokens=400,
                        json_mode=True,
                        timeout=10,
                    )
                    ai_res = json.loads(text_resp)
                    for ts in ai_res.get('discard_timestamps', []):
                        for (d, m) in candidate_by_ts.get(ts, []):
                            discard_timestamps.add((d, m, ts))
                except Exception as e:
                    print(f"[AI Report Filter] AI API call failed: {e}")
                    for cnd in candidates:
                        discard_timestamps.add((cnd['device_id'], cnd['metric_name'], cnd['timestamp']))
            else:
                # No API key: discard all statistical candidates directly
                for cnd in candidates:
                    discard_timestamps.add((cnd['device_id'], cnd['metric_name'], cnd['timestamp']))

        device_data = defaultdict(lambda: {'wan_in': [], 'wan_out': []})
        for r in rows:
            if (r['device_id'], r['metric_name'], r['timestamp']) in discard_timestamps:
                continue
            did = r['device_id']
            mname = r['metric_name']
            ts_str = r['timestamp']
            val = r['val'] or 0.0

            try:
                ts = datetime.fromisoformat(ts_str.replace(' ', 'T'))
            except Exception:
                continue
            device_data[did][mname].append((ts, val))

        # Breakdown harian dibangun dari device_data yang SUDAH lolos filter discard_timestamps
        # di atas -- BUKAN query SQL terpisah -- supaya angka chart harian selalu konsisten
        # dengan angka resmi bulanan (anomali yang sudah difilter bulanan tidak boleh
        # muncul lagi di breakdown harian).
        daily_raw = defaultdict(lambda: defaultdict(lambda: {'rx': [], 'tx': []}))
        for did, metrics in device_data.items():
            for ts, val in metrics.get('wan_in', []):
                daily_raw[did][ts.strftime('%Y-%m-%d')]['rx'].append(val)
            for ts, val in metrics.get('wan_out', []):
                daily_raw[did][ts.strftime('%Y-%m-%d')]['tx'].append(val)

        daily_by_device = defaultdict(list)
        for did, days in daily_raw.items():
            for day in sorted(days.keys()):
                rx_list = days[day]['rx']
                tx_list = days[day]['tx']
                daily_by_device[did].append({
                    'date': day,
                    'rx_avg_mbps': round((sum(rx_list) / len(rx_list) if rx_list else 0.0) / 1e6, 2),
                    'tx_avg_mbps': round((sum(tx_list) / len(tx_list) if tx_list else 0.0) / 1e6, 2),
                    'rx_peak_mbps': round((max(rx_list) if rx_list else 0.0) / 1e6, 2),
                    'tx_peak_mbps': round((max(tx_list) if tx_list else 0.0) / 1e6, 2),
                })

        # Titik acuan waktu BERSAMA (bukan per-router) buat window "24 jam terakhir" /
        # "7 hari terakhir" di chart_data -- kalau tiap router pakai max_ts miliknya sendiri,
        # router yang datanya berhenti lebih awal (misal SNMP bermasalah) akan punya window
        # yang tidak selaras dengan router lain, dan saat dijumlah ke backbone_raw_buckets
        # (dikunci berdasarkan string timestamp), sebagian besar titik cuma keisi salah satu
        # router -- bikin grafik "total backbone" naik-turun palsu yang sebenarnya cuma
        # mencerminkan window mana yang kebetulan tumpang tindih, bukan perubahan traffic asli.
        overall_max_ts = datetime.min
        for _did, _metrics in device_data.items():
            _rx = _metrics.get('wan_in', [])
            _tx = _metrics.get('wan_out', [])
            if _rx:
                overall_max_ts = max(overall_max_ts, _rx[-1][0])
            if _tx:
                overall_max_ts = max(overall_max_ts, _tx[-1][0])
            
        # Query health metrics (cpu, memory, temperature) and alerts for the routers
        def _read_health_and_alerts():
            with self.conn() as c:
                h_rows = c.execute('''
                    SELECT device_id, metric_name, CAST(metric_value AS REAL) as val
                    FROM snmp_metrics
                    WHERE metric_name IN ('cpu_usage', 'memory_usage', 'temperature')
                      AND timestamp >= ? AND timestamp < ?
                ''', (month_start, month_end)).fetchall()
                a_rows = c.execute('''
                    SELECT device_id, COUNT(*) as cnt
                    FROM alerts
                    WHERE created_at >= ? AND created_at < ?
                    GROUP BY device_id
                ''', (month_start, month_end)).fetchall()
                return h_rows, a_rows
        health_rows, alert_rows = self._run_with_retry(_read_health_and_alerts)

        health_vals = defaultdict(list)
        for hr in health_rows:
            if hr['val'] is not None:
                health_vals[(hr['device_id'], hr['metric_name'])].append(hr['val'])
                
        device_alert_counts = {ar['device_id']: ar['cnt'] for ar in alert_rows}
        total_backbone_rx_bps_sum = 0.0
        total_backbone_tx_bps_sum = 0.0
        backbone_peaks_rx = []
        backbone_peaks_tx = []
        backbone_daily = defaultdict(lambda: {'rx_avg': 0.0, 'tx_avg': 0.0, 'rx_peak': 0.0, 'tx_peak': 0.0})
        backbone_raw_buckets = {
            "1month": defaultdict(lambda: {'rx': 0.0, 'tx': 0.0}),
            "7days": defaultdict(lambda: {'rx': 0.0, 'tx': 0.0}),
            "24hours": defaultdict(lambda: {'rx': 0.0, 'tx': 0.0})
        }
        for router in routers:
            rid = router['id']
            rdata = device_data[rid]
            
            # Calculate health statistics
            cpu_list = health_vals[(rid, 'cpu_usage')]
            mem_list = health_vals[(rid, 'memory_usage')]
            temp_list = health_vals[(rid, 'temperature')]
            
            avg_cpu = sum(cpu_list) / len(cpu_list) if cpu_list else 0.0
            peak_cpu = max(cpu_list) if cpu_list else 0.0
            
            avg_mem = sum(mem_list) / len(mem_list) if mem_list else 0.0
            peak_mem = max(mem_list) if mem_list else 0.0
            
            avg_temp = sum(temp_list) / len(temp_list) if temp_list else 0.0
            peak_temp = max(temp_list) if temp_list else 0.0
            
            alert_count = device_alert_counts.get(rid, 0)
            
            # Calculate rx (wan_in) statistics
            rx_points = rdata['wan_in']
            total_rx_bytes = 0.0
            max_rx_bps = 0.0
            total_rx_dt = 0.0
            
            for i in range(len(rx_points) - 1):
                t1, v1 = rx_points[i]
                t2, v2 = rx_points[i+1]
                dt = (t2 - t1).total_seconds()
                if 0 < dt < 300:
                    total_rx_bytes += (v1 / 8.0) * dt
                    total_rx_dt += dt
                if v1 > max_rx_bps:
                    max_rx_bps = v1
            if rx_points:
                if rx_points[-1][1] > max_rx_bps:
                    max_rx_bps = rx_points[-1][1]
                    
            avg_rx_bps = (total_rx_bytes * 8.0) / total_rx_dt if total_rx_dt > 0 else 0.0
            
            # Calculate tx (wan_out) statistics
            tx_points = rdata['wan_out']
            total_tx_bytes = 0.0
            max_tx_bps = 0.0
            total_tx_dt = 0.0
            
            for i in range(len(tx_points) - 1):
                t1, v1 = tx_points[i]
                t2, v2 = tx_points[i+1]
                dt = (t2 - t1).total_seconds()
                if 0 < dt < 300:
                    total_tx_bytes += (v1 / 8.0) * dt
                    total_tx_dt += dt
                if v1 > max_tx_bps:
                    max_tx_bps = v1
            if tx_points:
                if tx_points[-1][1] > max_tx_bps:
                    max_tx_bps = tx_points[-1][1]
                    
            avg_tx_bps = (total_tx_bytes * 8.0) / total_tx_dt if total_tx_dt > 0 else 0.0
            
            no_data = False
            if not rx_points and not tx_points:
                total_rx_bytes = 0.0
                total_tx_bytes = 0.0
                avg_rx_bps = 0.0
                avg_tx_bps = 0.0
                max_rx_bps = 0.0
                max_tx_bps = 0.0
                no_data = True
                
            chart_data = {"1month": [], "7days": [], "24hours": []}
            if not no_data:
                max_ts = overall_max_ts
                
                def bucket_data(points, start_ts, bucket_func):
                    buckets = defaultdict(float)
                    for t, v in points:
                        if t >= start_ts:
                            b_ts = bucket_func(t)
                            if v > buckets[b_ts]:
                                buckets[b_ts] = v
                    return buckets

                ts_24h = max_ts - timedelta(hours=24)
                ts_7d = max_ts - timedelta(days=7)
                
                b24_rx = bucket_data(rx_points, ts_24h, lambda t: t.replace(minute=(t.minute // 15) * 15, second=0, microsecond=0))
                b24_tx = bucket_data(tx_points, ts_24h, lambda t: t.replace(minute=(t.minute // 15) * 15, second=0, microsecond=0))
                
                b7d_rx = bucket_data(rx_points, ts_7d, lambda t: t.replace(hour=(t.hour // 2) * 2, minute=0, second=0, microsecond=0))
                b7d_tx = bucket_data(tx_points, ts_7d, lambda t: t.replace(hour=(t.hour // 2) * 2, minute=0, second=0, microsecond=0))
                
                b1m_rx = bucket_data(rx_points, datetime.min, lambda t: t.replace(hour=(t.hour // 6) * 6, minute=0, second=0, microsecond=0))
                b1m_tx = bucket_data(tx_points, datetime.min, lambda t: t.replace(hour=(t.hour // 6) * 6, minute=0, second=0, microsecond=0))

                def merge_buckets(brx, btx):
                    keys = sorted(set(brx.keys()) | set(btx.keys()))
                    return [
                        {
                            "ts": k.strftime('%Y-%m-%d %H:%M:%S'),
                            "rx": round(brx.get(k, 0.0) / 1e6, 2),
                            "tx": round(btx.get(k, 0.0) / 1e6, 2)
                        }
                        for k in keys
                    ]

                chart_data["24hours"] = merge_buckets(b24_rx, b24_tx)
                chart_data["7days"] = merge_buckets(b7d_rx, b7d_tx)
                chart_data["1month"] = merge_buckets(b1m_rx, b1m_tx)
                

            p95_rx_mbps = self.calc_percentile([v / 1e6 for _, v in rx_points], 95) if rx_points else 0.0
            p95_tx_mbps = self.calc_percentile([v / 1e6 for _, v in tx_points], 95) if tx_points else 0.0

            uplink_mbps = float(router.get('uplink_speed_mbps') or 1000.0)
            peak_r_rx = round(max_rx_bps / 1e6, 2)
            peak_r_tx = round(max_tx_bps / 1e6, 2)

            router_stats = {
                'id': rid,
                'name': router['name'],
                'ip': router['ip'],
                'uplink_speed_mbps': int(uplink_mbps),
                'uplink_utilization_pct': round((max(peak_r_rx, peak_r_tx) / uplink_mbps) * 100.0, 1) if uplink_mbps > 0 else 0.0,
                'include_in_aggregate': router.get('include_in_aggregate', 1),
                'total_rx_gb': round(total_rx_bytes / 1e9, 2),
                'total_tx_gb': round(total_tx_bytes / 1e9, 2),
                'avg_rx_mbps': round(avg_rx_bps / 1e6, 2),
                'avg_tx_mbps': round(avg_tx_bps / 1e6, 2),
                'p95_rx_mbps': p95_rx_mbps,
                'p95_tx_mbps': p95_tx_mbps,
                'peak_rx_mbps': peak_r_rx,
                'peak_tx_mbps': peak_r_tx,
                
                # Health metrics
                'avg_cpu': round(avg_cpu, 1),
                'peak_cpu': round(peak_cpu, 1),
                'avg_mem': round(avg_mem, 1),
                'peak_mem': round(peak_mem, 1),
                'avg_temp': round(avg_temp, 1),
                'peak_temp': round(peak_temp, 1),
                'total_alerts': alert_count,
                'daily_points': daily_by_device[rid],
                'chart_data': chart_data
            }
            if no_data:
                router_stats['no_data'] = True
            report['routers'].append(router_stats)
            
            if router.get('include_in_aggregate', 1) == 1:
                total_backbone_rx_bps_sum += avg_rx_bps
                total_backbone_tx_bps_sum += avg_tx_bps
                backbone_peaks_rx.append(max_rx_bps)
                backbone_peaks_tx.append(max_tx_bps)
                for pt in daily_by_device[rid]:
                    day = pt['date']
                    backbone_daily[day]['rx_avg'] += pt['rx_avg_mbps']
                    backbone_daily[day]['tx_avg'] += pt['tx_avg_mbps']
                    backbone_daily[day]['rx_peak'] += pt['rx_peak_mbps']
                    backbone_daily[day]['tx_peak'] += pt['tx_peak_mbps']
                    
                # Aggregate chart_data for backbone
                for time_range in ["1month", "7days", "24hours"]:
                    for pt in chart_data.get(time_range, []):
                        ts = pt['ts']
                        backbone_raw_buckets[time_range][ts]['rx'] += pt['rx']
                        backbone_raw_buckets[time_range][ts]['tx'] += pt['tx']
            
        report['backbone']['daily_points'] = [
            {
                'date': day,
                'rx_avg_mbps': round(stats['rx_avg'], 2),
                'tx_avg_mbps': round(stats['tx_avg'], 2),
                'rx_peak_mbps': round(stats['rx_peak'], 2),
                'tx_peak_mbps': round(stats['tx_peak'], 2)
            }
            for day, stats in sorted(backbone_daily.items())
        ]
        report['backbone']['chart_data'] = {
            time_range: [
                {
                    "ts": ts,
                    "rx": round(vals['rx'], 2),
                    "tx": round(vals['tx'], 2)
                }
                for ts, vals in sorted(buckets.items())
            ]
            for time_range, buckets in backbone_raw_buckets.items()
        }
        bb_1m_pts = report['backbone']['chart_data'].get('1month', [])
        report['backbone']['avg_in_mbps'] = round(total_backbone_rx_bps_sum / 1e6, 2)
        report['backbone']['avg_out_mbps'] = round(total_backbone_tx_bps_sum / 1e6, 2)
        report['backbone']['p95_in_mbps'] = self.calc_percentile([pt['rx'] for pt in bb_1m_pts], 95) if bb_1m_pts else round(sum(r.get('p95_rx_mbps', 0.0) for r in report['routers'] if r.get('include_in_aggregate', 1) == 1), 2)
        report['backbone']['p95_out_mbps'] = self.calc_percentile([pt['tx'] for pt in bb_1m_pts], 95) if bb_1m_pts else round(sum(r.get('p95_tx_mbps', 0.0) for r in report['routers'] if r.get('include_in_aggregate', 1) == 1), 2)
        campus_cap = float(self.get_campus_total_bandwidth_mbps() or 6000.0)
        report['backbone']['campus_capacity_mbps'] = int(campus_cap)
        report['backbone']['peak_in_mbps'] = round(max(backbone_peaks_rx) / 1e6, 2) if backbone_peaks_rx else 0.0
        report['backbone']['peak_out_mbps'] = round(max(backbone_peaks_tx) / 1e6, 2) if backbone_peaks_tx else 0.0
        report['backbone']['total_in_gb'] = round(sum(r['total_rx_gb'] for r in report['routers'] if r.get('include_in_aggregate', 1) == 1), 2)
        report['backbone']['total_out_gb'] = round(sum(r['total_tx_gb'] for r in report['routers'] if r.get('include_in_aggregate', 1) == 1), 2)

        # Calculate Bandwidth Utilization % against Total Campus Internet Capacity
        if campus_cap > 0:
            peak_traffic = max(report['backbone']['peak_in_mbps'], report['backbone']['peak_out_mbps'])
            avg_traffic = max(report['backbone']['avg_in_mbps'], report['backbone']['avg_out_mbps'])
            p95_traffic = max(report['backbone']['p95_in_mbps'], report['backbone']['p95_out_mbps'])

            report['backbone']['utilization_peak_pct'] = round((peak_traffic / campus_cap) * 100.0, 1)
            report['backbone']['utilization_avg_pct'] = round((avg_traffic / campus_cap) * 100.0, 1)
            report['backbone']['utilization_p95_pct'] = round((p95_traffic / campus_cap) * 100.0, 1)
            report['backbone']['utilization_in_peak_pct'] = round((report['backbone']['peak_in_mbps'] / campus_cap) * 100.0, 1)
            report['backbone']['utilization_out_peak_pct'] = round((report['backbone']['peak_out_mbps'] / campus_cap) * 100.0, 1)
            report['backbone']['utilization_in_avg_pct'] = round((report['backbone']['avg_in_mbps'] / campus_cap) * 100.0, 1)
            report['backbone']['utilization_out_avg_pct'] = round((report['backbone']['avg_out_mbps'] / campus_cap) * 100.0, 1)
        else:
            report['backbone']['utilization_peak_pct'] = 0.0
            report['backbone']['utilization_avg_pct'] = 0.0
            report['backbone']['utilization_p95_pct'] = 0.0
            report['backbone']['utilization_in_peak_pct'] = 0.0
            report['backbone']['utilization_out_peak_pct'] = 0.0
            report['backbone']['utilization_in_avg_pct'] = 0.0
            report['backbone']['utilization_out_avg_pct'] = 0.0
        
        # 3. Save report to DB (with lock & retry to survive concurrent poller writes)
        report_json = json.dumps(report)
        def _save_report():
            with self._write_lock:
                with self.conn() as c:
                    c.execute('INSERT OR REPLACE INTO monthly_reports (report_month, report_data, generated_at) VALUES (?, ?, datetime("now"))',
                              (month_str, report_json))
        self._run_with_retry(_save_report)
                      
        return report

    def get_monthly_reports(self):
        with self.conn() as c:
            rows = c.execute('SELECT * FROM monthly_reports ORDER BY report_month DESC').fetchall()
            return [dict(r) for r in rows]

    def delete_monthly_report(self, report_id):
        with self.conn() as c:
            c.execute('DELETE FROM monthly_reports WHERE id = ?', (report_id,))

    # ============================================================
    # DOWNTIME ANALYSIS (BLACKBOX FORENSICS)
    # ============================================================

    def save_downtime_analysis(self, device_id, down_time, up_time, duration_sec, ping_pattern, snmp_pattern, reboot_detected, justification, confidence):
        with self.conn() as c:
            c.execute('''
                INSERT INTO downtime_analysis 
                (device_id, down_time, up_time, duration_sec, ping_pattern, snmp_pattern, reboot_detected, justification, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (device_id, down_time, up_time, duration_sec, ping_pattern, snmp_pattern, reboot_detected, justification, confidence))

    def get_downtime_analysis(self, device_id, limit=10):
        with self.conn() as c:
            rows = c.execute('''
                SELECT * FROM downtime_analysis 
                WHERE device_id = ? 
                ORDER BY down_time DESC 
                LIMIT ?
            ''', (device_id, limit)).fetchall()
            return [dict(r) for r in rows]
