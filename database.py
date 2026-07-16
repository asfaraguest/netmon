#!/usr/bin/env python3
"""
NetMon - Database Manager
SQLite-based persistent storage
"""

import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(BASE_DIR, 'netmon.db')
DB_PATH = os.environ.get('DB_PATH', DEFAULT_DB)


class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self._init_db()

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA cache_size=-2000")
        c.execute("PRAGMA temp_store=MEMORY")
        c.execute("PRAGMA mmap_size=268435456")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def _init_db(self):
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
                    wan_out       REAL DEFAULT NULL,
                    client_count  INTEGER DEFAULT NULL,
                    uplink_speed_mbps INTEGER DEFAULT 1000,
                    alerts_enabled INTEGER DEFAULT 1,
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
                'include_in_aggregate': "INTEGER DEFAULT 1"
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
                'groq_api_key': '',
                'alert_on_down': 'true',
                'alert_on_up': 'true',
                'default_community': 'public',
                'default_snmp_version': '2c',
                'unifi_host': '',
                'unifi_user': '',
                'unifi_pass': '',
                'unifi_port': '8443',
                'unifi_site': 'default',
                'app_name': 'NetMon',
                'alert_retention_days': '30',
                'log_retention_days': '90',
                'traffic_retention_hours': '720',
                'report_metrics_retention_hours': '1440',
                'interface_chart_retention_hours': '168',
                'anomaly_cap_multiplier': '1.05',
                'anomaly_cap_gbps': '5.0',
            }
            for k, v in defaults.items():
                c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

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
        with self.conn() as c:
            cur = c.execute('''
                INSERT INTO devices
                    (name, ip, mac, type, vendor, model, zone_id,
                     snmp_enabled, snmp_community, snmp_version, snmp_port,
                     icon, pos_x, pos_y, description, status, source, uplink_speed_mbps, alerts_enabled, wan_iface_idx, include_in_aggregate)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
            ))
            return cur.lastrowid

    def update_device(self, device_id, data):
        allowed = ['name', 'ip', 'mac', 'type', 'vendor', 'model', 'zone_id',
                   'snmp_enabled', 'snmp_community', 'snmp_version', 'snmp_port',
                   'icon', 'pos_x', 'pos_y', 'description', 'status',
                   'last_seen', 'last_polled', 'uptime', 'sys_name',
                   'cpu_usage', 'memory_usage', 'temperature', 'wan_in', 'wan_out',
                   'uplink_speed_mbps', 'alerts_enabled', 'wan_iface_idx', 'include_in_aggregate']
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
        with self.conn() as c:
            c.execute(f'UPDATE devices SET {", ".join(fields)} WHERE id = ?', tuple(values))

    def delete_device(self, device_id):
        with self.conn() as c:
            c.execute('DELETE FROM devices WHERE id = ?', (device_id,))

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
            return c.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged=0').fetchone()[0]

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
        with self.conn() as c:
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
        with self.conn() as c:
            c.execute('INSERT INTO snmp_metrics (device_id, metric_name, metric_value) VALUES (?, ?, ?)',
                      (device_id, name, str(value)))

    def save_interface_traffic(self, device_id, iface_name, iface_idx, rx_bps, tx_bps):
        with self.conn() as c:
            c.execute('INSERT INTO interface_traffic (device_id,iface_name,iface_idx,rx_bps,tx_bps) VALUES (?,?,?,?,?)',
                      (device_id, iface_name, iface_idx, rx_bps, tx_bps))

    def get_interface_traffic(self, device_id, iface_name=None, hours=1):
        try:
            poll_interval = max(5, int(self.get_settings().get('traffic_poll_interval', 10)))
        except Exception:
            poll_interval = 10
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
        Real peak per-device per-bucket (MAX), baru dijumlahkan lintas-device (SUM) -- bukan SUM
        mentah lintas-waktu, supaya tidak menggelembungkan nilai saat bucket berisi banyak sample."""
        if hours <= 2:
            bucket_fmt = "strftime('%H:%M', m.timestamp, 'localtime')"
            limit = 130
        elif hours <= 24:
            bucket_fmt = ("strftime('%H:', m.timestamp, 'localtime') || "
                          "(CASE WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 15 THEN '00' "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 30 THEN '15' "
                          "WHEN CAST(strftime('%M', m.timestamp, 'localtime') AS INTEGER) < 45 THEN '30' ELSE '45' END)")
            limit = 100
        else:
            bucket_fmt = "strftime('%m-%d %H:00', m.timestamp, 'localtime')"
            limit = 200

        with self.conn() as c:
            rows = c.execute(f'''
                WITH per_device_bucket AS (
                    SELECT
                        m.device_id,
                        {bucket_fmt} AS bucket,
                        MAX(CASE WHEN m.metric_name = 'wan_in' THEN CAST(m.metric_value AS REAL) ELSE 0 END) AS rx_peak,
                        MAX(CASE WHEN m.metric_name = 'wan_out' THEN CAST(m.metric_value AS REAL) ELSE 0 END) AS tx_peak
                    FROM snmp_metrics m
                    JOIN devices d ON m.device_id = d.id
                    WHERE d.type = 'router'
                      AND d.include_in_aggregate = 1
                      AND m.metric_name IN ('wan_in', 'wan_out')
                      AND m.timestamp >= datetime('now', ? || ' hours')
                    GROUP BY m.device_id, bucket
                )
                SELECT bucket, SUM(rx_peak) AS rx_sum, SUM(tx_peak) AS tx_sum
                FROM per_device_bucket
                GROUP BY bucket
                ORDER BY bucket ASC
                LIMIT ?
            ''', (f'-{hours}', limit)).fetchall()

        return [{'t': r['bucket'], 'in': round((r['rx_sum'] or 0) / 1000000.0, 2), 'out': round((r['tx_sum'] or 0) / 1000000.0, 2)} for r in rows]

    def get_device_interfaces(self, device_id, hours=24):
        with self.conn() as c:
            rows = c.execute('''
                SELECT DISTINCT iface_name, iface_idx FROM interface_traffic
                WHERE device_id=? AND sampled_at >= datetime('now', ? || ' hours')
                ORDER BY iface_idx ASC
            ''', (device_id, f'-{int(hours)}')).fetchall()
            return [{'name': r[0], 'idx': r[1]} for r in rows]

    def cleanup_interface_traffic(self, interface_retention_hours=168, metrics_retention_hours=None):
        # metrics_retention_hours default None -> pakai interface_retention_hours (kompatibel mundur
        # kalau caller lama cuma kirim 1 parameter). snmp_metrics itu sumber data laporan bulanan,
        # jadi dikasih retensi jauh lebih panjang dp interface_traffic (yang cuma buat chart recent).
        if metrics_retention_hours is None:
            metrics_retention_hours = interface_retention_hours
        with self.conn() as c:
            c.execute("DELETE FROM interface_traffic WHERE sampled_at < datetime('now', ? || ' hours')",
                      (f'-{int(interface_retention_hours)}',))
            c.execute("DELETE FROM snmp_metrics WHERE timestamp < datetime('now', ? || ' hours')",
                      (f'-{int(metrics_retention_hours)}',))


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
        with self.conn() as c:
            total    = c.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
            up       = c.execute("SELECT COUNT(*) FROM devices WHERE status='up'").fetchone()[0]
            down     = c.execute("SELECT COUNT(*) FROM devices WHERE status='down'").fetchone()[0]
            warning  = c.execute("SELECT COUNT(*) FROM devices WHERE status='warning'").fetchone()[0]
            unknown  = c.execute("SELECT COUNT(*) FROM devices WHERE status='unknown'").fetchone()[0]
            snmp_en  = c.execute("SELECT COUNT(*) FROM devices WHERE snmp_enabled=1").fetchone()[0]
            unacked  = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND is_false_alarm=0").fetchone()[0]
            critical = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0 AND severity='critical' AND is_false_alarm=0").fetchone()[0]
            zones    = c.execute('SELECT COUNT(*) FROM zones').fetchone()[0]
            return {
                'total': total, 'up': up, 'down': down, 'warning': warning,
                'unknown': unknown, 'snmp_enabled': snmp_en,
                'unacked_alerts': unacked, 'critical_alerts': critical, 'zones': zones
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
            with self.conn() as c:
                c.execute('INSERT OR REPLACE INTO monthly_reports (report_month, report_data, generated_at) VALUES (?, ?, datetime("now"))',
                          (month_str, json.dumps(report)))
            return report
            
        # Parse month_str to calendar month bounds
        year, mon = month_str.split('-')
        year, mon = int(year), int(mon)
        month_start = f"{year:04d}-{mon:02d}-01 00:00:00"
        next_year, next_mon = (year + 1, 1) if mon == 12 else (year, mon + 1)
        month_end = f"{next_year:04d}-{next_mon:02d}-01 00:00:00"

        # 2. Query metrics for the specified calendar month
        with self.conn() as c:
            rows = c.execute('''
                SELECT device_id, metric_name, timestamp, CAST(metric_value AS REAL) as val
                FROM snmp_metrics
                WHERE metric_name IN ('wan_in', 'wan_out')
                  AND timestamp >= ? AND timestamp < ?
                ORDER BY timestamp ASC
            ''', (month_start, month_end)).fetchall()

            
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
                    import urllib.request
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
                                "content": "You are a network traffic analyst. Respond ONLY with a raw JSON object containing \"discard_timestamps\" as a list of strings."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        "temperature": 0.1
                    }

                    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
                    with urllib.request.urlopen(req, timeout=8) as response:
                        res_data = json.loads(response.read().decode('utf-8'))
                        text_resp = res_data['choices'][0]['message']['content'].strip()
                        ai_res = json.loads(text_resp)
                        for ts in ai_res.get('discard_timestamps', []):
                            for (d, m) in candidate_by_ts.get(ts, []):
                                discard_timestamps.add((d, m, ts))
                except Exception as e:
                    print(f"[AI Report Filter] Groq API call failed: {e}")
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

            
        # Query health metrics (cpu, memory, temperature) and alerts for the routers
        with self.conn() as c:
            health_rows = c.execute('''
                SELECT device_id, metric_name, CAST(metric_value AS REAL) as val
                FROM snmp_metrics
                WHERE metric_name IN ('cpu_usage', 'memory_usage', 'temperature')
                  AND timestamp >= ? AND timestamp < ?
            ''', (month_start, month_end)).fetchall()
            
            alert_rows = c.execute('''
                SELECT device_id, COUNT(*) as cnt
                FROM alerts
                WHERE created_at >= ? AND created_at < ?
                GROUP BY device_id
            ''', (month_start, month_end)).fetchall()

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
                max_ts = max((rx_points[-1][0] if rx_points else datetime.min), (tx_points[-1][0] if tx_points else datetime.min))
                
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
                

            router_stats = {
                'id': rid,
                'name': router['name'],
                'ip': router['ip'],
                'include_in_aggregate': router.get('include_in_aggregate', 1),
                'total_rx_gb': round(total_rx_bytes / 1e9, 2),
                'total_tx_gb': round(total_tx_bytes / 1e9, 2),
                'avg_rx_mbps': round(avg_rx_bps / 1e6, 2),
                'avg_tx_mbps': round(avg_tx_bps / 1e6, 2),
                'peak_rx_mbps': round(max_rx_bps / 1e6, 2),
                'peak_tx_mbps': round(max_tx_bps / 1e6, 2),
                
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
        report['backbone']['avg_in_mbps'] = round(total_backbone_rx_bps_sum / 1e6, 2)
        report['backbone']['avg_out_mbps'] = round(total_backbone_tx_bps_sum / 1e6, 2)
        report['backbone']['peak_in_mbps'] = round(max(backbone_peaks_rx) / 1e6, 2) if backbone_peaks_rx else 0.0
        report['backbone']['peak_out_mbps'] = round(max(backbone_peaks_tx) / 1e6, 2) if backbone_peaks_tx else 0.0
        report['backbone']['total_in_gb'] = round(sum(r['total_rx_gb'] for r in report['routers'] if r.get('include_in_aggregate', 1) == 1), 2)
        report['backbone']['total_out_gb'] = round(sum(r['total_tx_gb'] for r in report['routers'] if r.get('include_in_aggregate', 1) == 1), 2)
        
        # 3. Save report to DB
        with self.conn() as c:
            c.execute('INSERT OR REPLACE INTO monthly_reports (report_month, report_data, generated_at) VALUES (?, ?, datetime("now"))',
                      (month_str, json.dumps(report)))
                      
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
