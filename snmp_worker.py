#!/usr/bin/env python3
"""
NetMon - SNMP Worker (puresnmp 2.x, Python 3.9+)
"""

import threading, socket, time, ipaddress, os, subprocess, re, sys, asyncio, logging
from datetime import datetime

logger = logging.getLogger('netmon.snmp')

# Set Windows Selector Event Loop Policy to prevent IOCP/Proactor event loop issues with UDP in background threads
if sys.platform == 'win32':
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

try:
    from puresnmp import PyWrapper, Client, V1, V2C
    from puresnmp.exc import SnmpError, Timeout as SnmpTimeout
    try:
        from puresnmp.pdu import NoSuchObject, NoSuchInstance
    except ImportError:
        # Older puresnmp versions may not have these
        NoSuchObject = type(None)
        NoSuchInstance = type(None)
    SNMP_OK = True
except ImportError:
    SNMP_OK = False
    NoSuchObject = type(None)
    NoSuchInstance = type(None)
    print("[SNMP] puresnmp not installed — run: pip install puresnmp")

OID = {
    'sysDescr':     '1.3.6.1.2.1.1.1.0',
    'sysUpTime':    '1.3.6.1.2.1.1.3.0',
    'sysName':      '1.3.6.1.2.1.1.5.0',
    'sysLocation':  '1.3.6.1.2.1.1.6.0',
    'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
    'ifDescr':      '1.3.6.1.2.1.2.2.1.2',
}


def _creds(version, community):
    return V1(community) if version == '1' else V2C(community)


def _client(ip, version, community, port, timeout=2.0, retries=1):
    c = Client(ip, _creds(version, community), port=port)
    try:
        c.configure(timeout=timeout, retries=retries)
    except Exception:
        try:
            c.config.timeout = timeout
            c.config.retries = retries
        except Exception:
            pass
    return PyWrapper(c)


def parse_uptime_to_seconds(uptime_str):
    if not uptime_str:
        return 0
    try:
        return float(uptime_str) / 100.0
    except ValueError:
        pass
    try:
        parts = uptime_str.split(',')
        days = 0
        time_part = uptime_str
        if len(parts) > 1:
            days_str = parts[0].lower().replace('days', '').replace('day', '').strip()
            days = int(days_str)
            time_part = parts[1].strip()
        time_parts = time_part.split(':')
        hours = 0
        minutes = 0
        seconds = 0.0
        if len(time_parts) == 3:
            hours = int(time_parts[0])
            minutes = int(time_parts[1])
            seconds = float(time_parts[2])
        elif len(time_parts) == 2:
            minutes = int(time_parts[0])
            seconds = float(time_parts[1])
        return (days * 86400) + (hours * 3600) + (minutes * 60) + seconds
    except Exception:
        return 0

class SNMPWorker:
    def __init__(self, db, socketio, telegram_bot=None):
        self.db = db
        self.socketio = socketio
        self.telegram_bot = telegram_bot
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._status = {'running':False,'progress':0,'total':0,'found':0,
                        'current_ip':'','message':'Idle','percent':0}
        self._interfaces_cache = {}
        self._if_meta_cache = {}
        self._if_prev = {}
        self.db_write_lock = threading.RLock()
        self._state_lock = threading.Lock()
        self._device_snmp_locks = {}
        self._last_cache_prune = 0.0
        self._last_snmp_ok = {}
        self._recent_unreachable = {}
        self._last_diag_log = {}
        self._ping_history = {}
        self._latest_ping = {}
        self._snmp_failing = set()
        self._consecutive_snmp_fails = {}
        self._consecutive_ping_fails = {}
        self._pending_analysis = {}
        self._metric_history = {}
        self._last_anomaly_alert = {}
        self._recent_traffic_drops = {}
        self._drop_lock = threading.Lock()
        self._speed_detected = {}
        self._iface_flap_history = {}
        self._iface_err_prev = {}
        self._last_iface_alert = {}
        self._restore_poller_state()

    def _get_device_lock(self, device_id):
        """Return a per-device RLock so concurrent status & traffic jobs don't flood the same router."""
        with self._state_lock:
            lock = self._device_snmp_locks.get(device_id)
            if lock is None:
                lock = threading.RLock()
                self._device_snmp_locks[device_id] = lock
            return lock

    def _prune_stale_caches(self):
        """Periodically prune in-memory caches for deleted devices (at most once per 60s)."""
        now_ts = time.time()
        with self._state_lock:
            if (now_ts - self._last_cache_prune) < 60.0:
                return
            self._last_cache_prune = now_ts
        try:
            active_dids = {d['id'] for d in self.db.get_all_devices()}
            with self._state_lock:
                for k in list(self._if_prev.keys()):
                    if k[0] not in active_dids:
                        self._if_prev.pop(k, None)
                for k in list(self._interfaces_cache.keys()):
                    if k not in active_dids:
                        self._interfaces_cache.pop(k, None)
                for k in list(self._if_meta_cache.keys()):
                    if k not in active_dids:
                        self._if_meta_cache.pop(k, None)
                for k in list(self._device_snmp_locks.keys()):
                    if k not in active_dids:
                        self._device_snmp_locks.pop(k, None)
        except Exception as e:
            print(f"[Worker] Failed to prune caches: {e}")

    def _restore_poller_state(self):
        """Warm up rolling metric baselines from recent DB records so restarts don't wipe anomaly state."""
        try:
            with self.db.conn() as c:
                rows = c.execute('''
                    SELECT device_id, metric_name, metric_value, timestamp
                    FROM snmp_metrics
                    WHERE metric_name IN ('cpu_usage', 'memory_usage', 'wan_in', 'wan_out')
                      AND timestamp >= datetime('now', '-10 minutes')
                    ORDER BY timestamp ASC
                ''').fetchall()
            from collections import defaultdict
            by_dev = defaultdict(list)
            for r in rows:
                by_dev[r['device_id']].append(r)
            for did, mrows in by_dev.items():
                buckets = {}
                for mr in mrows:
                    ts_key = str(mr['timestamp'])[:17]
                    b = buckets.setdefault(ts_key, {'ts': time.time(), 'cpu': None, 'mem': None, 'traffic_bps': None})
                    try:
                        val = float(mr['metric_value'])
                    except (ValueError, TypeError):
                        continue
                    if mr['metric_name'] == 'cpu_usage':
                        b['cpu'] = val
                    elif mr['metric_name'] == 'memory_usage':
                        b['mem'] = val
                    elif mr['metric_name'] in ('wan_in', 'wan_out'):
                        b['traffic_bps'] = max(b['traffic_bps'] or 0.0, val)
                self._metric_history[did] = list(buckets.values())[-12:]

            saved_flap = self.db.get_poller_state('iface_flap_history')
            if isinstance(saved_flap, dict):
                now_ts = time.time()
                for k_str, v in saved_flap.items():
                    parts = k_str.split(':', 1)
                    if len(parts) == 2 and isinstance(v, dict):
                        changes = [ts for ts in v.get('changes', []) if (now_ts - ts) <= 900]
                        self._iface_flap_history[(int(parts[0]), parts[1])] = {
                            'state': v.get('state', 'up'),
                            'changes': changes
                        }
        except Exception as e:
            print(f"[SNMPWorker] State warmup skipped: {e}")

    def _persist_flap_state(self):
        try:
            serializable = {f"{k[0]}:{k[1]}": v for k, v in self._iface_flap_history.items() if v.get('changes')}
            self.db.set_poller_state('iface_flap_history', serializable)
        except Exception as e:
            print(f"[SNMPWorker] Persist flap state error: {e}")

    def get_scan_status(self): return dict(self._status)
    def stop_scan(self):       self._stop.set()

    # ─── anomaly / spike cap helper ─────────────────────────────────
    def _anomaly_limit_bps(self, effective_speed_bps):
        """Batas atas (bps) untuk mendeteksi spike/anomali traffic.
        Secara mutlak dibatasi oleh:
          1. Toleransi link fisik: effective_speed_bps * anomaly_cap_multiplier
          2. Plafon total ISP kampus: campus_total_bandwidth_mbps * 1e6 * anomaly_cap_multiplier
          3. Plafon settings anomaly_cap_gbps (jika disetel)
        Traffic tidak boleh melebihi kapasitas link fisik maupun total bandwidth seluruh ISP kampus.
        """
        try:
            mult = float(self.db.get_settings().get('anomaly_cap_multiplier', 1.05))
        except (ValueError, TypeError):
            mult = 1.05
        try:
            cap_gbps = float(self.db.get_settings().get('anomaly_cap_gbps', 5.0))
        except (ValueError, TypeError):
            cap_gbps = 5.0

        # Plafon mutlak dari total bandwidth ISP kampus
        try:
            campus_bw_mbps = float(self.db.get_campus_total_bandwidth_mbps() or 5000)
            isp_ceiling_bps = (campus_bw_mbps * 1e6) * mult
        except Exception:
            isp_ceiling_bps = 5.0 * 1e9 * mult

        cap_bps = min(cap_gbps * 1e9, isp_ceiling_bps)

        if effective_speed_bps and effective_speed_bps > 0:
            limit = effective_speed_bps * mult
            return min(limit, cap_bps)
        return cap_bps

    @staticmethod
    def _calc_median(values):
        if not values:
            return 0.0
        s = sorted(values)
        n = len(s)
        if n % 2 == 1:
            return s[n // 2]
        return (s[n // 2 - 1] + s[n // 2]) / 2.0

    def _assess_traffic_drop_factors(self, device, older_med_mbps, cur_traffic_mbps, now_ts, drop_min_mbps):
        """Multi-factor evaluation before raising a traffic drop alert.
        Considers: 30-min DB baseline (filters short bursts), maintenance/parent state,
        ping latency & packet loss, residual traffic vs near-zero blackhole,
        multi-router campus correlation, and campus off-peak/transition hours.
        Returns (should_alert: bool, severity: str|None, message: str|None).
        """
        did = device['id']
        ip = device.get('ip', '')
        name = device.get('name', ip)

        # Factor A: Maintenance window or upstream parent device DOWN -> suppress
        try:
            in_maint, _ = self.db.is_device_in_maintenance(did)
            if in_maint:
                return False, None, None
            p_down, _ = self.db.is_upstream_parent_down(did)
            if p_down:
                return False, None, None
        except Exception:
            pass

        # Factor B: 30-minute DB baseline verification (rejects short 1-2 min download/speedtest bursts)
        effective_baseline_mbps = older_med_mbps
        try:
            with self.db.conn() as c:
                rows = c.execute('''
                    SELECT substr(timestamp, 1, 19) AS ts_sec, MAX(CAST(metric_value AS REAL)) AS max_bps
                    FROM snmp_metrics
                    WHERE device_id = ?
                      AND metric_name IN ('wan_in', 'wan_out')
                      AND timestamp >= datetime('now', '-35 minutes')
                      AND timestamp < datetime('now', '-2 minutes')
                    GROUP BY ts_sec
                    ORDER BY ts_sec ASC
                ''', (did,)).fetchall()
            if len(rows) >= 6:
                db_mbps_list = [(r['max_bps'] or 0.0) / 1e6 for r in rows]
                db_med_mbps = self._calc_median(db_mbps_list)
                if db_med_mbps < (drop_min_mbps * 0.60) or cur_traffic_mbps > (db_med_mbps * 0.25):
                    print(f"[Anomaly Engine] Traffic drop suppressed for {name} ({ip}): short burst ended (30m median={db_med_mbps:.1f} Mbps, cur={cur_traffic_mbps:.1f} Mbps)")
                    return False, None, None
                effective_baseline_mbps = (older_med_mbps + db_med_mbps) / 2.0
        except Exception as dbe:
            logger.warning(f"[Anomaly Engine] 30m baseline check skipped for {ip}: {dbe}")

        drop_pct = max(0.0, (1.0 - (cur_traffic_mbps / effective_baseline_mbps)) * 100.0) if effective_baseline_mbps > 0 else 0.0

        # Factor C: Ping health & packet loss
        p_stat = self._latest_ping.get(ip, {})
        pkt_loss = p_stat.get('packet_loss')
        if pkt_loss is None:
            pkt_loss = device.get('packet_loss') or 0.0
        pkt_loss = float(pkt_loss)
        lat_ms = p_stat.get('latency_ms')
        if lat_ms is None:
            lat_ms = device.get('latency_ms')
        lat_str = f"{float(lat_ms):.1f} ms" if lat_ms is not None else "-"
        has_ping_degradation = (pkt_loss >= 5.0) or (lat_ms is not None and float(lat_ms) >= 120.0)

        # Factor D: Near-zero blackhole vs residual active traffic
        is_near_zero = cur_traffic_mbps < 1.5
        is_residual_active = cur_traffic_mbps >= 2.5

        # Factor E: Multi-router correlation across campus within 5 minutes
        other_drops = 0
        with self._drop_lock:
            cutoff = now_ts - 300
            stale = [k for k, v in self._recent_traffic_drops.items() if v.get('ts', 0) < cutoff]
            for k in stale:
                del self._recent_traffic_drops[k]
            self._recent_traffic_drops[did] = {
                'ts': now_ts,
                'baseline_mbps': effective_baseline_mbps,
                'cur_mbps': cur_traffic_mbps,
                'zone_id': device.get('zone_id'),
            }
            other_drops = sum(1 for k in self._recent_traffic_drops if k != did)

        down_routers = 0
        try:
            with self.db.conn() as c:
                row = c.execute("SELECT COUNT(*) FROM devices WHERE type='router' AND status='down'").fetchone()
                down_routers = int(row[0]) if row else 0
        except Exception:
            pass
        correlated_outage = (other_drops >= 1) or (down_routers >= 2)

        # Factor F: Campus schedule / off-peak transition awareness
        now_dt = datetime.now()
        hhmm = now_dt.hour * 100 + now_dt.minute
        is_sunday = (now_dt.weekday() == 6)
        is_break_window = (1130 <= hhmm <= 1315)
        is_after_hours = (hhmm >= 1545) or (hhmm <= 645)
        is_transition_or_offpeak = is_sunday or is_break_window or is_after_hours

        if is_transition_or_offpeak and is_residual_active and not has_ping_degradation and not correlated_outage:
            print(f"[Anomaly Engine] Traffic drop suppressed for {name} ({ip}): off-peak/transition schedule with healthy ping & residual traffic ({cur_traffic_mbps:.1f} Mbps)")
            return False, None, None

        if cur_traffic_mbps >= 5.0 and pkt_loss < 5.0 and not correlated_outage and drop_pct < 92.0:
            print(f"[Anomaly Engine] Traffic drop suppressed for {name} ({ip}): residual traffic {cur_traffic_mbps:.1f} Mbps healthy (0% loss, single router)")
            return False, None, None

        # Construct evidence-based verdict
        if correlated_outage:
            sev = 'critical' if (is_near_zero and other_drops >= 2) else 'warning'
            msg = (
                f"ANOMALI TRAFFIC DROP (MULTI-ROUTER): Trafik {name} ({ip}) anjlok "
                f"{effective_baseline_mbps:.1f} → {cur_traffic_mbps:.1f} Mbps (-{drop_pct:.0f}%), "
                f"bersamaan dengan {other_drops} router lain & {down_routers} router DOWN "
                f"[Ping: {lat_str}, Loss: {pkt_loss:.0f}%]. Indikasi kuat gangguan upstream ISP / Firewall / Core BGP!"
            )
            return True, sev, msg

        if is_near_zero or has_ping_degradation:
            msg = (
                f"ANOMALI TRAFFIC DROP: Trafik {name} ({ip}) turun drastis "
                f"{effective_baseline_mbps:.1f} → {cur_traffic_mbps:.1f} Mbps (-{drop_pct:.0f}%) "
                f"[Ping: {lat_str}, Loss: {pkt_loss:.0f}%, router lain normal]. "
                f"Periksa port/kabel WAN lokal, switch gedung, atau perpindahan routing ISP."
            )
            return True, 'warning', msg

        msg = (
            f"PENURUNAN TRAFIK SIGNIFIKAN: Trafik {name} ({ip}) turun tajam "
            f"{effective_baseline_mbps:.1f} → {cur_traffic_mbps:.1f} Mbps (-{drop_pct:.0f}%), "
            f"namun ping normal ({lat_str}, loss {pkt_loss:.0f}%), router lain normal & trafik masih mengalir. "
            f"Kemungkinan sesi aktivitas gedung selesai atau switching jalur ISP."
        )
        return True, 'info', msg

    def _analyze_metric_anomalies(self, device, metrics, traffic_data=None):
        """Menganalisa lonjakan traffic, penurunan traffic (multi-faktor), dan resource usage (CPU/RAM).
        Dilengkapi cooldown per perangkat untuk mencegah alert flapping.
        """
        try:
            settings = self.db.get_settings()
        except Exception:
            return

        if settings.get('anomaly_alert_enabled', 'true').lower() != 'true':
            return

        did = device['id']
        ip = device.get('ip', '')
        name = device.get('name', ip)

        try:
            traffic_mult = float(settings.get('traffic_spike_multiplier', 4.0))
            min_mbps = float(settings.get('traffic_spike_min_mbps', 80.0))
            cpu_thresh = float(settings.get('cpu_spike_threshold', 92.0))
            cpu_jump_thresh = float(settings.get('cpu_jump_threshold', 65.0))
            mem_thresh = float(settings.get('memory_spike_threshold', 95.0))
        except (ValueError, TypeError):
            traffic_mult, min_mbps, cpu_thresh, cpu_jump_thresh, mem_thresh = 4.0, 80.0, 92.0, 65.0, 95.0

        now_ts = time.time()
        cpu = metrics.get('cpu_usage') if metrics else None
        mem = metrics.get('memory_usage') if metrics else None

        has_valid_traffic = bool(traffic_data and ('wan_in' in traffic_data or 'wan_out' in traffic_data))
        cur_wan_in = float(traffic_data.get('wan_in') or 0.0) if has_valid_traffic else 0.0
        cur_wan_out = float(traffic_data.get('wan_out') or 0.0) if has_valid_traffic else 0.0
        cur_traffic_bps = max(cur_wan_in, cur_wan_out) if has_valid_traffic else None
        cur_traffic_mbps = (cur_traffic_bps / 1e6) if cur_traffic_bps is not None else 0.0

        if did not in self._metric_history:
            self._metric_history[did] = []

        history = self._metric_history[did]

        # Anomaly Detection Flags
        traffic_spike = False
        traffic_drop = False
        drop_sev = None
        drop_msg = None
        spike_ratio = 1.0
        cpu_critical = False
        cpu_jumped = False
        prev_cpu = None
        mem_critical = False

        uplink_mbps = float(device.get('uplink_speed_mbps') or 1000)
        uplink_bps = uplink_mbps * 1e6
        utilization_pct = (cur_traffic_bps / uplink_bps * 100) if (cur_traffic_bps is not None and uplink_bps > 0) else 0.0
        drop_min_mbps = float(settings.get('traffic_drop_min_mbps', 50.0) or 50.0)

        # Require at least 4 previous samples to establish reliable baseline
        if len(history) >= 4:
            # 1. Traffic Spike & Multi-Factor Traffic Drop Analysis (only when traffic poll succeeded)
            prev_traffics = [h['traffic_bps'] for h in history if h.get('traffic_bps') is not None]
            if has_valid_traffic and prev_traffics:
                avg_prev = sum(prev_traffics) / len(prev_traffics)
                if cur_traffic_mbps >= min_mbps and avg_prev > 0:
                    spike_ratio = cur_traffic_bps / avg_prev
                    if spike_ratio >= traffic_mult and (utilization_pct >= 60.0 or cur_traffic_mbps >= 300.0):
                        traffic_spike = True

                # Multi-factor Traffic Drop Check: require >=5 older samples & 3 consecutive low samples
                if len(prev_traffics) >= 5:
                    older = prev_traffics[:-2]
                    older_mbps = [v / 1e6 for v in older]
                    older_med_mbps = self._calc_median(older_mbps)
                    sustained_cnt = sum(1 for v in older_mbps if v >= (drop_min_mbps * 0.60))
                    last1_mbps = prev_traffics[-1] / 1e6
                    last2_mbps = prev_traffics[-2] / 1e6

                    if older_med_mbps >= drop_min_mbps and sustained_cnt >= max(2, int(len(older_mbps) * 0.7)):
                        is_3poll_low = (
                            cur_traffic_mbps <= (older_med_mbps * 0.15)
                            and last1_mbps <= (older_med_mbps * 0.20)
                            and last2_mbps <= (older_med_mbps * 0.25)
                        )
                        not_recovering = cur_traffic_mbps <= (last1_mbps * 1.4 + 0.5)
                        if is_3poll_low and not_recovering:
                            traffic_drop, drop_sev, drop_msg = self._assess_traffic_drop_factors(
                                device, older_med_mbps, cur_traffic_mbps, now_ts, drop_min_mbps
                            )

            # 2. CPU Spike Analysis (require sustained critical CPU or extreme jump into heavy load >= 85%)
            prev_cpus = [h['cpu'] for h in history if h.get('cpu') is not None]
            if prev_cpus:
                prev_cpu = prev_cpus[-1]
            if cpu is not None:
                if cpu >= cpu_thresh and prev_cpu is not None and prev_cpu >= (cpu_thresh - 10.0):
                    cpu_critical = True
                if prev_cpu is not None and (cpu - prev_cpu) >= cpu_jump_thresh and cpu >= 85.0:
                    cpu_jumped = True

            # 3. Memory Spike Analysis (require sustained near-exhaustion)
            prev_mems = [h['mem'] for h in history if h.get('mem') is not None]
            prev_mem = prev_mems[-1] if prev_mems else None
            if mem is not None and mem >= mem_thresh and prev_mem is not None and prev_mem >= mem_thresh:
                mem_critical = True

        # Append current sample to rolling history (keep latest 12 samples)
        history.append({
            'ts': now_ts,
            'cpu': cpu,
            'mem': mem,
            'traffic_bps': cur_traffic_bps
        })
        if len(history) > 12:
            history.pop(0)

        # Evaluate correlation & construct alert if anomaly detected
        severity = None
        alert_msg = None

        if traffic_spike and (cpu_critical or cpu_jumped):
            severity = 'critical'
            alert_msg = (
                f"ANOMALI KRITIS: Lonjakan Traffic drastis ({cur_traffic_mbps:.1f} Mbps, {spike_ratio:.1f}x baseline) "
                f"bersamaan dengan lonjakan CPU ({cpu:.1f}%) pada {name} ({ip}). Indikasi DDoS / Flood / Routing Loop!"
            )
        elif traffic_spike and utilization_pct >= 85.0:
            severity = 'warning'
            alert_msg = (
                f"ANOMALI TRAFFIC: Lonjakan throughput mendekati saturasi link ({cur_traffic_mbps:.1f} Mbps, "
                f"{utilization_pct:.1f}% link) pada {name} ({ip}) [CPU: {cpu if cpu is not None else '-'}%]."
            )
        elif cpu_critical:
            severity = 'warning'
            alert_msg = (
                f"ANOMALI RESOURCE: Beban CPU tinggi berkelanjutan ({cpu:.1f}%) pada {name} ({ip})."
            )
        elif mem_critical:
            severity = 'warning'
            alert_msg = (
                f"ANOMALI RESOURCE: Penggunaan RAM kritis ({mem:.1f}%) pada {name} ({ip}). Risiko OOM Crash!"
            )
        elif traffic_drop and drop_sev and drop_msg:
            severity = drop_sev
            alert_msg = drop_msg

        if not severity or not alert_msg:
            return

        # Cooldown check: prevent duplicate alert within 600s (10m) unless escalating to critical
        last_alert = self._last_anomaly_alert.get(did, {})
        last_ts = last_alert.get('ts', 0)
        last_sev = last_alert.get('severity', '')
        if (now_ts - last_ts < 600) and not (severity == 'critical' and last_sev != 'critical'):
            return

        self._last_anomaly_alert[did] = {
            'ts': now_ts,
            'severity': severity,
            'msg': alert_msg
        }

        print(f"[Anomaly Engine] Triggering {severity.upper()} anomaly alert for {name} ({ip})")
        self._alert(device, severity, alert_msg)

    # ─── low-level helpers ───────────────────────────────────────────

    async def _async_get(self, ip, community, oids, port, version, timeout):
        c = _client(ip, version, community, port, timeout=timeout, retries=1)
        res = {}
        # Try multiget first (single SNMP request for all OIDs — faster & more reliable)
        try:
            multi_result = await c.multiget(oids)
            if multi_result and isinstance(multi_result, (list, tuple)):
                for i, val in enumerate(multi_result):
                    if i < len(oids):
                        # Filter out NoSuchObject/NoSuchInstance sentinel values
                        if val is None or isinstance(val, (NoSuchObject, NoSuchInstance)):
                            continue
                        if isinstance(val, bytes):
                            try:
                                val = val.decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                        str_val = str(val)
                        # Also filter string representations of sentinel values
                        if str_val.lower() in ('nosuchobject', 'nosuchinstance', 'endofmibview', 'none'):
                            continue
                        res[oids[i]] = str_val
                if res:
                    return res
        except (SnmpTimeout, asyncio.TimeoutError) as e:
            # Device may not support multiple varbinds in 1 PDU or dropped the multiget packet.
            # Fall through to individual gets below!
            pass
        except Exception as e:
            pass

        # Fallback to individual gets if multiget fails or times out
        for oid in oids:
            try:
                val = await c.get(oid)
                # Filter out NoSuchObject/NoSuchInstance sentinel values
                if val is None or isinstance(val, (NoSuchObject, NoSuchInstance)):
                    continue
                # Clean up bytes to string if needed
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                str_val = str(val)
                # Also filter string representations of sentinel values
                if str_val.lower() in ('nosuchobject', 'nosuchinstance', 'endofmibview', 'none'):
                    continue
                res[oid] = str_val
            except (SnmpTimeout, asyncio.TimeoutError):
                continue
            except Exception:
                continue
        return res if res else None

    def _log_diag_throttled(self, key, message, cooldown=60.0):
        now_ts = time.time()
        with self._state_lock:
            last = self._last_diag_log.get(key, 0.0)
            if (now_ts - last) < cooldown:
                return
            self._last_diag_log[key] = now_ts
        print(message)

    def _get(self, ip, community, oids, port=161, version='2c', timeout=2):
        if not SNMP_OK: return None
        for attempt in range(2):
            try:
                coro = self._async_get(ip, community, oids, port, version, timeout)
                res = asyncio.run(coro)
                if res:
                    return res
                if attempt == 0:
                    time.sleep(0.5)
            except Exception as e:
                self._log_diag_throttled(('snmp_get', ip), f"[SNMP _get WARN] {ip}: {type(e).__name__}: {e}")
                if attempt == 0:
                    time.sleep(0.5)
        return None

    async def _async_walk(self, ip, community, base_oid, port, version, timeout):
        c = _client(ip, version, community, port, timeout=timeout, retries=1)
        res = {}
        try:
            async for oid, val in c.walk(base_oid):
                # Clean up bytes to string if needed
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                res[str(oid)] = str(val)
        except Exception:
            pass
        return res

    def _walk(self, ip, community, base_oid, port=161, version='2c', timeout=2):
        if not SNMP_OK: return {}
        for attempt in range(2):
            try:
                coro = self._async_walk(ip, community, base_oid, port, version, timeout)
                res = asyncio.run(coro)
                if res:
                    return res
            except Exception:
                pass
        return {}

    # ─── poll a single device ────────────────────────────────────────

    def _ping(self, ip):
        import time, subprocess, platform, re
        start_time = time.time()
        is_alive = False
        latency_ms = None
        packet_loss = 0.0
        
        # 1. Try standard OS Ping (numeric -n on Linux skips slow/blocking PTR DNS lookups)
        is_win = platform.system().lower() == 'windows'
        if is_win:
            cmd = ['ping', '-n', '2', '-w', '1500', ip]
            run_timeout = 6.0
        else:
            cmd = ['ping', '-n', '-c', '3', '-i', '0.25', '-W', '2', ip]
            run_timeout = 7.0
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
                timeout=run_timeout,
                text=True
            )
            out = (res.stdout or '') + (res.stderr or '')
            if res.returncode == 0:
                is_alive = True
                # Parse latency
                # Linux: rtt min/avg/max/mdev = 0.354/0.512/0.670/0.158 ms
                # Or: time=0.45 ms
                m_lat = re.search(r'(?:rtt|round-trip)[^=]*=\s*[\d\.]+/([\d\.]+)/', out)
                if m_lat:
                    try:
                        latency_ms = round(float(m_lat.group(1)), 1)
                    except Exception:
                        pass
                else:
                    m_time = re.findall(r'time[=<]([\d\.]+)\s*ms', out)
                    if m_time:
                        try:
                            times = [float(x) for x in m_time]
                            latency_ms = round(sum(times) / len(times), 1)
                        except Exception:
                            pass
                
                # Parse packet loss
                m_loss = re.search(r'(\d+)%\s*packet loss', out)
                if m_loss:
                    try:
                        packet_loss = float(m_loss.group(1))
                    except Exception:
                        pass
            else:
                stderr_txt = (res.stderr or '').strip()
                if stderr_txt:
                    self._log_diag_throttled(('ping_stderr', ip), f"[Ping WARN] {ip} rc={res.returncode}: {stderr_txt}")
                m_loss = re.search(r'(\d+)%\s*packet loss', out)
                if m_loss:
                    try:
                        packet_loss = float(m_loss.group(1))
                    except Exception:
                        packet_loss = 100.0
                else:
                    packet_loss = 100.0
        except Exception as pe:
            self._log_diag_throttled(('ping_exc', ip), f"[Ping ERROR] {ip}: {type(pe).__name__}: {pe}")

        # 2. Fallback to TCP connection check on common router/server ports (if ICMP is rate-limited/blocked)
        if not is_alive:
            import socket
            common_ports = [22, 80, 443, 179, 8291, 8728, 445]
            for port in common_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.4)
                    t0 = time.time()
                    result = s.connect_ex((ip, port))
                    s.close()
                    if result == 0 or result in (111, 10061):
                        is_alive = True
                        latency_ms = round((time.time() - t0) * 1000.0, 1)
                        packet_loss = 0.0
                        break
                except Exception:
                    pass

        elapsed = (time.time() - start_time) * 1000.0  # in ms
        if latency_ms is None and is_alive:
            latency_ms = round(elapsed / 2.0, 1)

        if not is_alive:
            latency_ms = None
            packet_loss = 100.0

        with self._state_lock:
            if ip not in self._ping_history:
                self._ping_history[ip] = []
            self._ping_history[ip].append((is_alive, latency_ms or elapsed))
            self._ping_history[ip] = self._ping_history[ip][-10:]
            self._latest_ping[ip] = {'latency_ms': latency_ms, 'packet_loss': packet_loss}
        return is_alive

    def _get_resource_metrics(self, ip, community, port, version, vendor_lower, descr_lower, sys_obj_id=None):
        cpu_usage = None
        memory_usage = None
        temperature = None
        
        sys_obj_id = str(sys_obj_id or '').lower()
        
        is_mikrotik = 'mikrotik' in vendor_lower or 'mikrotik' in descr_lower or 'routeros' in descr_lower or '14988' in sys_obj_id
        is_ruijie = 'ruijie' in vendor_lower or 'ruijie' in descr_lower or 'reyee' in vendor_lower or 'reyee' in descr_lower or '4881' in sys_obj_id or 'rgos' in descr_lower or ('rg-' in descr_lower and 'rap' in descr_lower)
        is_ubiquiti = 'ubiquiti' in vendor_lower or 'ubnt' in vendor_lower or 'ubiquiti' in descr_lower or 'uap' in descr_lower or 'unifi' in descr_lower or '41112' in sys_obj_id
        is_cisco = 'cisco' in vendor_lower or 'cisco' in descr_lower or ('9.1.' in sys_obj_id or '9.9.' in sys_obj_id or '.9.' in sys_obj_id)
        
        # --- VENDOR SPECIFIC QUERIES ---
        # 1. MikroTik
        if is_mikrotik:
            res = self._get(ip, community, [
                '1.3.6.1.4.1.14988.1.1.3.10.0', # CPU Load
                '1.3.6.1.4.1.14988.1.1.3.8.0',  # Temperature
                '1.3.6.1.4.1.14988.1.1.3.14.0', # Total RAM in bytes
                '1.3.6.1.4.1.14988.1.1.3.17.0'  # Free RAM in bytes
            ], port=port, version=version)
            if res:
                if res.get('1.3.6.1.4.1.14988.1.1.3.10.0') is not None:
                    try: cpu_usage = float(res['1.3.6.1.4.1.14988.1.1.3.10.0'])
                    except ValueError: pass
                if res.get('1.3.6.1.4.1.14988.1.1.3.8.0') is not None:
                    try:
                        temperature = float(res['1.3.6.1.4.1.14988.1.1.3.8.0']) / 10.0
                    except ValueError: pass
                if res.get('1.3.6.1.4.1.14988.1.1.3.14.0') and res.get('1.3.6.1.4.1.14988.1.1.3.17.0'):
                    try:
                        tot = float(res['1.3.6.1.4.1.14988.1.1.3.14.0'])
                        fre = float(res['1.3.6.1.4.1.14988.1.1.3.17.0'])
                        if tot > 0:
                            memory_usage = ((tot - fre) / tot) * 100.0
                    except Exception: pass
                    
        # 2. Ruijie / Reyee
        elif is_ruijie:
            res = self._get(ip, community, [
                '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0',   # CPU 1
                '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.2.0',   # CPU 2
                '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.3.0',   # CPU 3
                '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.15.0',  # CPU 4
                '1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1.3.0', # RAM Util 1
                '1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1.2.0', # RAM Util 2
                '1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1.1.0', # RAM Util 3
                '1.3.6.1.4.1.4881.1.1.10.2.1.1.16.0',     # Temp 1
                '1.3.6.1.4.1.4881.1.1.10.2.1.1.20.0'      # Temp 2
            ], port=port, version=version)
            
            cpu_val = None
            mem_val = None
            temp_val = None
            
            if res:
                for k in ['1.3.6.1.4.1.4881.1.1.10.2.36.1.1.1.0', '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.2.0', '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.3.0', '1.3.6.1.4.1.4881.1.1.10.2.36.1.1.15.0']:
                    if res.get(k) is not None:
                        cpu_val = res[k]
                        break
                for k in ['1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1.3.0', '1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1.2.0', '1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1.1.0']:
                    if res.get(k) is not None:
                        mem_val = res[k]
                        break
                for k in ['1.3.6.1.4.1.4881.1.1.10.2.1.1.16.0', '1.3.6.1.4.1.4881.1.1.10.2.1.1.20.0']:
                    if res.get(k) is not None:
                        temp_val = res[k]
                        break
            
            if cpu_val is None:
                cpu_walk = self._walk(ip, community, '1.3.6.1.4.1.4881.1.1.10.2.36.1.1', port=port, version=version)
                if cpu_walk:
                    for v in cpu_walk.values():
                        try:
                            float(v)
                            cpu_val = v
                            break
                        except ValueError: pass
                        
            if mem_val is None:
                mem_walk = self._walk(ip, community, '1.3.6.1.4.1.4881.1.1.10.2.35.1.1.1', port=port, version=version)
                if mem_walk:
                    for v in mem_walk.values():
                        try:
                            float(v)
                            mem_val = v
                            break
                        except ValueError: pass
                        
            if temp_val is None:
                temp_walk = self._walk(ip, community, '1.3.6.1.4.1.4881.1.1.10.2.1.1', port=port, version=version)
                if temp_walk:
                    for v in temp_walk.values():
                        try:
                            float(v)
                            temp_val = v
                            break
                        except ValueError: pass
                        
            if cpu_val is not None:
                try: cpu_usage = float(cpu_val)
                except ValueError: pass
            if mem_val is not None:
                try: memory_usage = float(mem_val)
                except ValueError: pass
            if temp_val is not None:
                try:
                    val = float(temp_val)
                    if val > 120: val /= 10.0
                    temperature = val
                except ValueError: pass
                
        # 3. Ubiquiti / UniFi SNMP
        elif is_ubiquiti:
            res = self._get(ip, community, [
                '1.3.6.1.4.1.41112.1.4.1.1.4.1', # CPU load percentage
                '1.3.6.1.4.1.41112.1.4.1.1.5.1'  # Memory usage percentage
            ], port=port, version=version)
            if res:
                if res.get('1.3.6.1.4.1.41112.1.4.1.1.4.1') is not None:
                    try: cpu_usage = float(res['1.3.6.1.4.1.41112.1.4.1.1.4.1'])
                    except ValueError: pass
                if res.get('1.3.6.1.4.1.41112.1.4.1.1.5.1') is not None:
                    try: memory_usage = float(res['1.3.6.1.4.1.41112.1.4.1.1.5.1'])
                    except ValueError: pass
                    
        # 4. Cisco
        elif is_cisco:
            res = self._get(ip, community, [
                '1.3.6.1.4.1.9.9.109.1.1.1.1.5.1', # CPU 1-min load %
                '1.3.6.1.4.1.9.9.48.1.1.1.5.1',    # Memory Used
                '1.3.6.1.4.1.9.9.48.1.1.1.6.1',    # Memory Free
                '1.3.6.1.4.1.9.9.13.1.3.1.3.1'     # Cisco Env Temp
            ], port=port, version=version)
            if res:
                if res.get('1.3.6.1.4.1.9.9.109.1.1.1.1.5.1') is not None:
                    try: cpu_usage = float(res['1.3.6.1.4.1.9.9.109.1.1.1.1.5.1'])
                    except ValueError: pass
                if res.get('1.3.6.1.4.1.9.9.48.1.1.1.5.1') is not None and res.get('1.3.6.1.4.1.9.9.48.1.1.1.6.1') is not None:
                    try:
                        used = float(res['1.3.6.1.4.1.9.9.48.1.1.1.5.1'])
                        free = float(res['1.3.6.1.4.1.9.9.48.1.1.1.6.1'])
                        if (used + free) > 0:
                            memory_usage = (used / (used + free)) * 100.0
                    except Exception: pass
                if res.get('1.3.6.1.4.1.9.9.13.1.3.1.3.1') is not None:
                    try: temperature = float(res['1.3.6.1.4.1.9.9.13.1.3.1.3.1'])
                    except ValueError: pass
                    
        # --- GENERIC FALLBACKS FOR ANY VENDOR IF STILL NONE ---
        if cpu_usage is None:
            cpu_walk = self._walk(ip, community, '1.3.6.1.2.1.25.3.3.1.2', port=port, version=version)
            if cpu_walk:
                cpu_vals = [float(v) for v in cpu_walk.values() if str(v).strip().isdigit()]
                if cpu_vals: cpu_usage = sum(cpu_vals) / len(cpu_vals)
            else:
                cpu_res = self._get(ip, community, ['1.3.6.1.2.1.25.3.3.1.2.1'], port=port, version=version)
                if cpu_res and cpu_res.get('1.3.6.1.2.1.25.3.3.1.2.1') is not None:
                    try: cpu_usage = float(cpu_res['1.3.6.1.2.1.25.3.3.1.2.1'])
                    except ValueError: pass
            
            # Try UCD-SNMP-MIB for Linux systems
            if cpu_usage is None:
                cpu_res = self._get(ip, community, [
                    '1.3.6.1.4.1.2021.11.9.0',
                    '1.3.6.1.4.1.2021.11.10.0'
                ], port=port, version=version)
                if cpu_res and cpu_res.get('1.3.6.1.4.1.2021.11.9.0') is not None:
                    try:
                        u = float(cpu_res.get('1.3.6.1.4.1.2021.11.9.0', 0))
                        s = float(cpu_res.get('1.3.6.1.4.1.2021.11.10.0', 0))
                        cpu_usage = u + s
                    except ValueError: pass
                    
        if memory_usage is None:
            # Try UCD-SNMP-MIB for Linux first (memTotalReal .5, memAvailReal .6)
            res_ucd = self._get(ip, community, [
                '1.3.6.1.4.1.2021.4.5.0',
                '1.3.6.1.4.1.2021.4.6.0'
            ], port=port, version=version)
            if res_ucd and res_ucd.get('1.3.6.1.4.1.2021.4.5.0') and res_ucd.get('1.3.6.1.4.1.2021.4.6.0'):
                try:
                    tot = float(res_ucd['1.3.6.1.4.1.2021.4.5.0'])
                    avail = float(res_ucd['1.3.6.1.4.1.2021.4.6.0'])
                    if tot > 0:
                        memory_usage = ((tot - avail) / tot) * 100.0
                except Exception: pass

            if memory_usage is None:
                storage_types = self._walk(ip, community, '1.3.6.1.2.1.25.2.3.1.2', port=port, version=version)
                ram_idx = None
                if storage_types:
                    for k, v in storage_types.items():
                        if v == '1.3.6.1.2.1.25.2.1.2': # Physical RAM type
                            ram_idx = k.split('.')[-1]
                            break
                if ram_idx:
                    res_ram = self._get(ip, community, [
                        f'1.3.6.1.2.1.25.2.3.1.5.{ram_idx}',
                        f'1.3.6.1.2.1.25.2.3.1.6.{ram_idx}'
                    ], port=port, version=version)
                    if res_ram:
                        try:
                            tot = float(res_ram.get(f'1.3.6.1.2.1.25.2.3.1.5.{ram_idx}', 0))
                            used = float(res_ram.get(f'1.3.6.1.2.1.25.2.3.1.6.{ram_idx}', 0))
                            if tot > 0:
                                memory_usage = (used / tot) * 100.0
                        except Exception: pass
                        
            if memory_usage is None:
                common_indices = ['65536', '1', '101', '102', '2', '3']
                oids_to_try = []
                for idx in common_indices:
                    oids_to_try.append(f'1.3.6.1.2.1.25.2.3.1.5.{idx}')
                    oids_to_try.append(f'1.3.6.1.2.1.25.2.3.1.6.{idx}')
                res_ram = self._get(ip, community, oids_to_try, port=port, version=version)
                if res_ram:
                    for idx in common_indices:
                        size_oid = f'1.3.6.1.2.1.25.2.3.1.5.{idx}'
                        used_oid = f'1.3.6.1.2.1.25.2.3.1.6.{idx}'
                        if res_ram.get(size_oid) and res_ram.get(used_oid):
                            try:
                                tot = float(res_ram[size_oid])
                                used = float(res_ram[used_oid])
                                if tot > 0 and used <= tot:
                                    memory_usage = (used / tot) * 100.0
                                    break
                            except Exception: pass
                            
        # Boundary validation & scaling normalization
        if cpu_usage is not None:
            if cpu_usage > 100.0: cpu_usage /= 10.0
            cpu_usage = max(0.0, min(100.0, cpu_usage))
            
        if memory_usage is not None:
            if memory_usage > 100.0: memory_usage /= 10.0
            memory_usage = max(0.0, min(100.0, memory_usage))
            
        if temperature is not None:
            if temperature > 150.0: temperature /= 10.0
            if temperature < -40.0 or temperature > 120.0:
                temperature = None
                
        return {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'temperature': temperature
        }

    def poll_device(self, device):
        self._prune_stale_caches()

        did, ip   = device['id'], device['ip']
        community = device.get('snmp_community', 'public') or 'public'
        try:
            port = int(device.get('snmp_port', 161) or 161)
        except Exception:
            port = 161
        version   = device.get('snmp_version', '2c') or '2c'
        old_st    = device.get('status', 'unknown')
        snmp_en   = bool(device.get('snmp_enabled', 0))
        now       = datetime.now().isoformat()
        dev_lock  = self._get_device_lock(did)

        # Target OIDs based on vendor detection
        vendor_lower = str(device.get('vendor') or '').lower()
        descr_lower = str(device.get('description') or '').lower()

        result = None
        if snmp_en:
            with dev_lock:
                result = self._get(ip, community, [
                    OID['sysDescr'],
                    '1.3.6.1.2.1.1.2.0', # sysObjectID
                    OID['sysUpTime'],
                    OID['sysName']
                ], port, version)

            # Jika offline (SNMP gagal), lakukan polling SNMP sekali lagi sebelum verifikasi ping
            if not result:
                time.sleep(1.0)
                with dev_lock:
                    result = self._get(ip, community, [
                        OID['sysDescr'],
                        '1.3.6.1.2.1.1.2.0',
                        OID['sysUpTime'],
                        OID['sysName']
                    ], port, version)

        if result:
            with self._state_lock:
                self._last_snmp_ok[did] = time.time()
            # ── SNMP responded: genuine UP with full data ──
            upd = {'status':'up', 'last_polled': now}
            if result.get(OID['sysName']):   upd['sys_name']    = result[OID['sysName']]
            
            sys_obj_id = str(result.get('1.3.6.1.2.1.1.2.0', '')).lower()
            if '14988' in sys_obj_id:
                upd['vendor'] = 'MikroTik'
            elif '4881' in sys_obj_id:
                upd['vendor'] = 'Ruijie'
            elif '41112' in sys_obj_id:
                upd['vendor'] = 'Ubiquiti'
            elif '9.1.' in sys_obj_id or '9.9.' in sys_obj_id or '.9.' in sys_obj_id:
                upd['vendor'] = 'Cisco'
                
            if result.get(OID['sysDescr']):  
                upd['description'] = result[OID['sysDescr']][:500]
                if not upd.get('vendor'):
                    desc_val = result[OID['sysDescr']].lower()
                    if 'ruijie' in desc_val or 'reyee' in desc_val:
                        upd['vendor'] = 'Ruijie'
                    elif 'mikrotik' in desc_val or 'routeros' in desc_val:
                        upd['vendor'] = 'MikroTik'
                    elif 'ubiquiti' in desc_val or 'ubnt' in desc_val or 'unifi' in desc_val:
                        upd['vendor'] = 'Ubiquiti'
                    elif 'cisco' in desc_val:
                        upd['vendor'] = 'Cisco'
            if result.get(OID['sysUpTime']): upd['uptime']      = result[OID['sysUpTime']]

            # Fetch updated vendor name
            current_vendor = upd.get('vendor') or device.get('vendor') or ''
            vendor_lower = str(current_vendor).lower()
            current_desc = upd.get('description') or device.get('description') or ''
            descr_lower = str(current_desc).lower()

            # Dynamic resource usage extraction & WAN traffic (serialized per device against traffic worker)
            with dev_lock:
                metrics = self._get_resource_metrics(ip, community, port, version, vendor_lower, descr_lower, result.get('1.3.6.1.2.1.1.2.0', ''))
            upd.update(metrics)

            # Telemetry: Measure ICMP Ping Latency & Packet Loss
            self._ping(ip)
            with self._state_lock:
                p_stat = dict(self._latest_ping.get(ip, {}))
            if p_stat.get('latency_ms') is not None:
                upd['latency_ms'] = p_stat['latency_ms']
            if p_stat.get('packet_loss') is not None:
                upd['packet_loss'] = p_stat['packet_loss']
            
            # Poll WAN traffic throughput outside DB write lock so SNMP I/O never stalls other writers
            traffic_data = None
            if device.get('type') == 'router':
                with dev_lock:
                    traffic_data = self._poll_router_traffic(device, ip, community, port, version)
                if traffic_data:
                    upd.update(traffic_data)

            metric_batch = []
            if metrics['cpu_usage'] is not None:
                metric_batch.append((did, 'cpu_usage', metrics['cpu_usage']))
            if metrics['memory_usage'] is not None:
                metric_batch.append((did, 'memory_usage', metrics['memory_usage']))
            if metrics['temperature'] is not None:
                metric_batch.append((did, 'temperature', metrics['temperature']))
            if upd.get('latency_ms') is not None:
                metric_batch.append((did, 'ping_latency', upd['latency_ms']))
            if upd.get('packet_loss') is not None:
                metric_batch.append((did, 'packet_loss', upd['packet_loss']))
            if traffic_data:
                metric_batch.append((did, 'wan_in', traffic_data['wan_in']))
                metric_batch.append((did, 'wan_out', traffic_data['wan_out']))
            if upd.get('uptime'):
                metric_batch.append((did, 'uptime', upd['uptime']))

            with self.db_write_lock:
                # Save all device timeseries metrics in one transaction
                if metric_batch:
                    self.db.save_metrics_batch(metric_batch)

                # Run live anomaly detection for traffic surges and sudden resource spikes
                self._analyze_metric_anomalies(device, metrics, traffic_data)

                new_uptime = upd.get('uptime')
                uptime_rebooted = self._detect_uptime_reboot(device, new_uptime)

                if old_st == 'down':
                    upd['last_seen'] = now
                    reboot_info = self._format_recovery_reboot_info(device, device.get('last_seen') or now, now, new_uptime, uptime_rebooted)
                    self._alert(device, 'info', f"{device.get('name',ip)} ({ip}) is back ONLINE{reboot_info}")
                    self.analyze_downtime_event(device, device.get('last_seen') or now, now, new_uptime)
                    self._pending_analysis.pop(ip, None)
                elif ip in self._pending_analysis:
                    down_time = self._pending_analysis.pop(ip)
                    self.analyze_downtime_event(device, down_time, now, new_uptime)
                elif old_st == 'unknown':
                    upd['last_seen'] = now
                elif uptime_rebooted:
                    self._handle_fast_reboot(device, now, new_uptime)

                with self._state_lock:
                    self._snmp_failing.discard(ip)
                    self._consecutive_snmp_fails[ip] = 0
                    self._consecutive_ping_fails[ip] = 0
                self.db.update_device(did, upd)

                try:
                    full_dev = self.db.get_device(did)
                    if full_dev:
                        self.socketio.emit('device_updated', full_dev)
                except Exception:
                    pass

        elif snmp_en:
            # ── SNMP enabled but SNMP FAILED: check ping, mark SNMP as broken ──
            is_alive = self._ping(ip)
            
            # Jika terdeteksi offline (ping gagal), lakukan prosedur verifikasi ganda sebelum alarm dilempar
            if not is_alive:
                print(f"[Verification] {ip} seems offline via SNMP and Ping. Retrying SNMP poll...")
                time.sleep(2.0)
                with dev_lock:
                    verify_snmp = self._get(ip, community, [OID['sysDescr'], '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.3.0'], port, version)
                if verify_snmp:
                    print(f"[Verification] SNMP responded on retry for {ip}. Keeping device UP.")
                    result = verify_snmp
                    upd = {'status': 'up', 'last_polled': now}
                    if verify_snmp.get('1.3.6.1.2.1.1.3.0'):
                        upd['uptime'] = verify_snmp['1.3.6.1.2.1.1.3.0']
                    new_uptime = upd.get('uptime')
                    uptime_rebooted = self._detect_uptime_reboot(device, new_uptime)
                    if old_st == 'down':
                        upd['last_seen'] = now
                        reboot_info = self._format_recovery_reboot_info(device, device.get('last_seen') or now, now, new_uptime, uptime_rebooted)
                        self._alert(device, 'info', f"{device.get('name',ip)} ({ip}) is back ONLINE{reboot_info}")
                        self.analyze_downtime_event(device, device.get('last_seen') or now, now, new_uptime)
                    elif uptime_rebooted and old_st != 'unknown':
                        self._handle_fast_reboot(device, now, new_uptime)
                    with self._state_lock:
                        self._snmp_failing.discard(ip)
                        self._consecutive_snmp_fails[ip] = 0
                        self._consecutive_ping_fails[ip] = 0
                    self.db.update_device(did, upd)
                    is_alive = True
                else:
                    # SNMP still offline, do robust ping procedure (3 retry pings)
                    print(f"[Verification] SNMP still offline on {ip}. Executing ping procedure...")
                    ping_ok = False
                    for attempt in range(3):
                        time.sleep(1.0)
                        if self._ping(ip):
                            ping_ok = True
                            break
                    if ping_ok:
                        print(f"[Verification] Ping procedure succeeded on attempt {attempt+1} for {ip}. Device is alive.")
                        is_alive = True
                    else:
                        print(f"[Verification] Ping procedure failed. {ip} unreachable on this poll cycle.")
                        is_alive = False

            if is_alive:
                # Device reachable via ping but SNMP is not responding (or revived above). Keep existing metrics.
                with self._state_lock:
                    self._consecutive_ping_fails[ip] = 0
                    p_stat = dict(self._latest_ping.get(ip, {}))
                with self.db_write_lock:
                    upd = {'status': 'up', 'last_polled': now}
                    if p_stat.get('latency_ms') is not None:
                        upd['latency_ms'] = p_stat['latency_ms']
                        self.db.save_metric(did, 'ping_latency', p_stat['latency_ms'])
                    if p_stat.get('packet_loss') is not None:
                        upd['packet_loss'] = p_stat['packet_loss']
                        self.db.save_metric(did, 'packet_loss', p_stat['packet_loss'])

                    if old_st == 'down':
                        upd['last_seen'] = now
                        self._alert(device, 'info', f"{device.get('name',ip)} ({ip}) is back ONLINE (ping only)")
                        self._pending_analysis[ip] = device.get('last_seen') or now
                    elif old_st == 'unknown':
                        upd['last_seen'] = now
                    # Only alert if SNMP was the one that actually failed (we didn't revive SNMP in verify block)
                    if not result:
                        fail_count = self._consecutive_snmp_fails.get(ip, 0) + 1
                        self._consecutive_snmp_fails[ip] = fail_count
                        if fail_count >= 2:
                            if ip not in self._snmp_failing:
                                self._alert(device, 'warning', f"SNMP unreachable on {device.get('name',ip)} ({ip}) — check community/config")
                                self._snmp_failing.add(ip)
                    else:
                        self._consecutive_snmp_fails[ip] = 0
                        self._snmp_failing.discard(ip)
                    print(f"[SNMP] FAILED for {ip} (consecutive: {self._consecutive_snmp_fails.get(ip, 0)}) — device alive via ping but SNMP not responding")
                    self.db.update_device(did, upd)
                    try:
                        full_dev = self.db.get_device(did)
                        if full_dev:
                            self.socketio.emit('device_updated', full_dev)
                    except Exception:
                        pass
            else:
                self._handle_unreachable_poll(device, did, ip, old_st, now, clear_snmp_metrics=True)

        else:
            # ── SNMP not enabled: ping-only check ──
            is_alive = self._ping(ip)
            if not is_alive:
                # Sebelum melempar notifikasi offline, lakukan polling SNMP ke perangkat
                print(f"[Verification Ping-Only] {ip} offline via ping. Polling SNMP...")
                with dev_lock:
                    snmp_check = self._get(ip, community, [OID['sysObjectID']], port, '2c')
                if snmp_check:
                    print(f"[Verification Ping-Only] {ip} responded to SNMP query. Mark as UP.")
                    is_alive = True
                else:
                    # Jika masih offline, lakukan prosedur ping ulang dengan 3 kali percobaan
                    print(f"[Verification Ping-Only] SNMP failed on {ip}. Executing ping procedure...")
                    ping_ok = False
                    for attempt in range(3):
                        time.sleep(1.0)
                        if self._ping(ip):
                            ping_ok = True
                            break
                    if ping_ok:
                        print(f"[Verification Ping-Only] Ping procedure succeeded on attempt {attempt+1} for {ip}.")
                        is_alive = True
                    else:
                        print(f"[Verification Ping-Only] Ping procedure failed. {ip} unreachable on this poll cycle.")
                        is_alive = False
                    
            if is_alive:
                with self._state_lock:
                    self._consecutive_ping_fails[ip] = 0
                    p_stat = dict(self._latest_ping.get(ip, {}))
                with self.db_write_lock:
                    upd = {'status': 'up', 'last_polled': now}
                    if p_stat.get('latency_ms') is not None:
                        upd['latency_ms'] = p_stat['latency_ms']
                        self.db.save_metric(did, 'ping_latency', p_stat['latency_ms'])
                    if p_stat.get('packet_loss') is not None:
                        upd['packet_loss'] = p_stat['packet_loss']
                        self.db.save_metric(did, 'packet_loss', p_stat['packet_loss'])

                    if old_st == 'down':
                        upd['last_seen'] = now
                        self._alert(device, 'info', f"{device.get('name',ip)} ({ip}) is back ONLINE")
                        self.analyze_downtime_event(device, device.get('last_seen') or now, now, None)
                    elif old_st == 'unknown':
                        upd['last_seen'] = now
                    self.db.update_device(did, upd)
                    try:
                        full_dev = self.db.get_device(did)
                        if full_dev:
                            self.socketio.emit('device_updated', full_dev)
                    except Exception:
                        pass
            else:
                self._handle_unreachable_poll(device, did, ip, old_st, now, clear_snmp_metrics=False)

        with self.db_write_lock:
            updated = self.db.get_device(did)
        if updated:
            self.socketio.emit('device_status_update', updated)
            self.socketio.emit('stats_update', self.db.get_dashboard_stats())
        return updated.get('status') if updated else 'unknown'

    def _handle_unreachable_poll(self, device, did, ip, old_st, now, clear_snmp_metrics=True):
        """Apply consecutive failure hysteresis (3 polls, or 5 during mass-outage bursts)
        plus recent-traffic SNMP liveness check before flipping an UP device to OFFLINE."""
        now_ts = time.time()
        with self._state_lock:
            last_snmp_ok = self._last_snmp_ok.get(did, 0.0)
            if old_st == 'up' and (now_ts - last_snmp_ok) <= 45.0:
                self._consecutive_ping_fails[ip] = 0
                recent_ok = True
            else:
                recent_ok = False
                fail_count = self._consecutive_ping_fails.get(ip, 0) + 1
                self._consecutive_ping_fails[ip] = fail_count
                self._recent_unreachable[did] = now_ts
                stale_unreach = [k for k, ts in self._recent_unreachable.items() if (now_ts - ts) > 90.0]
                for k in stale_unreach:
                    del self._recent_unreachable[k]
                concurrent_fails = len(self._recent_unreachable)

        if recent_ok:
            print(f"[Poll Guard] {device.get('name', ip)} ({ip}) had live SNMP traffic <45s ago — keeping UP")
            with self.db_write_lock:
                self.db.update_device(did, {'last_polled': now})
            return

        # Determine hysteresis threshold: 3 normal cycles, or 5 if >=50% of UP devices fail together
        threshold = 3
        if old_st == 'up':
            try:
                with self.db.conn() as c:
                    up_total = int(c.execute("SELECT COUNT(*) FROM devices WHERE status='up'").fetchone()[0])
                if up_total >= 4 and concurrent_fails >= max(3, int(up_total * 0.5)):
                    threshold = 5
                    print(f"[Mass-Outage Guard] {concurrent_fails}/{up_total} UP devices unreachable simultaneously — raising threshold to {fail_count}/{threshold} for {device.get('name', ip)} ({ip})")
            except Exception:
                pass

        # Hysteresis: keep UP until consecutive poll threshold is met
        if old_st == 'up' and fail_count < threshold:
            print(f"[Poll Hysteresis] {device.get('name', ip)} ({ip}) unreachable ({fail_count}/{threshold}) — keeping UP until confirmed")
            with self.db_write_lock:
                self.db.update_device(did, {'last_polled': now})
            return

        upd = {'status': 'down', 'last_polled': now, 'latency_ms': None, 'packet_loss': 100.0}
        if clear_snmp_metrics:
            upd.update({'cpu_usage': None, 'memory_usage': None, 'temperature': None})

        with self.db_write_lock:
            self._snmp_failing.discard(ip)
            self._pending_analysis.pop(ip, None)
            self.db.update_device(did, upd)
            self.db.save_metric(did, 'packet_loss', 100.0)
            try:
                full_dev = self.db.get_device(did)
                if full_dev:
                    self.socketio.emit('device_updated', full_dev)
            except Exception:
                pass
            if old_st != 'down':
                s = self.db.get_settings()
                if s.get('alert_on_down', 'true') == 'true':
                    self._alert(device, 'critical',
                                f"DEVICE DOWN: {device.get('name', ip)} ({ip}) — unreachable")

    def get_detailed_stats(self, device):
        ip = device['ip']
        community = device.get('snmp_community', 'public') or 'public'
        try:
            port = int(device.get('snmp_port', 161) or 161)
        except Exception:
            port = 161
        version = device.get('snmp_version', '2c') or '2c'
        cache_key = device['id']

        # Fast path: If the device is down or SNMP is disabled, do not poll OIDs.
        # Directly format and return cached interface and status info to avoid blocking threads.
        if device.get('status') == 'down' or not device.get('snmp_enabled'):
            cached = self._interfaces_cache.get(cache_key)
            interfaces = []
            if cached:
                if_desc = cached.get('if_desc', {})
                if_type = cached.get('if_type', {})
                if_speed = cached.get('if_speed', {})
                if_oper = cached.get('if_oper', {})
                if_hc_in = cached.get('if_hc_in', {})
                if_hc_out = cached.get('if_hc_out', {})
                if_in = cached.get('if_in', {})
                if_out = cached.get('if_out', {})
                if_high_speed = cached.get('if_high_speed', {})
                
                for oid, name in if_desc.items():
                    idx = oid.split('.')[-1]
                    t = if_type.get(f"1.3.6.1.2.1.2.2.1.3.{idx}", "6")
                    if t == '24': continue
                    name_lower = str(name).lower()
                    if 'loopback' in name_lower or name_lower in ('lo','lo0'): continue
                    
                    status_val = if_oper.get(f"1.3.6.1.2.1.2.2.1.8.{idx}", "4")
                    status = 'up' if str(status_val) == '1' else 'down'
                    
                    speed_bps = 0
                    if f"1.3.6.1.31.1.1.1.15.{idx}" in if_high_speed:
                        try: speed_bps = float(if_high_speed[f"1.3.6.1.31.1.1.1.15.{idx}"]) * 1000000
                        except ValueError: pass
                    if speed_bps == 0 and f"1.3.6.1.2.1.31.1.1.1.15.{idx}" in if_high_speed:
                        try: speed_bps = float(if_high_speed[f"1.3.6.1.2.1.31.1.1.1.15.{idx}"]) * 1000000
                        except ValueError: pass
                    if speed_bps == 0:
                        try: speed_bps = float(if_speed.get(f"1.3.6.1.2.1.2.2.1.5.{idx}", 0))
                        except ValueError: pass
                    
                    rx_bytes = 0
                    tx_bytes = 0
                    hc_in_val = if_hc_in.get(f"1.3.6.1.2.1.31.1.1.1.6.{idx}") or if_hc_in.get(f"1.3.6.1.31.1.1.1.6.{idx}")
                    hc_out_val = if_hc_out.get(f"1.3.6.1.2.1.31.1.1.1.10.{idx}") or if_hc_out.get(f"1.3.6.1.31.1.1.1.10.{idx}")
                    
                    if hc_in_val is not None:
                        try: rx_bytes = int(hc_in_val)
                        except ValueError: pass
                    else:
                        try: rx_bytes = int(if_in.get(f"1.3.6.1.2.1.2.2.1.10.{idx}", 0))
                        except ValueError: pass
                    if hc_out_val is not None:
                        try: tx_bytes = int(hc_out_val)
                        except ValueError: pass
                    else:
                        try: tx_bytes = int(if_out.get(f"1.3.6.1.2.1.2.2.1.16.{idx}", 0))
                        except ValueError: pass
                        
                    interfaces.append({
                        'index': int(idx),
                        'name': str(name),
                        'status': status,
                        'speed': speed_bps,
                        'rx_bytes': rx_bytes,
                        'tx_bytes': tx_bytes
                    })
                interfaces.sort(key=lambda x: x['index'])

            return {
                'uptime': device.get('uptime'),
                'sys_name': device.get('sys_name') or device.get('name'),
                'description': device.get('description') or 'Device offline',
                'cpu_usage': device.get('cpu_usage'),
                'memory_usage': device.get('memory_usage'),
                'temperature': device.get('temperature'),
                'interfaces': interfaces
            }

        # 1. Fetch system details
        res_sys = self._get(ip, community, [
            '1.3.6.1.2.1.1.1.0', # sysDescr
            '1.3.6.1.2.1.1.2.0', # sysObjectID
            '1.3.6.1.2.1.1.3.0', # sysUpTime
            '1.3.6.1.2.1.1.5.0', # sysName
        ], port=port, version=version)
        
        if not res_sys:
            # SNMP not responding. Return cached status/interfaces instead of trying walks
            cached = self._interfaces_cache.get(cache_key)
            interfaces = []
            if cached:
                if_desc = cached.get('if_desc', {})
                if_type = cached.get('if_type', {})
                if_speed = cached.get('if_speed', {})
                if_oper = cached.get('if_oper', {})
                if_hc_in = cached.get('if_hc_in', {})
                if_hc_out = cached.get('if_hc_out', {})
                if_in = cached.get('if_in', {})
                if_out = cached.get('if_out', {})
                if_high_speed = cached.get('if_high_speed', {})
                
                for oid, name in if_desc.items():
                    idx = oid.split('.')[-1]
                    t = if_type.get(f"1.3.6.1.2.1.2.2.1.3.{idx}", "6")
                    if t == '24': continue
                    name_lower = str(name).lower()
                    if 'loopback' in name_lower or name_lower in ('lo','lo0'): continue
                    
                    status_val = if_oper.get(f"1.3.6.1.2.1.2.2.1.8.{idx}", "4")
                    status = 'up' if str(status_val) == '1' else 'down'
                    
                    speed_bps = 0
                    if f"1.3.6.1.31.1.1.1.15.{idx}" in if_high_speed:
                        try: speed_bps = float(if_high_speed[f"1.3.6.1.31.1.1.1.15.{idx}"]) * 1000000
                        except ValueError: pass
                    if speed_bps == 0 and f"1.3.6.1.2.1.31.1.1.1.15.{idx}" in if_high_speed:
                        try: speed_bps = float(if_high_speed[f"1.3.6.1.2.1.31.1.1.1.15.{idx}"]) * 1000000
                        except ValueError: pass
                    if speed_bps == 0:
                        try: speed_bps = float(if_speed.get(f"1.3.6.1.2.1.2.2.1.5.{idx}", 0))
                        except ValueError: pass
                    
                    rx_bytes = 0
                    tx_bytes = 0
                    hc_in_val = if_hc_in.get(f"1.3.6.1.2.1.31.1.1.1.6.{idx}") or if_hc_in.get(f"1.3.6.1.31.1.1.1.6.{idx}")
                    hc_out_val = if_hc_out.get(f"1.3.6.1.2.1.31.1.1.1.10.{idx}") or if_hc_out.get(f"1.3.6.1.31.1.1.1.10.{idx}")
                    
                    if hc_in_val is not None:
                        try: rx_bytes = int(hc_in_val)
                        except ValueError: pass
                    else:
                        try: rx_bytes = int(if_in.get(f"1.3.6.1.2.1.2.2.1.10.{idx}", 0))
                        except ValueError: pass
                    if hc_out_val is not None:
                        try: tx_bytes = int(hc_out_val)
                        except ValueError: pass
                    else:
                        try: tx_bytes = int(if_out.get(f"1.3.6.1.2.1.2.2.1.16.{idx}", 0))
                        except ValueError: pass
                        
                    interfaces.append({
                        'index': int(idx),
                        'name': str(name),
                        'status': status,
                        'speed': speed_bps,
                        'rx_bytes': rx_bytes,
                        'tx_bytes': tx_bytes
                    })
                interfaces.sort(key=lambda x: x['index'])

            return {
                'uptime': device.get('uptime'),
                'sys_name': device.get('sys_name') or device.get('name'),
                'description': device.get('description') or 'SNMP request timeout',
                'cpu_usage': device.get('cpu_usage'),
                'memory_usage': device.get('memory_usage'),
                'temperature': device.get('temperature'),
                'interfaces': interfaces
            }
        
        sys_obj_id = ""
        uptime = ""
        sys_name = ""
        description = ""
        if res_sys:
            uptime = res_sys.get('1.3.6.1.2.1.1.3.0', '')
            sys_name = res_sys.get('1.3.6.1.2.1.1.5.0', '')
            description = res_sys.get('1.3.6.1.2.1.1.1.0', '')
            sys_obj_id = res_sys.get('1.3.6.1.2.1.1.2.0', '')

        # 2. CPU / Memory / Temp based on unified parser
        vendor_lower = str(device.get('vendor') or '').lower()
        descr_lower = str(description or device.get('description') or '').lower()
        
        metrics = self._get_resource_metrics(ip, community, port, version, vendor_lower, descr_lower, sys_obj_id)
        cpu_usage = metrics['cpu_usage']
        memory_usage = metrics['memory_usage']
        temperature = metrics['temperature']

        # 3. Interfaces info (Parallel SNMP Walks) with cache fallback
        new_desc, new_type, new_speed, new_oper = {}, {}, {}, {}
        new_hc_in, new_hc_out, new_in, new_out, new_high_speed = {}, {}, {}, {}, {}
        new_in_err, new_out_err, new_in_disc, new_out_disc = {}, {}, {}, {}
        
        try:
            async def fetch_all_walks():
                tasks = [
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.2', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.3', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.5', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.8', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.6', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.10', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.10', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.16', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.15', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.14', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.20', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.13', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.19', port, version, timeout=1.5)
                ]
                return await asyncio.gather(*tasks, return_exceptions=True)
                
            results = asyncio.run(fetch_all_walks())
            if results and len(results) >= 9:
                def clean_res(val):
                    return val if isinstance(val, dict) else {}
                new_desc = clean_res(results[0])
                new_type = clean_res(results[1])
                new_speed = clean_res(results[2])
                new_oper = clean_res(results[3])
                new_hc_in = clean_res(results[4])
                new_hc_out = clean_res(results[5])
                new_in = clean_res(results[6])
                new_out = clean_res(results[7])
                new_high_speed = clean_res(results[8])
                if len(results) >= 13:
                    new_in_err = clean_res(results[9])
                    new_out_err = clean_res(results[10])
                    new_in_disc = clean_res(results[11])
                    new_out_disc = clean_res(results[12])
        except Exception as e:
            print(f"[SNMP Detail] Parallel walks failed: {e}")

        cached = self._interfaces_cache.get(cache_key)
        
        # Prevent partial-read cache poisoning (e.g. if device rate limits after 1 min and returns only Loopback)
        # We only consider the new walk valid if it has at least 80% of the interfaces we saw before.
        is_valid = False
        if new_desc:
            if not cached:
                is_valid = True
            else:
                cache_age = time.time() - cached.get('_ts', 0)
                if len(new_desc) >= len(cached['if_desc']):
                    is_valid = True          # sama atau lebih banyak → selalu valid
                elif cache_age > 300:
                    is_valid = True          # cache stale >5 menit → izinkan refresh
                # else: lebih sedikit DAN cache masih fresh → rate-limited, tolak

        if is_valid:
            # Cache the successful SNMP walk, merging new values with cached values
            self._interfaces_cache[cache_key] = {
                '_ts': time.time(),
                'if_desc': {**cached['if_desc'], **new_desc} if (cached and new_desc) else (new_desc or {}),
                'if_type': {**cached['if_type'], **new_type} if (cached and new_type) else (new_type or {}),
                'if_speed': {**cached['if_speed'], **new_speed} if (cached and new_speed) else (new_speed or {}),
                'if_oper': {**cached['if_oper'], **new_oper} if (cached and new_oper) else (new_oper or {}),
                'if_hc_in': {**cached['if_hc_in'], **new_hc_in} if (cached and new_hc_in) else (new_hc_in or {}),
                'if_hc_out': {**cached['if_hc_out'], **new_hc_out} if (cached and new_hc_out) else (new_hc_out or {}),
                'if_in': {**cached['if_in'], **new_in} if (cached and new_in) else (new_in or {}),
                'if_out': {**cached['if_out'], **new_out} if (cached and new_out) else (new_out or {}),
                'if_high_speed': {**cached['if_high_speed'], **new_high_speed} if (cached and new_high_speed) else (new_high_speed or {})
            }
            if_desc = self._interfaces_cache[cache_key]['if_desc']
            if_type = self._interfaces_cache[cache_key]['if_type']
            if_speed = self._interfaces_cache[cache_key]['if_speed']
            if_oper = self._interfaces_cache[cache_key]['if_oper']
            if_hc_in = self._interfaces_cache[cache_key]['if_hc_in']
            if_hc_out = self._interfaces_cache[cache_key]['if_hc_out']
            if_in = self._interfaces_cache[cache_key]['if_in']
            if_out = self._interfaces_cache[cache_key]['if_out']
            if_high_speed = self._interfaces_cache[cache_key]['if_high_speed']
        else:
            # Momentary walk failure or partial read: use cache merged with any partial new results
            cached = self._interfaces_cache.get(cache_key)
            if cached:
                if_desc = {**cached['if_desc'], **new_desc} if new_desc else cached['if_desc']
                if_type = {**cached['if_type'], **new_type} if new_type else cached['if_type']
                if_speed = {**cached['if_speed'], **new_speed} if new_speed else cached['if_speed']
                if_oper = {**cached['if_oper'], **new_oper} if new_oper else cached['if_oper']
                if_hc_in = {**cached['if_hc_in'], **new_hc_in} if new_hc_in else cached['if_hc_in']
                if_hc_out = {**cached['if_hc_out'], **new_hc_out} if new_hc_out else cached['if_hc_out']
                if_in = {**cached['if_in'], **new_in} if new_in else cached['if_in']
                if_out = {**cached['if_out'], **new_out} if new_out else cached['if_out']
                if_high_speed = {**cached['if_high_speed'], **new_high_speed} if new_high_speed else cached['if_high_speed']
            else:
                if_desc, if_type, if_speed, if_oper = {}, {}, {}, {}
                if_hc_in, if_hc_out, if_in, if_out, if_high_speed = {}, {}, {}, {}, {}

        interfaces = []
        for oid, name in if_desc.items():
            idx = oid.split('.')[-1]
            t = if_type.get(f"1.3.6.1.2.1.2.2.1.3.{idx}", "6")
            
            if t == '24': continue
            name_lower = str(name).lower()
            if 'loopback' in name_lower or name_lower in ('lo','lo0'): continue
            
            status_val = if_oper.get(f"1.3.6.1.2.1.2.2.1.8.{idx}", "4")
            status = 'up' if str(status_val) == '1' else 'down'
            
            speed_bps = 0
            if f"1.3.6.1.31.1.1.1.15.{idx}" in if_high_speed:
                try:
                    speed_bps = float(if_high_speed[f"1.3.6.1.31.1.1.1.15.{idx}"]) * 1000000
                except ValueError:
                    pass
            
            if speed_bps == 0 and f"1.3.6.1.2.1.31.1.1.1.15.{idx}" in if_high_speed:
                try:
                    speed_bps = float(if_high_speed[f"1.3.6.1.2.1.31.1.1.1.15.{idx}"]) * 1000000
                except ValueError:
                    pass

            if speed_bps == 0:
                try:
                    speed_bps = float(if_speed.get(f"1.3.6.1.2.1.2.2.1.5.{idx}", 0))
                except ValueError:
                    pass
            
            rx_bytes = 0
            tx_bytes = 0
            
            hc_in_val = if_hc_in.get(f"1.3.6.1.2.1.31.1.1.1.6.{idx}") or if_hc_in.get(f"1.3.6.1.31.1.1.1.6.{idx}")
            hc_out_val = if_hc_out.get(f"1.3.6.1.2.1.31.1.1.1.10.{idx}") or if_hc_out.get(f"1.3.6.1.31.1.1.1.10.{idx}")
            
            if hc_in_val is not None:
                try: rx_bytes = int(hc_in_val)
                except ValueError: pass
            else:
                try: rx_bytes = int(if_in.get(f"1.3.6.1.2.1.2.2.1.10.{idx}", 0))
                except ValueError: pass
                
            if hc_out_val is not None:
                try: tx_bytes = int(hc_out_val)
                except ValueError: pass
            else:
                try: tx_bytes = int(if_out.get(f"1.3.6.1.2.1.2.2.1.16.{idx}", 0))
                except ValueError: pass

            try: in_err = int(new_in_err.get(f"1.3.6.1.2.1.2.2.1.14.{idx}", 0))
            except ValueError: in_err = 0
            try: out_err = int(new_out_err.get(f"1.3.6.1.2.1.2.2.1.20.{idx}", 0))
            except ValueError: out_err = 0
            try: in_disc = int(new_in_disc.get(f"1.3.6.1.2.1.2.2.1.13.{idx}", 0))
            except ValueError: in_disc = 0
            try: out_disc = int(new_out_disc.get(f"1.3.6.1.2.1.2.2.1.19.{idx}", 0))
            except ValueError: out_disc = 0

            interfaces.append({
                'index': int(idx),
                'name': str(name),
                'status': status,
                'speed': speed_bps,
                'rx_bytes': rx_bytes,
                'tx_bytes': tx_bytes,
                'in_errors': in_err,
                'out_errors': out_err,
                'in_discards': in_disc,
                'out_discards': out_disc
            })
            
        interfaces.sort(key=lambda x: x['index'])
        
        return {
            'uptime': uptime,
            'sys_name': sys_name,
            'description': description,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'temperature': temperature,
            'interfaces': interfaces
        }

    def collect_interface_traffic(self, device):
        """Walk ifHCInOctets/ifHCOutOctets, hitung bps dari delta, simpan ke DB."""
        if not SNMP_OK:
            return
        did       = device['id']
        # Fetch latest device status from DB to avoid polling offline/disabled devices
        latest = self.db.get_device(did)
        if not latest or latest.get('status') == 'down' or not latest.get('snmp_enabled'):
            return
        ip        = device.get('ip', '')
        community = device.get('snmp_community', 'public') or 'public'
        try:
            port = int(device.get('snmp_port', 161) or 161)
        except Exception:
            port = 161
        version   = device.get('snmp_version', '2c') or '2c'

        now_ts = time.time()
        with self._state_lock:
            meta_entry = self._if_meta_cache.get(did)
        need_meta = not meta_entry or (now_ts - meta_entry.get('ts', 0)) >= 300
        cached_64 = True if need_meta else meta_entry.get('is_64bit', True)

        async def _fetch_traffic_walks():
            if need_meta:
                return await asyncio.gather(
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.2', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.15', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.5', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.6', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.10', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.14', port, version, timeout=1.5),
                    self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.20', port, version, timeout=1.5),
                    return_exceptions=True
                )
            in_oid = '1.3.6.1.2.1.31.1.1.1.6' if cached_64 else '1.3.6.1.2.1.2.2.1.10'
            out_oid = '1.3.6.1.2.1.31.1.1.1.10' if cached_64 else '1.3.6.1.2.1.2.2.1.16'
            return await asyncio.gather(
                self._async_walk(ip, community, in_oid, port, version, timeout=1.5),
                self._async_walk(ip, community, out_oid, port, version, timeout=1.5),
                self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.14', port, version, timeout=1.5),
                self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.20', port, version, timeout=1.5),
                return_exceptions=True
            )

        def _ok_dict(val):
            return val if isinstance(val, dict) else {}

        dev_lock = self._get_device_lock(did)
        try:
            with dev_lock:
                walk_res = asyncio.run(_fetch_traffic_walks())
        except Exception:
            return

        if need_meta:
            if_desc = _ok_dict(walk_res[0])
            if not if_desc:
                return
            if_high_speed = _ok_dict(walk_res[1])
            if_speed = _ok_dict(walk_res[2])
            hc_in = _ok_dict(walk_res[3])
            hc_out = _ok_dict(walk_res[4])
            if_in_err = _ok_dict(walk_res[5])
            if_out_err = _ok_dict(walk_res[6])
            is_64bit = True
            if not hc_in:
                async def _fetch_32bit():
                    return await asyncio.gather(
                        self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.10', port, version, timeout=1.5),
                        self._async_walk(ip, community, '1.3.6.1.2.1.2.2.1.16', port, version, timeout=1.5),
                        return_exceptions=True
                    )
                try:
                    with dev_lock:
                        fb_res = asyncio.run(_fetch_32bit())
                    hc_in = _ok_dict(fb_res[0])
                    hc_out = _ok_dict(fb_res[1])
                except Exception:
                    hc_in, hc_out = {}, {}
                if not hc_in:
                    return
                is_64bit = False
            with self._state_lock:
                self._if_meta_cache[did] = {
                    'ts': now_ts,
                    'if_desc': if_desc,
                    'if_high_speed': if_high_speed,
                    'if_speed': if_speed,
                    'is_64bit': is_64bit,
                }
        else:
            if_desc = meta_entry['if_desc']
            if not if_desc:
                return
            if_high_speed = meta_entry['if_high_speed']
            if_speed = meta_entry['if_speed']
            hc_in = _ok_dict(walk_res[0])
            hc_out = _ok_dict(walk_res[1])
            if_in_err = _ok_dict(walk_res[2])
            if_out_err = _ok_dict(walk_res[3])
            is_64bit = cached_64
            # Skip false 32-bit fallback when cached 64-bit device goes RTO/unreachable
            if not hc_in:
                return

        now_ts = time.time()
        with self._state_lock:
            self._last_snmp_ok[did] = now_ts
        settings = self.db.get_settings()
        traffic_interval = max(5, int(settings.get('traffic_poll_interval', 15)))
        logged_gap = False
        traffic_batch = []

        for oid, name in if_desc.items():
            idx = oid.split('.')[-1]
            if str(name).lower() in ('lo', 'lo0') or 'loopback' in str(name).lower():
                continue

            # Cacti Interface Error Rate Tracking
            try:
                cur_in_err = int(if_in_err.get(f'1.3.6.1.2.1.2.2.1.14.{idx}', 0) or 0)
                cur_out_err = int(if_out_err.get(f'1.3.6.1.2.1.2.2.1.20.{idx}', 0) or 0)
                cur_tot_err = cur_in_err + cur_out_err
                err_key = (did, idx)
                prev_err = self._iface_err_prev.get(err_key)
                self._iface_err_prev[err_key] = cur_tot_err
                if prev_err is not None and cur_tot_err > prev_err:
                    d_err = cur_tot_err - prev_err
                    if d_err >= 50:
                        last_e_ts = self._last_iface_alert.get(('err', did, idx), 0)
                        if now_ts - last_e_ts >= 900:
                            self._last_iface_alert[('err', did, idx)] = now_ts
                            self._alert(
                                latest or device, 'warning',
                                f"INTERFACE ERROR: Port {name} pada {(latest or device).get('name', ip)} ({ip}) "
                                f"mengalami +{d_err} packet errors (IN:{cur_in_err}/OUT:{cur_out_err}). Cek kabel/SFP!"
                            )
            except Exception:
                pass
            rx = next((int(v) for k in [
                f'1.3.6.1.2.1.31.1.1.1.6.{idx}', f'1.3.6.1.31.1.1.1.6.{idx}',
                f'1.3.6.1.2.1.2.2.1.10.{idx}']
                if (v := (hc_in or {}).get(k)) is not None), None)
            tx = next((int(v) for k in [
                f'1.3.6.1.2.1.31.1.1.1.10.{idx}', f'1.3.6.1.31.1.1.1.10.{idx}',
                f'1.3.6.1.2.1.2.2.1.16.{idx}']
                if (v := (hc_out or {}).get(k)) is not None), None)
            if rx is None or tx is None:
                continue
            key = (did, idx)
            with self._state_lock:
                prev = self._if_prev.get(key)
                self._if_prev[key] = {'rx': rx, 'tx': tx, 'ts': now_ts, 'is_64bit': is_64bit}
            if prev:
                if prev.get('is_64bit') != is_64bit:
                    continue
                dt = now_ts - prev['ts']
                if dt <= 0:
                    continue
                if dt > 3 * traffic_interval and not logged_gap:
                    print(f"[Traffic] Gap polling terdeteksi device_id={did} dt={dt:.1f}s (expected ~{traffic_interval}s)")
                    logged_gap = True
                d_rx = rx - prev['rx']
                d_tx = tx - prev['tx']
                
                # Get link capacity
                speed_bps = 0
                if if_high_speed:
                    h_speed = if_high_speed.get(f"1.3.6.1.2.1.31.1.1.1.15.{idx}") or if_high_speed.get(f"1.3.6.1.31.1.1.1.15.{idx}")
                    if h_speed is not None:
                        try:
                            speed_bps = float(h_speed) * 1e6
                        except ValueError:
                            pass
                if speed_bps == 0 and if_speed:
                    l_speed = if_speed.get(f"1.3.6.1.2.1.2.2.1.5.{idx}")
                    if l_speed is not None:
                        try:
                            speed_bps = float(l_speed)
                        except ValueError:
                            pass
                
                uplink_bps_fallback = float((latest or device).get('uplink_speed_mbps') or 1000) * 1e6
                effective_if_speed = speed_bps if speed_bps > 0 else uplink_bps_fallback
                if (latest or device).get('wan_iface_idx') and str((latest or device).get('wan_iface_idx')) == str(idx):
                    effective_if_speed = min(effective_if_speed, uplink_bps_fallback)

                limit_bps = self._anomaly_limit_bps(effective_if_speed)

                # Rollover / Reboot protection for 32-bit counters
                if d_rx < 0:
                    if is_64bit:
                        d_rx = 0
                    else:
                        is_short_dt = dt < (2 * traffic_interval)
                        is_large_negative_delta = (prev['rx'] - rx) > 2**31
                        if is_short_dt and is_large_negative_delta:
                            # Rollover asli: counter 32-bit habis
                            d_rx += 2**32
                        else:
                            # Reboot device atau gap: reset ke 0
                            d_rx = 0
                            
                if d_tx < 0:
                    if is_64bit:
                        d_tx = 0
                    else:
                        is_short_dt = dt < (2 * traffic_interval)
                        is_large_negative_delta = (prev['tx'] - tx) > 2**31
                        if is_short_dt and is_large_negative_delta:
                            d_tx += 2**32
                        else:
                            d_tx = 0
                            
                rx_bps = (d_rx * 8) / dt
                tx_bps = (d_tx * 8) / dt
                
                if rx_bps > limit_bps:
                    cap_mbps = (limit_bps / 1e6) if limit_bps > 0 else 100000.0
                    print(f"[Traffic] Spike terdeteksi pada device_id={did} interface={name} (rx_bps={rx_bps:.1f} melebihi limit {cap_mbps:.1f} Mbps) - reset to 0")
                    rx_bps = 0.0
                    if hasattr(self, '_if_prev') and (did, str(idx)) in self._if_prev:
                        self._if_prev[(did, str(idx))] = None

                if tx_bps > limit_bps:
                    cap_mbps = (limit_bps / 1e6) if limit_bps > 0 else 100000.0
                    print(f"[Traffic] Spike terdeteksi pada device_id={did} interface={name} (tx_bps={tx_bps:.1f} melebihi limit {cap_mbps:.1f} Mbps) - reset to 0")
                    tx_bps = 0.0
                    if hasattr(self, '_if_prev') and (did, str(idx)) in self._if_prev:
                        self._if_prev[(did, str(idx))] = None
                
                traffic_batch.append((did, str(name), int(idx), rx_bps, tx_bps))

        if traffic_batch:
            with self.db_write_lock:
                self.db.save_interface_traffic_batch(traffic_batch)

    def capture_live_traffic(self, device, sample_seconds=3):
        """Ambil 2 sampel SNMP berjarak sample_seconds detik dan kembalikan delta traffic instan per-interface."""
        if not SNMP_OK:
            return None, "Modul SNMP (puresnmp) tidak aktif atau belum terpasang."
        ip = device.get('ip', '')
        community = device.get('snmp_community', 'public') or 'public'
        try:
            port = int(device.get('snmp_port', 161) or 161)
        except Exception:
            port = 161
        version = device.get('snmp_version', '2c') or '2c'

        if_desc = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.2', port, version, timeout=2)
        if not if_desc:
            return None, f"SNMP ke {ip} unreachable atau tidak merespons (cek community/port)."

        # Cek apakah device mendukung 64-bit HC counter
        hc_in_1 = self._walk(ip, community, '1.3.6.1.2.1.31.1.1.1.6', port, version, timeout=2)
        hc_out_1 = self._walk(ip, community, '1.3.6.1.2.1.31.1.1.1.10', port, version, timeout=2)
        is_64bit = True
        if not hc_in_1:
            hc_in_1 = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.10', port, version, timeout=2)
            hc_out_1 = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.16', port, version, timeout=2)
            is_64bit = False

        t1 = time.time()
        time.sleep(max(1, int(sample_seconds)))

        if is_64bit:
            hc_in_2 = self._walk(ip, community, '1.3.6.1.2.1.31.1.1.1.6', port, version, timeout=2)
            hc_out_2 = self._walk(ip, community, '1.3.6.1.2.1.31.1.1.1.10', port, version, timeout=2)
        else:
            hc_in_2 = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.10', port, version, timeout=2)
            hc_out_2 = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.16', port, version, timeout=2)

        t2 = time.time()
        dt = max(0.1, t2 - t1)

        results = []
        for oid, name in if_desc.items():
            idx = oid.split('.')[-1]
            name_str = str(name).strip()
            if name_str.lower() in ('lo', 'lo0') or 'loopback' in name_str.lower():
                continue

            rx1 = next((int(v) for k in [f'1.3.6.1.2.1.31.1.1.1.6.{idx}', f'1.3.6.1.31.1.1.1.6.{idx}', f'1.3.6.1.2.1.2.2.1.10.{idx}'] if (v := (hc_in_1 or {}).get(k)) is not None), None)
            tx1 = next((int(v) for k in [f'1.3.6.1.2.1.31.1.1.1.10.{idx}', f'1.3.6.1.31.1.1.1.10.{idx}', f'1.3.6.1.2.1.2.2.1.16.{idx}'] if (v := (hc_out_1 or {}).get(k)) is not None), None)
            rx2 = next((int(v) for k in [f'1.3.6.1.2.1.31.1.1.1.6.{idx}', f'1.3.6.1.31.1.1.1.6.{idx}', f'1.3.6.1.2.1.2.2.1.10.{idx}'] if (v := (hc_in_2 or {}).get(k)) is not None), None)
            tx2 = next((int(v) for k in [f'1.3.6.1.2.1.31.1.1.1.10.{idx}', f'1.3.6.1.31.1.1.1.10.{idx}', f'1.3.6.1.2.1.2.2.1.16.{idx}'] if (v := (hc_out_2 or {}).get(k)) is not None), None)

            if rx1 is None or rx2 is None or tx1 is None or tx2 is None:
                continue

            delta_rx = rx2 - rx1
            delta_tx = tx2 - tx1
            if delta_rx < 0:
                delta_rx += (2**64 if is_64bit else 2**32)
            if delta_tx < 0:
                delta_tx += (2**64 if is_64bit else 2**32)

            rx_bps = (delta_rx * 8.0) / dt
            tx_bps = (delta_tx * 8.0) / dt

            results.append({
                'name': name_str,
                'idx': idx,
                'rx_bps': rx_bps,
                'tx_bps': tx_bps,
                'total_bps': rx_bps + tx_bps
            })

        results.sort(key=lambda x: x['total_bps'], reverse=True)
        return results, None

    def _poll_router_traffic(self, device, ip, community, port, version):
        did = device['id']
        # 1. Walk ifDescr and ifOperStatus to find the best WAN interface
        if_desc = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.2', port, version)
        if_st = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.8', port, version)
        
        target_idx = None
        
        # Check if manual WAN interface index is configured and exists
        configured_idx = device.get('wan_iface_idx', '')
        if configured_idx:
            oid_key = f"1.3.6.1.2.1.2.2.1.2.{configured_idx}"
            if if_desc and oid_key in if_desc:
                target_idx = str(configured_idx)
                
        if not target_idx:
            # Look for active interface (OperStatus 1 = UP) with WAN/ether1/sfp/eth0/pppoe description
            for oid, desc in if_desc.items():
                idx = oid.split('.')[-1]
                status = str(if_st.get(f"1.3.6.1.2.1.2.2.1.8.{idx}", ""))
                if status == '1':
                    desc_lower = str(desc).lower()
                    if 'wan' in desc_lower or 'pppoe' in desc_lower or desc_lower in ('ether1', 'sfpplus1', 'sfp1', 'eth0', 'ge0/0'):
                        target_idx = idx
                        break
            
            # Fallback to first active non-loopback interface if no 'wan' named interface is found
            if not target_idx:
                for oid, status in if_st.items():
                    if str(status) == '1':
                        idx = oid.split('.')[-1]
                        desc = if_desc.get(f"1.3.6.1.2.1.2.2.1.2.{idx}", "")
                        desc_lower = str(desc).lower()
                        if 'loopback' not in desc_lower and desc_lower not in ('lo', 'lo0'):
                            target_idx = idx
                            break
                        
        if not target_idx:
            return None
            
        # 2. Query traffic and link capacity (ifHighSpeed/ifSpeed) in a single request
        traffic = self._get(ip, community, [
            f"1.3.6.1.2.1.31.1.1.1.6.{target_idx}",  # ifHCInOctets
            f"1.3.6.1.2.1.31.1.1.1.10.{target_idx}", # ifHCOutOctets
            f"1.3.6.1.2.1.2.2.1.10.{target_idx}",    # ifInOctets
            f"1.3.6.1.2.1.2.2.1.16.{target_idx}",    # ifOutOctets
            f"1.3.6.1.2.1.31.1.1.1.15.{target_idx}", # ifHighSpeed
            f"1.3.6.1.2.1.2.2.1.5.{target_idx}"      # ifSpeed
        ], port, version)
        
        if not traffic:
            return None

        # 3. Auto-detect physical interface uplink speed (cached, reusing existing walk)
        try:
            should_detect_speed = (did not in self._speed_detected) or (time.time() - self._speed_detected.get(did, 0) > 3600) or (not device.get('uplink_speed_mbps'))
            if should_detect_speed and if_desc and if_st:
                self._speed_detected[did] = time.time()
                if_high_speeds = self._walk(ip, community, '1.3.6.1.2.1.31.1.1.1.15', port, version) # ifHighSpeed (Mbps)
                if_low_speeds = self._walk(ip, community, '1.3.6.1.2.1.2.2.1.5', port, version)     # ifSpeed (bps)
                
                max_detected_speed = 0
                for oid, name in if_desc.items():
                    idx = oid.split('.')[-1]
                    status = str(if_st.get(f"1.3.6.1.2.1.2.2.1.8.{idx}", ""))
                    if status == '1': # Hanya interface aktif (OperStatus UP)
                        name_lower = str(name).lower()
                        
                        # Kecualikan port virtual/tunnel/loopback/bridge yang melaporkan kecepatan palsu
                        if any(x in name_lower for x in ('loopback', 'lo0', 'lo ', 'bridge', 'br-', 'tunnel', 'tun', 'tap', 'gre', 'l2tp', 'ovpn', 'sstp', 'wg', 'vlan', 'docker', 'pppoe')):
                            continue
                            
                        # Dapatkan kecepatan link
                        h_speed = if_high_speeds.get(f"1.3.6.1.2.1.31.1.1.1.15.{idx}") if if_high_speeds else None
                        l_speed = if_low_speeds.get(f"1.3.6.1.2.1.2.2.1.5.{idx}") if if_low_speeds else None
                        
                        speed_mbps = 0
                        if h_speed is not None:
                            try: speed_mbps = int(h_speed)
                            except: pass
                        elif l_speed is not None:
                            try: speed_mbps = int(l_speed) // 1000000
                            except: pass
                            
                        if speed_mbps > max_detected_speed:
                            max_detected_speed = speed_mbps
                
                wan_detected_speed = 0
                if target_idx:
                    h_wan = if_high_speeds.get(f"1.3.6.1.2.1.31.1.1.1.15.{target_idx}") if if_high_speeds else None
                    l_wan = if_low_speeds.get(f"1.3.6.1.2.1.2.2.1.5.{target_idx}") if if_low_speeds else None
                    if h_wan is not None:
                        try: wan_detected_speed = int(h_wan)
                        except Exception: pass
                    elif l_wan is not None:
                        try: wan_detected_speed = int(l_wan) // 1000000
                        except Exception: pass

                speed_to_use = wan_detected_speed if wan_detected_speed > 0 else max_detected_speed

                if speed_to_use > 0:
                    standard_speeds = [100, 1000, 2500, 5000, 10000, 25000, 40000, 100000]
                    closest_speed = min(standard_speeds, key=lambda x: abs(x - speed_to_use))
                    
                    if abs(closest_speed - speed_to_use) / closest_speed <= 0.2:
                        final_speed = closest_speed
                    else:
                        final_speed = speed_to_use

                    # Unless device is Core BGP router, a building router's WAN uplink
                    # cannot physically exceed the campus total ISP bandwidth capacity.
                    try:
                        campus_bw_cap = int(self.db.get_campus_total_bandwidth_mbps() or 5000)
                    except Exception:
                        campus_bw_cap = 5000
                    dev_name_low = str(device.get('name', '')).lower()
                    if 'bgp' not in dev_name_low and 'core' not in dev_name_low and final_speed > campus_bw_cap:
                        final_speed = min(final_speed, campus_bw_cap)

                    with self.db_write_lock:
                        cur_dev = self.db.get_device(did)
                        if cur_dev and (not cur_dev.get('uplink_speed_mbps') or cur_dev.get('uplink_speed_mbps') == 1000 or cur_dev.get('uplink_speed_mbps') > campus_bw_cap):
                            self.db.update_device(did, {'uplink_speed_mbps': final_speed})
                            print(f"[Speed Auto-Detect] Updated {cur_dev.get('name', ip)} uplink capacity to {final_speed} Mbps")
        except Exception as se:
            print(f"[Speed Auto-Detect] Error scanning interface speeds: {se}")
            
        try:
            in_octets = None
            out_octets = None
            is_64bit = False
            
            hc_in_val = traffic.get(f"1.3.6.1.2.1.31.1.1.1.6.{target_idx}")
            hc_out_val = traffic.get(f"1.3.6.1.2.1.31.1.1.1.10.{target_idx}")
            if hc_in_val is not None and hc_out_val is not None:
                in_octets = int(hc_in_val)
                out_octets = int(hc_out_val)
                is_64bit = True
            else:
                in_octets = int(traffic.get(f"1.3.6.1.2.1.2.2.1.10.{target_idx}", 0))
                out_octets = int(traffic.get(f"1.3.6.1.2.1.2.2.1.16.{target_idx}", 0))
            
            now_ts = time.time()
            if not hasattr(self, '_last_traffic'):
                self._last_traffic = {}
                
            last_data = self._last_traffic.get(did)
            self._last_traffic[did] = {"in": in_octets, "out": out_octets, "ts": now_ts, "is_64bit": is_64bit}
            
            if last_data:
                if last_data.get("is_64bit") != is_64bit:
                    return None
                delta_t = now_ts - last_data["ts"]
                if delta_t > 0:
                    settings = self.db.get_settings()
                    poll_interval = max(10, int(settings.get('poll_interval', 30)))
                    if delta_t > 3 * poll_interval:
                        print(f"[Traffic] Gap polling terdeteksi device_id={did} dt={delta_t:.1f}s (expected ~{poll_interval}s)")
                    delta_in = in_octets - last_data["in"]
                    delta_out = out_octets - last_data["out"]
                    
                    # Rollover / Reboot protection for 32-bit counters
                    if delta_in < 0:
                        if is_64bit:
                            delta_in = 0
                        else:
                            is_short_dt = delta_t < (2 * poll_interval)
                            is_large_negative_delta = (last_data["in"] - in_octets) > 2**31
                            if is_short_dt and is_large_negative_delta:
                                # Rollover asli
                                delta_in += 2**32
                            else:
                                # Reboot device atau gap: reset ke 0
                                delta_in = 0
                                
                    if delta_out < 0:
                        if is_64bit:
                            delta_out = 0
                        else:
                            is_short_dt = delta_t < (2 * poll_interval)
                            is_large_negative_delta = (last_data["out"] - out_octets) > 2**31
                            if is_short_dt and is_large_negative_delta:
                                delta_out += 2**32
                            else:
                                delta_out = 0
                                
                    wan_in_bps = (delta_in * 8) / delta_t
                    wan_out_bps = (delta_out * 8) / delta_t
                    
                    # Determine speed_bps
                    speed_bps = 0
                    h_speed = traffic.get(f"1.3.6.1.2.1.31.1.1.1.15.{target_idx}")
                    l_speed = traffic.get(f"1.3.6.1.2.1.2.2.1.5.{target_idx}")
                    if h_speed is not None:
                        try:
                            speed_bps = float(h_speed) * 1e6
                        except ValueError:
                            pass
                    if speed_bps == 0 and l_speed is not None:
                        try:
                            speed_bps = float(l_speed)
                        except ValueError:
                            pass
                    
                    # Prevent false positives on PPPoE/virtual interfaces that report 0 or fake low speeds
                    # by falling back to the auto-detected physical uplink speed
                    uplink_bps_fallback = float(device.get('uplink_speed_mbps') or 1000) * 1e6
                    effective_speed = speed_bps if speed_bps > 0 else uplink_bps_fallback
                    if uplink_bps_fallback > 0 and speed_bps > 0:
                        effective_speed = min(speed_bps, uplink_bps_fallback)
                    
                    # Custom rule: 
                    # If link is 1 Gbps, limit is ~1 Gbps (plus 5% tolerance).
                    # If link is 10 Gbps, limit is capped at 5 Gbps (since total ISP BW is only 6 Gbps).
                    limit_bps = self._anomaly_limit_bps(effective_speed)
                    
                    if wan_in_bps > limit_bps or wan_out_bps > limit_bps:
                        cap_mbps = (limit_bps / 1e6) if limit_bps > 0 else 100000.0
                        print(f"[Traffic] Spike terdeteksi pada device_id={did} WAN interface={target_idx} (wan_in={wan_in_bps:.1f}, wan_out={wan_out_bps:.1f} melebihi limit {cap_mbps:.1f} Mbps) - dropped")
                        # Reset cached counter baseline so corrupted counters do not cause secondary spikes next poll
                        if hasattr(self, '_last_traffic') and did in self._last_traffic:
                            self._last_traffic[did] = None
                        return None

                    return {"wan_in": wan_in_bps, "wan_out": wan_out_bps}
        except Exception:
            pass
        return None

    def _check_ifaces(self, device, ip, community, port, version):
        if_st   = self._walk(ip, community, OID['ifOperStatus'], port, version)
        if_desc = self._walk(ip, community, OID['ifDescr'],      port, version)
        did = device['id']
        now_ts = time.time()
        down = []
        flapping = []
        for oid, st in if_st.items():
            idx  = oid.split('.')[-1]
            name = if_desc.get(f"{OID['ifDescr']}.{idx}", f'if{idx}')
            lo   = name.lower()
            if 'loopback' in lo or lo in ('lo','lo0'): continue
            is_down = str(st) in ('2', 'down')
            cur_state = 'down' if is_down else 'up'

            # Track state transitions for Port Flapping detection (3+ changes within 15m)
            fkey = (did, idx)
            fentry = self._iface_flap_history.get(fkey)
            if fentry is None:
                self._iface_flap_history[fkey] = {'state': cur_state, 'changes': []}
            else:
                changes = [ts for ts in fentry['changes'] if (now_ts - ts) <= 900]
                if fentry['state'] != cur_state:
                    changes.append(now_ts)
                    fentry['state'] = cur_state
                    fentry['changes'] = changes
                    self._persist_flap_state()
                    if len(changes) >= 3:
                        last_f_ts = self._last_iface_alert.get(('flap', did, idx), 0)
                        if now_ts - last_f_ts >= 900:
                            self._last_iface_alert[('flap', did, idx)] = now_ts
                            flapping.append(f"{name} ({len(changes)}x)")
                else:
                    fentry['changes'] = changes

            if is_down:
                down.append(name)

        if flapping:
            self._alert(device, 'warning',
                        f"PORT FLAPPING: Interface tidak stabil pada {device.get('name',ip)} ({ip}): {', '.join(flapping[:5])} dalam 15 menit terakhir")
        if down:
            self._alert(device, 'warning',
                        f"Interface(s) DOWN on {device.get('name',ip)}: {', '.join(down[:5])}")
            return 'warning'
        return 'ok'

    def _alert(self, device, severity, message):
        # Skip if alerts are muted for this device
        if not device.get('alerts_enabled', 1):
            return

        did = device.get('id')
        suppress_telegram = False

        # 1. Zabbix Parent-Child Upstream Dependency check (suppress child DOWN alerts if parent is DOWN)
        if did and (severity == 'critical' or 'device down' in message.lower()):
            try:
                p_down, p_dev = self.db.is_upstream_parent_down(did)
                if p_down and p_dev:
                    p_label = p_dev.get('name') or p_dev.get('ip') or f"ID#{p_dev.get('id')}"
                    message = f"{message} [Suppressed: Upstream Parent {p_label} DOWN]"
                    suppress_telegram = True
            except Exception as pe:
                print(f"[Alert Dependency] Parent check error: {pe}")

        # 2. Zabbix Maintenance Window check (suppress Telegram notifications while in maintenance)
        if did:
            try:
                in_maint, maint_until = self.db.is_device_in_maintenance(did)
                if in_maint:
                    message = f"[MAINTENANCE s/d {maint_until}] {message}"
                    suppress_telegram = True
            except Exception as me:
                print(f"[Alert Maintenance] Maintenance check error: {me}")

        with self.db_write_lock:
            aid = self.db.add_alert({'device_id':device['id'],
                                      'device_name':device.get('name',device.get('ip','')),
                                      'device_ip':device.get('ip',''),
                                      'severity':severity, 'message':message})
        
        try:
            import ai_detector
            ai_detector.analyze_alert(self.db, self.socketio, aid)
        except Exception as ae:
            print(f"[Alert AI] Trigger failed: {ae}")

        self.socketio.emit('new_alert', {
            'id':aid,'device_id':device['id'],
            'device_name':device.get('name',''), 'device_ip':device.get('ip',''),
            'severity':severity, 'message':message, 'acknowledged':0,
            'created_at':datetime.now().isoformat()
        })
        self.socketio.emit('stats_update', self.db.get_dashboard_stats())

        # Check alert from DB to inspect AI detector classification
        is_false_alarm = 0
        ai_analysis = None
        try:
            with self.db.conn() as c:
                row = c.execute("SELECT is_false_alarm, ai_analysis FROM alerts WHERE id = ?", (aid,)).fetchone()
                if row:
                    is_false_alarm = row['is_false_alarm']
                    ai_analysis = row['ai_analysis']
        except Exception:
            pass

        # Send Telegram notification if alert is valid and not suppressed by Parent Dependency or Maintenance Window
        if getattr(self, 'telegram_bot', None) and not is_false_alarm and not suppress_telegram:
            try:
                is_recovery = (severity == 'info' and 'online' in message.lower())
                alert_data = {
                    'id': aid,
                    'device_id': device['id'],
                    'device_name': device.get('name', device.get('ip', '')),
                    'device_ip': device.get('ip', ''),
                    'severity': severity,
                    'message': message,
                    'ai_analysis': ai_analysis
                }
                self.telegram_bot.send_alert(alert_data, device=device, is_recovery=is_recovery)
            except Exception as te:
                print(f"[Telegram Alert] Failed to dispatch alert: {te}")

    # ─── network scan ────────────────────────────────────────────────

    def scan_network(self, cidr, community='public', version='2c', zone_id=1, method='snmp', **kwargs):
        if method == 'snmp' and not SNMP_OK:
            self.socketio.emit('scan_error', {'error':'puresnmp not installed. Run: pip install puresnmp'})
            return

        ping_timeout = kwargs.get('ping_timeout') or 1.5
        snmp_timeout = kwargs.get('snmp_timeout') or 2.5
        retries = kwargs.get('retries') or 1
        max_workers = kwargs.get('max_workers') or 30

        with self._lock:
            self._stop.clear()
            self._status.update({'running':True,'found':0,'progress':0,'message':f'Scanning {cidr}…'})

        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            net   = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            total = len(hosts)
            self._status['total'] = total
            self.socketio.emit('scan_started', {'network':str(net),'total':total})

            found = []
            progress_counter = 0
            progress_lock = threading.Lock()

            def scan_ip(ip):
                if self._stop.is_set(): return None
                
                dev = None
                
                if method == 'snmp':
                    oids = [OID['sysName'], OID['sysDescr'], '1.3.6.1.2.1.1.2.0']
                    
                    # Try with user-provided community string first
                    result = self._get(ip, community, oids, version=version, timeout=snmp_timeout)
                    # Fallback to SNMPv1 if v2c failed
                    if not result and version == '2c':
                        result = self._get(ip, community, oids, version='1', timeout=snmp_timeout)
                    
                    # Try common community strings if user-provided one failed
                    if not result:
                        for alt_community in ('public', 'private'):
                            if alt_community == community:
                                continue
                            result = self._get(ip, alt_community, oids, version=version, timeout=snmp_timeout)
                            if result:
                                # Override community with the one that worked
                                community_used = alt_community
                                break
                        else:
                            community_used = community
                    else:
                        community_used = community
                        
                    if result:
                        name  = result.get(OID['sysName'],'').strip() or ip
                        descr = result.get(OID['sysDescr'],'').strip()
                        sys_obj_id = str(result.get('1.3.6.1.2.1.1.2.0', '')).lower()
                        descr_lower = descr.lower()
                        vendor = 'Unknown'
                        if '4881' in sys_obj_id or 'ruijie' in descr_lower or 'reyee' in descr_lower or 'rgos' in descr_lower:
                            vendor = 'Ruijie'
                        elif '14988' in sys_obj_id or 'mikrotik' in descr_lower or 'routeros' in descr_lower:
                            vendor = 'MikroTik'
                        elif '41112' in sys_obj_id or 'ubiquiti' in descr_lower or 'ubnt' in descr_lower or 'unifi' in descr_lower:
                            vendor = 'Ubiquiti'
                        elif 'cisco' in descr_lower:
                            vendor = 'Cisco'
                        
                        dev = {'name':name,'ip':ip,'type':self._guess_type(descr, vendor=vendor),
                               'vendor':vendor,
                               'icon':self._guess_icon(descr, vendor=vendor),'description':descr[:200],
                               'sys_name':name,'snmp_enabled':True,
                               'snmp_community':community_used,'snmp_version':version,
                               'status':'up','zone_id':zone_id, 'source':'scan'}
                        print(f"[Scan] SNMP detected: {ip} → {name} ({vendor})")
                
                elif method == 'icmp':
                    ping_cmd = ["ping", "-n", "1", "-w", "500", ip] if os.name == 'nt' else ["ping", "-c", "1", "-W", "1", ip]
                    res = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if res.returncode == 0:
                        dev = {'name':ip,'ip':ip,'type':'unknown','vendor':'Unknown','icon':'unknown',
                               'description':'Discovered via ICMP','snmp_enabled':False,
                               'status':'up','zone_id':zone_id, 'source':'scan'}
                
                elif method == 'arp':
                    ping_cmd = ["ping", "-n", "1", "-w", "500", ip] if os.name == 'nt' else ["ping", "-c", "1", "-W", "1", ip]
                    subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    out = ""
                    try:
                        if os.name == 'nt':
                            res = subprocess.run(["arp", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
                            out = res.stdout
                        else:
                            res = subprocess.run(["arp", "-n", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1)
                            out = res.stdout
                            if (not out or "No ARP" in out) and os.path.exists("/proc/net/arp"):
                                with open("/proc/net/arp", "r") as f:
                                    out = f.read()
                    except Exception:
                        pass
                    
                    mac = ""
                    mac_re = re.compile(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})')
                    for line in out.splitlines():
                        if ip in line:
                            m = mac_re.search(line)
                            if m:
                                mac = m.group(0).replace('-', ':').lower()
                                break
                    if mac:
                        detected_vendor = 'Unknown'
                        detected_type = 'unknown'
                        
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
                            detected_vendor = OUI_MAP.get(oui, 'Unknown')
                            if detected_vendor != 'Unknown':
                                if detected_vendor in ('Ubiquiti', 'Ruijie', 'MikroTik', 'Cisco', 'TP-Link', 'Huawei'):
                                    detected_type = 'network_device'
                                elif detected_vendor in ('VMware', 'Microsoft'):
                                    detected_type = 'server'
                                    
                        dev = {'name':ip,'ip':ip,'mac':mac,'type':detected_type,'vendor':detected_vendor,'icon':'unknown',
                               'description':f'Discovered via ARP ({detected_vendor})' if detected_vendor != 'Unknown' else 'Discovered via ARP',
                               'snmp_enabled':False,
                               'status':'up','zone_id':zone_id, 'source':'scan'}

                if dev:
                    try:
                        with self.db_write_lock:
                            existing = self.db.get_device_by_ip(ip)
                            if existing:
                                updates = {'status':'up','zone_id':zone_id}

                                if method == 'snmp':
                                    # SNMP scan: update all fields including SNMP config
                                    if 'sys_name' in dev: updates['sys_name'] = dev['sys_name']
                                    if 'description' in dev: updates['description'] = dev['description']
                                    if 'vendor' in dev: updates['vendor'] = dev['vendor']
                                    updates['snmp_enabled'] = 1
                                    if dev.get('snmp_community'): updates['snmp_community'] = dev['snmp_community']
                                    if dev.get('snmp_version'): updates['snmp_version'] = dev['snmp_version']
                                else:
                                    # ICMP/ARP scan: NEVER overwrite snmp_enabled, community,
                                    # version, description, or vendor on existing devices
                                    # to protect data from prior SNMP detection
                                    if dev.get('mac'): updates['mac'] = dev['mac']

                                self.db.update_device(existing['id'], updates)
                                dev['id'] = existing['id']
                            else:
                                dev['id'] = self.db.add_device(dev)
                        return dev
                    except Exception as e:
                        print(f"[Scan] Failed to save device {ip} to DB: {e}")
                return None

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(scan_ip, str(host)): str(host) for host in hosts}
                for future in as_completed(futures):
                    if self._stop.is_set():
                        break
                    ip = futures[future]
                    with progress_lock:
                        progress_counter += 1
                        pct = round((progress_counter)/total*100)
                        self._status.update({'progress':progress_counter,'current_ip':ip,'percent':pct,
                                             'message':f'Scanning {ip}…'})
                        self.socketio.emit('scan_progress',
                                           {'progress':progress_counter,'total':total,'percent':pct,'current_ip':ip})
                    try:
                        dev = future.result()
                        if dev:
                            found.append(dev)
                            with progress_lock:
                                self._status['found'] += 1
                            self.socketio.emit('device_found', dev)
                    except Exception as e:
                        print(f"[Scan] Error scanning {ip}: {e}")

            self._status.update({'running':False,'percent':100,
                                 'message':f'Done — {len(found)} device(s) found'})
            self.socketio.emit('scan_complete', {'found':len(found),'devices':found})
            self.db.add_access_log({'source':'Scanner',
                                    'message':f'Scan {cidr}: {len(found)} found','type':'scan'})
        except Exception as e:
            self._status.update({'running':False,'message':f'Error: {e}'})
            self.socketio.emit('scan_error', {'error':str(e)})
        finally:
            self._status['running'] = False

    def _guess_type(self, d, vendor=''):
        if not d: return 'unknown'
        d = d.lower()
        vendor = vendor.lower()
        if any(x in d for x in ('switch','catalyst','nexus')): return 'switch'
        if any(x in d for x in ('router','routeros','mikrotik')): return 'router'
        if any(x in d for x in ('linux','ubuntu','debian','centos')): return 'server'
        if any(x in d for x in ('windows','win32')): return 'server'
        if any(x in d for x in ('access point','aironet','unifi','rap','rg-rap','wlan ap','wireless ap','reyee ap')): return 'access_point'
        if vendor == 'ruijie' and ('rgos' in d or 'rg-' in d) and not any(x in d for x in ('nbs','nps','s29','s37','s57')): return 'access_point'
        if any(x in d for x in ('firewall','pfsense','fortigate','checkpoint')): return 'firewall'
        if any(x in d for x in ('printer','laserjet')): return 'printer'
        return 'unknown'

    def _guess_icon(self, d, vendor=''):
        t = self._guess_type(d, vendor=vendor)
        return {'switch':'switch','router':'router','server':'server',
                'access_point':'wifi','firewall':'shield','printer':'printer'}.get(t,'device')

    def _detect_uptime_reboot(self, device, new_uptime_str):
        """Return True if SNMP sysUpTime dropped significantly, indicating a reboot."""
        if not new_uptime_str:
            return False
        prev_sec = parse_uptime_to_seconds(device.get('uptime'))
        new_sec = parse_uptime_to_seconds(new_uptime_str)
        # Guard against brand-new/0-uptime devices and 32-bit TimeTicks 497-day wraparound
        if prev_sec > 120 and prev_sec < 42900000 and 0 < new_sec < (prev_sec - 60):
            return True
        return False

    def _format_recovery_reboot_info(self, device, down_time_str, up_time_str, new_uptime_str, uptime_rebooted):
        """Build reboot status suffix for recovery alerts."""
        if not new_uptime_str:
            return ""
        is_reboot = bool(uptime_rebooted)
        if not is_reboot:
            try:
                t_down = datetime.fromisoformat(down_time_str)
                t_up = datetime.fromisoformat(up_time_str)
                dur_sec = max(0, (t_up - t_down).total_seconds())
                up_sec = parse_uptime_to_seconds(new_uptime_str)
                if 0 < up_sec < (dur_sec + 60):
                    is_reboot = True
            except Exception:
                pass
        if is_reboot:
            return f" | 🔄 Reboot: YA (Uptime baru: {new_uptime_str})"
        return f" | 🔌 Reboot: TIDAK (Uptime tetap: {new_uptime_str})"

    def _handle_fast_reboot(self, device, now, new_uptime_str):
        """Alert and log a fast reboot that occurred between polling intervals."""
        did = device['id']
        ip = device['ip']
        prev_up = device.get('uptime') or '-'
        self._alert(
            device,
            'warning',
            f"{device.get('name', ip)} ({ip}) terdeteksi REBOOT (Uptime: {prev_up} → {new_uptime_str})"
        )
        try:
            with self.db_write_lock:
                self.db.save_downtime_analysis(
                    did, now, now, 0,
                    'fast_reboot', 'uptime_reset', 1,
                    'Reboot Cepat Terdeteksi (Uptime SNMP reset di antara interval polling)', 95.0
                )
        except Exception as e:
            print(f"[BlackBox] Failed to save fast reboot for {ip}: {e}")

    def analyze_downtime_event(self, device, down_time_str, up_time_str, current_uptime_str=None):
        try:
            did = device['id']
            ip = device['ip']
            
            # 1. Parse times with robust normalization for SQLite dates
            try:
                down_clean = str(down_time_str).replace(' ', 'T').replace('Z', '')
                up_clean = str(up_time_str).replace(' ', 'T').replace('Z', '')
                down_t = datetime.fromisoformat(down_clean)
                up_t = datetime.fromisoformat(up_clean)
                duration_sec = int((up_t - down_t).total_seconds())
            except Exception:
                duration_sec = 0
            
            if duration_sec <= 0:
                duration_sec = 30 # Default minimum duration if event was transient or parsing fell back
            
            # 2. Analyze Ping Pattern from history
            ping_history = self._ping_history.get(ip, [])
            ping_pattern = 'instant_drop'
            if len(ping_history) >= 3:
                live_pings = [p for p in ping_history if p[0]]
                if live_pings:
                    rtts = [p[1] for p in live_pings]
                    avg_rtt = sum(rtts) / len(rtts)
                    spikes = [r for r in rtts if r > avg_rtt * 3.0 and r > 50]
                    if len(spikes) > 0 or len(live_pings) < len(ping_history) - 2:
                        ping_pattern = 'gradual_degrade'
            
            # 3. Analyze SNMP Metrics before down
            snmp_pattern = 'normal_metrics'
            cpu_trend, ram_trend, tmp_trend, wan_in_trend, wan_out_trend = [], [], [], [], []
            with self.db_write_lock:
                with self.db.conn() as c:
                    rows = c.execute('''
                        SELECT metric_name, metric_value FROM snmp_metrics
                        WHERE device_id = ? AND timestamp <= ? AND timestamp >= datetime(?, '-10 minutes')
                        ORDER BY timestamp DESC LIMIT 100
                    ''', (did, down_time_str, down_time_str)).fetchall()
                    for r in rows:
                        try:
                            val_f = float(r['metric_value'])
                            if r['metric_name'] == 'cpu_usage': cpu_trend.append(val_f)
                            elif r['metric_name'] == 'memory_usage': ram_trend.append(val_f)
                            elif r['metric_name'] == 'temperature': tmp_trend.append(val_f)
                            elif r['metric_name'] == 'wan_in': wan_in_trend.append(val_f)
                            elif r['metric_name'] == 'wan_out': wan_out_trend.append(val_f)
                        except Exception: pass

            uplink_bps = float(device.get('uplink_speed_mbps') or 1000) * 1e6 * 0.95
            bw_sat = (wan_in_trend and max(wan_in_trend) > uplink_bps) or (wan_out_trend and max(wan_out_trend) > uplink_bps)

            if tmp_trend and max(tmp_trend) > 85.0: snmp_pattern = 'thermal_shutdown'
            elif ram_trend and max(ram_trend) > 95.0: snmp_pattern = 'memory_leak'
            elif cpu_trend and max(cpu_trend) > 95.0: snmp_pattern = 'cpu_exhaustion'
            elif bw_sat: snmp_pattern = 'bandwidth_saturation'
                
            # 4. Check Reboot
            reboot_detected = 0
            if current_uptime_str:
                uptime_sec = parse_uptime_to_seconds(current_uptime_str)
                if uptime_sec > 0 and uptime_sec < (duration_sec + 60):
                    reboot_detected = 1
            
            # 5. Determine Heuristic Root Cause
            justification = "Koneksi Terputus / Jaringan Tidak Stabil"
            confidence = 70.0
            
            if reboot_detected:
                if snmp_pattern == 'thermal_shutdown':
                    justification = "Thermal Shutdown (Perangkat mati akibat Overheating > 85°C)"
                    confidence = 95.0
                elif snmp_pattern == 'memory_leak':
                    justification = "OS Crash: Memory Exhaustion (Kemungkinan OOM/Memory Leak)"
                    confidence = 90.0
                elif snmp_pattern == 'cpu_exhaustion':
                    justification = "OS Crash: CPU Saturation (Routing Loop / Proses Hang)"
                    confidence = 90.0
                else:
                    justification = "Restart Sengaja / Mati Lampu (Perangkat reboot normal)"
                    confidence = 95.0
            else:
                if ping_pattern == 'gradual_degrade':
                    if snmp_pattern == 'bandwidth_saturation':
                        justification = "Link Saturated / DDoS (Trafik penuh >95% menyebabkan Ping RTO)"
                        confidence = 90.0
                    else:
                        justification = "Congestion / Network Loop (Penurunan performa jaringan bertahap hingga RTO)"
                        confidence = 85.0
                elif ping_pattern == 'instant_drop':
                    if current_uptime_str is None:
                        justification = "Perangkat Restart / Mati Listrik / Kabel Lan Lepas"
                    else:
                        justification = "Kabel Lan Lepas / Port Down (Link jaringan terputus tanpa reboot)"
                    confidence = 90.0

            # 6. Mass Failure Override
            with self.db_write_lock:
                with self.db.conn() as c:
                    concurrent_downs = c.execute('''
                        SELECT COUNT(DISTINCT device_id) FROM downtime_analysis 
                        WHERE abs(strftime('%s', down_time) - strftime('%s', ?)) <= 30
                    ''', (down_time_str,)).fetchone()[0]
            if concurrent_downs >= 2:
                justification = "Parent Link / Upstream Failure (Kematian massal bersama perangkat lain)"
                confidence = 95.0
            
            # Save analysis results
            with self.db_write_lock:
                self.db.save_downtime_analysis(
                    did, down_time_str, up_time_str, duration_sec, 
                    ping_pattern, snmp_pattern, reboot_detected, justification, confidence
                )
                
            print(f"[BlackBox] Downtime analyzed for {ip}: {justification} (Confidence: {confidence}%)")
            
        except Exception as e:
            print(f"[BlackBox Error] Failed to analyze downtime: {e}")
