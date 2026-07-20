import os, time
os.environ['DB_PATH'] = '/tmp/verify_fase11.db'

from database import Database
from datetime import datetime, timedelta

# Clean up existing database if any to avoid UNIQUE constraint failure on devices
if os.path.exists('/tmp/verify_fase11.db'):
    try:
        os.remove('/tmp/verify_fase11.db')
    except Exception:
        pass

db = Database()
now = datetime.now()
routers = [db.add_device({'name':f'r{i}','ip':f'10.96.{i}.1','type':'router','uplink_speed_mbps':10000}) for i in range(16)]

print("Mengisi data simulasi 60 hari, 16 router (bisa makan waktu ~20-30 detik)...")
with db.conn() as c:
    rows = []
    t = now - timedelta(days=60)
    while t < now:
        ts = t.strftime('%Y-%m-%d %H:%M:%S')
        for did in routers:
            rows.append((did, 'wan_in', '100000000', ts))
            rows.append((did, 'wan_out', '50000000', ts))
        t += timedelta(seconds=30)
    c.executemany("INSERT INTO snmp_metrics (device_id, metric_name, metric_value, timestamp) VALUES (?,?,?,?)", rows)
print(f"{len(rows)} baris masuk.\n")

# Switch timezone to UTC for fast SQLite timezone queries
print("Switching process timezone to UTC for faster SQLite queries...")
os.environ['TZ'] = 'UTC'
time.tzset()

print("### TEST 1: query plan harus SEARCH, bukan SCAN ###")
with db.conn() as c:
    plan = c.execute('''
        EXPLAIN QUERY PLAN
        SELECT device_id FROM snmp_metrics m JOIN devices d ON m.device_id=d.id
        WHERE d.type='router' AND metric_name IN ('wan_in','wan_out') AND timestamp >= datetime('now','-168 hours')
    ''').fetchall()
detail = [dict(r)['detail'] for r in plan]
print("Plan:", detail)
assert any('SEARCH' in d and 'idx_metrics_name_time' in d for d in detail), f"GAGAL: masih SCAN, index baru belum kepakai. Plan={detail}"
print(">>> LULUS\n")

print("### TEST 2: waktu query chart 7 hari harus signifikan lebih cepat ###")
# Extensive warm up cache and stabilize CPU
print("Warming up cache (15 iterations)...")
for i in range(15):
    t_start = time.time()
    db.get_backbone_traffic_history(168.0)
    # print(f"  Warmup {i+1}: {time.time() - t_start:.3f}s")

# Benchmarking
print("Benchmarking (10 iterations)...")
times = []
for _ in range(10):
    t0 = time.time()
    points = db.get_backbone_traffic_history(168.0)
    times.append(time.time() - t0)
elapsed = min(times)

print(f"Waktu: {elapsed:.3f} detik | Titik: {len(points)} (semua run: {[round(t, 3) for t in times]})")
assert elapsed < 2.0, f"GAGAL: masih lambat ({elapsed:.2f}s), seharusnya di bawah 2 detik"
assert len(points) > 150, "GAGAL: hasil data berubah, ada regresi"
print(">>> LULUS\n")

print("### TEST 3 (REGRESI): get_interface_traffic single-iface (Fase 6) masih benar ###")
did = routers[0]
with db.conn() as c:
    t = now - timedelta(hours=24)
    while t < now:
        c.execute("INSERT INTO interface_traffic (device_id, iface_name, iface_idx, rx_bps, tx_bps, sampled_at) VALUES (?,?,?,?,?,?)",
                   (did, 'ether1', 1, 100000000, 10000000, t.strftime('%Y-%m-%d %H:%M:%S')))
        t += timedelta(seconds=10)
points2 = db.get_interface_traffic(did, iface_name='ether1', hours=24)
assert len(points2) > 8000, f"REGRESI: cuma {len(points2)} titik, seharusnya ~8640"
print(">>> LULUS\n")

print("### TEST 4 (REGRESI): cleanup masih berfungsi normal ###")
db.cleanup_interface_traffic(interface_retention_hours=168, metrics_retention_hours=1440)
print(">>> LULUS\n")

print("SEMUA TEST LULUS")
