#!/usr/bin/env python3
"""
Test regresi otomatis untuk generate_and_save_monthly_report().
Jalankan: python3 test_report_accuracy.py
Exit code 0 = semua lulus, exit code 1 = ada yang gagal (bisa dipakai di CI/pre-commit hook).

Ini BUKAN pengganti test menyeluruh -- ini konsolidasi dari kasus-kasus yang
riwayatnya PERNAH benar-benar rusak (masing-masing dicatat komentarnya), supaya
perbaikan/refactor berikutnya tidak diam-diam meregresi hal yang sama lagi.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta

_tmpdir = tempfile.mkdtemp(prefix='netmon_test_')
os.environ['DB_PATH'] = os.path.join(_tmpdir, 'test_report.db')

from database import Database

db = Database()
now = datetime.now()
first_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

_failures = []


def check(name, condition, detail=""):
    if condition:
        print(f"  [OK]   {name}")
    else:
        print(f"  [GAGAL] {name}  {detail}")
        _failures.append(name)


def ins_metric(did, name, val, ts):
    with db.conn() as c:
        c.execute(
            "INSERT INTO snmp_metrics (device_id, metric_name, metric_value, timestamp) VALUES (?,?,?,?)",
            (did, name, str(val), ts.strftime('%Y-%m-%d %H:%M:%S')),
        )


print("\nTEST 1: no_data harus jujur, bukan angka random")
did1 = db.add_device({'name': 't1-nodata', 'ip': '10.250.1.1', 'type': 'router', 'uplink_speed_mbps': 1000})
rep1 = db.generate_and_save_monthly_report(now.strftime('%Y-%m'))
r1 = next(r for r in rep1['routers'] if r['id'] == did1)
check("no_data flag ke-set True", r1.get('no_data') is True)
check("avg_rx_mbps = 0.0 (bukan angka random)", r1['avg_rx_mbps'] == 0.0)
check("peak_rx_mbps = 0.0 (bukan angka random)", r1['peak_rx_mbps'] == 0.0)

print("\nTEST 2: rata-rata time-weighted (bukan rata-rata sederhana per titik)")
did2 = db.add_device({'name': 't2-avg', 'ip': '10.250.1.2', 'type': 'router', 'uplink_speed_mbps': 10000})
base2 = now - timedelta(minutes=20)
for sec, val in [(0, 95e6), (10, 105e6), (250, 98e6), (260, 102e6)]:
    ins_metric(did2, 'wan_in', val, base2 + timedelta(seconds=sec))
rep2 = db.generate_and_save_monthly_report(now.strftime('%Y-%m'))
r2 = next(r for r in rep2['routers'] if r['id'] == did2)
expected_weighted = (95 * 10 + 105 * 240 + 98 * 10) / 260
naive_avg = (95 + 105 + 98 + 102) / 4
check(f"avg_rx_mbps time-weighted (~{expected_weighted:.2f})",
      abs(r2['avg_rx_mbps'] - expected_weighted) < 0.05, f"dapat {r2['avg_rx_mbps']}")
check("BUKAN rata-rata naif lama (100.0)", abs(r2['avg_rx_mbps'] - naive_avg) > 1.0)

print("\nTEST 3: filter bulan kalender, bukan rolling 30 hari dari sekarang")
did3 = db.add_device({'name': 't3-month', 'ip': '10.250.1.3', 'type': 'router', 'uplink_speed_mbps': 10000})
this_month_vals = [48, 49, 50, 51, 52]
for i, v in enumerate(this_month_vals):
    ins_metric(did3, 'wan_in', v * 1e6, now - timedelta(minutes=(50 - i * 10)))
wrong_month_point = first_of_month - timedelta(days=2)
ins_metric(did3, 'wan_in', 55e6, wrong_month_point)
rep3 = db.generate_and_save_monthly_report(now.strftime('%Y-%m'))
r3 = next(r for r in rep3['routers'] if r['id'] == did3)
check("data bulan lalu TIDAK ikut terhitung (peak=52, bukan 55)", r3['peak_rx_mbps'] == 52.0,
      f"dapat {r3['peak_rx_mbps']}")

print("\nTEST 4: anomali wan_in tidak boleh collateral damage ke wan_out")
did4 = db.add_device({'name': 't4-collision', 'ip': '10.250.1.4', 'type': 'router', 'uplink_speed_mbps': 1000})
base4 = now - timedelta(minutes=15)
t0, t_spike, t2 = base4, base4 + timedelta(seconds=200), base4 + timedelta(seconds=210)
ins_metric(did4, 'wan_in', 100e6, t0)
ins_metric(did4, 'wan_in', 600e6, t_spike)
ins_metric(did4, 'wan_in', 100e6, t2)
ins_metric(did4, 'wan_out', 80e6, t0)
ins_metric(did4, 'wan_out', 100e6, t_spike)
ins_metric(did4, 'wan_out', 120e6, t2)
rep4 = db.generate_and_save_monthly_report(now.strftime('%Y-%m'))
r4 = next(r for r in rep4['routers'] if r['id'] == did4)
check("anomali wan_in (600) berhasil terbuang", r4['peak_rx_mbps'] == 100.0, f"dapat {r4['peak_rx_mbps']}")
expected_tx_avg = (80 * 200 + 100 * 10) / 210
check(f"wan_out normal TIDAK ikut terbuang (avg_tx ~{expected_tx_avg:.2f})",
      abs(r4['avg_tx_mbps'] - expected_tx_avg) < 0.05, f"dapat {r4['avg_tx_mbps']}")

print("\nTEST 5: filter anomali statistik jalan tanpa API key AI")
did5 = db.add_device({'name': 't5-stat', 'ip': '10.250.1.5', 'type': 'router', 'uplink_speed_mbps': 1000})
base5 = now - timedelta(minutes=10)
for i, v in enumerate([48, 49, 50, 51, 52]):
    ins_metric(did5, 'wan_in', v * 1e6, base5 + timedelta(seconds=i * 30))
ins_metric(did5, 'wan_in', 700e6, base5 + timedelta(seconds=200))
rep5 = db.generate_and_save_monthly_report(now.strftime('%Y-%m'))
r5 = next(r for r in rep5['routers'] if r['id'] == did5)
check("outlier statistik (700) terbuang walau tanpa Groq API key", r5['peak_rx_mbps'] <= 52.0,
      f"dapat {r5['peak_rx_mbps']}")

print("\n" + "=" * 55)
if _failures:
    print(f"GAGAL: {len(_failures)} test tidak lulus -> {_failures}")
    sys.exit(1)
else:
    print("SEMUA TEST LULUS")
    sys.exit(0)
