#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime, timedelta

# Create a temporary DB file path
TEST_DB_PATH = '/tmp/verify_backbone.db'
if os.path.exists(TEST_DB_PATH):
    os.remove(TEST_DB_PATH)

os.environ['DB_PATH'] = TEST_DB_PATH

try:
    from database import Database
    db = Database()
    
    router1_id = db.add_device({'name':'Router-Agg1','ip':'10.0.0.1','type':'router','uplink_speed_mbps':1000, 'include_in_aggregate': 1})
    router2_id = db.add_device({'name':'Router-Agg2','ip':'10.0.0.2','type':'router','uplink_speed_mbps':1000, 'include_in_aggregate': 1})
    router3_id = db.add_device({'name':'Router-NoAgg','ip':'10.0.0.3','type':'router','uplink_speed_mbps':1000, 'include_in_aggregate': 0})
    
    now = datetime.now()
    month_str = now.strftime('%Y-%m')
    
    # 24h testing points
    ts1 = now - timedelta(hours=2) # Point 1
    ts2 = now - timedelta(hours=10) # Point 2
    
    with db.conn() as c:
        for did, val, ts in [(router1_id, 100e6, ts1), (router2_id, 200e6, ts1), (router3_id, 500e6, ts1)]:
            c.execute("INSERT INTO snmp_metrics (device_id, metric_name, metric_value, timestamp) VALUES (?,?,?,?)", 
                      (did, 'wan_in', str(val), ts.strftime('%Y-%m-%d %H:%M:%S')))
                      
        for did, val, ts in [(router1_id, 50e6, ts2), (router2_id, 150e6, ts2), (router3_id, 1000e6, ts2)]:
            c.execute("INSERT INTO snmp_metrics (device_id, metric_name, metric_value, timestamp) VALUES (?,?,?,?)", 
                      (did, 'wan_in', str(val), ts.strftime('%Y-%m-%d %H:%M:%S')))
    
    report = db.generate_and_save_monthly_report(month_str)
    
    assert 'backbone' in report, "Backbone missing"
    bb = report['backbone']
    
    assert 'chart_data' in bb, "Backbone chart_data missing"
    cd = bb['chart_data']
    assert '24hours' in cd, "24hours missing in backbone chart_data"
    
    b24 = cd['24hours']
    assert len(b24) == 2, f"Expected 2 points in backbone 24hours, got {len(b24)}"
    
    # Validation logic:
    # ts1 point: Router1 (100) + Router2 (200) = 300. Router3 (500) ignored.
    # ts2 point: Router1 (50) + Router2 (150) = 200. Router3 (1000) ignored.
    
    vals = sorted([pt['rx'] for pt in b24])
    assert vals[0] == 200.0, f"Expected first value 200.0, got {vals[0]}"
    assert vals[1] == 300.0, f"Expected second value 300.0, got {vals[1]}"
    
    print(">>> VERIFICATION PASSED: Backbone aggregates chart_data correctly and respects include_in_aggregate")
    
except Exception as e:
    print(f"❌ FAIL: {e}")
    sys.exit(1)
finally:
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
