#!/usr/bin/env python3
"""
Force Dashboard Refresh
Triggers the dashboard's internal refresh mechanism to show different data
"""

import urllib.request
import time
from datetime import datetime

DASHBOARD_URL = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"

def force_refresh():
    """Force dashboard to refresh by making multiple requests"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Forcing dashboard refresh...")
    
    # Make multiple requests to different endpoints to trigger refresh
    endpoints = ["/", "/api/status", "/api/threats", "/api/engagements", "/api/intelligence"]
    
    for i in range(3):  # 3 refresh cycles
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Refresh cycle {i+1}")
        
        for endpoint in endpoints:
            try:
                url = f"{DASHBOARD_URL}{endpoint}"
                headers = {
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache',
                    'User-Agent': 'DashboardRefresher/1.0'
                }
                
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        print(f"   ✅ {endpoint} refreshed")
                    else:
                        print(f"   ⚠️  {endpoint} returned {response.status}")
                        
            except Exception as e:
                print(f"   ❌ {endpoint} failed: {e}")
        
        time.sleep(2)  # Wait between cycles
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Dashboard refresh complete")
    print("🔄 Try refreshing your browser - the dashboard may show different numbers now")

if __name__ == "__main__":
    force_refresh()