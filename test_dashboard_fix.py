#!/usr/bin/env python3
"""
Test Dashboard API After Fix
"""

import json
import urllib.request
from datetime import datetime

DASHBOARD_URL = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"

def test_dashboard_api():
    """Test the fixed dashboard API"""
    print("🧪 Testing fixed dashboard API...")
    
    # Test data
    test_data = {
        "timestamp": datetime.now().isoformat(),
        "source": "test_fix",
        "active_honeypots": 3,
        "total_attacks": 2,
        "total_engagements": 1,
        "honeypots": [
            {
                "id": "test_hp_fixed",
                "type": "web_application", 
                "status": "active",
                "source_ip": "192.168.1.200"
            }
        ],
        "threats": [
            {
                "id": "test_threat",
                "type": "SQL Injection",
                "source_ip": "192.168.1.200",
                "confidence": 0.95
            }
        ]
    }
    
    try:
        url = f"{DASHBOARD_URL}/api/update"
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'DashboardTester/1.0'
        }
        
        request_data = json.dumps(test_data).encode('utf-8')
        req = urllib.request.Request(url, data=request_data, headers=headers)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                response_data = response.read().decode()
                print("✅ Dashboard API is working!")
                print(f"   Response: {response_data}")
                return True
            else:
                print(f"⚠️  Dashboard returned HTTP {response.status}")
                
    except Exception as e:
        print(f"❌ Dashboard test failed: {e}")
        
    return False

if __name__ == "__main__":
    test_dashboard_api()
