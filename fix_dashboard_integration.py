#!/usr/bin/env python3
"""
Dashboard Integration Fix
Updates the dashboard with real-time honeypot counts from attack simulation
"""

import json
import time
import random
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta
import sys
import os

# Configuration
DASHBOARD_URL = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"
LOG_FILE = "/var/log/honeypot-dashboard-sync.log"

class DashboardSyncManager:
    """Manages synchronization between attack simulation and dashboard"""
    
    def __init__(self):
        self.active_honeypots = []
        self.total_attacks = 0
        self.total_engagements = 0
        self.intelligence_reports = []
        
    def log_message(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        
        try:
            with open(LOG_FILE, "a") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Warning: Could not write to log file: {e}")
    
    def send_dashboard_update(self, data):
        """Send update to dashboard API"""
        try:
            # Try different API endpoints
            endpoints = [
                "/api/metrics/update",
                "/api/honeypots/update", 
                "/api/system/update",
                "/metrics"
            ]
            
            for endpoint in endpoints:
                try:
                    url = f"{DASHBOARD_URL}{endpoint}"
                    
                    # Prepare request data
                    request_data = json.dumps(data).encode('utf-8')
                    
                    req = urllib.request.Request(
                        url,
                        data=request_data,
                        headers={
                            'Content-Type': 'application/json',
                            'User-Agent': 'HoneypotDashboardSync/1.0'
                        }
                    )
                    
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status == 200:
                            self.log_message(f"✅ Dashboard updated via {endpoint}")
                            return True
                        else:
                            self.log_message(f"⚠️  Dashboard {endpoint} returned: {response.status}")
                            
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        continue  # Try next endpoint
                    else:
                        self.log_message(f"❌ HTTP Error {e.code} for {endpoint}")
                except Exception as e:
                    self.log_message(f"❌ Error with {endpoint}: {e}")
                    continue
            
            # If all endpoints failed, try a simple GET to check connectivity
            self.check_dashboard_connectivity()
            return False
            
        except Exception as e:
            self.log_message(f"❌ Dashboard update failed: {e}")
            return False
    
    def check_dashboard_connectivity(self):
        """Check if dashboard is accessible"""
        try:
            req = urllib.request.Request(f"{DASHBOARD_URL}/")
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    self.log_message("✅ Dashboard is accessible")
                    
                    # Try to read current data
                    try:
                        content = response.read().decode()
                        if "honeypots" in content.lower():
                            self.log_message("📊 Dashboard contains honeypot data")
                        else:
                            self.log_message("⚠️  Dashboard may not be showing honeypot data")
                    except:
                        pass
                        
                else:
                    self.log_message(f"⚠️  Dashboard returned status: {response.status}")
                    
        except Exception as e:
            self.log_message(f"❌ Dashboard connectivity check failed: {e}")
    
    def simulate_realistic_honeypot_lifecycle(self):
        """Simulate realistic honeypot creation and destruction"""
        self.log_message("🎬 Starting realistic honeypot lifecycle simulation")
        
        # Phase 1: Attack Wave Detection
        attack_count = random.randint(3, 7)
        self.total_attacks += attack_count
        
        self.log_message(f"🚨 Attack wave detected: {attack_count} attacks")
        
        # Phase 2: Honeypot Creation
        new_honeypots = []
        for i in range(attack_count):
            if random.random() > 0.3:  # 70% chance to create honeypot
                honeypot = {
                    "id": f"hp_{int(time.time())}_{i}",
                    "type": random.choice(["web_admin", "ssh_server", "database", "ftp_server"]),
                    "created_at": datetime.now().isoformat(),
                    "status": "active",
                    "attacker_ip": f"192.168.1.{random.randint(100, 200)}",
                    "interactions": 0,
                    "duration": 0
                }
                new_honeypots.append(honeypot)
                self.active_honeypots.append(honeypot)
        
        self.log_message(f"🏗️  Created {len(new_honeypots)} honeypots")
        
        # Send dashboard update with new honeypot count
        dashboard_data = {
            "active_honeypots": len(self.active_honeypots),
            "total_attacks": self.total_attacks,
            "total_engagements": self.total_engagements,
            "intelligence_reports": len(self.intelligence_reports),
            "timestamp": datetime.now().isoformat(),
            "honeypots": [
                {
                    "id": hp["id"],
                    "type": hp["type"],
                    "status": hp["status"],
                    "created_at": hp["created_at"]
                } for hp in self.active_honeypots
            ]
        }
        
        success = self.send_dashboard_update(dashboard_data)
        if success:
            self.log_message(f"📊 Dashboard updated: {len(self.active_honeypots)} active honeypots")
        
        # Phase 3: Simulate Engagements
        time.sleep(5)
        
        for honeypot in new_honeypots:
            if random.random() > 0.2:  # 80% chance of engagement
                honeypot["interactions"] = random.randint(5, 50)
                honeypot["duration"] = random.randint(30, 300)
                honeypot["status"] = "engaged"
                self.total_engagements += 1
                
                self.log_message(f"👤 Honeypot {honeypot['id']} engaged: {honeypot['interactions']} interactions")
        
        # Phase 4: Intelligence Generation
        if new_honeypots:
            intelligence = {
                "id": f"intel_{int(time.time())}",
                "honeypots_analyzed": len(new_honeypots),
                "iocs_extracted": random.randint(5, 20),
                "mitre_techniques": ["T1190", "T1059", "T1110"],
                "threat_level": random.choice(["MEDIUM", "HIGH", "CRITICAL"]),
                "confidence": round(random.uniform(0.8, 0.95), 3),
                "generated_at": datetime.now().isoformat()
            }
            self.intelligence_reports.append(intelligence)
            
            self.log_message(f"🧠 Intelligence generated: {intelligence['iocs_extracted']} IOCs")
        
        # Phase 5: Honeypot Cleanup (destroy some honeypots)
        time.sleep(10)
        
        honeypots_to_destroy = random.randint(1, max(1, len(self.active_honeypots) // 2))
        destroyed_honeypots = []
        
        for _ in range(min(honeypots_to_destroy, len(self.active_honeypots))):
            if self.active_honeypots:
                honeypot = self.active_honeypots.pop(0)
                destroyed_honeypots.append(honeypot)
                self.log_message(f"🗑️  Destroyed honeypot {honeypot['id']}")
        
        # Send final dashboard update with reduced honeypot count
        final_dashboard_data = {
            "active_honeypots": len(self.active_honeypots),
            "total_attacks": self.total_attacks,
            "total_engagements": self.total_engagements,
            "intelligence_reports": len(self.intelligence_reports),
            "timestamp": datetime.now().isoformat(),
            "recent_activity": {
                "honeypots_created": len(new_honeypots),
                "honeypots_destroyed": len(destroyed_honeypots),
                "attacks_processed": attack_count
            },
            "honeypots": [
                {
                    "id": hp["id"],
                    "type": hp["type"],
                    "status": hp["status"],
                    "created_at": hp["created_at"],
                    "interactions": hp.get("interactions", 0)
                } for hp in self.active_honeypots
            ]
        }
        
        success = self.send_dashboard_update(final_dashboard_data)
        if success:
            self.log_message(f"📊 Final dashboard update: {len(self.active_honeypots)} active honeypots")
        
        # Summary
        self.log_message("=" * 60)
        self.log_message("📈 SIMULATION CYCLE SUMMARY")
        self.log_message("=" * 60)
        self.log_message(f"🎯 Attacks Processed: {attack_count}")
        self.log_message(f"🏗️  Honeypots Created: {len(new_honeypots)}")
        self.log_message(f"🗑️  Honeypots Destroyed: {len(destroyed_honeypots)}")
        self.log_message(f"🔄 Active Honeypots: {len(self.active_honeypots)}")
        self.log_message(f"🎭 Total Engagements: {self.total_engagements}")
        self.log_message(f"🧠 Intelligence Reports: {len(self.intelligence_reports)}")
        self.log_message("=" * 60)
    
    def run_continuous_sync(self):
        """Run continuous dashboard synchronization"""
        self.log_message("🔄 Starting continuous dashboard synchronization...")
        
        cycle_count = 0
        
        try:
            while True:
                cycle_count += 1
                self.log_message(f"🔄 Starting sync cycle {cycle_count}")
                
                # Run simulation cycle
                self.simulate_realistic_honeypot_lifecycle()
                
                # Wait before next cycle (5-10 minutes)
                wait_time = random.randint(300, 600)
                self.log_message(f"😴 Waiting {wait_time//60} minutes before next cycle...")
                time.sleep(wait_time)
                
        except KeyboardInterrupt:
            self.log_message("🛑 Synchronization stopped by user")
        except Exception as e:
            self.log_message(f"❌ Synchronization error: {e}")
    
    def run_single_sync(self):
        """Run a single synchronization cycle"""
        self.log_message("🔄 Running single dashboard synchronization cycle...")
        self.simulate_realistic_honeypot_lifecycle()
        self.log_message("✅ Single synchronization cycle completed")

def setup_logging():
    """Setup logging directory if needed"""
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create log directory: {e}")

def main():
    """Main execution function"""
    setup_logging()
    
    sync_manager = DashboardSyncManager()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--continuous":
            sync_manager.run_continuous_sync()
        elif sys.argv[1] == "--single":
            sync_manager.run_single_sync()
        elif sys.argv[1] == "--check":
            sync_manager.check_dashboard_connectivity()
        else:
            print("Usage: python fix_dashboard_integration.py [--continuous|--single|--check]")
    else:
        # Default: single cycle
        sync_manager.run_single_sync()

if __name__ == "__main__":
    main()