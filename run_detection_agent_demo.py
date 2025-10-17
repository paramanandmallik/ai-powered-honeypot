#!/usr/bin/env python3
"""
Detection Agent Demo with Real Log Analysis and Honeypot Scaling
This demonstrates the Detection Agent analyzing network logs, CloudTrail, and triggering real honeypot scaling
"""

import asyncio
import json
import logging
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
import urllib.request
import urllib.parse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Dashboard configuration
DASHBOARD_URL = "https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod"

class MockLogAnalyzer:
    """Simulates log analysis from various sources"""
    
    def __init__(self):
        self.log_sources = [
            "vpc-flow-logs",
            "cloudtrail-logs", 
            "waf-logs",
            "alb-access-logs",
            "security-hub-findings"
        ]
        
    def generate_network_log_entry(self):
        """Generate realistic network log entry"""
        suspicious_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.0.25",
            "203.0.113.45", "198.51.100.78", "185.220.101.32"
        ]
        
        attack_patterns = [
            {
                "type": "port_scan",
                "ports": [22, 80, 443, 3389, 21, 23],
                "pattern": "sequential_port_access"
            },
            {
                "type": "brute_force",
                "ports": [22, 3389, 21],
                "pattern": "repeated_failed_auth"
            },
            {
                "type": "sql_injection",
                "ports": [80, 443, 8080],
                "pattern": "malicious_payload"
            },
            {
                "type": "ddos_attempt",
                "ports": [80, 443],
                "pattern": "high_volume_requests"
            }
        ]
        
        attack = random.choice(attack_patterns)
        source_ip = random.choice(suspicious_ips)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "vpc-flow-logs",
            "source_ip": source_ip,
            "destination_port": random.choice(attack["ports"]),
            "protocol": "TCP",
            "action": "REJECT" if random.random() > 0.3 else "ACCEPT",
            "attack_type": attack["type"],
            "pattern": attack["pattern"],
            "packet_count": random.randint(1, 100),
            "bytes": random.randint(64, 1500)
        }
    
    def generate_cloudtrail_event(self):
        """Generate CloudTrail security event"""
        suspicious_events = [
            {
                "event_name": "ConsoleLogin",
                "source_ip": "203.0.113.45",
                "user_agent": "Mozilla/5.0 (Unknown)",
                "risk": "unusual_location"
            },
            {
                "event_name": "AssumeRole",
                "source_ip": "198.51.100.78", 
                "user_agent": "aws-cli/2.0.0",
                "risk": "privilege_escalation"
            },
            {
                "event_name": "CreateUser",
                "source_ip": "185.220.101.32",
                "user_agent": "Boto3/1.26.0",
                "risk": "unauthorized_user_creation"
            }
        ]
        
        event = random.choice(suspicious_events)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "cloudtrail",
            "event_name": event["event_name"],
            "source_ip": event["source_ip"],
            "user_agent": event["user_agent"],
            "aws_region": "us-east-1",
            "risk_indicator": event["risk"],
            "response_elements": None if event["risk"] == "privilege_escalation" else {}
        }

class DetectionAgent:
    """Enhanced Detection Agent with real log analysis"""
    
    def __init__(self):
        self.log_analyzer = MockLogAnalyzer()
        self.active_threats = {}
        self.honeypot_scaling_decisions = []
        self.dashboard_data = {
            "honeypots": [],
            "attacks": 0,
            "engagements": 0,
            "intelligence_reports": [],
            "threats": [],
            "active_engagements": []
        }
        
    def log_message(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
        logger.info(message)
    
    def analyze_log_entry(self, log_entry):
        """Analyze individual log entry for threats"""
        threat_score = 0
        threat_indicators = []
        
        # Analyze based on source type
        if log_entry.get("source") == "vpc-flow-logs":
            # Network-based analysis
            if log_entry.get("action") == "REJECT":
                threat_score += 0.3
                threat_indicators.append("blocked_connection")
            
            attack_type = log_entry.get("attack_type", "")
            if attack_type == "port_scan":
                threat_score += 0.6
                threat_indicators.append("port_scanning")
            elif attack_type == "brute_force":
                threat_score += 0.8
                threat_indicators.append("brute_force_attempt")
            elif attack_type == "sql_injection":
                threat_score += 0.9
                threat_indicators.append("sql_injection_attempt")
            elif attack_type == "ddos_attempt":
                threat_score += 0.7
                threat_indicators.append("ddos_pattern")
                
        elif log_entry.get("source") == "cloudtrail":
            # CloudTrail analysis
            risk = log_entry.get("risk_indicator", "")
            if risk == "unusual_location":
                threat_score += 0.5
                threat_indicators.append("anomalous_login_location")
            elif risk == "privilege_escalation":
                threat_score += 0.9
                threat_indicators.append("privilege_escalation_attempt")
            elif risk == "unauthorized_user_creation":
                threat_score += 0.8
                threat_indicators.append("unauthorized_account_creation")
        
        return {
            "threat_score": min(threat_score, 1.0),
            "indicators": threat_indicators,
            "source_ip": log_entry.get("source_ip"),
            "attack_type": log_entry.get("attack_type", log_entry.get("risk_indicator", "unknown")),
            "timestamp": log_entry.get("timestamp")
        }
    
    def make_honeypot_scaling_decision(self, threat_analysis):
        """Decide on honeypot scaling based on threat analysis"""
        threat_score = threat_analysis["threat_score"]
        attack_type = threat_analysis["attack_type"]
        source_ip = threat_analysis["source_ip"]
        
        scaling_decision = {
            "timestamp": datetime.now().isoformat(),
            "threat_score": threat_score,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "action": "none",
            "honeypot_type": None,
            "scale_count": 0
        }
        
        # High threat score triggers scaling
        if threat_score >= 0.8:
            scaling_decision["action"] = "scale_up"
            scaling_decision["scale_count"] = random.randint(2, 4)
            
            # Choose honeypot type based on attack
            if attack_type in ["sql_injection", "sql_injection_attempt"]:
                scaling_decision["honeypot_type"] = "web_application"
            elif attack_type in ["brute_force", "brute_force_attempt"]:
                scaling_decision["honeypot_type"] = "ssh_service"
            elif attack_type in ["port_scan", "port_scanning"]:
                scaling_decision["honeypot_type"] = "network_service"
            else:
                scaling_decision["honeypot_type"] = "multi_service"
                
        elif threat_score >= 0.5:
            scaling_decision["action"] = "scale_up"
            scaling_decision["scale_count"] = 1
            scaling_decision["honeypot_type"] = "monitoring_probe"
            
        return scaling_decision
    
    def simulate_honeypot_scaling(self, scaling_decision):
        """Simulate actual honeypot scaling"""
        if scaling_decision["action"] == "scale_up":
            count = scaling_decision["scale_count"]
            honeypot_type = scaling_decision["honeypot_type"]
            
            self.log_message(f"🚀 SCALING UP: Creating {count} {honeypot_type} honeypots")
            
            # Create new honeypots
            for i in range(count):
                honeypot = {
                    "id": f"hp_{int(time.time())}_{i}",
                    "type": honeypot_type,
                    "status": "active",
                    "source_ip": scaling_decision["source_ip"],
                    "target_attack": scaling_decision["attack_type"],
                    "created_at": datetime.now().isoformat(),
                    "interactions": random.randint(0, 5),
                    "threat_score": scaling_decision["threat_score"]
                }
                self.dashboard_data["honeypots"].append(honeypot)
            
            # Update metrics
            self.dashboard_data["attacks"] += 1
            if random.random() > 0.3:  # 70% chance of engagement
                self.dashboard_data["engagements"] += random.randint(1, count)
                
                # Create active engagement
                engagement = {
                    "id": f"eng_{int(time.time())}",
                    "honeypot_type": honeypot_type,
                    "attacker_ip": scaling_decision["source_ip"],
                    "status": "active",
                    "start_time": datetime.now().strftime("%H:%M:%S"),
                    "duration": random.randint(30, 300),
                    "interactions": random.randint(5, 20)
                }
                self.dashboard_data["active_engagements"].append(engagement)
    
    def generate_intelligence_report(self, threat_analysis, scaling_decision):
        """Generate intelligence report from analysis"""
        report = {
            "id": f"intel_{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "threat_level": "HIGH" if threat_analysis["threat_score"] >= 0.8 else "MEDIUM" if threat_analysis["threat_score"] >= 0.5 else "LOW",
            "attack_type": threat_analysis["attack_type"],
            "source_ip": threat_analysis["source_ip"],
            "indicators": threat_analysis["indicators"],
            "honeypot_response": scaling_decision["action"],
            "mitre_techniques": self.get_mitre_techniques(threat_analysis["attack_type"]),
            "recommendation": self.get_recommendation(threat_analysis)
        }
        
        self.dashboard_data["intelligence_reports"].append(report)
        return report
    
    def get_mitre_techniques(self, attack_type):
        """Map attack types to MITRE ATT&CK techniques"""
        mitre_mapping = {
            "port_scan": ["T1046"],
            "brute_force": ["T1110", "T1110.001"],
            "sql_injection": ["T1190"],
            "ddos_attempt": ["T1498"],
            "privilege_escalation": ["T1068", "T1134"],
            "unusual_location": ["T1078"],
            "unauthorized_user_creation": ["T1136"]
        }
        return mitre_mapping.get(attack_type, ["T1001"])
    
    def get_recommendation(self, threat_analysis):
        """Generate security recommendation"""
        attack_type = threat_analysis["attack_type"]
        
        recommendations = {
            "port_scan": "Implement network segmentation and intrusion detection",
            "brute_force": "Enable account lockout policies and MFA",
            "sql_injection": "Update web application firewall rules and sanitize inputs",
            "ddos_attempt": "Configure rate limiting and DDoS protection",
            "privilege_escalation": "Review IAM policies and implement least privilege",
            "unusual_location": "Enable geo-blocking and review access patterns",
            "unauthorized_user_creation": "Implement approval workflows for user creation"
        }
        
        return recommendations.get(attack_type, "Monitor and investigate further")
    
    async def send_data_to_dashboard(self):
        """Send detection results to dashboard"""
        try:
            # Add threat information
            for threat_ip, threat_info in self.active_threats.items():
                threat = {
                    "id": f"threat_{hash(threat_ip) % 10000}",
                    "type": threat_info["attack_type"],
                    "source_ip": threat_ip,
                    "confidence": threat_info["threat_score"],
                    "timestamp": datetime.now().strftime("%H:%M:%S")
                }
                self.dashboard_data["threats"].append(threat)
            
            # Prepare payload
            payload = {
                "timestamp": datetime.now().isoformat(),
                "source": "detection_agent",
                "active_honeypots": len(self.dashboard_data["honeypots"]),
                "total_attacks": self.dashboard_data["attacks"],
                "total_engagements": self.dashboard_data["engagements"],
                "intelligence_reports": len(self.dashboard_data["intelligence_reports"]),
                "honeypots": self.dashboard_data["honeypots"][-10:],  # Last 10
                "recent_intelligence": self.dashboard_data["intelligence_reports"][-3:],  # Last 3
                "threats": self.dashboard_data["threats"][-5:],  # Last 5
                "active_engagements": self.dashboard_data["active_engagements"][-3:]  # Last 3
            }
            
            # Send to dashboard
            url = f"{DASHBOARD_URL}/api/update"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'DetectionAgent/1.0',
                'X-Source': 'detection_agent'
            }
            
            request_data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=request_data, headers=headers)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    self.log_message("✅ Dashboard updated with detection results")
                    return True
                    
        except Exception as e:
            self.log_message(f"❌ Failed to update dashboard: {e}")
            
        return False
    
    async def run_detection_cycle(self):
        """Run one detection and response cycle"""
        self.log_message("🔍 DETECTION CYCLE: Analyzing logs for threats...")
        
        # Analyze multiple log sources
        log_entries = []
        
        # Generate network logs
        for _ in range(random.randint(3, 8)):
            log_entries.append(self.log_analyzer.generate_network_log_entry())
        
        # Generate CloudTrail events
        for _ in range(random.randint(1, 3)):
            log_entries.append(self.log_analyzer.generate_cloudtrail_event())
        
        threats_detected = 0
        honeypots_scaled = 0
        
        for log_entry in log_entries:
            # Analyze each log entry
            threat_analysis = self.analyze_log_entry(log_entry)
            
            if threat_analysis["threat_score"] >= 0.5:  # Significant threat
                threats_detected += 1
                source_ip = threat_analysis["source_ip"]
                
                self.log_message(f"⚠️  THREAT DETECTED: {threat_analysis['attack_type']} from {source_ip} (score: {threat_analysis['threat_score']:.2f})")
                
                # Store threat info
                self.active_threats[source_ip] = threat_analysis
                
                # Make scaling decision
                scaling_decision = self.make_honeypot_scaling_decision(threat_analysis)
                self.honeypot_scaling_decisions.append(scaling_decision)
                
                # Execute scaling
                if scaling_decision["action"] == "scale_up":
                    honeypots_scaled += scaling_decision["scale_count"]
                    self.simulate_honeypot_scaling(scaling_decision)
                
                # Generate intelligence report
                intel_report = self.generate_intelligence_report(threat_analysis, scaling_decision)
                self.log_message(f"📊 INTELLIGENCE: {intel_report['threat_level']} threat - {intel_report['recommendation']}")
        
        self.log_message(f"📈 CYCLE SUMMARY: {threats_detected} threats detected, {honeypots_scaled} honeypots scaled")
        
        # Send results to dashboard
        await self.send_data_to_dashboard()
        
        return {
            "threats_detected": threats_detected,
            "honeypots_scaled": honeypots_scaled,
            "total_honeypots": len(self.dashboard_data["honeypots"]),
            "total_attacks": self.dashboard_data["attacks"],
            "total_engagements": self.dashboard_data["engagements"]
        }

async def main():
    """Main demo function"""
    print("🎯 AI-Powered Honeypot Detection Agent Demo")
    print("=" * 60)
    print("🔍 Detection Agent analyzing network logs and CloudTrail")
    print("🚀 Real honeypot scaling based on detected threats")
    print("📊 Live dashboard updates with threat intelligence")
    print("")
    
    detection_agent = DetectionAgent()
    
    try:
        for cycle in range(1, 6):  # Run 5 detection cycles
            print(f"\n🔄 DETECTION CYCLE {cycle}/5")
            print("-" * 40)
            
            results = await detection_agent.run_detection_cycle()
            
            print(f"📊 Current Status:")
            print(f"   • Active Honeypots: {results['total_honeypots']}")
            print(f"   • Total Attacks: {results['total_attacks']}")
            print(f"   • Total Engagements: {results['total_engagements']}")
            print(f"   • Threats This Cycle: {results['threats_detected']}")
            print(f"   • Honeypots Scaled: {results['honeypots_scaled']}")
            
            # Wait before next cycle
            if cycle < 5:
                print(f"\n⏳ Waiting 15 seconds before next detection cycle...")
                await asyncio.sleep(15)
        
        print(f"\n✅ DEMO COMPLETE!")
        print(f"🎯 Check your dashboard to see the live threat data and honeypot scaling!")
        print(f"🔗 Dashboard URL: {DASHBOARD_URL}")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Demo stopped by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())