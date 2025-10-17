#!/usr/bin/env python3
"""
Simple Demo Script for AI-Powered Honeypot System
No external dependencies required - pure Python simulation
"""

import time
import json
from datetime import datetime
import random

class SimpleHoneypotDemo:
    def __init__(self):
        self.attacks_launched = []
        self.detections = []
        self.intelligence_reports = []
        
    def run_demo(self):
        """Run the complete demo simulation"""
        print("🎭 AI-Powered Honeypot System - Live Demo")
        print("=" * 55)
        print("Simulating real-time web attack detection and response...")
        print()
        
        # Step 1: System initialization
        self.show_system_startup()
        
        # Step 2: Launch attacks
        self.simulate_web_attacks()
        
        # Step 3: Show AI detection
        self.show_ai_detection()
        
        # Step 4: Show honeypot engagement
        self.show_honeypot_engagement()
        
        # Step 5: Show intelligence extraction
        self.show_intelligence_extraction()
        
        # Step 6: Summary
        self.show_demo_summary()
        
    def show_system_startup(self):
        """Simulate system startup"""
        print("🚀 Initializing AI-Powered Honeypot System...")
        
        agents = [
            "Detection Agent (AI Threat Analysis)",
            "Coordinator Agent (Orchestration)", 
            "Interaction Agent (Attacker Engagement)",
            "Intelligence Agent (Data Analysis)"
        ]
        
        for agent in agents:
            print(f"   ✅ {agent} - Online")
            time.sleep(0.5)
        
        print("   ✅ AgentCore Runtime - Connected")
        print("   ✅ Honeypot Infrastructure - Ready")
        print("   ✅ AI Models - Loaded")
        print()
        time.sleep(1)
        
    def simulate_web_attacks(self):
        """Simulate incoming web attacks"""
        print("🎯 Incoming Web Attacks Detected...")
        print("-" * 40)
        
        attacks = [
            {
                "type": "SQL Injection",
                "payload": "' OR '1'='1 --",
                "source_ip": "192.168.1.100",
                "target": "/admin/login",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            },
            {
                "type": "Cross-Site Scripting (XSS)",
                "payload": "<script>alert('XSS')</script>",
                "source_ip": "192.168.1.100", 
                "target": "/search?q=",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            },
            {
                "type": "Admin Brute Force",
                "payload": "admin:password123",
                "source_ip": "192.168.1.100",
                "target": "/admin/login",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            },
            {
                "type": "Directory Traversal",
                "payload": "../../../etc/passwd",
                "source_ip": "192.168.1.100",
                "target": "/files?path=",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
        ]
        
        for attack in attacks:
            print(f"🚨 {attack['timestamp']} - {attack['type']}")
            print(f"   Source: {attack['source_ip']}")
            print(f"   Target: {attack['target']}")
            print(f"   Payload: {attack['payload']}")
            print()
            
            self.attacks_launched.append(attack)
            time.sleep(1.5)
    
    def show_ai_detection(self):
        """Show AI threat detection process"""
        print("🤖 AI Detection Agent Analysis...")
        print("-" * 40)
        
        for attack in self.attacks_launched:
            print(f"🔍 Analyzing: {attack['type']}")
            
            # Simulate AI processing time
            for i in range(3):
                print("   🧠 Processing...", end="", flush=True)
                time.sleep(0.5)
                print(".", end="", flush=True)
                time.sleep(0.5)
            print()
            
            # Generate confidence score
            confidence = random.uniform(0.75, 0.95)
            
            detection = {
                "attack_type": attack['type'],
                "confidence_score": confidence,
                "threat_level": "HIGH" if confidence > 0.85 else "MEDIUM",
                "engagement_decision": confidence > 0.75,
                "mitre_technique": self.get_mitre_technique(attack['type']),
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
            
            print(f"   ✅ Threat Identified: {detection['threat_level']}")
            print(f"   📊 Confidence: {confidence:.1%}")
            print(f"   🎯 MITRE Technique: {detection['mitre_technique']}")
            print(f"   🎭 Engagement: {'APPROVED' if detection['engagement_decision'] else 'DENIED'}")
            print()
            
            self.detections.append(detection)
            time.sleep(1)
    
    def show_honeypot_engagement(self):
        """Show honeypot engagement process"""
        print("🎭 Honeypot Engagement Initiated...")
        print("-" * 40)
        
        engaged_attacks = [d for d in self.detections if d['engagement_decision']]
        
        for detection in engaged_attacks:
            print(f"🏗️  Creating honeypot for: {detection['attack_type']}")
            print("   📦 Provisioning isolated environment...")
            time.sleep(1)
            print("   🔧 Configuring synthetic data...")
            time.sleep(0.8)
            print("   🎪 Honeypot ready - awaiting attacker...")
            print()
            
            # Simulate attacker interaction
            print(f"👤 Attacker engaging with {detection['attack_type']} honeypot...")
            
            interactions = self.simulate_attacker_interaction(detection['attack_type'])
            
            for interaction in interactions:
                print(f"   💬 Attacker: {interaction['attacker_action']}")
                print(f"   🤖 Honeypot: {interaction['honeypot_response']}")
                time.sleep(1.2)
            
            print(f"   ⏰ Session duration: {random.randint(45, 180)} seconds")
            print(f"   📝 {random.randint(15, 35)} interactions captured")
            print()
    
    def simulate_attacker_interaction(self, attack_type):
        """Simulate realistic attacker-honeypot interactions"""
        
        interactions_map = {
            "SQL Injection": [
                {"attacker_action": "SELECT * FROM users", "honeypot_response": "3 rows returned"},
                {"attacker_action": "SHOW TABLES", "honeypot_response": "users, orders, products"},
                {"attacker_action": "SELECT password FROM users", "honeypot_response": "Access granted"}
            ],
            "Cross-Site Scripting (XSS)": [
                {"attacker_action": "Inject XSS payload", "honeypot_response": "Script executed"},
                {"attacker_action": "Attempt cookie theft", "honeypot_response": "Session cookie captured"},
                {"attacker_action": "Try DOM manipulation", "honeypot_response": "DOM modified successfully"}
            ],
            "Admin Brute Force": [
                {"attacker_action": "Try admin:admin", "honeypot_response": "Login failed"},
                {"attacker_action": "Try admin:password", "honeypot_response": "Login failed"},
                {"attacker_action": "Try admin:123456", "honeypot_response": "Login successful!"}
            ],
            "Directory Traversal": [
                {"attacker_action": "Access ../etc/passwd", "honeypot_response": "File contents displayed"},
                {"attacker_action": "Try ../etc/shadow", "honeypot_response": "Permission denied"},
                {"attacker_action": "Enumerate directories", "honeypot_response": "Directory listing shown"}
            ]
        }
        
        return interactions_map.get(attack_type, [
            {"attacker_action": "Probe system", "honeypot_response": "System responds"},
            {"attacker_action": "Attempt exploit", "honeypot_response": "Exploit appears successful"}
        ])
    
    def show_intelligence_extraction(self):
        """Show intelligence extraction and analysis"""
        print("🧠 Intelligence Agent Analysis...")
        print("-" * 40)
        
        print("📊 Extracting intelligence from captured sessions...")
        time.sleep(1.5)
        
        # Generate intelligence report
        report = {
            "campaign_name": "Multi-Vector Web Attack Campaign",
            "attack_techniques": len(set(d['attack_type'] for d in self.detections)),
            "mitre_techniques": list(set(d['mitre_technique'] for d in self.detections)),
            "iocs_extracted": [
                "192.168.1.100",
                "' OR '1'='1 --",
                "<script>alert('XSS')</script>",
                "admin:password123",
                "../../../etc/passwd"
            ],
            "threat_actor_profile": {
                "sophistication": "Low-Medium",
                "motivation": "Opportunistic",
                "tools": "Automated scanners, Manual testing"
            },
            "confidence": 0.87
        }
        
        print(f"📋 Campaign Analysis Complete:")
        print(f"   🎯 Attack Techniques: {report['attack_techniques']}")
        print(f"   🔍 MITRE Techniques: {', '.join(report['mitre_techniques'])}")
        print(f"   🚩 IOCs Extracted: {len(report['iocs_extracted'])}")
        print(f"   👤 Threat Actor: {report['threat_actor_profile']['sophistication']}")
        print(f"   📈 Confidence: {report['confidence']:.1%}")
        print()
        
        print("🔍 Key Indicators of Compromise (IOCs):")
        for ioc in report['iocs_extracted']:
            print(f"   - {ioc}")
        print()
        
        self.intelligence_reports.append(report)
        
    def show_demo_summary(self):
        """Show final demo summary"""
        print("🎉 Demo Complete - System Performance Summary")
        print("=" * 55)
        
        total_attacks = len(self.attacks_launched)
        detected_attacks = len(self.detections)
        engaged_attacks = len([d for d in self.detections if d['engagement_decision']])
        
        print(f"📊 Attack Statistics:")
        print(f"   🎯 Total Attacks: {total_attacks}")
        print(f"   🔍 Detected: {detected_attacks} ({detected_attacks/total_attacks:.0%})")
        print(f"   🎭 Engaged: {engaged_attacks} ({engaged_attacks/total_attacks:.0%})")
        print()
        
        print(f"🧠 Intelligence Generated:")
        print(f"   📋 Reports: {len(self.intelligence_reports)}")
        print(f"   🚩 IOCs: {len(self.intelligence_reports[0]['iocs_extracted']) if self.intelligence_reports else 0}")
        print(f"   🎯 MITRE Techniques: {len(self.intelligence_reports[0]['mitre_techniques']) if self.intelligence_reports else 0}")
        print()
        
        print("✅ What the AI System Accomplished:")
        print("   🤖 Detected sophisticated web attacks using AI")
        print("   🎭 Created realistic honeypot environments")
        print("   💬 Engaged attackers with convincing responses")
        print("   🧠 Extracted actionable threat intelligence")
        print("   📊 Mapped attacks to MITRE ATT&CK framework")
        print("   🚀 Generated intelligence for future defense")
        print()
        
        print("💡 Business Value:")
        print("   🛡️  Enhanced threat detection capabilities")
        print("   📈 Improved security intelligence")
        print("   ⚡ Automated incident response")
        print("   🎯 Proactive threat hunting data")
        
    def get_mitre_technique(self, attack_type):
        """Map attack types to MITRE ATT&CK techniques"""
        mapping = {
            "SQL Injection": "T1190",
            "Cross-Site Scripting (XSS)": "T1059.007", 
            "Admin Brute Force": "T1110.001",
            "Directory Traversal": "T1083"
        }
        return mapping.get(attack_type, "T1190")

def main():
    """Main demo function"""
    demo = SimpleHoneypotDemo()
    
    print("🎬 Starting AI-Powered Honeypot Demo...")
    print("   This demo simulates real web attacks and shows")
    print("   how the AI system detects, engages, and learns.")
    print()
    
    input("Press Enter to start the demo...")
    print()
    
    demo.run_demo()

if __name__ == "__main__":
    main()