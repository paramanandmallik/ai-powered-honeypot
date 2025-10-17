#!/usr/bin/env python3
"""
Local Detection Agent Demo - No AWS Dependencies
Shows the detection agent working with local dashboard simulation
"""

import time
import random
from datetime import datetime

class LocalDashboard:
    def __init__(self):
        self.honeypots = []
        self.attacks = 0
        self.engagements = 0
        
    def update(self, data):
        if 'honeypots' in data:
            self.honeypots = data['honeypots']
        if 'attacks' in data:
            self.attacks = data['attacks']
        if 'engagements' in data:
            self.engagements = data['engagements']
        
        print(f"📊 DASHBOARD UPDATED:")
        print(f"   • Active Honeypots: {len(self.honeypots)}")
        print(f"   • Total Attacks: {self.attacks}")
        print(f"   • Total Engagements: {self.engagements}")
        print()

def simulate_detection_cycle():
    """Simulate one detection cycle"""
    threats = [
        {"type": "SQL Injection", "ip": "192.168.1.100", "score": 0.9},
        {"type": "Brute Force", "ip": "10.0.0.50", "score": 0.8},
        {"type": "Port Scan", "ip": "172.16.0.25", "score": 0.6},
        {"type": "DDoS Attempt", "ip": "203.0.113.45", "score": 1.0}
    ]
    
    detected_threats = random.sample(threats, random.randint(1, 3))
    honeypots_created = 0
    
    print(f"🔍 DETECTION CYCLE: Analyzing network logs...")
    
    for threat in detected_threats:
        print(f"⚠️  THREAT DETECTED: {threat['type']} from {threat['ip']} (score: {threat['score']:.1f})")
        
        # Scale honeypots based on threat
        if threat['score'] >= 0.8:
            scale_count = random.randint(2, 4)
        else:
            scale_count = 1
            
        honeypots_created += scale_count
        print(f"🚀 SCALING UP: Creating {scale_count} honeypots for {threat['type']}")
    
    return {
        'honeypots': [{'id': f'hp_{i}', 'type': 'web', 'status': 'active'} for i in range(honeypots_created)],
        'attacks': len(detected_threats),
        'engagements': random.randint(0, len(detected_threats))
    }

def main():
    print("🎯 AI-Powered Honeypot Detection Agent - LOCAL DEMO")
    print("=" * 60)
    print("🔍 Detection Agent analyzing logs and scaling honeypots")
    print("📊 Local dashboard showing real-time updates")
    print()
    
    dashboard = LocalDashboard()
    total_honeypots = 0
    total_attacks = 0
    total_engagements = 0
    
    try:
        for cycle in range(1, 6):
            print(f"🔄 DETECTION CYCLE {cycle}/5")
            print("-" * 40)
            
            # Run detection
            results = simulate_detection_cycle()
            
            # Update totals
            total_honeypots += len(results['honeypots'])
            total_attacks += results['attacks']
            total_engagements += results['engagements']
            
            # Update dashboard
            dashboard.update({
                'honeypots': [{'id': f'hp_{i}', 'type': 'active'} for i in range(total_honeypots)],
                'attacks': total_attacks,
                'engagements': total_engagements
            })
            
            if cycle < 5:
                print("⏳ Waiting 3 seconds before next cycle...")
                time.sleep(3)
        
        print("✅ DEMO COMPLETE!")
        print(f"🎯 Final Results:")
        print(f"   • Total Honeypots Scaled: {total_honeypots}")
        print(f"   • Total Attacks Detected: {total_attacks}")
        print(f"   • Total Engagements: {total_engagements}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Demo stopped by user")

if __name__ == "__main__":
    main()