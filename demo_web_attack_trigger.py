#!/usr/bin/env python3
"""
Demo Web Attack Trigger
Simple script to trigger web attacks against the honeypot system for demonstration purposes
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from typing import Dict, Any

# Import the existing attacker simulator
from tests.simulation.attacker_simulator import AttackerSimulator
from tests.simulation.threat_feed_generator import ThreatFeedGenerator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WebAttackDemo:
    """Orchestrates web attack demonstrations"""
    
    def __init__(self):
        # Configure honeypot endpoints for demo
        self.honeypot_endpoints = {
            "web_admin": "http://localhost:8080",
            "ssh": "localhost:2222",
            "database_mysql": "localhost:3306",
            "ftp": "localhost:21"
        }
        
        self.attacker_simulator = AttackerSimulator(self.honeypot_endpoints)
        self.threat_generator = ThreatFeedGenerator()
        
    async def run_web_attack_demo(self, attack_type: str = "comprehensive"):
        """Run web attack demonstration"""
        
        print("🎭 Starting AI-Powered Honeypot Web Attack Demo")
        print("=" * 60)
        
        if attack_type == "quick":
            scenarios = ["web_admin_attack"]
        elif attack_type == "comprehensive":
            scenarios = ["web_admin_attack", "sql_injection_focused", "xss_focused"]
        else:
            scenarios = [attack_type]
        
        results = []
        
        for scenario_name in scenarios:
            print(f"\n🚀 Launching {scenario_name}...")
            
            # Generate threat feed entry first
            threat_data = await self._generate_threat_feed(scenario_name)
            print(f"📡 Generated threat feed: {threat_data['threat_type']}")
            
            # Run the attack simulation
            if scenario_name == "web_admin_attack":
                result = await self._run_web_admin_attack()
            elif scenario_name == "sql_injection_focused":
                result = await self._run_sql_injection_attack()
            elif scenario_name == "xss_focused":
                result = await self._run_xss_attack()
            else:
                result = await self.attacker_simulator.run_scenario(scenario_name)
            
            results.append(result)
            
            # Display results
            self._display_attack_result(result)
            
            # Wait between attacks for demo effect
            if len(scenarios) > 1:
                print("\n⏳ Waiting 10 seconds before next attack...")
                await asyncio.sleep(10)
        
        # Summary
        self._display_demo_summary(results)
        
        return results
    
    async def _generate_threat_feed(self, attack_type: str) -> Dict[str, Any]:
        """Generate threat feed data for the attack"""
        
        threat_configs = {
            "web_admin_attack": {
                "threat_type": "web_application_attack",
                "source_ip": "192.168.1.100",
                "attack_vector": "web_admin_brute_force",
                "confidence": 0.85
            },
            "sql_injection_focused": {
                "threat_type": "sql_injection",
                "source_ip": "10.0.0.50",
                "attack_vector": "database_exploitation",
                "confidence": 0.92
            },
            "xss_focused": {
                "threat_type": "cross_site_scripting",
                "source_ip": "172.16.0.25",
                "attack_vector": "web_application_exploit",
                "confidence": 0.78
            }
        }
        
        config = threat_configs.get(attack_type, threat_configs["web_admin_attack"])
        
        # Generate threat using the threat feed generator
        threat_data = await self.threat_generator.generate_web_threat(
            threat_type=config["threat_type"],
            source_ip=config["source_ip"],
            confidence=config["confidence"]
        )
        
        return threat_data
    
    async def _run_web_admin_attack(self):
        """Run comprehensive web admin attack"""
        
        print("🌐 Targeting web admin panel...")
        
        # Create custom web admin attack scenario
        from tests.simulation.attacker_simulator import AttackScenario
        
        web_scenario = AttackScenario(
            name="Demo Web Admin Attack",
            description="Comprehensive web admin panel attack for demo",
            target_honeypot="web_admin",
            attack_steps=[
                {"action": "directory_enumeration", "target": "web_admin"},
                {"action": "login_brute_force", "target": "web_admin", "attempts": 15},
                {"action": "sql_injection_test", "target": "web_admin"},
                {"action": "xss_test", "target": "web_admin"},
                {"action": "file_upload_test", "target": "web_admin"},
                {"action": "privilege_escalation", "target": "web_admin"}
            ],
            expected_duration=300,
            success_indicators=["admin_access", "sql_injection_success", "file_uploaded"]
        )
        
        return await self.attacker_simulator.simulate_web_attack(
            self.honeypot_endpoints["web_admin"], 
            web_scenario
        )
    
    async def _run_sql_injection_attack(self):
        """Run focused SQL injection attack"""
        
        print("💉 Launching SQL injection attack...")
        
        from tests.simulation.attacker_simulator import AttackScenario
        
        sqli_scenario = AttackScenario(
            name="SQL Injection Demo",
            description="Focused SQL injection attack demonstration",
            target_honeypot="web_admin",
            attack_steps=[
                {"action": "parameter_discovery", "target": "web_admin"},
                {"action": "sql_injection_test", "target": "web_admin", "intensive": True},
                {"action": "database_enumeration", "target": "web_admin"},
                {"action": "data_extraction", "target": "web_admin"}
            ],
            expected_duration=180,
            success_indicators=["sql_injection_success", "data_extracted"]
        )
        
        return await self.attacker_simulator.simulate_web_attack(
            self.honeypot_endpoints["web_admin"],
            sqli_scenario
        )
    
    async def _run_xss_attack(self):
        """Run focused XSS attack"""
        
        print("🔗 Launching XSS attack...")
        
        from tests.simulation.attacker_simulator import AttackScenario
        
        xss_scenario = AttackScenario(
            name="XSS Demo Attack",
            description="Cross-site scripting attack demonstration",
            target_honeypot="web_admin",
            attack_steps=[
                {"action": "form_discovery", "target": "web_admin"},
                {"action": "xss_test", "target": "web_admin", "intensive": True},
                {"action": "stored_xss_test", "target": "web_admin"},
                {"action": "dom_xss_test", "target": "web_admin"}
            ],
            expected_duration=120,
            success_indicators=["xss_success", "stored_xss_success"]
        )
        
        return await self.attacker_simulator.simulate_web_attack(
            self.honeypot_endpoints["web_admin"],
            xss_scenario
        )
    
    def _display_attack_result(self, result):
        """Display attack result in a demo-friendly format"""
        
        print(f"\n📊 Attack Result: {result.scenario_name}")
        print("-" * 40)
        print(f"⏱️  Duration: {(result.end_time - result.start_time).total_seconds():.1f} seconds")
        print(f"✅ Steps Completed: {result.steps_completed}/{result.total_steps}")
        print(f"🎯 Success: {'Yes' if result.success else 'No'}")
        
        if result.captured_data:
            print(f"\n📋 Captured Intelligence:")
            for key, value in result.captured_data.items():
                if isinstance(value, (list, dict)):
                    print(f"   {key}: {len(value) if isinstance(value, list) else len(value.keys())} items")
                else:
                    print(f"   {key}: {str(value)[:50]}...")
        
        if result.errors:
            print(f"\n⚠️  Errors Encountered: {len(result.errors)}")
            for error in result.errors[:3]:  # Show first 3 errors
                print(f"   - {error}")
    
    def _display_demo_summary(self, results):
        """Display overall demo summary"""
        
        print("\n" + "=" * 60)
        print("🎉 Demo Summary")
        print("=" * 60)
        
        total_attacks = len(results)
        successful_attacks = sum(1 for r in results if r.success)
        total_duration = sum((r.end_time - r.start_time).total_seconds() for r in results)
        
        print(f"📈 Total Attacks: {total_attacks}")
        print(f"✅ Successful: {successful_attacks}")
        print(f"⏱️  Total Duration: {total_duration:.1f} seconds")
        print(f"🎯 Success Rate: {(successful_attacks/total_attacks)*100:.1f}%")
        
        print(f"\n🧠 Intelligence Collected:")
        all_data = {}
        for result in results:
            for key, value in result.captured_data.items():
                if key not in all_data:
                    all_data[key] = []
                all_data[key].append(value)
        
        for data_type, values in all_data.items():
            print(f"   - {data_type}: {len(values)} instances")
        
        print(f"\n🔍 What the AI System Learned:")
        print("   - Attack patterns and techniques")
        print("   - Attacker behavior and timing")
        print("   - IOCs and threat indicators")
        print("   - MITRE ATT&CK technique mapping")
        print("   - Intelligence for future threat detection")

async def main():
    """Main demo function"""
    
    if len(sys.argv) > 1:
        attack_type = sys.argv[1]
    else:
        attack_type = "comprehensive"
    
    print("🚀 AI-Powered Honeypot Demo Starting...")
    print(f"Attack Type: {attack_type}")
    print("Available types: quick, comprehensive, web_admin_attack, sql_injection_focused, xss_focused")
    
    demo = WebAttackDemo()
    
    try:
        results = await demo.run_web_attack_demo(attack_type)
        
        # Save results for analysis
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"demo_results_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump([{
                "scenario_name": r.scenario_name,
                "start_time": r.start_time.isoformat(),
                "end_time": r.end_time.isoformat(),
                "success": r.success,
                "steps_completed": r.steps_completed,
                "total_steps": r.total_steps,
                "captured_data": r.captured_data,
                "errors": r.errors
            } for r in results], f, indent=2)
        
        print(f"\n💾 Results saved to: {results_file}")
        
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        logger.exception("Demo execution failed")

if __name__ == "__main__":
    asyncio.run(main())