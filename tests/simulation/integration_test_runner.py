"""
Enhanced Integration Test Runner
Comprehensive integration testing with simulation components
"""

import asyncio
import json
import logging
import os
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import aiohttp
import redis.asyncio as redis

# Import simulation modules
from threat_feed_generator import SyntheticThreatGenerator, ThreatEvent
from attacker_simulator import AttackerSimulator, AttackResult
from performance_tester import PerformanceTester, PerformanceMetrics
from intelligence_validator import IntelligenceValidator, IntelligenceReport, ValidationReport

logger = logging.getLogger(__name__)

@dataclass
class TestEnvironment:
    """Configuration for test environment"""
    agentcore_url: str = "http://localhost:8000"
    detection_agent_url: str = "http://localhost:8001"
    coordinator_agent_url: str = "http://localhost:8002"
    interaction_agent_url: str = "http://localhost:8003"
    intelligence_agent_url: str = "http://localhost:8004"
    dashboard_url: str = "http://localhost:8090"
    redis_url: str = "redis://localhost:6379/0"
    database_url: str = "postgresql://honeypot:honeypot_dev_password@localhost:5432/honeypot_intelligence"
    
    # Honeypot endpoints
    ssh_honeypot: str = "localhost:2222"
    web_admin_honeypot: str = "http://localhost:8080"
    database_honeypot_mysql: str = "localhost:3306"
    database_honeypot_postgres: str = "localhost:5433"

class ThreatSimulator:
    """Simulates threat feeds for testing detection logic"""
    
    def __init__(self):
        self.threat_generator = SyntheticThreatGenerator()
        
    def generate_synthetic_threats(self, count: int = 10) -> List[ThreatEvent]:
        """Generate synthetic threats for testing"""
        return self.threat_generator.generate_threat_feed(count)
    
    def generate_threat_campaign(self, size: int = 5) -> List[ThreatEvent]:
        """Generate coordinated threat campaign"""
        return self.threat_generator.generate_threat_campaign(size)
    
    def export_threats(self, threats: List[ThreatEvent], filename: str) -> str:
        """Export threats to file"""
        return self.threat_generator.export_to_json(threats, filename)

class AttackerSimulationRunner:
    """Runs attacker simulations against honeypots"""
    
    def __init__(self, honeypot_endpoints: Dict[str, str] = None):
        self.attacker_simulator = AttackerSimulator(honeypot_endpoints)
    
    async def simulate_attack(self, attack_type: str, duration: int = 60) -> AttackResult:
        """Simulate specific attack type"""
        return await self.attacker_simulator.run_scenario(attack_type)
    
    async def simulate_attack_campaign(self, scenarios: List[str]) -> List[AttackResult]:
        """Simulate coordinated attack campaign"""
        return await self.attacker_simulator.run_campaign(scenarios)
    
    def get_available_scenarios(self) -> List[str]:
        """Get available attack scenarios"""
        return self.attacker_simulator.get_available_scenarios()

class PerformanceTestRunner:
    """Runs performance and load tests"""
    
    def __init__(self, base_urls: Dict[str, str] = None):
        self.performance_tester = PerformanceTester(base_urls)
    
    async def run_load_test(self, test_name: str) -> PerformanceMetrics:
        """Run specific load test"""
        config = self.performance_tester.test_configs.get(test_name)
        if not config:
            raise ValueError(f"Unknown test: {test_name}")
        
        return await self.performance_tester.run_load_test(config)
    
    async def run_stress_test(self, service: str = "agentcore") -> List[PerformanceMetrics]:
        """Run stress test with increasing load"""
        return await self.performance_tester.run_stress_test(service)
    
    async def run_endurance_test(self, service: str = "agentcore", hours: int = 1) -> PerformanceMetrics:
        """Run endurance test"""
        return await self.performance_tester.run_endurance_test(service, duration_hours=hours)

class IntelligenceValidationRunner:
    """Validates intelligence extraction quality"""
    
    def __init__(self):
        self.intelligence_validator = IntelligenceValidator()
    
    async def validate_intelligence_report(self, report: IntelligenceReport) -> ValidationReport:
        """Validate intelligence report quality"""
        return await self.intelligence_validator.validate_report(report)
    
    def create_sample_report(self, session_data: Dict[str, Any]) -> IntelligenceReport:
        """Create sample intelligence report from session data"""
        return IntelligenceReport(
            report_id=f"report-{random.randint(1000, 9999)}",
            session_id=session_data.get("session_id", "unknown"),
            timestamp=datetime.utcnow(),
            mitre_techniques=session_data.get("mitre_techniques", []),
            iocs=session_data.get("iocs", []),
            threat_assessment=session_data.get("threat_assessment", ""),
            confidence_score=session_data.get("confidence_score", 0.5),
            raw_session_data=session_data,
            extracted_commands=session_data.get("commands", []),
            extracted_credentials=session_data.get("credentials", [])
        )

class IntegrationTestRunner:
    """Runs comprehensive integration tests"""
    
    def __init__(self, environment: TestEnvironment = None):
        self.env = environment or TestEnvironment()
        self.redis_client = None
        
        # Initialize simulation components
        self.threat_simulator = ThreatSimulator()
        self.attacker_simulator = AttackerSimulationRunner()
        self.performance_tester = PerformanceTestRunner()
        self.intelligence_validator = IntelligenceValidationRunner()
        
    async def initialize(self):
        """Initialize test environment"""
        try:
            # Connect to Redis
            self.redis_client = redis.from_url(self.env.redis_url)
            await self.redis_client.ping()
            logger.info("Connected to Redis for integration testing")
            
            # Verify all services are running
            await self.verify_services()
            
        except Exception as e:
            logger.error(f"Failed to initialize integration test environment: {e}")
            raise
    
    async def verify_services(self):
        """Verify all required services are running"""
        services = {
            "AgentCore Runtime": self.env.agentcore_url,
            "Detection Agent": self.env.detection_agent_url,
            "Coordinator Agent": self.env.coordinator_agent_url,
            "Interaction Agent": self.env.interaction_agent_url,
            "Intelligence Agent": self.env.intelligence_agent_url,
            "Dashboard": self.env.dashboard_url
        }
        
        async with aiohttp.ClientSession() as session:
            for service_name, url in services.items():
                try:
                    async with session.get(f"{url}/health", timeout=5) as response:
                        if response.status == 200:
                            logger.info(f"✓ {service_name} is running")
                        else:
                            logger.warning(f"⚠ {service_name} returned status {response.status}")
                except Exception as e:
                    logger.error(f"✗ {service_name} is not accessible: {e}")
                    raise
    
    async def run_end_to_end_test(self) -> Dict[str, Any]:
        """Run complete end-to-end integration test"""
        logger.info("Starting end-to-end integration test")
        
        test_results = {
            "test_id": f"e2e-{int(time.time())}",
            "start_time": datetime.utcnow().isoformat(),
            "steps": [],
            "success": False,
            "errors": []
        }
        
        try:
            # Step 1: Generate synthetic threat
            logger.info("Step 1: Generating synthetic threat")
            threats = self.threat_simulator.generate_synthetic_threats(1)
            threat_data = self._convert_threat_to_dict(threats[0])
            test_results["steps"].append({
                "step": 1,
                "name": "Generate Threat",
                "success": True,
                "data": threat_data
            })
            
            # Step 2: Submit threat to Detection Agent
            logger.info("Step 2: Submitting threat to Detection Agent")
            detection_result = await self.submit_threat_for_detection(threat_data)
            test_results["steps"].append({
                "step": 2,
                "name": "Threat Detection",
                "success": detection_result.get("engagement_decision", False),
                "data": detection_result
            })
            
            # Step 3: Coordinator creates honeypot
            if detection_result.get("engagement_decision"):
                logger.info("Step 3: Coordinator creating honeypot")
                honeypot_result = await self.create_honeypot_environment()
                test_results["steps"].append({
                    "step": 3,
                    "name": "Honeypot Creation",
                    "success": honeypot_result.get("success", False),
                    "data": honeypot_result
                })
                
                # Step 4: Simulate attacker interaction
                if honeypot_result.get("success"):
                    logger.info("Step 4: Simulating attacker interaction")
                    interaction_result = await self.simulate_attacker_interaction(
                        honeypot_result["honeypot_id"]
                    )
                    test_results["steps"].append({
                        "step": 4,
                        "name": "Attacker Interaction",
                        "success": interaction_result.get("success", False),
                        "data": interaction_result
                    })
                    
                    # Step 5: Intelligence extraction
                    if interaction_result.get("success"):
                        logger.info("Step 5: Extracting intelligence")
                        intelligence_result = await self.extract_intelligence(
                            interaction_result["session_id"]
                        )
                        test_results["steps"].append({
                            "step": 5,
                            "name": "Intelligence Extraction",
                            "success": intelligence_result.get("success", False),
                            "data": intelligence_result
                        })
                        
                        # Step 6: Validate intelligence quality
                        if intelligence_result.get("success"):
                            logger.info("Step 6: Validating intelligence quality")
                            validation_result = await self.validate_intelligence_quality(
                                intelligence_result
                            )
                            test_results["steps"].append({
                                "step": 6,
                                "name": "Intelligence Validation",
                                "success": validation_result.get("success", False),
                                "data": validation_result
                            })
            
            # Check overall success
            test_results["success"] = all(
                step.get("success", False) for step in test_results["steps"]
            )
            
        except Exception as e:
            logger.error(f"End-to-end test failed: {e}")
            test_results["errors"].append(str(e))
        
        test_results["end_time"] = datetime.utcnow().isoformat()
        
        logger.info(f"End-to-end test completed. Success: {test_results['success']}")
        return test_results
    
    def _convert_threat_to_dict(self, threat: ThreatEvent) -> Dict[str, Any]:
        """Convert ThreatEvent to dictionary"""
        return {
            "event_id": threat.event_id,
            "timestamp": threat.timestamp.isoformat(),
            "source_ip": threat.source_ip,
            "target_ip": threat.target_ip,
            "target_port": threat.target_port,
            "protocol": threat.protocol,
            "threat_type": threat.threat_type.value,
            "severity": threat.severity.value,
            "confidence_score": threat.confidence_score,
            "description": threat.description,
            "mitre_techniques": threat.mitre_techniques,
            "indicators": [
                {
                    "type": ind.indicator_type,
                    "value": ind.value,
                    "confidence": ind.confidence
                }
                for ind in threat.indicators
            ]
        }
    
    async def submit_threat_for_detection(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit threat to Detection Agent for analysis"""
        async with aiohttp.ClientSession() as session:
            try:
                # Submit to AgentCore message bus
                message_data = {
                    "exchange": "agent.events",
                    "routing_key": "threat.detected",
                    "message_data": threat_data,
                    "message_type": "threat_event"
                }
                
                async with session.post(
                    f"{self.env.agentcore_url}/messages/publish",
                    json=message_data,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        # Wait for detection agent to process
                        await asyncio.sleep(2)
                        
                        # Check for engagement decision
                        return {
                            "engagement_decision": threat_data["confidence_score"] > 0.75,
                            "confidence_score": threat_data["confidence_score"],
                            "message_id": (await response.json()).get("message_id")
                        }
                    else:
                        return {"engagement_decision": False, "error": f"HTTP {response.status}"}
                        
            except Exception as e:
                return {"engagement_decision": False, "error": str(e)}
    
    async def create_honeypot_environment(self) -> Dict[str, Any]:
        """Request Coordinator Agent to create honeypot"""
        async with aiohttp.ClientSession() as session:
            try:
                honeypot_data = {
                    "honeypot_id": f"honeypot-ssh-{random.randint(1000, 9999)}",
                    "honeypot_type": "ssh",
                    "endpoint": self.env.ssh_honeypot,
                    "metadata": {
                        "created_for_test": True,
                        "test_timestamp": datetime.utcnow().isoformat()
                    }
                }
                
                async with session.post(
                    f"{self.env.agentcore_url}/honeypots/register",
                    json=honeypot_data,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        
                        # Wait for honeypot to be ready
                        await asyncio.sleep(3)
                        
                        return {
                            "success": True,
                            "honeypot_id": honeypot_data["honeypot_id"],
                            "endpoint": honeypot_data["endpoint"]
                        }
                    else:
                        return {"success": False, "error": f"HTTP {response.status}"}
                        
            except Exception as e:
                return {"success": False, "error": str(e)}
    
    async def simulate_attacker_interaction(self, honeypot_id: str) -> Dict[str, Any]:
        """Simulate attacker interaction with honeypot"""
        try:
            session_id = f"session-{random.randint(1000, 9999)}"
            
            # Create engagement session
            session_data = {
                "session_id": session_id,
                "honeypot_id": honeypot_id,
                "attacker_ip": f"192.168.100.{random.randint(1, 254)}",
                "metadata": {
                    "test_session": True,
                    "attack_type": "brute_force"
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.env.agentcore_url}/sessions/create",
                    json=session_data,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        # Simulate interaction events
                        interaction_events = [
                            {"action": "login_attempt", "username": "admin", "password": "admin"},
                            {"action": "login_attempt", "username": "root", "password": "password"},
                            {"action": "successful_login", "username": "admin", "password": "password"},
                            {"action": "command_execution", "command": "whoami"},
                            {"action": "command_execution", "command": "ls -la"},
                            {"action": "command_execution", "command": "cat /etc/passwd"}
                        ]
                        
                        # Publish interaction events
                        for event in interaction_events:
                            event_data = {
                                "exchange": "agent.events",
                                "routing_key": "session.interaction",
                                "message_data": {
                                    "session_id": session_id,
                                    "honeypot_id": honeypot_id,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    **event
                                },
                                "message_type": "interaction"
                            }
                            
                            await session.post(
                                f"{self.env.agentcore_url}/messages/publish",
                                json=event_data
                            )
                            
                            await asyncio.sleep(0.5)  # Realistic timing
                        
                        # End session
                        await session.post(
                            f"{self.env.agentcore_url}/sessions/{session_id}/end"
                        )
                        
                        return {
                            "success": True,
                            "session_id": session_id,
                            "interactions": len(interaction_events),
                            "session_data": {
                                "commands": ["whoami", "ls -la", "cat /etc/passwd"],
                                "credentials": [{"username": "admin", "password": "password"}],
                                "mitre_techniques": ["T1110", "T1078", "T1021"],
                                "confidence_score": 0.87
                            }
                        }
                    else:
                        return {"success": False, "error": f"HTTP {response.status}"}
                        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def extract_intelligence(self, session_id: str) -> Dict[str, Any]:
        """Request Intelligence Agent to extract intelligence"""
        try:
            # Wait for intelligence processing
            await asyncio.sleep(3)
            
            # Simulate intelligence extraction by publishing request
            async with aiohttp.ClientSession() as session:
                intelligence_request = {
                    "exchange": "agent.commands",
                    "routing_key": "intelligence-agent",
                    "message_data": {
                        "command": "extract_intelligence",
                        "parameters": {
                            "session_id": session_id,
                            "analysis_type": "comprehensive"
                        }
                    },
                    "message_type": "command"
                }
                
                async with session.post(
                    f"{self.env.agentcore_url}/messages/publish",
                    json=intelligence_request,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        # Wait for processing
                        await asyncio.sleep(5)
                        
                        # Simulate successful intelligence extraction
                        report_id = f"report-{random.randint(1000, 9999)}"
                        
                        return {
                            "success": True,
                            "report_id": report_id,
                            "session_id": session_id,
                            "mitre_techniques": ["T1110", "T1078", "T1021"],
                            "confidence_score": 0.87,
                            "iocs": [
                                {"type": "ip", "value": f"192.168.100.{random.randint(1, 254)}"},
                                {"type": "credential", "value": "admin:password"}
                            ],
                            "threat_assessment": "SSH brute force attack successfully compromised system using weak credentials. Attacker performed reconnaissance and attempted privilege escalation.",
                            "extracted_commands": ["whoami", "ls -la", "cat /etc/passwd"],
                            "extracted_credentials": [{"username": "admin", "password": "password"}]
                        }
                    else:
                        return {"success": False, "error": f"HTTP {response.status}"}
                        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def validate_intelligence_quality(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the quality of extracted intelligence"""
        try:
            # Create intelligence report for validation
            report = self.intelligence_validator.create_sample_report(intelligence_data)
            
            # Run validation
            validation_report = await self.intelligence_validator.validate_intelligence_report(report)
            
            return {
                "success": validation_report.overall_score > 0.6,
                "report_id": intelligence_data.get("report_id"),
                "validation_score": validation_report.overall_score,
                "passed_tests": validation_report.passed_tests,
                "failed_tests": validation_report.failed_tests,
                "warning_tests": validation_report.warning_tests,
                "recommendations": validation_report.recommendations
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_comprehensive_test_suite(self) -> Dict[str, Any]:
        """Run comprehensive test suite including all test types"""
        logger.info("Starting comprehensive test suite")
        
        suite_results = {
            "suite_id": f"comprehensive-{int(time.time())}",
            "start_time": datetime.utcnow().isoformat(),
            "tests": {},
            "overall_success": False,
            "summary": {}
        }
        
        try:
            # 1. End-to-end integration test
            logger.info("Running end-to-end integration test")
            suite_results["tests"]["e2e"] = await self.run_end_to_end_test()
            
            # 2. Performance tests
            logger.info("Running performance tests")
            perf_results = []
            
            # Quick load tests
            for test_name in ["agent_health_check", "message_publishing"]:
                try:
                    result = await self.performance_tester.run_load_test(test_name)
                    perf_results.append({
                        "test_name": test_name,
                        "success": result.throughput_rps > 0,
                        "throughput_rps": result.throughput_rps,
                        "avg_response_time": result.avg_response_time
                    })
                except Exception as e:
                    perf_results.append({
                        "test_name": test_name,
                        "success": False,
                        "error": str(e)
                    })
            
            suite_results["tests"]["performance"] = perf_results
            
            # 3. Attack simulation tests
            logger.info("Running attack simulation tests")
            attack_results = []
            
            # Run quick attack scenarios
            scenarios = ["ssh_brute_force", "web_admin_attack"]
            for scenario in scenarios:
                try:
                    result = await self.attacker_simulator.simulate_attack(scenario, 30)
                    attack_results.append({
                        "scenario": scenario,
                        "success": result.success,
                        "steps_completed": result.steps_completed,
                        "total_steps": result.total_steps
                    })
                except Exception as e:
                    attack_results.append({
                        "scenario": scenario,
                        "success": False,
                        "error": str(e)
                    })
            
            suite_results["tests"]["attack_simulation"] = attack_results
            
            # 4. Intelligence validation tests
            logger.info("Running intelligence validation tests")
            
            # Create sample intelligence reports and validate them
            validation_results = []
            
            for i in range(3):
                sample_data = {
                    "session_id": f"test-session-{i}",
                    "mitre_techniques": ["T1110", "T1078"],
                    "iocs": [{"type": "ip", "value": f"192.168.1.{i+100}"}],
                    "threat_assessment": "Test threat assessment for validation",
                    "confidence_score": 0.8,
                    "commands": ["whoami", "ls"],
                    "credentials": [{"username": "test", "password": "test"}]
                }
                
                try:
                    validation_result = await self.validate_intelligence_quality(sample_data)
                    validation_results.append({
                        "sample": i,
                        "success": validation_result["success"],
                        "validation_score": validation_result["validation_score"]
                    })
                except Exception as e:
                    validation_results.append({
                        "sample": i,
                        "success": False,
                        "error": str(e)
                    })
            
            suite_results["tests"]["intelligence_validation"] = validation_results
            
            # Calculate overall success
            all_tests_success = []
            
            # E2E test success
            all_tests_success.append(suite_results["tests"]["e2e"]["success"])
            
            # Performance tests success
            perf_success = all(test.get("success", False) for test in perf_results)
            all_tests_success.append(perf_success)
            
            # Attack simulation success
            attack_success = any(test.get("success", False) for test in attack_results)
            all_tests_success.append(attack_success)
            
            # Intelligence validation success
            intel_success = all(test.get("success", False) for test in validation_results)
            all_tests_success.append(intel_success)
            
            suite_results["overall_success"] = all(all_tests_success)
            
            # Generate summary
            suite_results["summary"] = {
                "e2e_success": suite_results["tests"]["e2e"]["success"],
                "performance_success": perf_success,
                "attack_simulation_success": attack_success,
                "intelligence_validation_success": intel_success,
                "total_tests_run": len(perf_results) + len(attack_results) + len(validation_results) + 1
            }
            
        except Exception as e:
            logger.error(f"Comprehensive test suite failed: {e}")
            suite_results["error"] = str(e)
        
        suite_results["end_time"] = datetime.utcnow().isoformat()
        
        logger.info(f"Comprehensive test suite completed. Overall success: {suite_results['overall_success']}")
        return suite_results
    
    async def cleanup(self):
        """Cleanup test environment"""
        if self.redis_client:
            await self.redis_client.close()

# Convenience functions for testing
async def run_quick_integration_test():
    """Run a quick integration test"""
    runner = IntegrationTestRunner()
    
    try:
        await runner.initialize()
        
        # Run end-to-end test
        e2e_result = await runner.run_end_to_end_test()
        
        # Export results
        results = {
            "end_to_end_test": e2e_result,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        with open("quick_integration_test_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        logger.info("Quick integration test completed")
        return results
        
    finally:
        await runner.cleanup()

async def run_comprehensive_test_suite():
    """Run comprehensive test suite"""
    runner = IntegrationTestRunner()
    
    try:
        await runner.initialize()
        
        # Run comprehensive test suite
        results = await runner.run_comprehensive_test_suite()
        
        # Export results
        with open("comprehensive_test_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        logger.info("Comprehensive test suite completed")
        return results
        
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Run integration tests")
    parser.add_argument("--test-type", choices=["quick", "comprehensive"], 
                       default="quick", help="Type of test to run")
    
    args = parser.parse_args()
    
    if args.test_type == "quick":
        asyncio.run(run_quick_integration_test())
    else:
        asyncio.run(run_comprehensive_test_suite())