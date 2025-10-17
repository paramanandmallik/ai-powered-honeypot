"""
Integration Test Runner for AI Honeypot System
Orchestrates comprehensive integration and end-to-end testing
"""

import pytest
import asyncio
import time
import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

from tests.integration.test_workflow_integration import TestWorkflowIntegration
from tests.integration.test_agentcore_messaging import TestAgentCoreMessaging
from tests.integration.test_honeypot_lifecycle import TestHoneypotLifecycle
from tests.integration.test_performance_testing import TestPerformanceTesting
from tests.integration.test_security_isolation import TestSecurityIsolation
from tests.integration.test_comprehensive_e2e import TestComprehensiveE2E
from tests.integration.test_end_to_end_comprehensive import TestEndToEndComprehensive


@pytest.mark.integration
@pytest.mark.runner
class TestIntegrationRunner:
    """Comprehensive integration test runner"""

    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.end_time = None
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.skipped_tests = 0

    @pytest.fixture(scope="class")
    async def integration_environment(self):
        """Setup comprehensive integration test environment"""
        config = {
            "use_mock_ai": True,
            "integration_mode": True,
            "comprehensive_logging": True,
            "performance_monitoring": True,
            "security_validation": True,
            "max_concurrent_requests": 20,
            "expected_throughput_rps": 10,
            "expected_response_time_ms": 2000
        }
        
        environment = {
            "config": config,
            "test_data": await self._generate_test_data(),
            "metrics": {
                "start_time": datetime.utcnow(),
                "test_count": 0,
                "error_count": 0
            }
        }
        
        yield environment
        
        # Generate final test report
        await self._generate_test_report(environment)

    async def _generate_test_data(self) -> Dict[str, Any]:
        """Generate comprehensive test data for integration tests"""
        return {
            "threat_samples": [
                {
                    "source_ip": "192.168.1.100",
                    "threat_type": "ssh_brute_force",
                    "confidence": 0.85,
                    "indicators": ["failed_logins", "credential_stuffing"]
                },
                {
                    "source_ip": "10.0.0.50",
                    "threat_type": "web_attack",
                    "confidence": 0.78,
                    "indicators": ["sql_injection", "xss_attempt"]
                },
                {
                    "source_ip": "172.16.0.25",
                    "threat_type": "port_scan",
                    "confidence": 0.92,
                    "indicators": ["port_enumeration", "service_discovery"]
                }
            ],
            "honeypot_configs": [
                {
                    "type": "ssh",
                    "port": 2222,
                    "max_sessions": 5
                },
                {
                    "type": "web_admin",
                    "port": 8080,
                    "ssl_enabled": True
                },
                {
                    "type": "database",
                    "port": 3306,
                    "fake_databases": ["users", "orders"]
                }
            ],
            "attack_scenarios": [
                {
                    "name": "reconnaissance",
                    "commands": ["whoami", "id", "uname -a", "ps aux"]
                },
                {
                    "name": "privilege_escalation",
                    "commands": ["sudo -l", "cat /etc/passwd", "find / -perm -4000"]
                },
                {
                    "name": "lateral_movement",
                    "commands": ["ssh admin@server", "scp file user@host:/tmp/"]
                }
            ]
        }

    async def test_comprehensive_workflow_integration(self, integration_environment):
        """Run comprehensive workflow integration tests"""
        self.start_time = time.time()
        
        # Initialize test classes
        workflow_tests = TestWorkflowIntegration()
        messaging_tests = TestAgentCoreMessaging()
        lifecycle_tests = TestHoneypotLifecycle()
        performance_tests = TestPerformanceTesting()
        security_tests = TestSecurityIsolation()
        e2e_tests = TestComprehensiveE2E()
        comprehensive_tests = TestEndToEndComprehensive()
        
        test_suites = [
            ("Workflow Integration", workflow_tests),
            ("AgentCore Messaging", messaging_tests),
            ("Honeypot Lifecycle", lifecycle_tests),
            ("Performance Testing", performance_tests),
            ("Security Isolation", security_tests),
            ("End-to-End Testing", e2e_tests),
            ("Comprehensive E2E", comprehensive_tests)
        ]
        
        suite_results = {}
        
        for suite_name, test_suite in test_suites:
            print(f"\n=== Running {suite_name} Tests ===")
            
            suite_start = time.time()
            suite_result = await self._run_test_suite(suite_name, test_suite, integration_environment)
            suite_duration = time.time() - suite_start
            
            suite_result["duration"] = suite_duration
            suite_results[suite_name] = suite_result
            
            print(f"{suite_name} completed in {suite_duration:.2f}s")
            print(f"Passed: {suite_result['passed']}, Failed: {suite_result['failed']}")
        
        self.end_time = time.time()
        
        # Aggregate results
        total_duration = self.end_time - self.start_time
        total_passed = sum(result["passed"] for result in suite_results.values())
        total_failed = sum(result["failed"] for result in suite_results.values())
        
        print(f"\n=== Integration Test Summary ===")
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Total Tests: {total_passed + total_failed}")
        print(f"Passed: {total_passed}")
        print(f"Failed: {total_failed}")
        print(f"Success Rate: {(total_passed / (total_passed + total_failed) * 100):.1f}%")
        
        # Verify overall success
        assert total_failed == 0, f"Integration tests failed: {total_failed} failures"
        assert total_passed > 0, "No integration tests were executed"

    async def _run_test_suite(self, suite_name: str, test_suite, environment) -> Dict[str, Any]:
        """Run a specific test suite and collect results"""
        results = {
            "suite_name": suite_name,
            "passed": 0,
            "failed": 0,
            "errors": [],
            "test_details": []
        }
        
        # Get all test methods from the test suite
        test_methods = [
            method for method in dir(test_suite)
            if method.startswith("test_") and callable(getattr(test_suite, method))
        ]
        
        for test_method_name in test_methods:
            test_start = time.time()
            
            try:
                test_method = getattr(test_suite, test_method_name)
                
                # Setup test environment if needed
                if hasattr(test_suite, 'setup_method'):
                    await test_suite.setup_method()
                
                # Run the test
                if asyncio.iscoroutinefunction(test_method):
                    await test_method(environment)
                else:
                    test_method(environment)
                
                test_duration = time.time() - test_start
                results["passed"] += 1
                results["test_details"].append({
                    "name": test_method_name,
                    "status": "passed",
                    "duration": test_duration
                })
                
            except Exception as e:
                test_duration = time.time() - test_start
                results["failed"] += 1
                results["errors"].append({
                    "test": test_method_name,
                    "error": str(e),
                    "duration": test_duration
                })
                results["test_details"].append({
                    "name": test_method_name,
                    "status": "failed",
                    "error": str(e),
                    "duration": test_duration
                })
                
                print(f"  FAILED: {test_method_name} - {str(e)}")
            
            finally:
                # Cleanup test environment if needed
                if hasattr(test_suite, 'teardown_method'):
                    await test_suite.teardown_method()
        
        return results

    async def test_performance_benchmarks(self, integration_environment):
        """Run performance benchmark tests"""
        config = integration_environment["config"]
        
        benchmarks = {
            "threat_detection_throughput": {
                "target": config["expected_throughput_rps"],
                "test": self._benchmark_threat_detection
            },
            "honeypot_creation_time": {
                "target": 5.0,  # seconds
                "test": self._benchmark_honeypot_creation
            },
            "interaction_response_time": {
                "target": config["expected_response_time_ms"],
                "test": self._benchmark_interaction_response
            },
            "intelligence_analysis_time": {
                "target": 10.0,  # seconds
                "test": self._benchmark_intelligence_analysis
            }
        }
        
        benchmark_results = {}
        
        for benchmark_name, benchmark_config in benchmarks.items():
            print(f"\nRunning benchmark: {benchmark_name}")
            
            try:
                result = await benchmark_config["test"](integration_environment)
                target = benchmark_config["target"]
                
                benchmark_results[benchmark_name] = {
                    "result": result,
                    "target": target,
                    "passed": result <= target if "time" in benchmark_name else result >= target
                }
                
                status = "PASS" if benchmark_results[benchmark_name]["passed"] else "FAIL"
                print(f"  {status}: {result} (target: {target})")
                
            except Exception as e:
                benchmark_results[benchmark_name] = {
                    "error": str(e),
                    "passed": False
                }
                print(f"  ERROR: {str(e)}")
        
        # Verify benchmark results
        failed_benchmarks = [
            name for name, result in benchmark_results.items()
            if not result["passed"]
        ]
        
        assert len(failed_benchmarks) == 0, f"Failed benchmarks: {failed_benchmarks}"

    async def _benchmark_threat_detection(self, environment) -> float:
        """Benchmark threat detection throughput"""
        from agents.detection.detection_agent import DetectionAgent
        
        detection = DetectionAgent(environment["config"])
        await detection.start()
        
        try:
            threat_count = 50
            threats = environment["test_data"]["threat_samples"] * (threat_count // 3 + 1)
            threats = threats[:threat_count]
            
            start_time = time.time()
            
            tasks = [detection.analyze_threat(threat) for threat in threats]
            await asyncio.gather(*tasks)
            
            duration = time.time() - start_time
            throughput = threat_count / duration
            
            return throughput
            
        finally:
            await detection.stop()

    async def _benchmark_honeypot_creation(self, environment) -> float:
        """Benchmark honeypot creation time"""
        from agents.coordinator.coordinator_agent import CoordinatorAgent
        
        coordinator = CoordinatorAgent(environment["config"])
        await coordinator.start()
        
        try:
            request = {
                "threat_data": environment["test_data"]["threat_samples"][0],
                "honeypot_type": "ssh"
            }
            
            start_time = time.time()
            result = await coordinator.create_honeypot(request)
            duration = time.time() - start_time
            
            if result and result.get("status") == "created":
                await coordinator.destroy_honeypot(result["honeypot_id"])
            
            return duration
            
        finally:
            await coordinator.stop()

    async def _benchmark_interaction_response(self, environment) -> float:
        """Benchmark interaction response time"""
        from agents.interaction.interaction_agent import InteractionAgent
        
        interaction = InteractionAgent(environment["config"])
        await interaction.start()
        
        try:
            session_id = "benchmark-session"
            
            start_time = time.time()
            response = await interaction.simulate_command(session_id, "whoami")
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            assert isinstance(response, str)
            assert len(response) > 0
            
            return duration
            
        finally:
            await interaction.stop()

    async def _benchmark_intelligence_analysis(self, environment) -> float:
        """Benchmark intelligence analysis time"""
        from agents.intelligence.intelligence_agent import IntelligenceAgent
        
        intelligence = IntelligenceAgent(environment["config"])
        await intelligence.start()
        
        try:
            session_data = {
                "session_id": "benchmark-session",
                "honeypot_type": "ssh",
                "interactions": [
                    {
                        "command": cmd,
                        "response": f"Response to {cmd}",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    for cmd in environment["test_data"]["attack_scenarios"][0]["commands"]
                ]
            }
            
            start_time = time.time()
            result = await intelligence.analyze_session(session_data)
            duration = time.time() - start_time
            
            assert "techniques_identified" in result
            
            return duration
            
        finally:
            await intelligence.stop()

    async def test_load_stress_testing(self, integration_environment):
        """Run load and stress testing scenarios"""
        stress_scenarios = [
            {
                "name": "concurrent_threats",
                "description": "Process multiple threats simultaneously",
                "test": self._stress_test_concurrent_threats
            },
            {
                "name": "honeypot_scaling",
                "description": "Create maximum number of honeypots",
                "test": self._stress_test_honeypot_scaling
            },
            {
                "name": "session_overload",
                "description": "Handle maximum concurrent sessions",
                "test": self._stress_test_session_overload
            }
        ]
        
        stress_results = {}
        
        for scenario in stress_scenarios:
            print(f"\nRunning stress test: {scenario['name']}")
            
            try:
                result = await scenario["test"](integration_environment)
                stress_results[scenario["name"]] = {
                    "passed": True,
                    "result": result
                }
                print(f"  PASS: {scenario['description']}")
                
            except Exception as e:
                stress_results[scenario["name"]] = {
                    "passed": False,
                    "error": str(e)
                }
                print(f"  FAIL: {str(e)}")
        
        # Verify stress test results
        failed_tests = [
            name for name, result in stress_results.items()
            if not result["passed"]
        ]
        
        # Allow some stress tests to fail (they test limits)
        assert len(failed_tests) <= len(stress_scenarios) * 0.3, f"Too many stress test failures: {failed_tests}"

    async def _stress_test_concurrent_threats(self, environment) -> Dict[str, Any]:
        """Stress test with concurrent threat processing"""
        from agents.detection.detection_agent import DetectionAgent
        
        detection = DetectionAgent(environment["config"])
        await detection.start()
        
        try:
            # Generate high load
            threat_count = 100
            threats = []
            
            for i in range(threat_count):
                threat = {
                    "source_ip": f"10.0.{i//256}.{i%256}",
                    "threat_type": "stress_test",
                    "confidence": 0.5 + (i % 10) * 0.05,
                    "indicators": ["stress_test"]
                }
                threats.append(threat)
            
            start_time = time.time()
            
            # Process all threats concurrently
            tasks = [detection.analyze_threat(threat) for threat in threats]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            duration = time.time() - start_time
            
            # Analyze results
            successful = sum(1 for r in results if not isinstance(r, Exception))
            failed = len(results) - successful
            
            return {
                "total_threats": threat_count,
                "successful": successful,
                "failed": failed,
                "duration": duration,
                "throughput": successful / duration
            }
            
        finally:
            await detection.stop()

    async def _stress_test_honeypot_scaling(self, environment) -> Dict[str, Any]:
        """Stress test honeypot scaling limits"""
        from agents.coordinator.coordinator_agent import CoordinatorAgent
        
        coordinator = CoordinatorAgent(environment["config"])
        await coordinator.start()
        
        try:
            max_attempts = 25
            created_honeypots = []
            
            for i in range(max_attempts):
                request = {
                    "threat_data": {"source_ip": f"192.168.1.{100 + i}"},
                    "honeypot_type": "ssh"
                }
                
                try:
                    result = await coordinator.create_honeypot(request)
                    if result and result.get("status") == "created":
                        created_honeypots.append(result["honeypot_id"])
                    else:
                        break  # Hit limit
                except Exception:
                    break  # Hit limit or error
            
            # Cleanup
            for hp_id in created_honeypots:
                await coordinator.destroy_honeypot(hp_id)
            
            return {
                "max_honeypots_created": len(created_honeypots),
                "attempted": max_attempts
            }
            
        finally:
            await coordinator.stop()

    async def _stress_test_session_overload(self, environment) -> Dict[str, Any]:
        """Stress test session handling under overload"""
        from agents.interaction.interaction_agent import InteractionAgent
        
        interaction = InteractionAgent(environment["config"])
        await interaction.start()
        
        try:
            session_count = 50
            sessions = [f"stress-session-{i}" for i in range(session_count)]
            
            # Initialize all sessions
            init_tasks = [
                interaction.initialize_session(session_id, {"type": "stress_test"})
                for session_id in sessions
            ]
            await asyncio.gather(*init_tasks, return_exceptions=True)
            
            # Send commands to all sessions simultaneously
            command_tasks = [
                interaction.simulate_command(session_id, "whoami")
                for session_id in sessions
            ]
            
            start_time = time.time()
            results = await asyncio.gather(*command_tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            successful = sum(1 for r in results if not isinstance(r, Exception))
            
            return {
                "total_sessions": session_count,
                "successful_responses": successful,
                "duration": duration,
                "response_rate": successful / duration
            }
            
        finally:
            await interaction.stop()

    async def _generate_test_report(self, environment):
        """Generate comprehensive test report"""
        end_time = datetime.utcnow()
        start_time = environment["metrics"]["start_time"]
        total_duration = (end_time - start_time).total_seconds()
        
        report = {
            "test_execution": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "total_duration_seconds": total_duration
            },
            "environment": {
                "config": environment["config"],
                "test_data_summary": {
                    "threat_samples": len(environment["test_data"]["threat_samples"]),
                    "honeypot_configs": len(environment["test_data"]["honeypot_configs"]),
                    "attack_scenarios": len(environment["test_data"]["attack_scenarios"])
                }
            },
            "metrics": environment["metrics"],
            "summary": {
                "total_tests": self.total_tests,
                "passed_tests": self.passed_tests,
                "failed_tests": self.failed_tests,
                "success_rate": (self.passed_tests / max(self.total_tests, 1)) * 100
            }
        }
        
        # Save report to file
        report_path = Path("test_logs") / "integration_test_report.json"
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\nIntegration test report saved to: {report_path}")