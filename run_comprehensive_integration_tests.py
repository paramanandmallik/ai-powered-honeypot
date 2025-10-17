#!/usr/bin/env python3
"""
Comprehensive Integration Test Execution Script
Runs all integration and end-to-end tests for the AI Honeypot System
"""

import asyncio
import sys
import os
import time
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from tests.integration.integration_test_config import get_test_config
from tests.integration.test_integration_runner import TestIntegrationRunner


class ComprehensiveTestExecutor:
    """Comprehensive integration test executor"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.test_results = {}
        self.start_time = None
        self.end_time = None
        
    async def run_all_tests(self, test_categories: List[str] = None):
        """Run all integration tests"""
        self.start_time = datetime.utcnow()
        
        print("=" * 80)
        print("AI HONEYPOT SYSTEM - COMPREHENSIVE INTEGRATION TESTS")
        print("=" * 80)
        print(f"Start Time: {self.start_time}")
        print(f"Test Environment: {self.config.get('test_environment', 'integration')}")
        print(f"Configuration: {self.config.get('agentcore_simulation', False) and 'AgentCore Simulation' or 'Standard'}")
        print()
        
        # Default test categories
        if test_categories is None:
            test_categories = [
                "messaging",
                "workflow", 
                "lifecycle",
                "performance",
                "security",
                "e2e",
                "comprehensive"
            ]
        
        # Test category mapping
        test_mapping = {
            "messaging": self._run_messaging_tests,
            "workflow": self._run_workflow_tests,
            "lifecycle": self._run_lifecycle_tests,
            "performance": self._run_performance_tests,
            "security": self._run_security_tests,
            "e2e": self._run_e2e_tests,
            "comprehensive": self._run_comprehensive_tests
        }
        
        # Execute test categories
        for category in test_categories:
            if category in test_mapping:
                print(f"\n{'='*60}")
                print(f"RUNNING {category.upper()} TESTS")
                print(f"{'='*60}")
                
                category_start = time.time()
                
                try:
                    result = await test_mapping[category]()
                    category_duration = time.time() - category_start
                    
                    self.test_results[category] = {
                        "status": "passed",
                        "duration": category_duration,
                        "result": result
                    }
                    
                    print(f"\n✅ {category.upper()} TESTS PASSED ({category_duration:.2f}s)")
                    
                except Exception as e:
                    category_duration = time.time() - category_start
                    
                    self.test_results[category] = {
                        "status": "failed",
                        "duration": category_duration,
                        "error": str(e)
                    }
                    
                    print(f"\n❌ {category.upper()} TESTS FAILED ({category_duration:.2f}s)")
                    print(f"Error: {str(e)}")
                    
                    if not self.config.get("continue_on_failure", True):
                        break
            else:
                print(f"⚠️  Unknown test category: {category}")
        
        self.end_time = datetime.utcnow()
        
        # Generate final report
        await self._generate_final_report()
        
        return self.test_results
    
    async def _run_messaging_tests(self):
        """Run AgentCore messaging integration tests"""
        from tests.integration.test_agentcore_messaging import TestAgentCoreMessaging
        
        test_class = TestAgentCoreMessaging()
        
        # Run key messaging tests
        test_methods = [
            "test_agent_registration_and_discovery",
            "test_threat_detection_messaging_flow",
            "test_honeypot_coordination_messaging",
            "test_concurrent_messaging",
            "test_message_throughput_performance"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    # Create mock environment for the test
                    mock_env = await self._create_mock_environment()
                    await method(mock_env)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _run_workflow_tests(self):
        """Run workflow integration tests"""
        from tests.integration.test_workflow_integration import TestWorkflowIntegration
        
        test_class = TestWorkflowIntegration()
        
        test_methods = [
            "test_complete_threat_response_workflow",
            "test_multi_honeypot_coordination",
            "test_concurrent_engagement_handling",
            "test_data_flow_integrity"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    integrated_system = await self._create_integrated_system()
                    await method(integrated_system)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _run_lifecycle_tests(self):
        """Run honeypot lifecycle tests"""
        from tests.integration.test_honeypot_lifecycle import TestHoneypotLifecycle
        
        test_class = TestHoneypotLifecycle()
        
        test_methods = [
            "test_complete_honeypot_lifecycle",
            "test_multi_type_honeypot_coordination",
            "test_honeypot_scaling_and_load_balancing",
            "test_session_isolation_and_containment"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    honeypot_system = await self._create_honeypot_system()
                    await method(honeypot_system)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _run_performance_tests(self):
        """Run performance integration tests"""
        from tests.integration.test_performance_testing import TestPerformanceTesting
        
        test_class = TestPerformanceTesting()
        
        test_methods = [
            "test_threat_detection_throughput",
            "test_concurrent_honeypot_creation",
            "test_interaction_agent_response_time",
            "test_system_scalability"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    performance_system = await self._create_performance_system()
                    await method(performance_system)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _run_security_tests(self):
        """Run security isolation tests"""
        from tests.integration.test_security_isolation import TestSecurityIsolation
        
        test_class = TestSecurityIsolation()
        
        test_methods = [
            "test_network_isolation_enforcement",
            "test_real_data_detection_and_protection",
            "test_privilege_escalation_prevention",
            "test_lateral_movement_detection",
            "test_emergency_containment_procedures"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    security_system = await self._create_security_system()
                    await method(security_system)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _run_e2e_tests(self):
        """Run end-to-end tests"""
        from tests.integration.test_comprehensive_e2e import TestComprehensiveE2E
        
        test_class = TestComprehensiveE2E()
        
        test_methods = [
            "test_complete_threat_lifecycle_ssh",
            "test_multi_honeypot_coordinated_attack",
            "test_performance_under_concurrent_load",
            "test_intelligence_quality_validation"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    e2e_system = await self._create_e2e_system()
                    await method(e2e_system)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _run_comprehensive_tests(self):
        """Run comprehensive end-to-end tests"""
        from tests.integration.test_end_to_end_comprehensive import TestEndToEndComprehensive
        
        test_class = TestEndToEndComprehensive()
        
        test_methods = [
            "test_complete_threat_lifecycle_ssh_comprehensive",
            "test_multi_vector_coordinated_attack_comprehensive",
            "test_system_resilience_and_recovery_comprehensive",
            "test_comprehensive_performance_benchmarking"
        ]
        
        results = {}
        for method_name in test_methods:
            if hasattr(test_class, method_name):
                method = getattr(test_class, method_name)
                
                try:
                    comprehensive_system = await self._create_comprehensive_system()
                    await method(comprehensive_system)
                    results[method_name] = "passed"
                    print(f"  ✅ {method_name}")
                except Exception as e:
                    results[method_name] = f"failed: {str(e)}"
                    print(f"  ❌ {method_name}: {str(e)}")
        
        return results
    
    async def _create_mock_environment(self):
        """Create mock environment for testing"""
        from unittest.mock import AsyncMock
        
        return {
            "sdk": AsyncMock(),
            "message_router": {},
            "sent_messages": []
        }
    
    async def _create_integrated_system(self):
        """Create integrated system for testing"""
        from agents.detection.detection_agent import DetectionAgent
        from agents.coordinator.coordinator_agent import CoordinatorAgent
        from agents.interaction.interaction_agent import InteractionAgent
        from agents.intelligence.intelligence_agent import IntelligenceAgent
        
        config = get_test_config("comprehensive")
        
        detection = DetectionAgent(config=config)
        coordinator = CoordinatorAgent(config=config)
        interaction = InteractionAgent(config=config)
        intelligence = IntelligenceAgent(config=config)
        
        await detection.start()
        await coordinator.start()
        await interaction.start()
        await intelligence.start()
        
        return {
            "detection": detection,
            "coordinator": coordinator,
            "interaction": interaction,
            "intelligence": intelligence
        }
    
    async def _create_honeypot_system(self):
        """Create honeypot system for testing"""
        return await self._create_integrated_system()
    
    async def _create_performance_system(self):
        """Create performance system for testing"""
        config = get_test_config("performance")
        return await self._create_integrated_system()
    
    async def _create_security_system(self):
        """Create security system for testing"""
        config = get_test_config("security")
        return await self._create_integrated_system()
    
    async def _create_e2e_system(self):
        """Create end-to-end system for testing"""
        return await self._create_integrated_system()
    
    async def _create_comprehensive_system(self):
        """Create comprehensive system for testing"""
        config = get_test_config("comprehensive")
        return await self._create_integrated_system()
    
    async def _generate_final_report(self):
        """Generate comprehensive final test report"""
        total_duration = (self.end_time - self.start_time).total_seconds()
        
        # Calculate summary statistics
        total_categories = len(self.test_results)
        passed_categories = sum(1 for result in self.test_results.values() if result["status"] == "passed")
        failed_categories = total_categories - passed_categories
        
        success_rate = (passed_categories / total_categories * 100) if total_categories > 0 else 0
        
        # Generate report
        report = {
            "test_execution": {
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "total_duration_seconds": total_duration,
                "configuration": self.config
            },
            "summary": {
                "total_categories": total_categories,
                "passed_categories": passed_categories,
                "failed_categories": failed_categories,
                "success_rate_percent": success_rate
            },
            "category_results": self.test_results,
            "recommendations": self._generate_recommendations()
        }
        
        # Save report to file
        report_dir = Path("test_logs")
        report_dir.mkdir(exist_ok=True)
        
        report_file = report_dir / f"comprehensive_integration_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "=" * 80)
        print("COMPREHENSIVE INTEGRATION TEST SUMMARY")
        print("=" * 80)
        print(f"Total Duration: {total_duration:.2f} seconds")
        print(f"Test Categories: {total_categories}")
        print(f"Passed: {passed_categories}")
        print(f"Failed: {failed_categories}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Report saved to: {report_file}")
        
        if failed_categories > 0:
            print("\nFAILED CATEGORIES:")
            for category, result in self.test_results.items():
                if result["status"] == "failed":
                    print(f"  ❌ {category}: {result.get('error', 'Unknown error')}")
        
        print("\n" + "=" * 80)
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        failed_categories = [
            category for category, result in self.test_results.items()
            if result["status"] == "failed"
        ]
        
        if "messaging" in failed_categories:
            recommendations.append("Review AgentCore messaging implementation and error handling")
        
        if "performance" in failed_categories:
            recommendations.append("Optimize system performance and resource utilization")
        
        if "security" in failed_categories:
            recommendations.append("Strengthen security controls and isolation mechanisms")
        
        if "comprehensive" in failed_categories:
            recommendations.append("Review end-to-end workflow integration and error recovery")
        
        if len(failed_categories) == 0:
            recommendations.append("All integration tests passed - system is ready for deployment")
        elif len(failed_categories) > len(self.test_results) * 0.5:
            recommendations.append("Multiple test failures detected - comprehensive system review required")
        
        return recommendations


async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Run comprehensive integration tests")
    parser.add_argument(
        "--categories",
        nargs="+",
        choices=["messaging", "workflow", "lifecycle", "performance", "security", "e2e", "comprehensive"],
        help="Test categories to run (default: all)"
    )
    parser.add_argument(
        "--config-type",
        choices=["default", "performance", "security", "comprehensive"],
        default="comprehensive",
        help="Configuration type to use"
    )
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Continue running tests even if some categories fail"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Get configuration
    config = get_test_config(args.config_type)
    config["continue_on_failure"] = args.continue_on_failure
    config["verbose"] = args.verbose
    
    # Create test executor
    executor = ComprehensiveTestExecutor(config)
    
    try:
        # Run tests
        results = await executor.run_all_tests(args.categories)
        
        # Determine exit code
        failed_count = sum(1 for result in results.values() if result["status"] == "failed")
        exit_code = 0 if failed_count == 0 else 1
        
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Test execution failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())