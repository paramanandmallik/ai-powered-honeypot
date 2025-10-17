#!/usr/bin/env python3
"""
Test Orchestration Script for AI Honeypot AgentCore System
Coordinates all testing activities including simulation, validation, and performance testing
"""

import asyncio
import argparse
import logging
import json
import os
import sys
import time
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from tests.simulation.comprehensive_test_framework import ComprehensiveTestFramework, TestConfiguration, TestScenarioType
from tests.simulation.threat_feed_generator import SyntheticThreatGenerator
from tests.simulation.attacker_simulator import AttackerSimulator
from tests.simulation.performance_tester import PerformanceTester
from tests.simulation.intelligence_validator import IntelligenceValidator
from tests.validation.system_validator import SystemValidator, ValidationLevel
from run_automated_tests import AutomatedTestRunner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/test_orchestration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TestOrchestrator:
    """Orchestrates comprehensive testing of the AI Honeypot system"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config/automated_test_config.json"
        self.test_framework = ComprehensiveTestFramework()
        self.automated_runner = AutomatedTestRunner(self.config_file)
        self.system_validator = SystemValidator()
        
        # Individual test components
        self.threat_generator = SyntheticThreatGenerator()
        self.attacker_simulator = AttackerSimulator()
        self.performance_tester = PerformanceTester()
        self.intelligence_validator = IntelligenceValidator()
        
        self.running = False
        self.test_results = []
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    async def initialize(self):
        """Initialize all test components"""
        logger.info("Initializing test orchestrator...")
        
        try:
            await self.test_framework.initialize()
            await self.automated_runner.initialize()
            await self.system_validator.initialize()
            await self.performance_tester.initialize()
            await self.intelligence_validator.initialize()
            
            logger.info("Test orchestrator initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize test orchestrator: {e}")
            raise
    
    async def run_comprehensive_test_cycle(self) -> Dict[str, Any]:
        """Run a complete test cycle covering all aspects of the system"""
        logger.info("Starting comprehensive test cycle")
        
        cycle_start = datetime.utcnow()
        cycle_results = {
            "cycle_id": f"cycle-{int(time.time())}",
            "start_time": cycle_start.isoformat(),
            "phases": {}
        }
        
        try:
            # Phase 1: System Health Validation
            logger.info("Phase 1: System Health Validation")
            health_result = await self._run_health_validation()
            cycle_results["phases"]["health_validation"] = health_result
            
            if not health_result["success"]:
                logger.error("System health validation failed, aborting test cycle")
                return cycle_results
            
            # Phase 2: Threat Detection Testing
            logger.info("Phase 2: Threat Detection Testing")
            threat_result = await self._run_threat_detection_tests()
            cycle_results["phases"]["threat_detection"] = threat_result
            
            # Phase 3: Attacker Simulation
            logger.info("Phase 3: Attacker Simulation")
            attack_result = await self._run_attacker_simulation()
            cycle_results["phases"]["attacker_simulation"] = attack_result
            
            # Phase 4: Performance Testing
            logger.info("Phase 4: Performance Testing")
            performance_result = await self._run_performance_tests()
            cycle_results["phases"]["performance_testing"] = performance_result
            
            # Phase 5: Intelligence Processing
            logger.info("Phase 5: Intelligence Processing")
            intelligence_result = await self._run_intelligence_tests()
            cycle_results["phases"]["intelligence_processing"] = intelligence_result
            
            # Phase 6: Security Validation
            logger.info("Phase 6: Security Validation")
            security_result = await self._run_security_validation()
            cycle_results["phases"]["security_validation"] = security_result
            
            # Phase 7: End-to-End Integration
            logger.info("Phase 7: End-to-End Integration")
            e2e_result = await self._run_end_to_end_tests()
            cycle_results["phases"]["end_to_end"] = e2e_result
            
            # Calculate overall results
            cycle_end = datetime.utcnow()
            cycle_results["end_time"] = cycle_end.isoformat()
            cycle_results["total_duration"] = (cycle_end - cycle_start).total_seconds()
            
            # Analyze results
            phase_successes = sum(1 for phase in cycle_results["phases"].values() if phase.get("success", False))
            total_phases = len(cycle_results["phases"])
            
            cycle_results["overall_success"] = phase_successes == total_phases
            cycle_results["success_rate"] = phase_successes / total_phases if total_phases > 0 else 0
            cycle_results["summary"] = {
                "total_phases": total_phases,
                "successful_phases": phase_successes,
                "failed_phases": total_phases - phase_successes
            }
            
            # Generate comprehensive report
            await self._generate_cycle_report(cycle_results)
            
            logger.info(f"Comprehensive test cycle completed: {phase_successes}/{total_phases} phases passed")
            
        except Exception as e:
            logger.error(f"Test cycle failed: {e}")
            cycle_results["error"] = str(e)
            cycle_results["overall_success"] = False
        
        return cycle_results
    
    async def _run_health_validation(self) -> Dict[str, Any]:
        """Run system health validation"""
        try:
            validation_report = await self.system_validator.validate_system(ValidationLevel.BASIC)
            
            return {
                "success": validation_report.overall_success,
                "validation_id": validation_report.validation_id,
                "tests_passed": validation_report.summary.get("successful_tests", 0),
                "total_tests": validation_report.summary.get("total_tests", 0),
                "duration": (validation_report.end_time - validation_report.start_time).total_seconds() if validation_report.end_time else 0
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _run_threat_detection_tests(self) -> Dict[str, Any]:
        """Run threat detection tests"""
        try:
            # Generate diverse threat scenarios
            threats = self.threat_generator.generate_threat_feed(50)
            
            # Test detection capabilities
            config = TestConfiguration(
                scenario_type=TestScenarioType.THREAT_DETECTION,
                threat_count=50,
                duration_seconds=180
            )
            
            result = await self.test_framework.run_test_scenario(config)
            
            return {
                "success": result.success,
                "threats_generated": len(threats),
                "detection_rate": result.summary.get("detection_rate", 0),
                "false_positives": result.summary.get("false_positives", 0),
                "duration": (result.end_time - result.start_time).total_seconds()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _run_attacker_simulation(self) -> Dict[str, Any]:
        """Run attacker simulation tests"""
        try:
            # Run multiple attack scenarios concurrently
            scenarios = ["ssh_brute_force", "web_admin_attack", "database_attack", "reconnaissance_scan"]
            
            config = TestConfiguration(
                scenario_type=TestScenarioType.ATTACKER_SIMULATION,
                attack_scenarios=scenarios,
                duration_seconds=300
            )
            
            result = await self.test_framework.run_test_scenario(config)
            
            return {
                "success": result.success,
                "scenarios_run": result.summary.get("scenarios_run", 0),
                "successful_scenarios": result.summary.get("successful_scenarios", 0),
                "success_rate": result.summary.get("success_rate", 0),
                "avg_completion_rate": result.summary.get("avg_completion_rate", 0),
                "duration": (result.end_time - result.start_time).total_seconds()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _run_performance_tests(self) -> Dict[str, Any]:
        """Run performance tests"""
        try:
            config = TestConfiguration(
                scenario_type=TestScenarioType.PERFORMANCE_LOAD,
                concurrent_users=10,
                duration_seconds=300,
                performance_targets={
                    "max_response_time": 2.0,
                    "min_throughput": 20.0,
                    "max_error_rate": 0.03
                }
            )
            
            result = await self.test_framework.run_test_scenario(config)
            
            return {
                "success": result.success,
                "total_requests": result.summary.get("total_requests", 0),
                "avg_response_time": result.summary.get("avg_response_time", 0),
                "requests_per_second": result.summary.get("requests_per_second", 0),
                "error_rate": result.summary.get("error_rate", 0),
                "performance_score": result.summary.get("performance_score", 0),
                "duration": (result.end_time - result.start_time).total_seconds()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _run_intelligence_tests(self) -> Dict[str, Any]:
        """Run intelligence processing tests"""
        try:
            config = TestConfiguration(
                scenario_type=TestScenarioType.INTELLIGENCE_PROCESSING,
                duration_seconds=240
            )
            
            result = await self.test_framework.run_test_scenario(config)
            
            return {
                "success": result.success,
                "sessions_processed": result.summary.get("sessions_processed", 0),
                "processing_success_rate": result.summary.get("processing_success_rate", 0),
                "avg_techniques_per_session": result.summary.get("avg_techniques_per_session", 0),
                "avg_confidence_score": result.summary.get("avg_confidence_score", 0),
                "duration": (result.end_time - result.start_time).total_seconds()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _run_security_validation(self) -> Dict[str, Any]:
        """Run security validation tests"""
        try:
            config = TestConfiguration(
                scenario_type=TestScenarioType.SECURITY_VALIDATION,
                duration_seconds=300
            )
            
            result = await self.test_framework.run_test_scenario(config)
            
            return {
                "success": result.success,
                "security_checks_run": result.summary.get("security_checks_run", 0),
                "security_checks_passed": result.summary.get("security_checks_passed", 0),
                "security_score": result.summary.get("security_score", 0),
                "critical_failures": result.summary.get("critical_failures", []),
                "duration": (result.end_time - result.start_time).total_seconds()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _run_end_to_end_tests(self) -> Dict[str, Any]:
        """Run end-to-end integration tests"""
        try:
            config = TestConfiguration(
                scenario_type=TestScenarioType.END_TO_END,
                duration_seconds=600
            )
            
            result = await self.test_framework.run_test_scenario(config)
            
            return {
                "success": result.success,
                "components_tested": result.summary.get("components_tested", 0),
                "successful_components": result.summary.get("successful_components", 0),
                "overall_success_rate": result.summary.get("overall_success_rate", 0),
                "component_breakdown": result.summary.get("component_breakdown", {}),
                "duration": (result.end_time - result.start_time).total_seconds()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _generate_cycle_report(self, cycle_results: Dict[str, Any]):
        """Generate comprehensive cycle report"""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            
            # JSON report
            json_filename = f"reports/automated_tests/comprehensive_cycle_{timestamp}.json"
            os.makedirs(os.path.dirname(json_filename), exist_ok=True)
            
            with open(json_filename, 'w') as f:
                json.dump(cycle_results, f, indent=2)
            
            # HTML report
            html_filename = f"reports/automated_tests/comprehensive_cycle_{timestamp}.html"
            await self._generate_html_report(cycle_results, html_filename)
            
            logger.info(f"Cycle reports generated: {json_filename}, {html_filename}")
            
        except Exception as e:
            logger.error(f"Failed to generate cycle report: {e}")
    
    async def _generate_html_report(self, cycle_results: Dict[str, Any], filename: str):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI Honeypot AgentCore - Comprehensive Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .phase {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .success {{ background-color: #d4edda; border-color: #c3e6cb; }}
        .failure {{ background-color: #f8d7da; border-color: #f5c6cb; }}
        .summary {{ background-color: #e2e3e5; padding: 15px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AI Honeypot AgentCore - Comprehensive Test Report</h1>
        <p><strong>Cycle ID:</strong> {cycle_results.get('cycle_id', 'N/A')}</p>
        <p><strong>Start Time:</strong> {cycle_results.get('start_time', 'N/A')}</p>
        <p><strong>End Time:</strong> {cycle_results.get('end_time', 'N/A')}</p>
        <p><strong>Duration:</strong> {cycle_results.get('total_duration', 0):.2f} seconds</p>
        <p><strong>Overall Success:</strong> {'✅ PASSED' if cycle_results.get('overall_success', False) else '❌ FAILED'}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Phases</td><td>{cycle_results.get('summary', {}).get('total_phases', 0)}</td></tr>
            <tr><td>Successful Phases</td><td>{cycle_results.get('summary', {}).get('successful_phases', 0)}</td></tr>
            <tr><td>Failed Phases</td><td>{cycle_results.get('summary', {}).get('failed_phases', 0)}</td></tr>
            <tr><td>Success Rate</td><td>{cycle_results.get('success_rate', 0):.2%}</td></tr>
        </table>
    </div>
    
    <h2>Phase Results</h2>
"""
        
        # Add phase results
        for phase_name, phase_result in cycle_results.get("phases", {}).items():
            success_class = "success" if phase_result.get("success", False) else "failure"
            status = "✅ PASSED" if phase_result.get("success", False) else "❌ FAILED"
            
            html_content += f"""
    <div class="phase {success_class}">
        <h3>{phase_name.replace('_', ' ').title()} - {status}</h3>
        <table>
"""
            
            # Add phase-specific metrics
            for key, value in phase_result.items():
                if key != "success":
                    html_content += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
            
            html_content += """
        </table>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    async def run_continuous_orchestration(self, interval_hours: int = 6):
        """Run continuous test orchestration"""
        logger.info(f"Starting continuous test orchestration (every {interval_hours} hours)")
        self.running = True
        
        while self.running:
            try:
                logger.info("Starting scheduled comprehensive test cycle")
                cycle_result = await self.run_comprehensive_test_cycle()
                
                if cycle_result.get("overall_success", False):
                    logger.info("Comprehensive test cycle completed successfully")
                else:
                    logger.warning("Comprehensive test cycle had failures")
                
                # Wait for next cycle
                if self.running:
                    sleep_seconds = interval_hours * 3600
                    logger.info(f"Waiting {interval_hours} hours until next test cycle")
                    
                    # Sleep in smaller intervals to allow for graceful shutdown
                    for _ in range(sleep_seconds // 60):
                        if not self.running:
                            break
                        await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in continuous orchestration: {e}")
                if self.running:
                    await asyncio.sleep(300)  # Wait 5 minutes before retry
        
        logger.info("Continuous test orchestration stopped")
    
    def stop_orchestration(self):
        """Stop continuous orchestration"""
        logger.info("Stopping test orchestration")
        self.running = False

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="AI Honeypot AgentCore Test Orchestrator")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--cycle", action="store_true", help="Run single comprehensive test cycle")
    parser.add_argument("--continuous", type=int, metavar="HOURS", help="Run continuous orchestration (interval in hours)")
    parser.add_argument("--phase", choices=[
        "health", "threats", "attacks", "performance", "intelligence", "security", "e2e"
    ], help="Run specific test phase")
    
    args = parser.parse_args()
    
    # Create orchestrator
    orchestrator = TestOrchestrator(args.config)
    await orchestrator.initialize()
    
    try:
        if args.phase:
            # Run specific phase
            phase_methods = {
                "health": orchestrator._run_health_validation,
                "threats": orchestrator._run_threat_detection_tests,
                "attacks": orchestrator._run_attacker_simulation,
                "performance": orchestrator._run_performance_tests,
                "intelligence": orchestrator._run_intelligence_tests,
                "security": orchestrator._run_security_validation,
                "e2e": orchestrator._run_end_to_end_tests
            }
            
            result = await phase_methods[args.phase]()
            print(f"Phase {args.phase} result: {'PASSED' if result['success'] else 'FAILED'}")
            print(json.dumps(result, indent=2))
            
        elif args.continuous:
            print(f"Starting continuous orchestration (every {args.continuous} hours)")
            print("Press Ctrl+C to stop")
            try:
                await orchestrator.run_continuous_orchestration(args.continuous)
            except KeyboardInterrupt:
                orchestrator.stop_orchestration()
                print("Continuous orchestration stopped")
                
        elif args.cycle:
            print("Running comprehensive test cycle")
            result = await orchestrator.run_comprehensive_test_cycle()
            print(f"Cycle result: {'PASSED' if result['overall_success'] else 'FAILED'}")
            print(f"Success rate: {result['success_rate']:.2%}")
            
        else:
            # Default: run single cycle
            print("Running default comprehensive test cycle")
            result = await orchestrator.run_comprehensive_test_cycle()
            print(f"Cycle result: {'PASSED' if result['overall_success'] else 'FAILED'}")
            print(f"Success rate: {result['success_rate']:.2%}")
    
    except Exception as e:
        logger.error(f"Test orchestration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())