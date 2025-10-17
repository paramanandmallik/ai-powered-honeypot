#!/usr/bin/env python3
"""
Automated Test Runner for AI Honeypot AgentCore System
Provides comprehensive testing capabilities with scheduling and reporting
"""

import asyncio
import argparse
import logging
import json
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from tests.simulation.comprehensive_test_framework import (
    ComprehensiveTestFramework, 
    TestConfiguration, 
    TestScenarioType
)
from tests.validation.system_validator import SystemValidator, ValidationLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/automated_tests.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AutomatedTestRunner:
    """Automated test runner with scheduling and reporting capabilities"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.test_framework = ComprehensiveTestFramework()
        self.system_validator = SystemValidator()
        
        self.test_history: List[Dict[str, Any]] = []
        self.running = False
        
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load test configuration"""
        default_config = {
            "test_schedules": {
                "continuous": {
                    "enabled": False,
                    "interval_minutes": 30,
                    "test_types": ["basic_functionality", "threat_detection"]
                },
                "performance": {
                    "enabled": False,
                    "interval_minutes": 120,
                    "test_types": ["performance_load"]
                },
                "comprehensive": {
                    "enabled": False,
                    "interval_minutes": 360,
                    "test_types": ["end_to_end", "security_validation"]
                }
            },
            "test_configurations": {
                "basic_functionality": {
                    "duration_seconds": 60,
                    "validation_checks": ["agent_health", "message_flow"]
                },
                "threat_detection": {
                    "threat_count": 20,
                    "duration_seconds": 120
                },
                "attacker_simulation": {
                    "attack_scenarios": ["ssh_brute_force", "web_admin_attack"],
                    "duration_seconds": 180
                },
                "performance_load": {
                    "concurrent_users": 5,
                    "duration_seconds": 300,
                    "performance_targets": {
                        "max_response_time": 2.0,
                        "min_throughput": 10.0,
                        "max_error_rate": 0.05
                    }
                },
                "intelligence_processing": {
                    "duration_seconds": 120
                },
                "security_validation": {
                    "duration_seconds": 180
                },
                "end_to_end": {
                    "duration_seconds": 600
                }
            },
            "reporting": {
                "output_directory": "reports/automated_tests",
                "keep_reports_days": 30,
                "email_notifications": {
                    "enabled": False,
                    "recipients": [],
                    "smtp_server": "",
                    "smtp_port": 587
                }
            },
            "failure_handling": {
                "max_consecutive_failures": 3,
                "failure_cooldown_minutes": 15,
                "auto_restart_services": True
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge with default config
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config file {config_file}: {e}")
        
        return default_config
    
    async def initialize(self):
        """Initialize test runner"""
        try:
            await self.test_framework.initialize()
            await self.system_validator.initialize()
            
            # Create output directory
            os.makedirs(self.config["reporting"]["output_directory"], exist_ok=True)
            
            logger.info("Automated test runner initialized")
        except Exception as e:
            logger.error(f"Failed to initialize test runner: {e}")
            raise
    
    async def run_single_test(self, test_type: str, custom_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run a single test scenario"""
        logger.info(f"Running single test: {test_type}")
        
        try:
            # Get test configuration
            test_config_data = self.config["test_configurations"].get(test_type, {})
            if custom_config:
                test_config_data.update(custom_config)
            
            # Create test configuration
            scenario_type = TestScenarioType(test_type)
            test_config = TestConfiguration(
                scenario_type=scenario_type,
                **test_config_data
            )
            
            # Run the test
            start_time = datetime.utcnow()
            result = await self.test_framework.run_test_scenario(test_config)
            
            # Record test result
            test_record = {
                "test_type": test_type,
                "start_time": start_time.isoformat(),
                "end_time": result.end_time.isoformat(),
                "duration_seconds": (result.end_time - result.start_time).total_seconds(),
                "success": result.success,
                "summary": result.summary,
                "errors": result.errors,
                "warnings": result.warnings
            }
            
            self.test_history.append(test_record)
            
            # Generate individual test report
            await self._generate_test_report(test_record)
            
            logger.info(f"Test {test_type} completed: {'PASSED' if result.success else 'FAILED'}")
            
            return test_record
            
        except Exception as e:
            logger.error(f"Test {test_type} failed with exception: {e}")
            error_record = {
                "test_type": test_type,
                "start_time": datetime.utcnow().isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "duration_seconds": 0,
                "success": False,
                "summary": {},
                "errors": [str(e)],
                "warnings": []
            }
            self.test_history.append(error_record)
            return error_record
    
    async def run_test_suite(self, test_types: List[str]) -> Dict[str, Any]:
        """Run a suite of tests"""
        logger.info(f"Running test suite: {test_types}")
        
        suite_start = datetime.utcnow()
        suite_results = []
        
        for test_type in test_types:
            result = await self.run_single_test(test_type)
            suite_results.append(result)
            
            # Add delay between tests
            await asyncio.sleep(5)
        
        suite_end = datetime.utcnow()
        
        # Generate suite summary
        suite_summary = {
            "suite_start": suite_start.isoformat(),
            "suite_end": suite_end.isoformat(),
            "total_duration": (suite_end - suite_start).total_seconds(),
            "test_types": test_types,
            "total_tests": len(suite_results),
            "passed_tests": sum(1 for r in suite_results if r["success"]),
            "failed_tests": sum(1 for r in suite_results if not r["success"]),
            "success_rate": sum(1 for r in suite_results if r["success"]) / len(suite_results) if suite_results else 0,
            "results": suite_results
        }
        
        # Generate suite report
        await self._generate_suite_report(suite_summary)
        
        logger.info(f"Test suite completed: {suite_summary['passed_tests']}/{suite_summary['total_tests']} passed")
        
        return suite_summary
    
    async def run_system_validation(self, level: ValidationLevel = ValidationLevel.COMPREHENSIVE) -> Dict[str, Any]:
        """Run system validation"""
        logger.info(f"Running system validation: {level.value}")
        
        try:
            validation_report = await self.system_validator.validate_system(level)
            
            validation_summary = {
                "validation_id": validation_report.validation_id,
                "validation_level": level.value,
                "start_time": validation_report.start_time.isoformat(),
                "end_time": validation_report.end_time.isoformat() if validation_report.end_time else None,
                "overall_success": validation_report.overall_success,
                "summary": validation_report.summary,
                "total_tests": len(validation_report.results),
                "passed_tests": sum(1 for r in validation_report.results if r.success),
                "failed_tests": sum(1 for r in validation_report.results if not r.success)
            }
            
            # Generate validation report
            await self._generate_validation_report(validation_summary, validation_report.results)
            
            logger.info(f"System validation completed: {'PASSED' if validation_report.overall_success else 'FAILED'}")
            
            return validation_summary
            
        except Exception as e:
            logger.error(f"System validation failed: {e}")
            return {
                "validation_level": level.value,
                "overall_success": False,
                "error": str(e)
            }
    
    async def run_continuous_testing(self):
        """Run continuous testing based on schedule"""
        logger.info("Starting continuous testing mode")
        self.running = True
        
        last_run_times = {}
        consecutive_failures = {}
        
        while self.running:
            try:
                current_time = datetime.utcnow()
                
                # Check each schedule
                for schedule_name, schedule_config in self.config["test_schedules"].items():
                    if not schedule_config.get("enabled", False):
                        continue
                    
                    interval_minutes = schedule_config.get("interval_minutes", 60)
                    test_types = schedule_config.get("test_types", [])
                    
                    # Check if it's time to run this schedule
                    last_run = last_run_times.get(schedule_name)
                    if last_run is None or (current_time - last_run).total_seconds() >= interval_minutes * 60:
                        
                        # Check consecutive failures
                        failures = consecutive_failures.get(schedule_name, 0)
                        max_failures = self.config["failure_handling"]["max_consecutive_failures"]
                        
                        if failures >= max_failures:
                            cooldown_minutes = self.config["failure_handling"]["failure_cooldown_minutes"]
                            if last_run and (current_time - last_run).total_seconds() < cooldown_minutes * 60:
                                logger.warning(f"Schedule {schedule_name} in cooldown due to consecutive failures")
                                continue
                            else:
                                # Reset failure count after cooldown
                                consecutive_failures[schedule_name] = 0
                        
                        logger.info(f"Running scheduled tests: {schedule_name}")
                        
                        try:
                            suite_result = await self.run_test_suite(test_types)
                            last_run_times[schedule_name] = current_time
                            
                            if suite_result["success_rate"] >= 0.8:
                                consecutive_failures[schedule_name] = 0
                            else:
                                consecutive_failures[schedule_name] = failures + 1
                                
                                # Handle failures
                                if self.config["failure_handling"]["auto_restart_services"]:
                                    await self._handle_test_failures(schedule_name, suite_result)
                            
                        except Exception as e:
                            logger.error(f"Scheduled test {schedule_name} failed: {e}")
                            consecutive_failures[schedule_name] = failures + 1
                
                # Sleep before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in continuous testing loop: {e}")
                await asyncio.sleep(60)
        
        logger.info("Continuous testing stopped")
    
    async def _handle_test_failures(self, schedule_name: str, suite_result: Dict[str, Any]):
        """Handle test failures by attempting service restart"""
        logger.warning(f"Handling test failures for schedule: {schedule_name}")
        
        failed_tests = [r for r in suite_result["results"] if not r["success"]]
        
        # Analyze failures and attempt remediation
        for failed_test in failed_tests:
            test_type = failed_test["test_type"]
            
            if test_type in ["basic_functionality", "agent_health"]:
                logger.info("Attempting to restart agents due to health check failures")
                await self._restart_agents()
            elif test_type == "performance_load":
                logger.info("Performance issues detected, checking system resources")
                await self._check_system_resources()
    
    async def _restart_agents(self):
        """Restart agent services"""
        try:
            import subprocess
            
            # Restart agents using docker-compose
            cmd = ["docker-compose", "-f", "docker-compose.dev.yml", "restart", 
                   "detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Agents restarted successfully")
                # Wait for agents to stabilize
                await asyncio.sleep(30)
            else:
                logger.error(f"Failed to restart agents: {result.stderr}")
                
        except Exception as e:
            logger.error(f"Error restarting agents: {e}")
    
    async def _check_system_resources(self):
        """Check system resource usage"""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            logger.info(f"System resources - CPU: {cpu_percent}%, Memory: {memory.percent}%, Disk: {disk.percent}%")
            
            if cpu_percent > 80:
                logger.warning("High CPU usage detected")
            if memory.percent > 80:
                logger.warning("High memory usage detected")
            if disk.percent > 80:
                logger.warning("High disk usage detected")
                
        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
    
    async def _generate_test_report(self, test_record: Dict[str, Any]):
        """Generate individual test report"""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"test_{test_record['test_type']}_{timestamp}.json"
            filepath = os.path.join(self.config["reporting"]["output_directory"], filename)
            
            with open(filepath, 'w') as f:
                json.dump(test_record, f, indent=2)
            
            logger.debug(f"Test report generated: {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to generate test report: {e}")
    
    async def _generate_suite_report(self, suite_summary: Dict[str, Any]):
        """Generate test suite report"""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"suite_report_{timestamp}.json"
            filepath = os.path.join(self.config["reporting"]["output_directory"], filename)
            
            with open(filepath, 'w') as f:
                json.dump(suite_summary, f, indent=2)
            
            logger.info(f"Suite report generated: {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to generate suite report: {e}")
    
    async def _generate_validation_report(self, validation_summary: Dict[str, Any], validation_results: List[Any]):
        """Generate system validation report"""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"validation_report_{timestamp}.json"
            filepath = os.path.join(self.config["reporting"]["output_directory"], filename)
            
            full_report = {
                "summary": validation_summary,
                "detailed_results": [
                    {
                        "component": r.component,
                        "test_name": r.test_name,
                        "success": r.success,
                        "message": r.message,
                        "duration_ms": r.duration_ms,
                        "details": r.details
                    }
                    for r in validation_results
                ]
            }
            
            with open(filepath, 'w') as f:
                json.dump(full_report, f, indent=2)
            
            logger.info(f"Validation report generated: {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to generate validation report: {e}")
    
    def stop_continuous_testing(self):
        """Stop continuous testing"""
        logger.info("Stopping continuous testing")
        self.running = False
    
    def get_test_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent test history"""
        return self.test_history[-limit:]
    
    def get_test_statistics(self) -> Dict[str, Any]:
        """Get test statistics"""
        if not self.test_history:
            return {"total_tests": 0}
        
        total_tests = len(self.test_history)
        passed_tests = sum(1 for t in self.test_history if t["success"])
        
        # Calculate statistics by test type
        by_type = {}
        for test in self.test_history:
            test_type = test["test_type"]
            if test_type not in by_type:
                by_type[test_type] = {"total": 0, "passed": 0}
            by_type[test_type]["total"] += 1
            if test["success"]:
                by_type[test_type]["passed"] += 1
        
        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "overall_success_rate": passed_tests / total_tests,
            "by_test_type": by_type,
            "last_test_time": self.test_history[-1]["end_time"] if self.test_history else None
        }

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="AI Honeypot AgentCore Automated Test Runner")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--test-type", help="Single test type to run")
    parser.add_argument("--test-suite", nargs="+", help="List of test types to run as suite")
    parser.add_argument("--validation", choices=["basic", "comprehensive", "security", "performance"], 
                       help="Run system validation")
    parser.add_argument("--continuous", action="store_true", help="Run continuous testing")
    parser.add_argument("--stats", action="store_true", help="Show test statistics")
    
    args = parser.parse_args()
    
    # Create test runner
    runner = AutomatedTestRunner(args.config)
    await runner.initialize()
    
    try:
        if args.stats:
            stats = runner.get_test_statistics()
            print(json.dumps(stats, indent=2))
        elif args.test_type:
            result = await runner.run_single_test(args.test_type)
            print(f"Test result: {'PASSED' if result['success'] else 'FAILED'}")
        elif args.test_suite:
            result = await runner.run_test_suite(args.test_suite)
            print(f"Suite result: {result['passed_tests']}/{result['total_tests']} passed")
        elif args.validation:
            level_map = {
                "basic": ValidationLevel.BASIC,
                "comprehensive": ValidationLevel.COMPREHENSIVE,
                "security": ValidationLevel.SECURITY,
                "performance": ValidationLevel.PERFORMANCE
            }
            result = await runner.run_system_validation(level_map[args.validation])
            print(f"Validation result: {'PASSED' if result['overall_success'] else 'FAILED'}")
        elif args.continuous:
            print("Starting continuous testing mode (Ctrl+C to stop)")
            try:
                await runner.run_continuous_testing()
            except KeyboardInterrupt:
                runner.stop_continuous_testing()
                print("Continuous testing stopped")
        else:
            # Run default test suite
            default_tests = ["basic_functionality", "threat_detection"]
            result = await runner.run_test_suite(default_tests)
            print(f"Default test suite result: {result['passed_tests']}/{result['total_tests']} passed")
    
    except Exception as e:
        logger.error(f"Test runner failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())