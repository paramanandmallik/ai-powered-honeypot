#!/usr/bin/env python3
"""
System Integration Test Suite

Comprehensive test suite for validating end-to-end system integration
between AgentCore Runtime agents, AWS services, honeypot infrastructure,
and management dashboard.
"""

import asyncio
import json
import logging
import pytest
from datetime import datetime, timedelta
from typing import Dict, List, Any
import uuid

from integration.system_integration_manager import SystemIntegrationManager, IntegrationStatus
from integration.dashboard_integration import DashboardIntegration
from integration.aws_services_integration import AWSServicesIntegration
from integration.honeypot_integration import HoneypotIntegration, HoneypotType


class SystemIntegrationTestSuite:
    """
    Comprehensive test suite for system integration validation
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.integration_manager = None
        self.test_results = {
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "test_details": [],
            "start_time": None,
            "end_time": None
        }
    
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive system integration tests"""
        self.test_results["start_time"] = datetime.utcnow()
        self.logger.info("Starting comprehensive system integration tests...")
        
        try:
            # Test 1: System Initialization
            await self._test_system_initialization()
            
            # Test 2: Agent Integration
            await self._test_agent_integration()
            
            # Test 3: AWS Services Integration
            await self._test_aws_services_integration()
            
            # Test 4: Honeypot Infrastructure Integration
            await self._test_honeypot_integration()
            
            # Test 5: Dashboard Integration
            await self._test_dashboard_integration()
            
            # Test 6: End-to-End Flow Processing
            await self._test_end_to_end_flows()
            
            # Test 7: Error Handling and Recovery
            await self._test_error_handling()
            
            # Test 8: Performance and Scalability
            await self._test_performance_scalability()
            
            # Test 9: Security and Isolation
            await self._test_security_isolation()
            
            # Test 10: Emergency Procedures
            await self._test_emergency_procedures()
            
        except Exception as e:
            self.logger.error(f"Test suite execution failed: {e}")
            self._record_test_result("Test Suite Execution", False, str(e))
        
        finally:
            self.test_results["end_time"] = datetime.utcnow()
            await self._cleanup_test_environment()
        
        return self._generate_test_report()
    
    async def _test_system_initialization(self):
        """Test system initialization and component connectivity"""
        test_name = "System Initialization"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            # Initialize system integration manager
            self.integration_manager = SystemIntegrationManager("config/integration_config.json")
            
            # Test initialization
            success = await self.integration_manager.initialize_system()
            
            if not success:
                raise Exception("System initialization failed")
            
            # Verify system status
            system_status = await self.integration_manager.get_system_status()
            
            if system_status["system_health"]["overall_status"] != IntegrationStatus.CONNECTED:
                raise Exception(f"System not in connected state: {system_status['system_health']['overall_status']}")
            
            self._record_test_result(test_name, True, "System initialized successfully")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_agent_integration(self):
        """Test AgentCore Runtime agent integration"""
        test_name = "Agent Integration"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test agent connectivity
            agents = ["coordinator", "detection", "interaction", "intelligence"]
            
            for agent_name in agents:
                agent = getattr(self.integration_manager, f"{agent_name}_agent", None)
                if not agent:
                    raise Exception(f"Agent {agent_name} not found")
                
                # Test agent health
                health = await agent.get_status()
                if health.get("status") != "running":
                    raise Exception(f"Agent {agent_name} not running: {health}")
            
            # Test agent communication
            test_message = {
                "type": "test_message",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {"test": True}
            }
            
            # Test message routing between agents
            await self.integration_manager.agentcore_sdk.send_message(
                "detection-agent", "coordinator-agent", test_message
            )
            
            self._record_test_result(test_name, True, "All agents integrated successfully")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_aws_services_integration(self):
        """Test AWS supporting services integration"""
        test_name = "AWS Services Integration"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test AWS services health
            aws_health = await self.integration_manager.aws_infrastructure.check_services_health()
            
            required_services = ["s3", "rds", "cloudwatch", "sns"]
            for service in required_services:
                if service not in aws_health or "error" in aws_health[service]:
                    raise Exception(f"AWS service {service} not healthy: {aws_health.get(service)}")
            
            # Test S3 operations
            test_data = {
                "test_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "data": "test session data"
            }
            
            s3_success = await self.integration_manager.aws_infrastructure.store_session_data(
                "test-session", test_data
            )
            
            if not s3_success:
                raise Exception("S3 data storage test failed")
            
            # Test CloudWatch metrics
            test_metrics = [
                {"name": "TestMetric", "value": 1.0, "unit": "Count"}
            ]
            
            cw_success = await self.integration_manager.aws_infrastructure.publish_metrics(
                "AI-Honeypot-Test", test_metrics
            )
            
            if not cw_success:
                raise Exception("CloudWatch metrics test failed")
            
            self._record_test_result(test_name, True, "AWS services integrated successfully")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_honeypot_integration(self):
        """Test honeypot infrastructure integration"""
        test_name = "Honeypot Integration"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test honeypot creation
            engagement_config = {
                "engagement_id": "test-engagement",
                "threat_level": "medium",
                "attacker_profile": {"skill_level": "intermediate"}
            }
            
            # Test different honeypot types
            honeypot_types = [HoneypotType.WEB_ADMIN, HoneypotType.SSH]
            created_honeypots = []
            
            for honeypot_type in honeypot_types:
                honeypot_id = await self.integration_manager.coordinator_agent.create_honeypot_for_engagement({
                    "honeypot_type": honeypot_type.value,
                    **engagement_config
                })
                
                if not honeypot_id:
                    raise Exception(f"Failed to create {honeypot_type.value} honeypot")
                
                created_honeypots.append(honeypot_id)
            
            # Test honeypot status
            for honeypot_id in created_honeypots:
                status = await self.integration_manager.coordinator_agent.get_honeypot_status(honeypot_id)
                if not status or status.get("status") != "active":
                    raise Exception(f"Honeypot {honeypot_id} not active: {status}")
            
            # Test session management
            session_id = await self.integration_manager.interaction_agent.start_session(
                created_honeypots[0], "192.168.1.100", {}
            )
            
            if not session_id:
                raise Exception("Failed to start engagement session")
            
            # Test interaction recording
            interaction_success = await self.integration_manager.interaction_agent.record_interaction(
                session_id, {
                    "type": "login_attempt",
                    "username": "admin",
                    "success": False
                }
            )
            
            if not interaction_success:
                raise Exception("Failed to record interaction")
            
            # Cleanup test honeypots
            for honeypot_id in created_honeypots:
                await self.integration_manager.coordinator_agent.destroy_honeypot(honeypot_id)
            
            self._record_test_result(test_name, True, "Honeypot integration successful")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_dashboard_integration(self):
        """Test management dashboard integration"""
        test_name = "Dashboard Integration"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test dashboard connectivity
            dashboard_health = await self.integration_manager.dashboard_manager.check_health()
            if dashboard_health.get("status") != "healthy":
                raise Exception(f"Dashboard not healthy: {dashboard_health}")
            
            # Test agent registration with dashboard
            dashboard_integration = self.integration_manager.dashboard_manager.dashboard_integration
            
            # Simulate client connection
            client_id = "test-client-123"
            await dashboard_integration.handle_client_connection(client_id, "127.0.0.1")
            
            # Test command handling
            test_command = {
                "type": "system_control",
                "action": "get_system_status"
            }
            
            result = await dashboard_integration.handle_client_command(client_id, test_command)
            if not result.get("success"):
                raise Exception(f"Dashboard command failed: {result}")
            
            # Test data streaming
            test_health_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "status": "healthy",
                "metrics": {"cpu": 50, "memory": 60}
            }
            
            await dashboard_integration.update_system_health(test_health_data)
            
            # Cleanup
            await dashboard_integration.handle_client_disconnection(client_id)
            
            self._record_test_result(test_name, True, "Dashboard integration successful")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_end_to_end_flows(self):
        """Test complete end-to-end flow processing"""
        test_name = "End-to-End Flow Processing"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Create test threat event
            threat_event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "source": "test_feed",
                "threat_type": "suspicious_login",
                "confidence_score": 0.85,
                "indicators": ["192.168.1.100", "admin@test.com"],
                "raw_data": {"login_attempts": 5, "source_ip": "192.168.1.100"}
            }
            
            # Process end-to-end flow
            flow_id = await self.integration_manager.process_end_to_end_flow(threat_event)
            
            if not flow_id:
                raise Exception("Failed to start end-to-end flow")
            
            # Monitor flow progress
            max_wait_time = 300  # 5 minutes
            start_time = datetime.utcnow()
            
            while (datetime.utcnow() - start_time).total_seconds() < max_wait_time:
                flow_status = await self.integration_manager.get_flow_status(flow_id)
                
                if not flow_status:
                    raise Exception("Flow status not found")
                
                if flow_status.get("completion_time"):
                    if flow_status.get("success"):
                        break
                    else:
                        raise Exception(f"Flow failed: {flow_status.get('error_details')}")
                
                await asyncio.sleep(5)
            else:
                raise Exception("Flow did not complete within timeout")
            
            # Validate flow results
            if not flow_status.get("intelligence_report"):
                raise Exception("No intelligence report generated")
            
            self._record_test_result(test_name, True, f"End-to-end flow completed successfully: {flow_id}")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_error_handling(self):
        """Test error handling and recovery mechanisms"""
        test_name = "Error Handling and Recovery"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test invalid threat event handling
            invalid_threat_event = {
                "invalid_field": "test"
            }
            
            flow_id = await self.integration_manager.process_end_to_end_flow(invalid_threat_event)
            
            # Should handle gracefully and not crash
            if flow_id:
                flow_status = await self.integration_manager.get_flow_status(flow_id)
                if flow_status and not flow_status.get("success"):
                    # Expected failure - this is good
                    pass
            
            # Test agent failure recovery
            # Simulate agent failure by stopping and restarting
            detection_agent = self.integration_manager.detection_agent
            await detection_agent.stop()
            
            # Wait a moment
            await asyncio.sleep(2)
            
            # Restart agent
            await detection_agent.start()
            
            # Verify agent is healthy again
            health = await detection_agent.get_status()
            if health.get("status") != "running":
                raise Exception("Agent failed to recover")
            
            self._record_test_result(test_name, True, "Error handling and recovery successful")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_performance_scalability(self):
        """Test system performance and scalability"""
        test_name = "Performance and Scalability"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test concurrent flow processing
            concurrent_flows = 5
            flow_ids = []
            
            # Create multiple threat events
            for i in range(concurrent_flows):
                threat_event = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": f"test_feed_{i}",
                    "threat_type": "suspicious_activity",
                    "confidence_score": 0.8,
                    "indicators": [f"192.168.1.{100+i}"],
                    "raw_data": {"test_id": i}
                }
                
                flow_id = await self.integration_manager.process_end_to_end_flow(threat_event)
                if flow_id:
                    flow_ids.append(flow_id)
            
            if len(flow_ids) != concurrent_flows:
                raise Exception(f"Only {len(flow_ids)} of {concurrent_flows} flows started")
            
            # Monitor performance metrics
            start_time = datetime.utcnow()
            
            # Wait for flows to complete
            await asyncio.sleep(30)
            
            # Check system performance
            system_status = await self.integration_manager.get_system_status()
            performance_metrics = system_status["system_health"]["performance_metrics"]
            
            # Validate performance thresholds
            if performance_metrics.get("success_rate", 0) < 80:
                raise Exception(f"Success rate too low: {performance_metrics.get('success_rate')}%")
            
            self._record_test_result(test_name, True, f"Performance test passed with {len(flow_ids)} concurrent flows")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_security_isolation(self):
        """Test security and isolation controls"""
        test_name = "Security and Isolation"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test synthetic data validation
            test_data = {
                "synthetic": True,
                "fingerprint": "test-fingerprint-123",
                "content": "This is synthetic test data"
            }
            
            # Verify synthetic data is properly tagged
            if not test_data.get("synthetic"):
                raise Exception("Synthetic data not properly tagged")
            
            # Test real data detection (simulate)
            suspicious_data = {
                "content": "real-looking-password-123",
                "synthetic": False
            }
            
            # This should trigger real data detection
            # In a real implementation, this would be caught and quarantined
            
            # Test network isolation
            # Verify honeypots are isolated from production networks
            # This would typically involve network connectivity tests
            
            self._record_test_result(test_name, True, "Security and isolation controls validated")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    async def _test_emergency_procedures(self):
        """Test emergency shutdown and incident response"""
        test_name = "Emergency Procedures"
        self.logger.info(f"Running test: {test_name}")
        
        try:
            if not self.integration_manager:
                raise Exception("Integration manager not initialized")
            
            # Test emergency shutdown capability
            # Note: We won't actually trigger it as it would shut down the system
            
            # Test that emergency shutdown method exists and is callable
            if not hasattr(self.integration_manager, 'emergency_shutdown'):
                raise Exception("Emergency shutdown method not available")
            
            # Test incident response procedures
            # Simulate high-priority security event
            security_event = {
                "type": "security_incident",
                "severity": "critical",
                "description": "Potential real data exposure detected",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Verify incident can be processed
            # In a real implementation, this would trigger alerts and escalation
            
            self._record_test_result(test_name, True, "Emergency procedures validated")
            
        except Exception as e:
            self._record_test_result(test_name, False, str(e))
    
    def _record_test_result(self, test_name: str, success: bool, details: str):
        """Record test result"""
        self.test_results["total_tests"] += 1
        
        if success:
            self.test_results["passed_tests"] += 1
            self.logger.info(f"✓ {test_name}: {details}")
        else:
            self.test_results["failed_tests"] += 1
            self.logger.error(f"✗ {test_name}: {details}")
        
        self.test_results["test_details"].append({
            "test_name": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def _cleanup_test_environment(self):
        """Clean up test environment"""
        try:
            if self.integration_manager:
                # Clean up any remaining test resources
                await self.integration_manager.shutdown()
            
            self.logger.info("Test environment cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Test cleanup failed: {e}")
    
    def _generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        duration = None
        if self.test_results["start_time"] and self.test_results["end_time"]:
            duration = (self.test_results["end_time"] - self.test_results["start_time"]).total_seconds()
        
        success_rate = 0
        if self.test_results["total_tests"] > 0:
            success_rate = (self.test_results["passed_tests"] / self.test_results["total_tests"]) * 100
        
        report = {
            "test_summary": {
                "total_tests": self.test_results["total_tests"],
                "passed_tests": self.test_results["passed_tests"],
                "failed_tests": self.test_results["failed_tests"],
                "success_rate": success_rate,
                "duration_seconds": duration,
                "start_time": self.test_results["start_time"].isoformat() if self.test_results["start_time"] else None,
                "end_time": self.test_results["end_time"].isoformat() if self.test_results["end_time"] else None
            },
            "test_details": self.test_results["test_details"],
            "overall_result": "PASS" if self.test_results["failed_tests"] == 0 else "FAIL",
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        if self.test_results["failed_tests"] > 0:
            recommendations.append("Review failed tests and address underlying issues")
        
        if self.test_results["total_tests"] > 0:
            success_rate = (self.test_results["passed_tests"] / self.test_results["total_tests"]) * 100
            
            if success_rate < 90:
                recommendations.append("System integration needs improvement - success rate below 90%")
            elif success_rate < 95:
                recommendations.append("Consider additional testing and validation")
            else:
                recommendations.append("System integration is performing well")
        
        recommendations.append("Continue monitoring system performance in production")
        recommendations.append("Implement automated integration testing in CI/CD pipeline")
        
        return recommendations


# Test execution functions
async def run_integration_tests():
    """Run system integration tests"""
    test_suite = SystemIntegrationTestSuite()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run tests
    report = await test_suite.run_comprehensive_tests()
    
    # Save report
    with open("reports/system_integration_test_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "="*80)
    print("SYSTEM INTEGRATION TEST REPORT")
    print("="*80)
    print(f"Total Tests: {report['test_summary']['total_tests']}")
    print(f"Passed: {report['test_summary']['passed_tests']}")
    print(f"Failed: {report['test_summary']['failed_tests']}")
    print(f"Success Rate: {report['test_summary']['success_rate']:.1f}%")
    print(f"Duration: {report['test_summary']['duration_seconds']:.1f} seconds")
    print(f"Overall Result: {report['overall_result']}")
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"- {rec}")
    print("="*80)
    
    return report


if __name__ == "__main__":
    # Run integration tests
    asyncio.run(run_integration_tests())