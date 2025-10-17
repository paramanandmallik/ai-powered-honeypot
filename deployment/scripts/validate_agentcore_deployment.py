#!/usr/bin/env python3
"""
AgentCore Runtime Deployment Validation Script
Validates that all agents are properly deployed and functioning in AgentCore Runtime.
"""

import os
import sys
import json
import time
import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AgentCoreValidator:
    """Validates AgentCore Runtime deployment"""
    
    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.build_dir = self.workspace_root / "build" / "agentcore"
        
        # AgentCore starter toolkit CLI configuration
        self.agentcore_cli = "agentcore"  # Amazon Bedrock AgentCore starter toolkit CLI
        self.deployment_region = os.getenv("AWS_REGION", "us-east-1")
        self.agentcore_runtime_endpoint = os.getenv("AGENTCORE_RUNTIME_ENDPOINT", "")
        
        # Validation configuration
        self.agents_to_validate = ["detection", "coordinator", "interaction", "intelligence"]
        self.validation_timeout = 60  # seconds per test
        self.health_check_retries = 3
        self.health_check_interval = 10  # seconds between retries
        
        logger.info(f"AgentCore Validator initialized for region: {self.deployment_region}")
    
    async def validate_deployment(self) -> Dict[str, Any]:
        """Validate complete AgentCore Runtime deployment"""
        try:
            logger.info("Starting comprehensive AgentCore Runtime deployment validation...")
            
            validation_results = {
                "validation_id": f"validate-{int(time.time())}",
                "timestamp": datetime.utcnow().isoformat(),
                "region": self.deployment_region,
                "overall_status": "in_progress",
                "tests": {}
            }
            
            # Test 1: Agent Health Checks
            logger.info("🔍 Testing agent health checks...")
            health_results = await self._validate_agent_health()
            validation_results["tests"]["agent_health"] = health_results
            
            # Test 2: Agent Communication
            logger.info("🔍 Testing agent communication...")
            communication_results = await self._validate_agent_communication()
            validation_results["tests"]["agent_communication"] = communication_results
            
            # Test 3: Workflow Integration
            logger.info("🔍 Testing workflow integration...")
            workflow_results = await self._validate_workflow_integration()
            validation_results["tests"]["workflow_integration"] = workflow_results
            
            # Test 4: Scaling and Performance
            logger.info("🔍 Testing scaling and performance...")
            scaling_results = await self._validate_scaling_performance()
            validation_results["tests"]["scaling_performance"] = scaling_results
            
            # Test 5: End-to-End Functionality
            logger.info("🔍 Testing end-to-end functionality...")
            e2e_results = await self._validate_end_to_end_functionality()
            validation_results["tests"]["end_to_end"] = e2e_results
            
            # Determine overall status
            all_tests_passed = all(
                test_result.get("status") == "passed" 
                for test_result in validation_results["tests"].values()
            )
            
            if all_tests_passed:
                validation_results["overall_status"] = "passed"
                logger.info("✅ All validation tests passed!")
            else:
                validation_results["overall_status"] = "failed"
                logger.error("❌ Some validation tests failed")
            
            # Save validation results
            self._save_validation_results(validation_results)
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return {
                "validation_id": f"validate-{int(time.time())}",
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": "error",
                "error": str(e)
            }
    
    async def _validate_agent_health(self) -> Dict[str, Any]:
        """Validate agent health checks"""
        try:
            health_results = {
                "status": "in_progress",
                "agents": {},
                "summary": {
                    "total_agents": len(self.agents_to_validate),
                    "healthy_agents": 0,
                    "unhealthy_agents": 0
                }
            }
            
            for agent_type in self.agents_to_validate:
                logger.info(f"Checking health of {agent_type} agent...")
                
                agent_health = await self._check_single_agent_health(agent_type)
                health_results["agents"][agent_type] = agent_health
                
                if agent_health.get("healthy", False):
                    health_results["summary"]["healthy_agents"] += 1
                else:
                    health_results["summary"]["unhealthy_agents"] += 1
            
            # Determine overall health status
            if health_results["summary"]["healthy_agents"] == health_results["summary"]["total_agents"]:
                health_results["status"] = "passed"
            else:
                health_results["status"] = "failed"
            
            return health_results
            
        except Exception as e:
            logger.error(f"Agent health validation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _check_single_agent_health(self, agent_type: str) -> Dict[str, Any]:
        """Check health of a single agent with retries using AgentCore starter toolkit"""
        for attempt in range(self.health_check_retries):
            try:
                # Use AgentCore starter toolkit to test agent health
                agent_name = f"ai-honeypot-{agent_type}-agent"
                agent_dir = self.build_dir / agent_name
                
                if not agent_dir.exists():
                    return {
                        "healthy": False,
                        "status": "agent_directory_not_found",
                        "error": f"Agent directory not found: {agent_dir}",
                        "attempt": attempt + 1
                    }
                
                # Test agent with a simple invoke
                cmd = [
                    self.agentcore_cli,
                    "invoke",
                    '{"prompt": "Health check"}'
                ]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=30,
                    cwd=str(agent_dir)
                )
                
                if result.returncode == 0:
                    try:
                        health_data = json.loads(result.stdout)
                        return {
                            "healthy": health_data.get("status") == "healthy",
                            "status": health_data.get("status", "unknown"),
                            "instances": health_data.get("instances", 0),
                            "response_time_ms": health_data.get("response_time_ms", 0),
                            "last_health_check": health_data.get("last_health_check"),
                            "attempt": attempt + 1,
                            "details": health_data
                        }
                    except json.JSONDecodeError:
                        # Fallback parsing
                        healthy = "healthy" in result.stdout.lower()
                        return {
                            "healthy": healthy,
                            "status": "healthy" if healthy else "unknown",
                            "attempt": attempt + 1,
                            "raw_output": result.stdout
                        }
                else:
                    if attempt < self.health_check_retries - 1:
                        logger.warning(f"Health check attempt {attempt + 1} failed for {agent_type}, retrying...")
                        await asyncio.sleep(self.health_check_interval)
                        continue
                    else:
                        return {
                            "healthy": False,
                            "status": "health_check_failed",
                            "error": result.stderr or result.stdout,
                            "attempt": attempt + 1
                        }
                        
            except Exception as e:
                if attempt < self.health_check_retries - 1:
                    logger.warning(f"Health check attempt {attempt + 1} failed for {agent_type}: {e}, retrying...")
                    await asyncio.sleep(self.health_check_interval)
                    continue
                else:
                    return {
                        "healthy": False,
                        "status": "health_check_error",
                        "error": str(e),
                        "attempt": attempt + 1
                    }
        
        return {
            "healthy": False,
            "status": "max_retries_exceeded",
            "attempts": self.health_check_retries
        }
    
    async def _validate_agent_communication(self) -> Dict[str, Any]:
        """Validate agent-to-agent communication"""
        try:
            communication_results = {
                "status": "in_progress",
                "tests": {}
            }
            
            # Test 1: Detection to Coordinator communication
            logger.info("Testing Detection -> Coordinator communication...")
            detection_to_coordinator = await self._test_agent_message(
                "detection", "coordinator", "test_engagement_decision", 
                {"test": True, "threat_confidence": 0.8}
            )
            communication_results["tests"]["detection_to_coordinator"] = detection_to_coordinator
            
            # Test 2: Coordinator to Interaction communication
            logger.info("Testing Coordinator -> Interaction communication...")
            coordinator_to_interaction = await self._test_agent_message(
                "coordinator", "interaction", "test_honeypot_ready",
                {"test": True, "honeypot_type": "web_admin"}
            )
            communication_results["tests"]["coordinator_to_interaction"] = coordinator_to_interaction
            
            # Test 3: Interaction to Intelligence communication
            logger.info("Testing Interaction -> Intelligence communication...")
            interaction_to_intelligence = await self._test_agent_message(
                "interaction", "intelligence", "test_session_completed",
                {"test": True, "session_id": "test-session-123"}
            )
            communication_results["tests"]["interaction_to_intelligence"] = interaction_to_intelligence
            
            # Test 4: Broadcast communication
            logger.info("Testing broadcast communication...")
            broadcast_test = await self._test_broadcast_message(
                "coordinator", "test_system_status", {"test": True}
            )
            communication_results["tests"]["broadcast"] = broadcast_test
            
            # Determine overall communication status
            all_comm_tests_passed = all(
                test.get("success", False) 
                for test in communication_results["tests"].values()
            )
            
            communication_results["status"] = "passed" if all_comm_tests_passed else "failed"
            
            return communication_results
            
        except Exception as e:
            logger.error(f"Agent communication validation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _test_agent_message(self, from_agent: str, to_agent: str, message_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Test message sending between specific agents using AgentCore starter toolkit"""
        try:
            # For AgentCore Runtime, we test individual agent invocation
            # Agent-to-agent communication is handled by the runtime itself
            
            # Test the target agent with a message
            agent_name = f"ai-honeypot-{to_agent}-agent"
            agent_dir = self.build_dir / agent_name
            
            if not agent_dir.exists():
                return {
                    "success": False,
                    "error": f"Target agent directory not found: {agent_dir}"
                }
            
            # Create test payload that simulates inter-agent communication
            test_payload = {
                "prompt": f"Test message from {from_agent} agent",
                "message_type": message_type,
                "test_data": payload
            }
            
            cmd = [
                self.agentcore_cli,
                "invoke",
                json.dumps(test_payload)
            ]
            
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=45,
                cwd=str(agent_dir)
            )
            response_time = (time.time() - start_time) * 1000
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "response_time_ms": response_time,
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or result.stdout,
                    "response_time_ms": response_time
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _test_broadcast_message(self, from_agent: str, message_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Test broadcast message functionality"""
        try:
            # Use AgentCore CLI to send broadcast message
            cmd = [
                self.agentcore_cli,
                "message",
                "broadcast",
                "--from", from_agent,
                "--type", message_type,
                "--payload", json.dumps(payload),
                "--region", self.deployment_region,
                "--timeout", "30"
            ]
            
            if self.agentcore_runtime_endpoint:
                cmd.extend(["--endpoint", self.agentcore_runtime_endpoint])
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            response_time = (time.time() - start_time) * 1000
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "response_time_ms": response_time,
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or result.stdout,
                    "response_time_ms": response_time
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _validate_workflow_integration(self) -> Dict[str, Any]:
        """Validate workflow integration"""
        try:
            workflow_results = {
                "status": "in_progress",
                "workflows": {}
            }
            
            # Test workflow execution
            logger.info("Testing workflow execution...")
            workflow_test = await self._test_workflow_execution()
            workflow_results["workflows"]["execution_test"] = workflow_test
            
            # Test workflow monitoring
            logger.info("Testing workflow monitoring...")
            monitoring_test = await self._test_workflow_monitoring()
            workflow_results["workflows"]["monitoring_test"] = monitoring_test
            
            # Determine overall workflow status
            all_workflow_tests_passed = all(
                test.get("success", False) 
                for test in workflow_results["workflows"].values()
            )
            
            workflow_results["status"] = "passed" if all_workflow_tests_passed else "failed"
            
            return workflow_results
            
        except Exception as e:
            logger.error(f"Workflow validation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _test_workflow_execution(self) -> Dict[str, Any]:
        """Test workflow execution"""
        try:
            # Trigger a test workflow
            cmd = [
                self.agentcore_cli,
                "workflow",
                "trigger",
                "--workflow", "threat-detection-to-engagement",
                "--data", json.dumps({"test": True, "threat_confidence": 0.8}),
                "--region", self.deployment_region
            ]
            
            if self.agentcore_runtime_endpoint:
                cmd.extend(["--endpoint", self.agentcore_runtime_endpoint])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or result.stdout
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _test_workflow_monitoring(self) -> Dict[str, Any]:
        """Test workflow monitoring"""
        try:
            # Check workflow status
            cmd = [
                self.agentcore_cli,
                "workflow",
                "status",
                "--region", self.deployment_region
            ]
            
            if self.agentcore_runtime_endpoint:
                cmd.extend(["--endpoint", self.agentcore_runtime_endpoint])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or result.stdout
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _validate_scaling_performance(self) -> Dict[str, Any]:
        """Validate scaling and performance"""
        try:
            scaling_results = {
                "status": "in_progress",
                "tests": {}
            }
            
            # Test auto-scaling
            logger.info("Testing auto-scaling...")
            scaling_test = await self._test_auto_scaling()
            scaling_results["tests"]["auto_scaling"] = scaling_test
            
            # Test performance under load
            logger.info("Testing performance under load...")
            performance_test = await self._test_performance_load()
            scaling_results["tests"]["performance_load"] = performance_test
            
            # Determine overall scaling status
            all_scaling_tests_passed = all(
                test.get("success", False) 
                for test in scaling_results["tests"].values()
            )
            
            scaling_results["status"] = "passed" if all_scaling_tests_passed else "failed"
            
            return scaling_results
            
        except Exception as e:
            logger.error(f"Scaling validation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _test_auto_scaling(self) -> Dict[str, Any]:
        """Test auto-scaling functionality"""
        try:
            # Check current scaling configuration
            cmd = [
                self.agentcore_cli,
                "scaling",
                "status",
                "--region", self.deployment_region
            ]
            
            if self.agentcore_runtime_endpoint:
                cmd.extend(["--endpoint", self.agentcore_runtime_endpoint])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or result.stdout
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _test_performance_load(self) -> Dict[str, Any]:
        """Test performance under load"""
        try:
            # Send multiple concurrent requests to test load handling
            tasks = []
            for i in range(5):  # Send 5 concurrent test messages
                task = self._test_agent_message(
                    "detection", "coordinator", f"load_test_{i}",
                    {"test": True, "load_test_id": i}
                )
                tasks.append(task)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            successful_requests = sum(1 for result in results if isinstance(result, dict) and result.get("success", False))
            total_requests = len(results)
            
            return {
                "success": successful_requests == total_requests,
                "successful_requests": successful_requests,
                "total_requests": total_requests,
                "success_rate": successful_requests / total_requests if total_requests > 0 else 0,
                "details": results
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _validate_end_to_end_functionality(self) -> Dict[str, Any]:
        """Validate end-to-end functionality"""
        try:
            e2e_results = {
                "status": "in_progress",
                "scenario": "threat_detection_to_intelligence"
            }
            
            logger.info("Running end-to-end scenario: threat detection to intelligence...")
            
            # Simulate complete workflow
            scenario_result = await self._run_e2e_scenario()
            e2e_results.update(scenario_result)
            
            e2e_results["status"] = "passed" if scenario_result.get("success", False) else "failed"
            
            return e2e_results
            
        except Exception as e:
            logger.error(f"End-to-end validation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _run_e2e_scenario(self) -> Dict[str, Any]:
        """Run end-to-end scenario"""
        try:
            scenario_steps = []
            
            # Step 1: Trigger threat detection
            logger.info("Step 1: Triggering threat detection...")
            step1 = await self._test_agent_message(
                "detection", "coordinator", "threat_detected",
                {
                    "test": True,
                    "source_ip": "192.168.1.100",
                    "threat_type": "brute_force",
                    "confidence": 0.85
                }
            )
            scenario_steps.append({"step": "threat_detection", "result": step1})
            
            if not step1.get("success", False):
                return {
                    "success": False,
                    "error": "Step 1 failed: Threat detection",
                    "steps": scenario_steps
                }
            
            # Step 2: Wait and check honeypot creation
            logger.info("Step 2: Checking honeypot creation...")
            await asyncio.sleep(5)  # Wait for processing
            
            step2 = await self._test_agent_message(
                "coordinator", "interaction", "honeypot_status",
                {"test": True, "honeypot_id": "test-honeypot-123"}
            )
            scenario_steps.append({"step": "honeypot_creation", "result": step2})
            
            # Step 3: Simulate session completion
            logger.info("Step 3: Simulating session completion...")
            step3 = await self._test_agent_message(
                "interaction", "intelligence", "session_completed",
                {
                    "test": True,
                    "session_id": "test-session-123",
                    "honeypot_type": "web_admin",
                    "interactions": ["login_attempt", "directory_traversal"]
                }
            )
            scenario_steps.append({"step": "session_completion", "result": step3})
            
            # Determine overall success
            all_steps_successful = all(step["result"].get("success", False) for step in scenario_steps)
            
            return {
                "success": all_steps_successful,
                "steps": scenario_steps,
                "total_steps": len(scenario_steps),
                "successful_steps": sum(1 for step in scenario_steps if step["result"].get("success", False))
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _save_validation_results(self, results: Dict[str, Any]):
        """Save validation results to file"""
        try:
            results_file = self.build_dir / f"validation_results_{results['validation_id']}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Also save as latest
            latest_file = self.build_dir / "latest_validation_results.json"
            with open(latest_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Validation results saved to: {results_file}")
            
        except Exception as e:
            logger.error(f"Failed to save validation results: {e}")

async def main():
    """Main validation script entry point"""
    try:
        # Get workspace root
        workspace_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Create validator
        validator = AgentCoreValidator(workspace_root)
        
        # Run validation
        results = await validator.validate_deployment()
        
        # Print results
        print("\n" + "="*60)
        print("AgentCore Runtime Deployment Validation Results")
        print("="*60)
        print(f"Validation ID: {results.get('validation_id', 'Unknown')}")
        print(f"Overall Status: {results.get('overall_status', 'Unknown')}")
        print(f"Region: {results.get('region', 'Unknown')}")
        print(f"Timestamp: {results.get('timestamp', 'Unknown')}")
        
        if "tests" in results:
            print("\nTest Results:")
            for test_name, test_result in results["tests"].items():
                status = test_result.get("status", "unknown")
                if status == "passed":
                    print(f"  ✅ {test_name.replace('_', ' ').title()}: {status}")
                elif status == "failed":
                    print(f"  ❌ {test_name.replace('_', ' ').title()}: {status}")
                else:
                    print(f"  ⚠️ {test_name.replace('_', ' ').title()}: {status}")
        
        # Exit with appropriate code
        if results.get("overall_status") == "passed":
            print("\n🎉 All validation tests passed! AgentCore Runtime deployment is healthy.")
            sys.exit(0)
        else:
            print("\n❌ Some validation tests failed. Check logs for details.")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Validation script failed: {e}")
        print(f"\n❌ Validation script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())