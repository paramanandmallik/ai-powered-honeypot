#!/usr/bin/env python3
"""
AgentCore Runtime Deployment Script
Automates the deployment of AI agents to Amazon Bedrock AgentCore Runtime.
"""

import os
import sys
import json
import yaml
import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AgentCoreDeployer:
    """Handles deployment of agents to AgentCore Runtime"""
    
    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.build_dir = self.workspace_root / "build" / "agentcore"
        self.config_dir = self.workspace_root / "deployment" / "agent-configs"
        
        # AgentCore starter toolkit CLI configuration
        self.agentcore_cli = "agentcore"  # Amazon Bedrock AgentCore starter toolkit CLI
        self.deployment_region = os.getenv("AWS_REGION", "us-east-1")
        self.agentcore_runtime_endpoint = os.getenv("AGENTCORE_RUNTIME_ENDPOINT", "")
        
        # Deployment configuration
        self.agents_to_deploy = ["detection", "coordinator", "interaction", "intelligence"]
        self.deployment_timeout = 300  # 5 minutes per agent
        
        logger.info(f"AgentCore Deployer initialized for region: {self.deployment_region}")
    
    def deploy_all_agents(self) -> Dict[str, Any]:
        """Deploy all agents to AgentCore Runtime"""
        try:
            logger.info("Starting deployment of all agents to AgentCore Runtime...")
            
            deployment_results = {
                "deployment_id": f"deploy-{int(time.time())}",
                "timestamp": datetime.utcnow().isoformat(),
                "region": self.deployment_region,
                "agents": {},
                "overall_status": "in_progress"
            }
            
            # Verify prerequisites
            if not self._verify_prerequisites():
                deployment_results["overall_status"] = "failed"
                deployment_results["error"] = "Prerequisites verification failed"
                return deployment_results
            
            # Deploy each agent
            successful_deployments = 0
            for agent_type in self.agents_to_deploy:
                try:
                    logger.info(f"Deploying {agent_type} agent...")
                    result = self.deploy_agent(agent_type)
                    deployment_results["agents"][agent_type] = result
                    
                    if result["status"] == "success":
                        successful_deployments += 1
                        logger.info(f"✅ {agent_type} agent deployed successfully")
                    else:
                        logger.error(f"❌ {agent_type} agent deployment failed: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    logger.error(f"❌ {agent_type} agent deployment failed with exception: {e}")
                    deployment_results["agents"][agent_type] = {
                        "status": "failed",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    }
            
            # Update overall status
            if successful_deployments == len(self.agents_to_deploy):
                deployment_results["overall_status"] = "success"
                logger.info(f"🎉 All {successful_deployments} agents deployed successfully!")
            elif successful_deployments > 0:
                deployment_results["overall_status"] = "partial_success"
                logger.warning(f"⚠️ {successful_deployments}/{len(self.agents_to_deploy)} agents deployed successfully")
            else:
                deployment_results["overall_status"] = "failed"
                logger.error("❌ No agents were deployed successfully")
            
            # Save deployment results
            self._save_deployment_results(deployment_results)
            
            # Configure agent workflows if all agents deployed successfully
            if deployment_results["overall_status"] == "success":
                logger.info("Configuring agent communication workflows...")
                workflow_result = self._configure_agent_workflows()
                deployment_results["workflow_configuration"] = workflow_result
            
            return deployment_results
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            return {
                "deployment_id": f"deploy-{int(time.time())}",
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": "failed",
                "error": str(e)
            }
    
    def deploy_agent(self, agent_type: str) -> Dict[str, Any]:
        """Deploy a single agent to AgentCore Runtime"""
        try:
            start_time = time.time()
            
            # Find agent package
            package_path = self._find_agent_package(agent_type)
            if not package_path:
                return {
                    "status": "failed",
                    "error": f"Agent package not found for {agent_type}",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Find agent configuration
            config_path = self._find_agent_config(agent_type)
            if not config_path:
                return {
                    "status": "failed", 
                    "error": f"Agent configuration not found for {agent_type}",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Deploy using AgentCore CLI
            deployment_result = self._deploy_with_agentcore_cli(agent_type, package_path, config_path)
            
            if deployment_result["success"]:
                # Verify deployment
                verification_result = self._verify_agent_deployment(agent_type)
                
                if verification_result["healthy"]:
                    deployment_time = time.time() - start_time
                    return {
                        "status": "success",
                        "agent_id": deployment_result.get("agent_id"),
                        "endpoint": deployment_result.get("endpoint"),
                        "deployment_time_seconds": deployment_time,
                        "health_status": verification_result,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                else:
                    return {
                        "status": "failed",
                        "error": "Agent deployment verification failed",
                        "health_status": verification_result,
                        "timestamp": datetime.utcnow().isoformat()
                    }
            else:
                return {
                    "status": "failed",
                    "error": deployment_result.get("error", "AgentCore CLI deployment failed"),
                    "cli_output": deployment_result.get("output"),
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to deploy {agent_type} agent: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _verify_prerequisites(self) -> bool:
        """Verify deployment prerequisites"""
        try:
            logger.info("Verifying deployment prerequisites...")
            
            # Check AgentCore CLI availability
            try:
                result = subprocess.run([self.agentcore_cli, "--version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.error("AgentCore CLI not available or not working")
                    return False
                logger.info(f"AgentCore CLI version: {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error(f"AgentCore CLI check failed: {e}")
                return False
            
            # Check AWS credentials
            try:
                result = subprocess.run(["aws", "sts", "get-caller-identity"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.error("AWS credentials not configured")
                    return False
                caller_info = json.loads(result.stdout)
                logger.info(f"AWS Account: {caller_info.get('Account', 'Unknown')}")
            except Exception as e:
                logger.error(f"AWS credentials check failed: {e}")
                return False
            
            # Check build directory exists
            if not self.build_dir.exists():
                logger.error(f"Build directory not found: {self.build_dir}")
                return False
            
            # Check agent packages exist
            missing_packages = []
            for agent_type in self.agents_to_deploy:
                if not self._find_agent_package(agent_type):
                    missing_packages.append(agent_type)
            
            if missing_packages:
                logger.error(f"Missing agent packages: {missing_packages}")
                return False
            
            logger.info("✅ All prerequisites verified")
            return True
            
        except Exception as e:
            logger.error(f"Prerequisites verification failed: {e}")
            return False
    
    def _find_agent_package(self, agent_type: str) -> Optional[Path]:
        """Find agent deployment package"""
        package_name = f"ai-honeypot-{agent_type}-agent-deployment-package.zip"
        package_path = self.build_dir / package_name
        
        if package_path.exists():
            return package_path
        
        # Try alternative naming
        alt_package_name = f"{agent_type}-agent-deployment-package.zip"
        alt_package_path = self.build_dir / alt_package_name
        
        if alt_package_path.exists():
            return alt_package_path
        
        return None
    
    def _find_agent_config(self, agent_type: str) -> Optional[Path]:
        """Find agent configuration file"""
        config_name = f"{agent_type}-agent.yaml"
        config_path = self.config_dir / config_name
        
        if config_path.exists():
            return config_path
        
        return None
    
    def _deploy_with_agentcore_cli(self, agent_type: str, package_path: Path, config_path: Path) -> Dict[str, Any]:
        """Deploy agent using Amazon Bedrock AgentCore starter toolkit"""
        try:
            logger.info(f"Deploying {agent_type} agent using AgentCore starter toolkit...")
            
            # Extract package to temporary directory for deployment
            import tempfile
            import zipfile
            
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract package
                with zipfile.ZipFile(package_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_path)
                
                # Change to extracted directory
                extracted_dir = temp_path
                main_py = extracted_dir / "main.py"
                
                if not main_py.exists():
                    return {
                        "success": False,
                        "error": f"main.py not found in package for {agent_type}"
                    }
                
                # Step 1: Configure the agent
                configure_cmd = [
                    self.agentcore_cli,
                    "configure",
                    "-e", "main.py",
                    "-r", self.deployment_region
                ]
                
                logger.debug(f"Configuring agent: {' '.join(configure_cmd)}")
                
                # Execute configure command in the extracted directory
                configure_result = subprocess.run(
                    configure_cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=60,
                    cwd=str(extracted_dir)
                )
                
                if configure_result.returncode != 0:
                    return {
                        "success": False,
                        "error": f"Agent configuration failed: {configure_result.stderr or configure_result.stdout}",
                        "output": configure_result.stderr or configure_result.stdout
                    }
                
                # Step 2: Launch the agent
                launch_cmd = [
                    self.agentcore_cli,
                    "launch"
                ]
                
                logger.debug(f"Launching agent: {' '.join(launch_cmd)}")
                
                # Execute launch command
                launch_result = subprocess.run(
                    launch_cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=self.deployment_timeout,
                    cwd=str(extracted_dir)
                )
                
                if launch_result.returncode == 0:
                    # Parse deployment output for ARN and other details
                    output_lines = launch_result.stdout.strip().split('\n')
                    agent_arn = None
                    logs_location = None
                    
                    for line in output_lines:
                        if "arn:aws:bedrock-agentcore" in line:
                            agent_arn = line.strip()
                        elif "CloudWatch Logs" in line or "/aws/bedrock-agentcore" in line:
                            logs_location = line.strip()
                    
                    return {
                        "success": True,
                        "agent_arn": agent_arn,
                        "agent_id": agent_arn.split('/')[-1] if agent_arn else None,
                        "logs_location": logs_location,
                        "output": launch_result.stdout
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Agent launch failed (exit code: {launch_result.returncode})",
                        "output": launch_result.stderr or launch_result.stdout
                    }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Deployment timeout after {self.deployment_timeout} seconds"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _verify_agent_deployment(self, agent_type: str) -> Dict[str, Any]:
        """Verify agent deployment health using AgentCore starter toolkit"""
        try:
            logger.info(f"Verifying {agent_type} agent deployment...")
            
            # Test the deployed agent using agentcore invoke
            test_cmd = [
                self.agentcore_cli,
                "invoke",
                '{"prompt": "Health check test"}'
            ]
            
            # Find the agent directory (should be in build/agentcore)
            agent_name = f"ai-honeypot-{agent_type}-agent"
            agent_dir = self.build_dir / agent_name
            
            if not agent_dir.exists():
                return {
                    "healthy": False,
                    "status": "agent_directory_not_found",
                    "error": f"Agent directory not found: {agent_dir}"
                }
            
            result = subprocess.run(
                test_cmd, 
                capture_output=True, 
                text=True, 
                timeout=30,
                cwd=str(agent_dir)
            )
            
            if result.returncode == 0:
                # Parse response to check if agent is responding
                try:
                    response_data = json.loads(result.stdout)
                    return {
                        "healthy": True,
                        "status": "healthy",
                        "response": response_data,
                        "test_successful": True
                    }
                except json.JSONDecodeError:
                    # Agent responded but not in JSON format
                    return {
                        "healthy": True,
                        "status": "healthy",
                        "raw_response": result.stdout,
                        "test_successful": True
                    }
            else:
                return {
                    "healthy": False,
                    "status": "invoke_failed",
                    "error": result.stderr or result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {
                "healthy": False,
                "status": "invoke_timeout",
                "error": "Agent invoke test timed out"
            }
        except Exception as e:
            logger.error(f"Agent verification failed: {e}")
            return {
                "healthy": False,
                "status": "verification_error",
                "error": str(e)
            }
    
    def _configure_agent_workflows(self) -> Dict[str, Any]:
        """Configure agent communication workflows"""
        try:
            logger.info("Configuring agent communication workflows...")
            
            # Define workflow configuration
            workflow_config = {
                "workflows": [
                    {
                        "name": "threat-detection-to-engagement",
                        "description": "Workflow from threat detection to honeypot engagement",
                        "trigger": {
                            "agent": "detection",
                            "event": "engagement_decision"
                        },
                        "steps": [
                            {
                                "agent": "coordinator",
                                "action": "create_honeypot",
                                "condition": "engagement_approved == true"
                            },
                            {
                                "agent": "interaction",
                                "action": "initialize_session",
                                "depends_on": "create_honeypot"
                            }
                        ]
                    },
                    {
                        "name": "session-completion-to-analysis",
                        "description": "Workflow from session completion to intelligence analysis",
                        "trigger": {
                            "agent": "interaction",
                            "event": "session_completed"
                        },
                        "steps": [
                            {
                                "agent": "intelligence",
                                "action": "analyze_session",
                                "timeout_seconds": 300
                            },
                            {
                                "agent": "coordinator",
                                "action": "cleanup_honeypot",
                                "depends_on": "analyze_session"
                            }
                        ]
                    }
                ]
            }
            
            # Deploy workflow configuration
            workflow_file = self.build_dir / "agent_workflows.json"
            with open(workflow_file, 'w') as f:
                json.dump(workflow_config, f, indent=2)
            
            # Use AgentCore CLI to configure workflows
            cmd = [
                self.agentcore_cli,
                "configure",
                "workflows",
                "--config", str(workflow_file),
                "--region", self.deployment_region
            ]
            
            if self.agentcore_runtime_endpoint:
                cmd.extend(["--endpoint", self.agentcore_runtime_endpoint])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "workflows_configured": len(workflow_config["workflows"]),
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or result.stdout
                }
                
        except Exception as e:
            logger.error(f"Workflow configuration failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _save_deployment_results(self, results: Dict[str, Any]):
        """Save deployment results to file"""
        try:
            results_file = self.build_dir / f"deployment_results_{results['deployment_id']}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Also save as latest
            latest_file = self.build_dir / "latest_deployment_results.json"
            with open(latest_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Deployment results saved to: {results_file}")
            
        except Exception as e:
            logger.error(f"Failed to save deployment results: {e}")

def main():
    """Main deployment script entry point"""
    try:
        # Get workspace root
        workspace_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Create deployer
        deployer = AgentCoreDeployer(workspace_root)
        
        # Deploy all agents
        results = deployer.deploy_all_agents()
        
        # Print results
        print("\n" + "="*60)
        print("AgentCore Runtime Deployment Results")
        print("="*60)
        print(f"Deployment ID: {results.get('deployment_id', 'Unknown')}")
        print(f"Overall Status: {results.get('overall_status', 'Unknown')}")
        print(f"Region: {results.get('region', 'Unknown')}")
        print(f"Timestamp: {results.get('timestamp', 'Unknown')}")
        
        if "agents" in results:
            print("\nAgent Deployment Status:")
            for agent_type, agent_result in results["agents"].items():
                status = agent_result.get("status", "unknown")
                if status == "success":
                    print(f"  ✅ {agent_type.upper()}: {status}")
                    if "agent_id" in agent_result:
                        print(f"     Agent ID: {agent_result['agent_id']}")
                    if "endpoint" in agent_result:
                        print(f"     Endpoint: {agent_result['endpoint']}")
                else:
                    print(f"  ❌ {agent_type.upper()}: {status}")
                    if "error" in agent_result:
                        print(f"     Error: {agent_result['error']}")
        
        if "workflow_configuration" in results:
            workflow_result = results["workflow_configuration"]
            if workflow_result.get("success"):
                print(f"\n✅ Workflows configured: {workflow_result.get('workflows_configured', 0)}")
            else:
                print(f"\n❌ Workflow configuration failed: {workflow_result.get('error', 'Unknown error')}")
        
        # Exit with appropriate code
        if results.get("overall_status") == "success":
            print("\n🎉 All agents deployed successfully to AgentCore Runtime!")
            sys.exit(0)
        elif results.get("overall_status") == "partial_success":
            print("\n⚠️ Partial deployment success. Check individual agent status.")
            sys.exit(1)
        else:
            print("\n❌ Deployment failed. Check logs for details.")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Deployment script failed: {e}")
        print(f"\n❌ Deployment script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()