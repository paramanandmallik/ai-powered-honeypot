#!/usr/bin/env python3
"""
AgentCore Runtime Deployment Manager
Handles packaging and deployment of AI agents to Amazon Bedrock AgentCore Runtime.
"""

import os
import sys
import json
import yaml
import shutil
import zipfile
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AgentCoreDeploymentManager:
    """Manages packaging and deployment of agents to AgentCore Runtime"""
    
    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.agents_dir = self.workspace_root / "agents"
        self.config_dir = self.workspace_root / "deployment" / "agent-configs"
        self.build_dir = self.workspace_root / "build" / "agentcore"
        
        # Ensure build directory exists
        self.build_dir.mkdir(parents=True, exist_ok=True)
        
        # Agent definitions
        self.agents = {
            "detection": {
                "name": "ai-honeypot-detection-agent",
                "entrypoint": "agents.detection.detection_agent:DetectionAgent",
                "main_file": "agents/detection/detection_agent.py",
                "dependencies": [
                    "agents/base_agent.py",
                    "agents/__init__.py",
                    "config/agentcore_sdk.py",
                    "config/__init__.py"
                ]
            },
            "coordinator": {
                "name": "ai-honeypot-coordinator-agent", 
                "entrypoint": "agents.coordinator.coordinator_agent:CoordinatorAgent",
                "main_file": "agents/coordinator/coordinator_agent.py",
                "dependencies": [
                    "agents/base_agent.py",
                    "agents/__init__.py",
                    "agents/coordinator/__init__.py",
                    "agents/coordinator/orchestration_engine.py",
                    "agents/coordinator/honeypot_manager.py",
                    "agents/coordinator/monitoring_system.py",
                    "config/agentcore_sdk.py",
                    "config/__init__.py"
                ]
            },
            "interaction": {
                "name": "ai-honeypot-interaction-agent",
                "entrypoint": "agents.interaction.interaction_agent:InteractionAgent", 
                "main_file": "agents/interaction/interaction_agent.py",
                "dependencies": [
                    "agents/base_agent.py",
                    "agents/__init__.py",
                    "agents/interaction/__init__.py",
                    "agents/interaction/security_controls.py",
                    "agents/interaction/synthetic_data_generator.py",
                    "config/agentcore_sdk.py",
                    "config/__init__.py"
                ]
            },
            "intelligence": {
                "name": "ai-honeypot-intelligence-agent",
                "entrypoint": "agents.intelligence.intelligence_agent:IntelligenceAgent",
                "main_file": "agents/intelligence/intelligence_agent.py", 
                "dependencies": [
                    "agents/base_agent.py",
                    "agents/__init__.py",
                    "agents/intelligence/__init__.py",
                    "agents/intelligence/intelligence_reporter.py",
                    "agents/intelligence/mitre_mapper.py",
                    "agents/intelligence/session_analyzer.py",
                    "config/agentcore_sdk.py",
                    "config/__init__.py"
                ]
            }
        }
        
        logger.info(f"AgentCore Deployment Manager initialized for {len(self.agents)} agents")
    
    def package_agent(self, agent_type: str) -> str:
        """Package a single agent for AgentCore Runtime deployment"""
        try:
            if agent_type not in self.agents:
                raise ValueError(f"Unknown agent type: {agent_type}")
            
            agent_config = self.agents[agent_type]
            agent_name = agent_config["name"]
            
            logger.info(f"Packaging agent: {agent_name}")
            
            # Create agent package directory
            package_dir = self.build_dir / agent_name
            package_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy agent files
            self._copy_agent_files(agent_type, package_dir)
            
            # Create agent.py entrypoint
            self._create_agent_entrypoint(agent_type, package_dir)
            
            # Copy requirements.txt
            self._create_requirements_file(agent_type, package_dir)
            
            # Copy agent configuration
            self._copy_agent_config(agent_type, package_dir)
            
            # Create deployment metadata
            self._create_deployment_metadata(agent_type, package_dir)
            
            # Create package zip
            package_path = self._create_package_zip(agent_name, package_dir)
            
            logger.info(f"Agent {agent_name} packaged successfully: {package_path}")
            return str(package_path)
            
        except Exception as e:
            logger.error(f"Failed to package agent {agent_type}: {e}")
            raise
    
    def package_all_agents(self) -> Dict[str, str]:
        """Package all agents for AgentCore Runtime deployment"""
        try:
            logger.info("Packaging all agents for AgentCore Runtime...")
            
            packaged_agents = {}
            
            for agent_type in self.agents.keys():
                try:
                    package_path = self.package_agent(agent_type)
                    packaged_agents[agent_type] = package_path
                except Exception as e:
                    logger.error(f"Failed to package {agent_type} agent: {e}")
                    packaged_agents[agent_type] = f"ERROR: {str(e)}"
            
            # Create deployment summary
            self._create_deployment_summary(packaged_agents)
            
            logger.info(f"Packaging complete. {len([p for p in packaged_agents.values() if not p.startswith('ERROR')])} agents packaged successfully")
            
            return packaged_agents
            
        except Exception as e:
            logger.error(f"Failed to package agents: {e}")
            raise
    
    def _copy_agent_files(self, agent_type: str, package_dir: Path):
        """Copy agent source files to package directory"""
        try:
            agent_config = self.agents[agent_type]
            
            # Copy main agent file
            main_file = self.workspace_root / agent_config["main_file"]
            if main_file.exists():
                dest_file = package_dir / "agent.py"
                shutil.copy2(main_file, dest_file)
                logger.debug(f"Copied main file: {main_file} -> {dest_file}")
            else:
                raise FileNotFoundError(f"Main agent file not found: {main_file}")
            
            # Copy dependencies
            for dep_path in agent_config["dependencies"]:
                src_file = self.workspace_root / dep_path
                if src_file.exists():
                    # Maintain directory structure
                    rel_path = Path(dep_path)
                    dest_file = package_dir / rel_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dest_file)
                    logger.debug(f"Copied dependency: {src_file} -> {dest_file}")
                else:
                    logger.warning(f"Dependency file not found: {src_file}")
            
            # Copy __init__.py files to ensure proper Python packaging
            self._ensure_init_files(package_dir)
            
        except Exception as e:
            logger.error(f"Failed to copy agent files for {agent_type}: {e}")
            raise
    
    def _ensure_init_files(self, package_dir: Path):
        """Ensure __init__.py files exist in all directories"""
        try:
            for root, dirs, files in os.walk(package_dir):
                root_path = Path(root)
                init_file = root_path / "__init__.py"
                if not init_file.exists():
                    init_file.write_text("# Auto-generated __init__.py for AgentCore Runtime deployment\n")
                    logger.debug(f"Created __init__.py: {init_file}")
                    
        except Exception as e:
            logger.error(f"Failed to ensure __init__.py files: {e}")
            raise
    
    def _create_agent_entrypoint(self, agent_type: str, package_dir: Path):
        """Create AgentCore Runtime entrypoint for the agent"""
        try:
            agent_config = self.agents[agent_type]
            
            entrypoint_content = f'''#!/usr/bin/env python3
"""
AgentCore Runtime Entrypoint for {agent_config["name"]}
Auto-generated deployment entrypoint for Amazon Bedrock AgentCore Runtime.
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Add package directory to Python path
package_dir = Path(__file__).parent
sys.path.insert(0, str(package_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def create_agent_app():
    """Create AgentCore Runtime application"""
    try:
        # Import agent class
        # The agent.py file contains the main agent class
        import importlib.util
        import sys
        
        # Load the agent module dynamically
        agent_file_path = Path(__file__).parent / "agent.py"
        agent_spec = importlib.util.spec_from_file_location("agent_module", agent_file_path)
        agent_module = importlib.util.module_from_spec(agent_spec)
        agent_spec.loader.exec_module(agent_module)
        
        # Get the agent class - it should be the main class in the agent.py file
        agent_class = None
        for name in dir(agent_module):
            obj = getattr(agent_module, name)
            if (isinstance(obj, type) and 
                hasattr(obj, '__bases__') and 
                any('BaseAgent' in str(base) for base in obj.__bases__)):
                agent_class = obj
                break
        
        if not agent_class:
            raise ImportError(f"Could not find agent class in agent.py for {agent_type} agent")
        
        # Create agent instance with AgentCore Runtime configuration
        config = {{
            "agentcore_runtime": True,
            "disable_metrics": False,
            "auto_scaling": True,
            "health_check_interval": 30
        }}
        
        agent = agent_class(config)
        
        # Create AgentCore Runtime app
        app = agent.create_agentcore_app()
        
        logger.info(f"{agent_config['name']} AgentCore Runtime app created successfully")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create AgentCore Runtime app: {{e}}")
        raise

# Create the app instance for AgentCore Runtime
app = create_agent_app()

if __name__ == "__main__":
    # For local testing
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''
            
            entrypoint_file = package_dir / "main.py"
            entrypoint_file.write_text(entrypoint_content)
            
            logger.debug(f"Created AgentCore entrypoint: {entrypoint_file}")
            
        except Exception as e:
            logger.error(f"Failed to create agent entrypoint for {agent_type}: {e}")
            raise
    
    def _create_requirements_file(self, agent_type: str, package_dir: Path):
        """Create requirements.txt for the agent package"""
        try:
            requirements = [
                "strands-agents>=0.1.0",
                "bedrock-agentcore>=0.1.0", 
                "boto3>=1.34.0",
                "fastapi>=0.104.0",
                "pydantic>=2.5.0",
                "httpx>=0.25.0",
                "anthropic>=0.25.0",
                "prometheus-client>=0.19.0",
                "uvicorn>=0.24.0",
                "python-multipart>=0.0.6"
            ]
            
            # Add agent-specific requirements
            if agent_type == "coordinator":
                requirements.extend([
                    "docker>=6.0.0",
                    "kubernetes>=25.0.0"
                ])
            elif agent_type == "interaction":
                requirements.extend([
                    "faker>=20.0.0",
                    "jinja2>=3.1.0"
                ])
            elif agent_type == "intelligence":
                requirements.extend([
                    "pandas>=2.0.0",
                    "numpy>=1.24.0"
                ])
            
            requirements_file = package_dir / "requirements.txt"
            requirements_file.write_text("\n".join(requirements) + "\n")
            
            logger.debug(f"Created requirements.txt: {requirements_file}")
            
        except Exception as e:
            logger.error(f"Failed to create requirements file for {agent_type}: {e}")
            raise
    
    def _copy_agent_config(self, agent_type: str, package_dir: Path):
        """Copy agent configuration file to package"""
        try:
            config_file = self.config_dir / f"{agent_type}-agent.yaml"
            
            if config_file.exists():
                dest_config = package_dir / "agent.yaml"
                shutil.copy2(config_file, dest_config)
                logger.debug(f"Copied agent config: {config_file} -> {dest_config}")
            else:
                logger.warning(f"Agent config file not found: {config_file}")
                # Create a basic config
                self._create_basic_agent_config(agent_type, package_dir)
                
        except Exception as e:
            logger.error(f"Failed to copy agent config for {agent_type}: {e}")
            raise
    
    def _create_basic_agent_config(self, agent_type: str, package_dir: Path):
        """Create a basic agent configuration if none exists"""
        try:
            agent_config = self.agents[agent_type]
            
            basic_config = {
                "apiVersion": "agentcore.amazon.com/v1",
                "kind": "Agent",
                "metadata": {
                    "name": agent_config["name"],
                    "namespace": "ai-honeypot-system",
                    "labels": {
                        "app": "ai-honeypot",
                        "component": agent_type,
                        "version": "v1.0.0"
                    }
                },
                "spec": {
                    "description": f"AI-Powered Honeypot System - {agent_type.title()} Agent",
                    "runtime": {
                        "type": "python",
                        "version": "3.11",
                        "entrypoint": "main:app",
                        "framework": "strands-agents"
                    },
                    "resources": {
                        "requests": {
                            "memory": "512Mi",
                            "cpu": "250m"
                        },
                        "limits": {
                            "memory": "1Gi", 
                            "cpu": "500m"
                        }
                    },
                    "scaling": {
                        "minReplicas": 1,
                        "maxReplicas": 3,
                        "targetCPUUtilizationPercentage": 70
                    },
                    "monitoring": {
                        "healthCheck": {
                            "path": "/health",
                            "intervalSeconds": 30,
                            "timeoutSeconds": 10,
                            "failureThreshold": 3
                        }
                    }
                }
            }
            
            config_file = package_dir / "agent.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(basic_config, f, default_flow_style=False)
            
            logger.debug(f"Created basic agent config: {config_file}")
            
        except Exception as e:
            logger.error(f"Failed to create basic agent config for {agent_type}: {e}")
            raise
    
    def _create_deployment_metadata(self, agent_type: str, package_dir: Path):
        """Create deployment metadata for the agent package"""
        try:
            agent_config = self.agents[agent_type]
            
            metadata = {
                "agent_name": agent_config["name"],
                "agent_type": agent_type,
                "entrypoint": agent_config["entrypoint"],
                "package_version": "1.0.0",
                "build_timestamp": datetime.utcnow().isoformat(),
                "agentcore_runtime_version": "1.0.0",
                "python_version": "3.11",
                "dependencies_count": len(agent_config["dependencies"]),
                "deployment_target": "amazon-bedrock-agentcore-runtime",
                "health_check_endpoint": "/health",
                "metrics_endpoint": "/metrics",
                "capabilities": self._get_agent_capabilities(agent_type)
            }
            
            metadata_file = package_dir / "deployment_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.debug(f"Created deployment metadata: {metadata_file}")
            
        except Exception as e:
            logger.error(f"Failed to create deployment metadata for {agent_type}: {e}")
            raise
    
    def _get_agent_capabilities(self, agent_type: str) -> List[str]:
        """Get agent capabilities based on type"""
        capabilities_map = {
            "detection": [
                "threat_analysis",
                "engagement_decision",
                "mitre_mapping", 
                "confidence_scoring",
                "ioc_extraction",
                "reputation_analysis"
            ],
            "coordinator": [
                "workflow_orchestration",
                "agent_coordination",
                "honeypot_lifecycle_management",
                "resource_management",
                "emergency_procedures",
                "system_monitoring"
            ],
            "interaction": [
                "attacker_engagement",
                "synthetic_data_generation",
                "persona_management",
                "conversation_handling",
                "security_controls",
                "session_management"
            ],
            "intelligence": [
                "session_analysis",
                "intelligence_extraction",
                "mitre_mapping",
                "report_generation",
                "pattern_recognition",
                "threat_assessment"
            ]
        }
        
        return capabilities_map.get(agent_type, [])
    
    def _create_package_zip(self, agent_name: str, package_dir: Path) -> Path:
        """Create deployment package zip file"""
        try:
            zip_path = self.build_dir / f"{agent_name}-deployment-package.zip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(package_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arc_name = file_path.relative_to(package_dir)
                        zipf.write(file_path, arc_name)
            
            logger.debug(f"Created deployment package: {zip_path}")
            return zip_path
            
        except Exception as e:
            logger.error(f"Failed to create package zip for {agent_name}: {e}")
            raise
    
    def _create_deployment_summary(self, packaged_agents: Dict[str, str]):
        """Create deployment summary report"""
        try:
            summary = {
                "deployment_summary": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "total_agents": len(packaged_agents),
                    "successful_packages": len([p for p in packaged_agents.values() if not p.startswith('ERROR')]),
                    "failed_packages": len([p for p in packaged_agents.values() if p.startswith('ERROR')]),
                    "target_platform": "amazon-bedrock-agentcore-runtime",
                    "package_format": "zip"
                },
                "packaged_agents": packaged_agents,
                "deployment_instructions": {
                    "step_1": "Upload agent packages to AgentCore Runtime",
                    "step_2": "Configure agent scaling and resources",
                    "step_3": "Deploy agents using AgentCore CLI",
                    "step_4": "Verify agent health and connectivity",
                    "step_5": "Configure agent communication workflows"
                },
                "next_steps": [
                    "Review agent configurations in deployment/agent-configs/",
                    "Test agent packages in staging environment",
                    "Deploy to production AgentCore Runtime",
                    "Monitor agent performance and scaling"
                ]
            }
            
            summary_file = self.build_dir / "deployment_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            
            logger.info(f"Created deployment summary: {summary_file}")
            
        except Exception as e:
            logger.error(f"Failed to create deployment summary: {e}")
            raise

def main():
    """Main deployment manager entry point"""
    try:
        # Get workspace root
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Create deployment manager
        manager = AgentCoreDeploymentManager(workspace_root)
        
        # Package all agents
        packaged_agents = manager.package_all_agents()
        
        # Print results
        print("\n" + "="*60)
        print("AgentCore Runtime Deployment Package Results")
        print("="*60)
        
        for agent_type, package_path in packaged_agents.items():
            if package_path.startswith('ERROR'):
                print(f"❌ {agent_type.upper()}: {package_path}")
            else:
                print(f"✅ {agent_type.upper()}: {package_path}")
        
        print("\n📦 All packages created in: build/agentcore/")
        print("📋 Deployment summary: build/agentcore/deployment_summary.json")
        print("\n🚀 Ready for AgentCore Runtime deployment!")
        
    except Exception as e:
        logger.error(f"Deployment packaging failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()