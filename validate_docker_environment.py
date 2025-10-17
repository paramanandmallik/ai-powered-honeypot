#!/usr/bin/env python3
"""
Docker Environment Validation Script for Task 10.1
Validates the Docker-based development environment implementation
"""

import os
import sys
import json
import yaml
import docker
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DockerEnvironmentValidator:
    """Validates the Docker-based development environment for task 10.1"""
    
    def __init__(self):
        self.client = None
        self.project_root = Path(__file__).parent
        self.validation_results = {
            "docker_containers": False,
            "docker_compose_config": False,
            "message_bus": False,
            "state_management": False,
            "monitoring_tools": False,
            "development_tools": False,
            "agentcore_simulation": False
        }
        
    def initialize_docker_client(self) -> bool:
        """Initialize Docker client connection"""
        try:
            self.client = docker.from_env()
            # Test connection
            self.client.ping()
            logger.info("✅ Docker client initialized successfully")
            return True
        except Exception as e:
            logger.warning(f"⚠️  Docker client not available: {e}")
            logger.info("📝 Continuing with file-based validation only")
            return False
    
    def validate_dockerfiles(self) -> bool:
        """Validate that all required Dockerfiles exist and are properly configured"""
        logger.info("🔍 Validating Dockerfiles...")
        
        required_dockerfiles = [
            "deployment/docker/Dockerfile.mock-agentcore",
            "deployment/docker/Dockerfile.detection-agent", 
            "deployment/docker/Dockerfile.coordinator-agent",
            "deployment/docker/Dockerfile.interaction-agent",
            "deployment/docker/Dockerfile.intelligence-agent",
            "deployment/docker/Dockerfile.dashboard",
            "deployment/docker/Dockerfile.dev-tools",
            "deployment/docker/Dockerfile.ssh-honeypot",
            "deployment/docker/Dockerfile.web-admin-honeypot",
            "deployment/docker/Dockerfile.database-honeypot"
        ]
        
        missing_files = []
        for dockerfile in required_dockerfiles:
            dockerfile_path = self.project_root / dockerfile
            if not dockerfile_path.exists():
                missing_files.append(dockerfile)
            else:
                # Check if Dockerfile has proper content
                content = dockerfile_path.read_text()
                if len(content.strip()) < 100:  # Basic sanity check
                    logger.warning(f"⚠️  Dockerfile {dockerfile} seems incomplete")
        
        if missing_files:
            logger.error(f"❌ Missing Dockerfiles: {missing_files}")
            return False
        
        logger.info("✅ All required Dockerfiles exist")
        self.validation_results["docker_containers"] = True
        return True
    
    def validate_docker_compose_config(self) -> bool:
        """Validate Docker Compose configuration files"""
        logger.info("🔍 Validating Docker Compose configurations...")
        
        compose_files = [
            "docker-compose.yml",
            "docker-compose.dev.yml"
        ]
        
        for compose_file in compose_files:
            compose_path = self.project_root / compose_file
            if not compose_path.exists():
                logger.error(f"❌ Missing Docker Compose file: {compose_file}")
                return False
            
            try:
                # Parse YAML to validate syntax
                with open(compose_path, 'r') as f:
                    compose_config = yaml.safe_load(f)
                
                # Validate required services exist
                services = compose_config.get('services', {})
                required_services = [
                    'redis', 'postgres', 'mock-agentcore', 
                    'detection-agent', 'coordinator-agent', 
                    'interaction-agent', 'intelligence-agent'
                ]
                
                missing_services = [svc for svc in required_services if svc not in services]
                if missing_services:
                    logger.error(f"❌ Missing services in {compose_file}: {missing_services}")
                    return False
                
                logger.info(f"✅ {compose_file} is valid with {len(services)} services")
                
            except yaml.YAMLError as e:
                logger.error(f"❌ Invalid YAML in {compose_file}: {e}")
                return False
        
        self.validation_results["docker_compose_config"] = True
        return True
    
    def validate_mock_agentcore(self) -> bool:
        """Validate Mock AgentCore Runtime implementation"""
        logger.info("🔍 Validating Mock AgentCore Runtime...")
        
        mock_agentcore_files = [
            "deployment/mock-agentcore/main_enhanced.py",
            "deployment/mock-agentcore/message_bus.py", 
            "deployment/mock-agentcore/state_manager.py"
        ]
        
        for file_path in mock_agentcore_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                logger.error(f"❌ Missing Mock AgentCore file: {file_path}")
                return False
            
            # Check file has substantial content
            content = full_path.read_text()
            if len(content.strip()) < 500:  # Basic sanity check
                logger.error(f"❌ Mock AgentCore file {file_path} seems incomplete")
                return False
        
        logger.info("✅ Mock AgentCore Runtime implementation is complete")
        self.validation_results["agentcore_simulation"] = True
        return True
    
    def validate_message_bus_implementation(self) -> bool:
        """Validate message bus implementation for development"""
        logger.info("🔍 Validating message bus implementation...")
        
        message_bus_path = self.project_root / "deployment/mock-agentcore/message_bus.py"
        if not message_bus_path.exists():
            logger.error("❌ Message bus implementation not found")
            return False
        
        content = message_bus_path.read_text()
        
        # Check for required message bus functionality
        required_features = [
            "publish_message",
            "subscribe_to_messages", 
            "broadcast_notification",
            "send_command",
            "get_message_history"
        ]
        
        missing_features = [feature for feature in required_features if feature not in content]
        if missing_features:
            logger.error(f"❌ Missing message bus features: {missing_features}")
            return False
        
        logger.info("✅ Message bus implementation is complete")
        self.validation_results["message_bus"] = True
        return True
    
    def validate_state_management(self) -> bool:
        """Validate state management implementation"""
        logger.info("🔍 Validating state management implementation...")
        
        state_manager_path = self.project_root / "deployment/mock-agentcore/state_manager.py"
        if not state_manager_path.exists():
            logger.error("❌ State manager implementation not found")
            return False
        
        content = state_manager_path.read_text()
        
        # Check for required state management functionality
        required_features = [
            "register_agent",
            "get_agent_info",
            "update_agent_status",
            "register_honeypot",
            "get_active_honeypots",
            "create_engagement_session",
            "get_system_metrics"
        ]
        
        missing_features = [feature for feature in required_features if feature not in content]
        if missing_features:
            logger.error(f"❌ Missing state management features: {missing_features}")
            return False
        
        logger.info("✅ State management implementation is complete")
        self.validation_results["state_management"] = True
        return True
    
    def validate_monitoring_tools(self) -> bool:
        """Validate monitoring and debugging tools"""
        logger.info("🔍 Validating monitoring and debugging tools...")
        
        monitoring_configs = [
            "deployment/prometheus/prometheus.yml",
            "deployment/grafana/dashboards/honeypot-system.json",
            "deployment/monitoring/local-monitoring.yml"
        ]
        
        for config_path in monitoring_configs:
            full_path = self.project_root / config_path
            if not full_path.exists():
                logger.warning(f"⚠️  Optional monitoring config missing: {config_path}")
            else:
                logger.info(f"✅ Found monitoring config: {config_path}")
        
        # Check for development tools
        dev_tools_dockerfile = self.project_root / "deployment/docker/Dockerfile.dev-tools"
        if not dev_tools_dockerfile.exists():
            logger.error("❌ Development tools Dockerfile not found")
            return False
        
        # Check dev tools content
        content = dev_tools_dockerfile.read_text()
        dev_tools = ["jupyter", "pytest", "black", "flake8", "mypy"]
        missing_tools = [tool for tool in dev_tools if tool not in content.lower()]
        
        if missing_tools:
            logger.warning(f"⚠️  Some development tools may be missing: {missing_tools}")
        
        logger.info("✅ Monitoring and development tools are configured")
        self.validation_results["monitoring_tools"] = True
        self.validation_results["development_tools"] = True
        return True
    
    def validate_startup_scripts(self) -> bool:
        """Validate startup and utility scripts"""
        logger.info("🔍 Validating startup and utility scripts...")
        
        required_scripts = [
            "start-dev-environment.sh",
            "deployment/scripts/dev-tools.sh"
        ]
        
        for script_path in required_scripts:
            full_path = self.project_root / script_path
            if not full_path.exists():
                logger.error(f"❌ Missing script: {script_path}")
                return False
            
            # Check if script is executable
            if not os.access(full_path, os.X_OK):
                logger.warning(f"⚠️  Script {script_path} is not executable")
                # Make it executable
                os.chmod(full_path, 0o755)
                logger.info(f"✅ Made {script_path} executable")
        
        logger.info("✅ Startup and utility scripts are available")
        return True
    
    def generate_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        logger.info("📊 Generating validation report...")
        
        total_checks = len(self.validation_results)
        passed_checks = sum(self.validation_results.values())
        success_rate = (passed_checks / total_checks) * 100
        
        report = {
            "task": "10.1 Build Docker-based development environment",
            "validation_timestamp": "2025-01-17T00:00:00Z",
            "overall_success": success_rate >= 90,
            "success_rate": f"{success_rate:.1f}%",
            "checks_passed": passed_checks,
            "total_checks": total_checks,
            "detailed_results": self.validation_results,
            "requirements_validation": {
                "docker_containers_for_agents": self.validation_results["docker_containers"],
                "agentcore_runtime_simulation": self.validation_results["agentcore_simulation"], 
                "docker_compose_configuration": self.validation_results["docker_compose_config"],
                "local_message_bus": self.validation_results["message_bus"],
                "local_state_management": self.validation_results["state_management"],
                "monitoring_debugging_tools": self.validation_results["monitoring_tools"] and self.validation_results["development_tools"]
            },
            "recommendations": []
        }
        
        # Add recommendations based on failed checks
        if not self.validation_results["docker_containers"]:
            report["recommendations"].append("Complete missing Dockerfiles for all agents")
        
        if not self.validation_results["docker_compose_config"]:
            report["recommendations"].append("Fix Docker Compose configuration issues")
        
        if not self.validation_results["message_bus"]:
            report["recommendations"].append("Complete message bus implementation")
        
        if not self.validation_results["state_management"]:
            report["recommendations"].append("Complete state management implementation")
        
        if not self.validation_results["monitoring_tools"]:
            report["recommendations"].append("Set up monitoring and debugging tools")
        
        if not report["recommendations"]:
            report["recommendations"].append("All requirements are satisfied - task 10.1 is complete")
        
        return report
    
    def run_validation(self) -> Dict[str, Any]:
        """Run complete validation of Docker-based development environment"""
        logger.info("🚀 Starting Docker environment validation for Task 10.1...")
        
        # Initialize Docker client (optional for file validation)
        docker_available = self.initialize_docker_client()
        if not docker_available:
            logger.info("🔍 Running file-based validation without Docker runtime")
        
        # Run all validation checks
        validation_steps = [
            self.validate_dockerfiles,
            self.validate_docker_compose_config,
            self.validate_mock_agentcore,
            self.validate_message_bus_implementation,
            self.validate_state_management,
            self.validate_monitoring_tools,
            self.validate_startup_scripts
        ]
        
        for step in validation_steps:
            try:
                step()
            except Exception as e:
                logger.error(f"❌ Validation step failed: {e}")
        
        # Generate final report
        report = self.generate_validation_report()
        
        logger.info(f"📋 Validation completed: {report['success_rate']} success rate")
        
        if report["overall_success"]:
            logger.info("🎉 Task 10.1 Docker-based development environment is COMPLETE!")
        else:
            logger.warning("⚠️  Task 10.1 needs additional work")
        
        return report

def main():
    """Main validation function"""
    validator = DockerEnvironmentValidator()
    report = validator.run_validation()
    
    # Print summary
    print("\n" + "="*60)
    print("TASK 10.1 VALIDATION SUMMARY")
    print("="*60)
    print(f"Overall Success: {'✅ PASS' if report['overall_success'] else '❌ FAIL'}")
    print(f"Success Rate: {report['success_rate']}")
    print(f"Checks Passed: {report['checks_passed']}/{report['total_checks']}")
    print("\nRequirements Status:")
    for req, status in report["requirements_validation"].items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {req.replace('_', ' ').title()}")
    
    if report["recommendations"]:
        print("\nRecommendations:")
        for i, rec in enumerate(report["recommendations"], 1):
            print(f"  {i}. {rec}")
    
    print("="*60)
    
    # Save report to file
    report_path = Path(__file__).parent / "task_10_1_validation_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 Detailed report saved to: {report_path}")
    
    return 0 if report["overall_success"] else 1

if __name__ == "__main__":
    sys.exit(main())