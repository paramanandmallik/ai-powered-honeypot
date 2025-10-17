"""
Local Deployment Verification and System Health Checks
Validates deployment integrity and system health
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import aiohttp
import docker
import psutil

logger = logging.getLogger(__name__)

@dataclass
class HealthCheck:
    component: str
    status: str  # healthy, unhealthy, degraded
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class DeploymentStatus:
    deployment_id: str
    start_time: datetime
    end_time: Optional[datetime]
    health_checks: List[HealthCheck] = field(default_factory=list)
    overall_health: str = "unknown"
    deployment_valid: bool = False
    issues: List[str] = field(default_factory=list)

class DeploymentValidator:
    """Validates local deployment and system health"""
    
    def __init__(self):
        self.docker_client = None
        self.health_checks = self._create_health_checks()
        
    def _create_health_checks(self) -> List[str]:
        """Create health check definitions"""
        return [
            "check_container_health",
            "check_service_connectivity",
            "check_agent_registration",
            "check_message_bus_health",
            "check_database_health",
            "check_monitoring_stack",
            "check_resource_availability",
            "check_log_collection",
            "check_security_controls"
        ]
    
    async def initialize(self):
        """Initialize deployment validator"""
        try:
            self.docker_client = docker.from_env()
            logger.info("Deployment validator initialized")
        except Exception as e:
            logger.error(f"Failed to initialize deployment validator: {e}")
            raise
    
    async def validate_deployment(self) -> DeploymentStatus:
        """Validate complete deployment"""
        status = DeploymentStatus(
            deployment_id=f"deploy-{int(time.time())}",
            start_time=datetime.utcnow()
        )
        
        try:
            # Run all health checks
            for check_name in self.health_checks:
                try:
                    health_check = await self._run_health_check(check_name)
                    status.health_checks.append(health_check)
                    
                    if health_check.status == "unhealthy":
                        status.issues.append(f"{health_check.component}: {health_check.message}")
                        
                except Exception as e:
                    error_check = HealthCheck(
                        component=check_name,
                        status="unhealthy",
                        message=f"Health check failed: {str(e)}"
                    )
                    status.health_checks.append(error_check)
                    status.issues.append(f"{check_name}: {str(e)}")
            
            # Determine overall health
            healthy_checks = sum(1 for hc in status.health_checks if hc.status == "healthy")
            total_checks = len(status.health_checks)
            
            if total_checks == 0:
                status.overall_health = "unknown"
            elif healthy_checks == total_checks:
                status.overall_health = "healthy"
            elif healthy_checks >= total_checks * 0.8:
                status.overall_health = "degraded"
            else:
                status.overall_health = "unhealthy"
            
            status.deployment_valid = status.overall_health in ["healthy", "degraded"]
            
        except Exception as e:
            logger.error(f"Deployment validation failed: {e}")
            status.issues.append(f"Validation error: {str(e)}")
        
        status.end_time = datetime.utcnow()
        return status
    
    async def _run_health_check(self, check_name: str) -> HealthCheck:
        """Run a specific health check"""
        try:
            # Get check method
            check_method = getattr(self, check_name)
            
            # Run check
            status, message, details = await check_method()
            
            return HealthCheck(
                component=check_name.replace("check_", ""),
                status=status,
                message=message,
                details=details
            )
            
        except Exception as e:
            return HealthCheck(
                component=check_name.replace("check_", ""),
                status="unhealthy",
                message=f"Check failed: {str(e)}"
            )
    
    async def check_container_health(self) -> Tuple[str, str, Dict[str, Any]]:
        """Check Docker container health"""
        try:
            containers = self.docker_client.containers.list()
            
            container_status = {}
            unhealthy_containers = []
            
            for container in containers:
                if "honeypot" in container.name:
                    health = container.attrs.get("State", {}).get("Health", {})
                    status = health.get("Status", "unknown")
                    
                    container_status[container.name] = {
                        "status": container.status,
                        "health": status
                    }
                    
                    if container.status != "running" or status == "unhealthy":
                        unhealthy_containers.append(container.name)
            
            details = {
                "containers": container_status,
                "total_containers": len(container_status),
                "unhealthy_containers": unhealthy_containers
            }
            
            if unhealthy_containers:
                return "unhealthy", f"Unhealthy containers: {unhealthy_containers}", details
            else:
                return "healthy", "All containers healthy", details
                
        except Exception as e:
            return "unhealthy", f"Container health check failed: {str(e)}", {}
    
    async def check_service_connectivity(self) -> Tuple[str, str, Dict[str, Any]]:
        """Check service connectivity"""
        try:
            services = {
                "AgentCore Runtime": "http://localhost:8000/health",
                "Detection Agent": "http://localhost:8001/health",
                "Coordinator Agent": "http://localhost:8002/health",
                "Interaction Agent": "http://localhost:8003/health",
                "Intelligence Agent": "http://localhost:8004/health",
                "Dashboard": "http://localhost:8090/health"
            }
            
            service_status = {}
            unreachable_services = []
            
            async with aiohttp.ClientSession() as session:
                for service_name, url in services.items():
                    try:
                        async with session.get(url, timeout=5) as response:
                            service_status[service_name] = {
                                "reachable": True,
                                "status_code": response.status,
                                "healthy": response.status == 200
                            }
                            
                            if response.status != 200:
                                unreachable_services.append(service_name)
                                
                    except Exception as e:
                        service_status[service_name] = {
                            "reachable": False,
                            "error": str(e)
                        }
                        unreachable_services.append(service_name)
            
            details = {
                "services": service_status,
                "unreachable_services": unreachable_services
            }
            
            if unreachable_services:
                return "degraded", f"Unreachable services: {unreachable_services}", details
            else:
                return "healthy", "All services reachable", details
                
        except Exception as e:
            return "unhealthy", f"Service connectivity check failed: {str(e)}", {}
    
    def export_status(self, status: DeploymentStatus, filename: str = None) -> str:
        """Export deployment status to JSON"""
        if not filename:
            filename = f"deployment_status_{status.deployment_id}.json"
        
        # Convert to serializable format
        status_data = {
            "deployment_id": status.deployment_id,
            "start_time": status.start_time.isoformat(),
            "end_time": status.end_time.isoformat() if status.end_time else None,
            "overall_health": status.overall_health,
            "deployment_valid": status.deployment_valid,
            "issues": status.issues,
            "health_checks": [
                {
                    "component": hc.component,
                    "status": hc.status,
                    "message": hc.message,
                    "details": hc.details,
                    "timestamp": hc.timestamp.isoformat()
                }
                for hc in status.health_checks
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(status_data, f, indent=2)
        
        logger.info(f"Exported deployment status to {filename}")
        return filename

# Convenience functions
async def validate_deployment():
    """Run deployment validation"""
    validator = DeploymentValidator()
    await validator.initialize()
    
    status = await validator.validate_deployment()
    validator.export_status(status, "deployment_validation.json")
    
    return status

if __name__ == "__main__":
    # Example usage
    async def main():
        validator = DeploymentValidator()
        await validator.initialize()
        
        status = await validator.validate_deployment()
        
        print(f"Deployment Health: {status.overall_health}")
        print(f"Deployment Valid: {status.deployment_valid}")
        print(f"Issues: {len(status.issues)}")
        
        if status.issues:
            print("\nIssues found:")
            for issue in status.issues:
                print(f"  - {issue}")
        
        validator.export_status(status)
    
    asyncio.run(main())