#!/usr/bin/env python3
"""
Local Validation and Verification Orchestrator
Task 10.3 Implementation: Comprehensive system validation and integration tests
"""

import asyncio
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from tests.validation.system_validator import SystemValidator, ValidationLevel
from tests.validation.deployment_validator import DeploymentValidator
from tests.validation.performance_validator import PerformanceValidator
from tests.validation.security_validator import SecurityValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/local_validation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationPhase:
    name: str
    description: str
    required: bool = True
    timeout_seconds: int = 300
    retry_count: int = 2

@dataclass
class ValidationResult:
    phase: str
    success: bool
    score: float
    duration: float
    details: Dict[str, Any] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

@dataclass
class LocalValidationReport:
    validation_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    phases: List[ValidationResult] = field(default_factory=list)
    overall_success: bool = False
    overall_score: float = 0.0
    critical_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class LocalValidationOrchestrator:
    """
    Orchestrates comprehensive local validation and verification
    Implements Task 10.3 requirements:
    - Create comprehensive system validation and integration tests
    - Implement security isolation verification and breach testing
    - Add performance benchmarking and optimization tools
    - Build local deployment verification and system health checks
    """
    
    def __init__(self):
        self.validation_phases = self._define_validation_phases()
        self.validators = {}
        self.report = None
        
    def _define_validation_phases(self) -> List[ValidationPhase]:
        """Define validation phases based on requirements"""
        return [
            ValidationPhase(
                name="infrastructure_validation",
                description="Validate Docker environment, databases, and core infrastructure",
                required=True,
                timeout_seconds=120
            ),
            ValidationPhase(
                name="deployment_verification",
                description="Verify local deployment integrity and system health",
                required=True,
                timeout_seconds=180
            ),
            ValidationPhase(
                name="security_isolation_verification",
                description="Verify security isolation and test for potential breaches",
                required=True,
                timeout_seconds=300
            ),
            ValidationPhase(
                name="performance_benchmarking",
                description="Run performance benchmarks and optimization analysis",
                required=False,
                timeout_seconds=240
            ),
            ValidationPhase(
                name="integration_testing",
                description="Test system integration and component communication",
                required=True,
                timeout_seconds=200
            ),
            ValidationPhase(
                name="system_health_verification",
                description="Comprehensive system health and readiness checks",
                required=True,
                timeout_seconds=150
            )
        ]
    
    async def initialize(self):
        """Initialize all validators"""
        try:
            logger.info("Initializing local validation orchestrator")
            
            # Initialize validators
            self.validators['system'] = SystemValidator()
            self.validators['deployment'] = DeploymentValidator()
            self.validators['performance'] = PerformanceValidator()
            self.validators['security'] = SecurityValidator()
            
            # Initialize each validator
            await self.validators['system'].initialize()
            await self.validators['deployment'].initialize()
            
            # Create necessary directories
            os.makedirs("logs", exist_ok=True)
            os.makedirs("reports/validation", exist_ok=True)
            
            logger.info("Local validation orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize validation orchestrator: {e}")
            raise
    
    async def run_comprehensive_validation(self, 
                                         include_optional: bool = True,
                                         fail_fast: bool = False) -> LocalValidationReport:
        """
        Run comprehensive local validation and verification
        
        Args:
            include_optional: Include optional validation phases
            fail_fast: Stop on first critical failure
        """
        self.report = LocalValidationReport(
            validation_id=f"local-validation-{int(time.time())}",
            start_time=datetime.utcnow(),
            metadata={
                "include_optional": include_optional,
                "fail_fast": fail_fast,
                "total_phases": len(self.validation_phases)
            }
        )
        
        logger.info(f"Starting comprehensive local validation: {self.report.validation_id}")
        
        try:
            for phase in self.validation_phases:
                # Skip optional phases if not requested
                if not phase.required and not include_optional:
                    logger.info(f"Skipping optional phase: {phase.name}")
                    continue
                
                logger.info(f"Running validation phase: {phase.name}")
                
                # Run phase with timeout and retry logic
                result = await self._run_validation_phase(phase)
                self.report.phases.append(result)
                
                # Check for critical failure
                if not result.success and phase.required and fail_fast:
                    logger.error(f"Critical failure in required phase: {phase.name}")
                    self.report.critical_issues.append(f"Critical failure: {phase.name}")
                    break
                
                # Log phase completion
                status = "✅ PASSED" if result.success else "❌ FAILED"
                logger.info(f"Phase {phase.name} completed: {status} (Score: {result.score:.1f}%)")
            
            # Calculate overall results
            self._calculate_overall_results()
            
            # Generate recommendations
            self._generate_recommendations()
            
            # Export reports
            await self._export_validation_reports()
            
        except Exception as e:
            logger.error(f"Validation orchestration failed: {e}")
            self.report.critical_issues.append(f"Orchestration error: {str(e)}")
        
        finally:
            self.report.end_time = datetime.utcnow()
            duration = (self.report.end_time - self.report.start_time).total_seconds()
            logger.info(f"Validation completed in {duration:.1f} seconds")
        
        return self.report
    
    async def _run_validation_phase(self, phase: ValidationPhase) -> ValidationResult:
        """Run a single validation phase with timeout and retry"""
        start_time = time.time()
        
        for attempt in range(phase.retry_count + 1):
            try:
                logger.debug(f"Running {phase.name} (attempt {attempt + 1})")
                
                # Run phase with timeout
                result = await asyncio.wait_for(
                    self._execute_validation_phase(phase),
                    timeout=phase.timeout_seconds
                )
                
                # Calculate duration
                duration = time.time() - start_time
                result.duration = duration
                
                return result
                
            except asyncio.TimeoutError:
                logger.warning(f"Phase {phase.name} timed out (attempt {attempt + 1})")
                if attempt == phase.retry_count:
                    return ValidationResult(
                        phase=phase.name,
                        success=False,
                        score=0.0,
                        duration=time.time() - start_time,
                        issues=[f"Phase timed out after {phase.timeout_seconds} seconds"]
                    )
            except Exception as e:
                logger.error(f"Phase {phase.name} failed (attempt {attempt + 1}): {e}")
                if attempt == phase.retry_count:
                    return ValidationResult(
                        phase=phase.name,
                        success=False,
                        score=0.0,
                        duration=time.time() - start_time,
                        issues=[f"Phase execution failed: {str(e)}"]
                    )
                
                # Wait before retry
                await asyncio.sleep(2 ** attempt)
    
    async def _execute_validation_phase(self, phase: ValidationPhase) -> ValidationResult:
        """Execute specific validation phase"""
        
        if phase.name == "infrastructure_validation":
            return await self._run_infrastructure_validation()
        elif phase.name == "deployment_verification":
            return await self._run_deployment_verification()
        elif phase.name == "security_isolation_verification":
            return await self._run_security_isolation_verification()
        elif phase.name == "performance_benchmarking":
            return await self._run_performance_benchmarking()
        elif phase.name == "integration_testing":
            return await self._run_integration_testing()
        elif phase.name == "system_health_verification":
            return await self._run_system_health_verification()
        else:
            raise ValueError(f"Unknown validation phase: {phase.name}")
    
    async def _run_infrastructure_validation(self) -> ValidationResult:
        """Run infrastructure validation (Requirements 6.1, 8.1)"""
        try:
            # Use system validator for infrastructure checks
            report = await self.validators['system'].validate_system(ValidationLevel.BASIC)
            
            # Extract infrastructure-specific results
            infrastructure_components = ['infrastructure', 'agents']
            infrastructure_results = [
                r for r in report.results 
                if r.component in infrastructure_components
            ]
            
            success_count = sum(1 for r in infrastructure_results if r.success)
            total_count = len(infrastructure_results)
            score = (success_count / total_count * 100) if total_count > 0 else 0
            
            issues = [r.message for r in infrastructure_results if not r.success]
            
            return ValidationResult(
                phase="infrastructure_validation",
                success=score >= 80,  # 80% threshold
                score=score,
                duration=0,  # Will be set by caller
                details={
                    "total_checks": total_count,
                    "passed_checks": success_count,
                    "docker_status": "validated" if any("docker" in r.test_name.lower() for r in infrastructure_results if r.success) else "failed",
                    "database_status": "validated" if any("postgres" in r.test_name.lower() or "redis" in r.test_name.lower() for r in infrastructure_results if r.success) else "failed"
                },
                issues=issues
            )
            
        except Exception as e:
            return ValidationResult(
                phase="infrastructure_validation",
                success=False,
                score=0.0,
                duration=0,
                issues=[f"Infrastructure validation failed: {str(e)}"]
            )
    
    async def _run_deployment_verification(self) -> ValidationResult:
        """Run deployment verification (Requirements 6.1, 8.1)"""
        try:
            # Use deployment validator
            status = await self.validators['deployment'].validate_deployment()
            
            # Convert deployment status to validation result
            score = 100 if status.overall_health == "healthy" else (
                75 if status.overall_health == "degraded" else 0
            )
            
            return ValidationResult(
                phase="deployment_verification",
                success=status.deployment_valid,
                score=score,
                duration=0,
                details={
                    "overall_health": status.overall_health,
                    "health_checks": len(status.health_checks),
                    "healthy_components": sum(1 for hc in status.health_checks if hc.status == "healthy"),
                    "deployment_id": status.deployment_id
                },
                issues=status.issues
            )
            
        except Exception as e:
            return ValidationResult(
                phase="deployment_verification",
                success=False,
                score=0.0,
                duration=0,
                issues=[f"Deployment verification failed: {str(e)}"]
            )
    
    async def _run_security_isolation_verification(self) -> ValidationResult:
        """Run security isolation verification and breach testing (Requirements 6.2, 6.3, 8.2)"""
        try:
            # Use security validator
            report = await self.validators['security'].validate_security()
            
            # Calculate security score
            total_tests = len(report.test_results)
            passed_tests = sum(1 for r in report.test_results if r.success)
            score = report.overall_security_score
            
            # Extract critical security issues
            critical_issues = [
                r.message for r in report.test_results 
                if not r.success and r.severity in ["critical", "high"]
            ]
            
            # Security-specific checks
            isolation_tests = [
                r for r in report.test_results 
                if "isolation" in r.test_name or "network" in r.test_name
            ]
            
            breach_tests = [
                r for r in report.test_results 
                if "breach" in r.test_name or "escape" in r.test_name
            ]
            
            return ValidationResult(
                phase="security_isolation_verification",
                success=score >= 70 and report.critical_issues == 0,  # No critical issues allowed
                score=score,
                duration=0,
                details={
                    "total_security_tests": total_tests,
                    "passed_security_tests": passed_tests,
                    "critical_issues": report.critical_issues,
                    "high_issues": report.high_issues,
                    "isolation_tests": len(isolation_tests),
                    "breach_tests": len(breach_tests),
                    "isolation_effective": all(r.success for r in isolation_tests)
                },
                issues=critical_issues,
                recommendations=[
                    r.recommendations for r in report.test_results 
                    if not r.success and r.recommendations
                ]
            )
            
        except Exception as e:
            return ValidationResult(
                phase="security_isolation_verification",
                success=False,
                score=0.0,
                duration=0,
                issues=[f"Security isolation verification failed: {str(e)}"]
            )
    
    async def _run_performance_benchmarking(self) -> ValidationResult:
        """Run performance benchmarking and optimization analysis (Requirements 8.1, 8.2)"""
        try:
            # Use performance validator
            report = await self.validators['performance'].run_performance_validation()
            
            # Calculate performance metrics
            passed_benchmarks = sum(1 for b in report.benchmarks if b.passed)
            total_benchmarks = len(report.benchmarks)
            
            # Extract key performance metrics
            response_time_benchmark = next((b for b in report.benchmarks if b.metric_name == "response_time"), None)
            throughput_benchmark = next((b for b in report.benchmarks if b.metric_name == "throughput"), None)
            cpu_benchmark = next((b for b in report.benchmarks if b.metric_name == "cpu_usage"), None)
            memory_benchmark = next((b for b in report.benchmarks if b.metric_name == "memory_usage"), None)
            
            return ValidationResult(
                phase="performance_benchmarking",
                success=report.overall_score >= 70,
                score=report.overall_score,
                duration=0,
                details={
                    "overall_performance_score": report.overall_score,
                    "benchmarks_passed": passed_benchmarks,
                    "total_benchmarks": total_benchmarks,
                    "avg_response_time_ms": response_time_benchmark.current_value if response_time_benchmark else None,
                    "throughput_rps": throughput_benchmark.current_value if throughput_benchmark else None,
                    "cpu_usage_percent": cpu_benchmark.current_value if cpu_benchmark else None,
                    "memory_usage_percent": memory_benchmark.current_value if memory_benchmark else None
                },
                issues=[f"Performance issue: {b.metric_name}" for b in report.benchmarks if not b.passed],
                recommendations=report.recommendations
            )
            
        except Exception as e:
            return ValidationResult(
                phase="performance_benchmarking",
                success=False,
                score=0.0,
                duration=0,
                issues=[f"Performance benchmarking failed: {str(e)}"]
            )
    
    async def _run_integration_testing(self) -> ValidationResult:
        """Run integration testing (Requirements 6.1, 8.1, 8.2)"""
        try:
            # Run comprehensive integration tests
            integration_tests = [
                self._test_agent_communication(),
                self._test_honeypot_lifecycle(),
                self._test_message_flow(),
                self._test_data_persistence(),
                self._test_monitoring_integration()
            ]
            
            results = await asyncio.gather(*integration_tests, return_exceptions=True)
            
            # Process results
            successful_tests = 0
            total_tests = len(results)
            issues = []
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    issues.append(f"Integration test {i+1} failed: {str(result)}")
                elif isinstance(result, dict) and result.get("success", False):
                    successful_tests += 1
                elif isinstance(result, dict):
                    issues.append(result.get("message", f"Integration test {i+1} failed"))
                else:
                    issues.append(f"Integration test {i+1} returned unexpected result")
            
            score = (successful_tests / total_tests * 100) if total_tests > 0 else 0
            
            return ValidationResult(
                phase="integration_testing",
                success=score >= 80,
                score=score,
                duration=0,
                details={
                    "total_integration_tests": total_tests,
                    "passed_integration_tests": successful_tests,
                    "test_results": [r if isinstance(r, dict) else {"error": str(r)} for r in results]
                },
                issues=issues
            )
            
        except Exception as e:
            return ValidationResult(
                phase="integration_testing",
                success=False,
                score=0.0,
                duration=0,
                issues=[f"Integration testing failed: {str(e)}"]
            )
    
    async def _run_system_health_verification(self) -> ValidationResult:
        """Run system health verification (Requirements 6.1, 6.2, 6.3)"""
        try:
            # Use system validator for comprehensive health check
            report = await self.validators['system'].validate_system(ValidationLevel.COMPREHENSIVE)
            
            # Calculate health score
            success_rate = report.summary.get("success_rate", 0)
            score = success_rate * 100
            
            # Extract component health
            component_health = {}
            for component, stats in report.summary.get("by_component", {}).items():
                component_health[component] = {
                    "health_percentage": (stats["successful"] / stats["total"] * 100) if stats["total"] > 0 else 0,
                    "total_checks": stats["total"],
                    "passed_checks": stats["successful"]
                }
            
            # Identify unhealthy components
            unhealthy_components = [
                comp for comp, health in component_health.items()
                if health["health_percentage"] < 80
            ]
            
            return ValidationResult(
                phase="system_health_verification",
                success=score >= 85 and len(unhealthy_components) == 0,
                score=score,
                duration=0,
                details={
                    "overall_health_score": score,
                    "total_health_checks": report.summary.get("total_tests", 0),
                    "passed_health_checks": report.summary.get("successful_tests", 0),
                    "component_health": component_health,
                    "unhealthy_components": unhealthy_components
                },
                issues=[f"Unhealthy component: {comp}" for comp in unhealthy_components]
            )
            
        except Exception as e:
            return ValidationResult(
                phase="system_health_verification",
                success=False,
                score=0.0,
                duration=0,
                issues=[f"System health verification failed: {str(e)}"]
            )
    
    # Integration test methods
    
    async def _test_agent_communication(self) -> Dict[str, Any]:
        """Test agent communication"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                # Test AgentCore Runtime
                async with session.get("http://localhost:8000/health", timeout=10) as response:
                    if response.status == 200:
                        health_data = await response.json()
                        
                        # Test agent registration endpoint
                        async with session.get("http://localhost:8000/agents", timeout=10) as agents_response:
                            if agents_response.status == 200:
                                agents_data = await agents_response.json()
                                agent_count = len(agents_data.get("agents", []))
                                
                                return {
                                    "success": agent_count >= 2,  # Expect at least 2 agents
                                    "message": f"Agent communication verified: {agent_count} agents",
                                    "agent_count": agent_count,
                                    "agentcore_health": health_data.get("status")
                                }
                            else:
                                return {"success": False, "message": f"Agent listing failed: HTTP {agents_response.status}"}
                    else:
                        return {"success": False, "message": f"AgentCore health check failed: HTTP {response.status}"}
        except Exception as e:
            return {"success": False, "message": f"Agent communication test failed: {str(e)}"}
    
    async def _test_honeypot_lifecycle(self) -> Dict[str, Any]:
        """Test honeypot lifecycle management"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                # Test honeypot creation
                honeypot_data = {
                    "honeypot_id": "test-validation-honeypot",
                    "honeypot_type": "ssh",
                    "configuration": {"port": 2223, "validation": True}
                }
                
                async with session.post(
                    "http://localhost:8002/honeypots/create",
                    json=honeypot_data,
                    timeout=15
                ) as response:
                    
                    if response.status == 200:
                        # Test honeypot status
                        async with session.get(
                            f"http://localhost:8002/honeypots/{honeypot_data['honeypot_id']}",
                            timeout=10
                        ) as status_response:
                            
                            if status_response.status == 200:
                                status_data = await status_response.json()
                                
                                # Clean up - destroy honeypot
                                async with session.delete(
                                    f"http://localhost:8002/honeypots/{honeypot_data['honeypot_id']}",
                                    timeout=10
                                ) as delete_response:
                                    
                                    return {
                                        "success": delete_response.status == 200,
                                        "message": "Honeypot lifecycle test completed",
                                        "created": True,
                                        "status_checked": True,
                                        "destroyed": delete_response.status == 200
                                    }
                            else:
                                return {"success": False, "message": f"Honeypot status check failed: HTTP {status_response.status}"}
                    else:
                        return {"success": False, "message": f"Honeypot creation failed: HTTP {response.status}"}
        except Exception as e:
            return {"success": False, "message": f"Honeypot lifecycle test failed: {str(e)}"}
    
    async def _test_message_flow(self) -> Dict[str, Any]:
        """Test message flow between components"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                # Test message publishing
                message_data = {
                    "exchange": "validation.test",
                    "routing_key": "integration.test",
                    "message_data": {
                        "test_type": "integration_validation",
                        "timestamp": datetime.utcnow().isoformat(),
                        "validation_id": self.report.validation_id if self.report else "unknown"
                    },
                    "message_type": "validation"
                }
                
                async with session.post(
                    "http://localhost:8000/messages/publish",
                    json=message_data,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        
                        return {
                            "success": True,
                            "message": "Message flow test completed",
                            "message_id": result.get("message_id"),
                            "published": True
                        }
                    else:
                        return {"success": False, "message": f"Message publishing failed: HTTP {response.status}"}
        except Exception as e:
            return {"success": False, "message": f"Message flow test failed: {str(e)}"}
    
    async def _test_data_persistence(self) -> Dict[str, Any]:
        """Test data persistence"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                # Test session data persistence
                session_data = {
                    "session_id": "validation-test-session",
                    "honeypot_id": "validation-honeypot",
                    "attacker_ip": "192.168.1.100",
                    "metadata": {"validation": True, "test_type": "data_persistence"}
                }
                
                async with session.post(
                    "http://localhost:8000/sessions/create",
                    json=session_data,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        # Test session retrieval
                        async with session.get(
                            f"http://localhost:8000/sessions/{session_data['session_id']}",
                            timeout=10
                        ) as get_response:
                            
                            if get_response.status == 200:
                                retrieved_data = await get_response.json()
                                
                                return {
                                    "success": True,
                                    "message": "Data persistence test completed",
                                    "session_created": True,
                                    "session_retrieved": True,
                                    "data_matches": retrieved_data.get("session_id") == session_data["session_id"]
                                }
                            else:
                                return {"success": False, "message": f"Session retrieval failed: HTTP {get_response.status}"}
                    else:
                        return {"success": False, "message": f"Session creation failed: HTTP {response.status}"}
        except Exception as e:
            return {"success": False, "message": f"Data persistence test failed: {str(e)}"}
    
    async def _test_monitoring_integration(self) -> Dict[str, Any]:
        """Test monitoring integration"""
        try:
            import aiohttp
            
            monitoring_services = [
                ("Dashboard", "http://localhost:8090/health"),
                ("Metrics", "http://localhost:8000/metrics")
            ]
            
            accessible_services = []
            
            async with aiohttp.ClientSession() as session:
                for service_name, endpoint in monitoring_services:
                    try:
                        async with session.get(endpoint, timeout=5) as response:
                            if response.status == 200:
                                accessible_services.append(service_name)
                    except Exception:
                        pass
            
            return {
                "success": len(accessible_services) >= 1,
                "message": f"Monitoring integration test: {len(accessible_services)} services accessible",
                "accessible_services": accessible_services,
                "total_services": len(monitoring_services)
            }
        except Exception as e:
            return {"success": False, "message": f"Monitoring integration test failed: {str(e)}"}
    
    def _calculate_overall_results(self):
        """Calculate overall validation results"""
        if not self.report.phases:
            self.report.overall_success = False
            self.report.overall_score = 0.0
            return
        
        # Calculate weighted score (required phases have higher weight)
        total_weight = 0
        weighted_score = 0
        
        for phase_def in self.validation_phases:
            phase_result = next((p for p in self.report.phases if p.phase == phase_def.name), None)
            if phase_result:
                weight = 2.0 if phase_def.required else 1.0
                total_weight += weight
                weighted_score += phase_result.score * weight
        
        self.report.overall_score = weighted_score / total_weight if total_weight > 0 else 0
        
        # Determine overall success
        required_phases = [p for p in self.report.phases if any(pd.name == p.phase and pd.required for pd in self.validation_phases)]
        required_success = all(p.success for p in required_phases)
        
        self.report.overall_success = required_success and self.report.overall_score >= 75
        
        # Extract critical issues
        for phase in self.report.phases:
            if not phase.success and any(pd.name == phase.phase and pd.required for pd in self.validation_phases):
                self.report.critical_issues.extend(phase.issues)
    
    def _generate_recommendations(self):
        """Generate recommendations based on validation results"""
        recommendations = []
        
        for phase in self.report.phases:
            if not phase.success:
                if phase.phase == "infrastructure_validation":
                    recommendations.extend([
                        "Check Docker daemon status and container health",
                        "Verify database connections and configurations",
                        "Review infrastructure logs for errors"
                    ])
                elif phase.phase == "deployment_verification":
                    recommendations.extend([
                        "Restart failed services and containers",
                        "Check service configuration files",
                        "Verify network connectivity between components"
                    ])
                elif phase.phase == "security_isolation_verification":
                    recommendations.extend([
                        "Review network isolation configuration",
                        "Strengthen security controls and access policies",
                        "Address identified security vulnerabilities"
                    ])
                elif phase.phase == "performance_benchmarking":
                    recommendations.extend([
                        "Optimize system performance and resource usage",
                        "Consider scaling resources or optimizing algorithms",
                        "Review performance bottlenecks and optimize"
                    ])
                elif phase.phase == "integration_testing":
                    recommendations.extend([
                        "Fix component integration issues",
                        "Check message bus and communication protocols",
                        "Verify API endpoints and data formats"
                    ])
                elif phase.phase == "system_health_verification":
                    recommendations.extend([
                        "Address system health issues",
                        "Monitor resource usage and system metrics",
                        "Implement health monitoring and alerting"
                    ])
                
                # Add phase-specific recommendations
                if phase.recommendations:
                    recommendations.extend(phase.recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if isinstance(rec, list):
                for r in rec:
                    if r not in seen:
                        seen.add(r)
                        unique_recommendations.append(r)
            elif rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        self.report.recommendations = unique_recommendations[:10]  # Limit to top 10
    
    async def _export_validation_reports(self):
        """Export validation reports in multiple formats"""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            
            # JSON report
            json_filename = f"reports/validation/local_validation_{timestamp}.json"
            await self._export_json_report(json_filename)
            
            # HTML report
            html_filename = f"reports/validation/local_validation_{timestamp}.html"
            await self._export_html_report(html_filename)
            
            # Summary report
            summary_filename = f"reports/validation/local_validation_summary_{timestamp}.txt"
            await self._export_summary_report(summary_filename)
            
            logger.info(f"Validation reports exported: {json_filename}, {html_filename}, {summary_filename}")
            
        except Exception as e:
            logger.error(f"Failed to export validation reports: {e}")
    
    async def _export_json_report(self, filename: str):
        """Export JSON validation report"""
        report_data = {
            "validation_id": self.report.validation_id,
            "start_time": self.report.start_time.isoformat(),
            "end_time": self.report.end_time.isoformat() if self.report.end_time else None,
            "overall_success": self.report.overall_success,
            "overall_score": self.report.overall_score,
            "metadata": self.report.metadata,
            "phases": [
                {
                    "phase": p.phase,
                    "success": p.success,
                    "score": p.score,
                    "duration": p.duration,
                    "details": p.details,
                    "issues": p.issues,
                    "recommendations": p.recommendations
                }
                for p in self.report.phases
            ],
            "critical_issues": self.report.critical_issues,
            "recommendations": self.report.recommendations
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    async def _export_html_report(self, filename: str):
        """Export HTML validation report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Local Validation Report - {self.report.validation_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .metric {{ background-color: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }}
        .metric.success {{ border-left-color: #28a745; }}
        .metric.warning {{ border-left-color: #ffc107; }}
        .metric.danger {{ border-left-color: #dc3545; }}
        .phase {{ margin: 15px 0; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6; }}
        .phase.success {{ background-color: #d4edda; border-color: #c3e6cb; }}
        .phase.failure {{ background-color: #f8d7da; border-color: #f5c6cb; }}
        .phase.warning {{ background-color: #fff3cd; border-color: #ffeaa7; }}
        .issues {{ background-color: #f8d7da; padding: 15px; border-radius: 8px; margin: 15px 0; }}
        .recommendations {{ background-color: #d1ecf1; padding: 15px; border-radius: 8px; margin: 15px 0; }}
        .progress-bar {{ width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; overflow: hidden; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #28a745 0%, #20c997 100%); transition: width 0.3s ease; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .status-success {{ background-color: #28a745; color: white; }}
        .status-failure {{ background-color: #dc3545; color: white; }}
        .status-warning {{ background-color: #ffc107; color: black; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Local Validation Report</h1>
            <p><strong>Validation ID:</strong> {self.report.validation_id}</p>
            <p><strong>Start Time:</strong> {self.report.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>End Time:</strong> {self.report.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if self.report.end_time else 'In Progress'}</p>
            <p><strong>Duration:</strong> {(self.report.end_time - self.report.start_time).total_seconds():.1f} seconds</p>
        </div>
        
        <div class="summary">
            <div class="metric {'success' if self.report.overall_success else 'danger'}">
                <h3>Overall Status</h3>
                <p style="font-size: 24px; margin: 5px 0;">{'✅ PASSED' if self.report.overall_success else '❌ FAILED'}</p>
            </div>
            <div class="metric">
                <h3>Overall Score</h3>
                <p style="font-size: 24px; margin: 5px 0;">{self.report.overall_score:.1f}%</p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {self.report.overall_score}%"></div>
                </div>
            </div>
            <div class="metric">
                <h3>Phases Completed</h3>
                <p style="font-size: 24px; margin: 5px 0;">{len(self.report.phases)}</p>
            </div>
            <div class="metric {'success' if len(self.report.critical_issues) == 0 else 'danger'}">
                <h3>Critical Issues</h3>
                <p style="font-size: 24px; margin: 5px 0;">{len(self.report.critical_issues)}</p>
            </div>
        </div>
"""
        
        # Add critical issues section
        if self.report.critical_issues:
            html_content += """
        <div class="issues">
            <h3>🚨 Critical Issues</h3>
            <ul>
"""
            for issue in self.report.critical_issues:
                html_content += f"<li>{issue}</li>"
            html_content += """
            </ul>
        </div>
"""
        
        # Add recommendations section
        if self.report.recommendations:
            html_content += """
        <div class="recommendations">
            <h3>💡 Recommendations</h3>
            <ul>
"""
            for rec in self.report.recommendations:
                html_content += f"<li>{rec}</li>"
            html_content += """
            </ul>
        </div>
"""
        
        # Add phases section
        html_content += """
        <h2>📋 Validation Phases</h2>
"""
        
        for phase in self.report.phases:
            phase_class = "success" if phase.success else ("warning" if phase.score >= 50 else "failure")
            status_badge_class = "status-success" if phase.success else "status-failure"
            status_text = "✅ PASSED" if phase.success else "❌ FAILED"
            
            html_content += f"""
        <div class="phase {phase_class}">
            <h3>{phase.phase.replace('_', ' ').title()} <span class="status-badge {status_badge_class}">{status_text}</span></h3>
            <p><strong>Score:</strong> {phase.score:.1f}% | <strong>Duration:</strong> {phase.duration:.1f}s</p>
            
            <div class="progress-bar" style="margin: 10px 0;">
                <div class="progress-fill" style="width: {phase.score}%"></div>
            </div>
"""
            
            # Add phase details
            if phase.details:
                html_content += """
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
"""
                for key, value in phase.details.items():
                    html_content += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
                html_content += """
            </table>
"""
            
            # Add phase issues
            if phase.issues:
                html_content += """
            <h4>Issues:</h4>
            <ul>
"""
                for issue in phase.issues:
                    html_content += f"<li>{issue}</li>"
                html_content += """
            </ul>
"""
            
            html_content += """
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    async def _export_summary_report(self, filename: str):
        """Export text summary report"""
        summary_content = f"""
AI HONEYPOT AGENTCORE - LOCAL VALIDATION SUMMARY
===============================================

Validation ID: {self.report.validation_id}
Start Time: {self.report.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
End Time: {self.report.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if self.report.end_time else 'In Progress'}
Duration: {(self.report.end_time - self.report.start_time).total_seconds():.1f} seconds

OVERALL RESULTS
===============
Status: {'PASSED' if self.report.overall_success else 'FAILED'}
Score: {self.report.overall_score:.1f}%
Phases Completed: {len(self.report.phases)}
Critical Issues: {len(self.report.critical_issues)}

PHASE RESULTS
=============
"""
        
        for phase in self.report.phases:
            status = "PASSED" if phase.success else "FAILED"
            summary_content += f"""
{phase.phase.replace('_', ' ').title()}: {status} ({phase.score:.1f}%)
  Duration: {phase.duration:.1f}s
  Issues: {len(phase.issues)}
"""
        
        if self.report.critical_issues:
            summary_content += f"""

CRITICAL ISSUES
===============
"""
            for i, issue in enumerate(self.report.critical_issues, 1):
                summary_content += f"{i}. {issue}\n"
        
        if self.report.recommendations:
            summary_content += f"""

RECOMMENDATIONS
===============
"""
            for i, rec in enumerate(self.report.recommendations, 1):
                summary_content += f"{i}. {rec}\n"
        
        with open(filename, 'w') as f:
            f.write(summary_content)

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Local Validation and Verification Orchestrator")
    parser.add_argument("--include-optional", action="store_true", help="Include optional validation phases")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first critical failure")
    parser.add_argument("--phase", help="Run specific validation phase only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        orchestrator = LocalValidationOrchestrator()
        await orchestrator.initialize()
        
        if args.phase:
            # Run specific phase only
            logger.info(f"Running specific validation phase: {args.phase}")
            # Implementation for single phase execution would go here
            print(f"Single phase execution not yet implemented: {args.phase}")
        else:
            # Run comprehensive validation
            report = await orchestrator.run_comprehensive_validation(
                include_optional=args.include_optional,
                fail_fast=args.fail_fast
            )
            
            # Print summary
            print(f"\n{'='*60}")
            print(f"LOCAL VALIDATION SUMMARY")
            print(f"{'='*60}")
            print(f"Status: {'✅ PASSED' if report.overall_success else '❌ FAILED'}")
            print(f"Score: {report.overall_score:.1f}%")
            print(f"Phases: {len(report.phases)}")
            print(f"Critical Issues: {len(report.critical_issues)}")
            
            if report.critical_issues:
                print(f"\nCritical Issues:")
                for issue in report.critical_issues[:5]:  # Show first 5
                    print(f"  - {issue}")
            
            if report.recommendations:
                print(f"\nTop Recommendations:")
                for rec in report.recommendations[:3]:  # Show top 3
                    print(f"  - {rec}")
            
            print(f"\nDetailed reports available in reports/validation/")
            
            # Exit with appropriate code
            sys.exit(0 if report.overall_success else 1)
            
    except KeyboardInterrupt:
        logger.info("Validation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())