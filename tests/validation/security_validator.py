"""
Security Validation and Breach Testing Framework
Validates security isolation and tests for potential breaches
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)

class SecurityTestType(Enum):
    ISOLATION = "isolation"
    BREACH = "breach"
    PENETRATION = "penetration"
    COMPLIANCE = "compliance"

@dataclass
class SecurityTestResult:
    test_name: str
    test_type: SecurityTestType
    success: bool
    severity: str  # low, medium, high, critical
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityValidationReport:
    validation_id: str
    start_time: datetime
    end_time: Optional[datetime]
    test_results: List[SecurityTestResult] = field(default_factory=list)
    overall_security_score: float = 0.0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0

class SecurityValidator:
    """Validates security controls and tests for breaches"""
    
    def __init__(self):
        self.security_tests = self._create_security_tests()
        
    def _create_security_tests(self) -> Dict[str, List[str]]:
        """Create security test definitions"""
        return {
            "network_isolation": [
                "test_external_network_access",
                "test_inter_container_communication",
                "test_port_exposure",
                "test_dns_resolution"
            ],
            "data_protection": [
                "test_synthetic_data_tagging",
                "test_real_data_detection",
                "test_data_encryption",
                "test_data_leakage_prevention"
            ],
            "access_control": [
                "test_authentication_bypass",
                "test_authorization_escalation",
                "test_session_management",
                "test_api_security"
            ],
            "container_security": [
                "test_container_escape",
                "test_privilege_escalation",
                "test_resource_limits",
                "test_security_contexts"
            ],
            "honeypot_isolation": [
                "test_honeypot_containment",
                "test_lateral_movement_prevention",
                "test_command_injection_protection",
                "test_file_system_isolation"
            ]
        }
    
    async def validate_security(self) -> SecurityValidationReport:
        """Run comprehensive security validation"""
        report = SecurityValidationReport(
            validation_id=f"security-{int(time.time())}",
            start_time=datetime.utcnow()
        )
        
        try:
            # Run all security test categories
            for category, tests in self.security_tests.items():
                logger.info(f"Running {category} security tests")
                
                for test_name in tests:
                    try:
                        result = await self._run_security_test(test_name)
                        report.test_results.append(result)
                        
                        # Count issues by severity
                        if not result.success:
                            if result.severity == "critical":
                                report.critical_issues += 1
                            elif result.severity == "high":
                                report.high_issues += 1
                            elif result.severity == "medium":
                                report.medium_issues += 1
                            elif result.severity == "low":
                                report.low_issues += 1
                                
                    except Exception as e:
                        error_result = SecurityTestResult(
                            test_name=test_name,
                            test_type=SecurityTestType.ISOLATION,
                            success=False,
                            severity="high",
                            message=f"Test execution failed: {str(e)}"
                        )
                        report.test_results.append(error_result)
                        report.high_issues += 1
            
            # Calculate security score
            total_tests = len(report.test_results)
            passed_tests = sum(1 for r in report.test_results if r.success)
            
            if total_tests > 0:
                base_score = (passed_tests / total_tests) * 100
                
                # Reduce score based on severity of issues
                penalty = (
                    report.critical_issues * 20 +
                    report.high_issues * 10 +
                    report.medium_issues * 5 +
                    report.low_issues * 2
                )
                
                report.overall_security_score = max(0, base_score - penalty)
            
        except Exception as e:
            logger.error(f"Security validation failed: {e}")
        
        report.end_time = datetime.utcnow()
        return report    

    async def _run_security_test(self, test_name: str) -> SecurityTestResult:
        """Run a specific security test"""
        try:
            # Get test method
            test_method = getattr(self, test_name)
            
            # Run test
            success, severity, message, details, recommendations = await test_method()
            
            return SecurityTestResult(
                test_name=test_name,
                test_type=self._get_test_type(test_name),
                success=success,
                severity=severity,
                message=message,
                details=details,
                recommendations=recommendations
            )
            
        except Exception as e:
            return SecurityTestResult(
                test_name=test_name,
                test_type=SecurityTestType.ISOLATION,
                success=False,
                severity="high",
                message=f"Test failed: {str(e)}"
            )
    
    def _get_test_type(self, test_name: str) -> SecurityTestType:
        """Get test type for test name"""
        if "isolation" in test_name or "containment" in test_name:
            return SecurityTestType.ISOLATION
        elif "breach" in test_name or "escape" in test_name:
            return SecurityTestType.BREACH
        elif "penetration" in test_name or "bypass" in test_name:
            return SecurityTestType.PENETRATION
        else:
            return SecurityTestType.COMPLIANCE 
   
    # Network isolation tests
    
    async def test_external_network_access(self) -> Tuple[bool, str, str, Dict[str, Any], List[str]]:
        """Test that honeypots cannot access external networks"""
        try:
            # Test external connectivity from honeypot containers
            external_hosts = ["8.8.8.8", "google.com", "github.com"]
            blocked_connections = 0
            
            for host in external_hosts:
                try:
                    # Simulate network test from honeypot perspective
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, 80))
                    sock.close()
                    
                    if result != 0:  # Connection failed (good for isolation)
                        blocked_connections += 1
                        
                except Exception:
                    blocked_connections += 1  # Exception means blocked (good)
            
            isolation_effective = blocked_connections == len(external_hosts)
            
            details = {
                "external_hosts_tested": external_hosts,
                "blocked_connections": blocked_connections,
                "total_tests": len(external_hosts),
                "isolation_percentage": (blocked_connections / len(external_hosts)) * 100
            }
            
            if isolation_effective:
                return True, "low", "External network access properly blocked", details, []
            else:
                return False, "high", "External network access not properly isolated", details, [
                    "Implement network isolation rules",
                    "Configure firewall to block external access",
                    "Review container network configuration"
                ]
                
        except Exception as e:
            return False, "medium", f"External network test failed: {str(e)}", {}, []    

    async def test_inter_container_communication(self) -> Tuple[bool, str, str, Dict[str, Any], List[str]]:
        """Test inter-container communication controls"""
        try:
            # Test that honeypots can only communicate with allowed services
            allowed_services = ["redis", "postgres", "mock-agentcore"]
            communication_tests = []
            
            for service in allowed_services:
                try:
                    # Test connection to allowed service
                    if service == "redis":
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex(("localhost", 6379))
                        sock.close()
                        communication_tests.append({"service": service, "allowed": True, "accessible": result == 0})
                    elif service == "postgres":
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex(("localhost", 5432))
                        sock.close()
                        communication_tests.append({"service": service, "allowed": True, "accessible": result == 0})
                    elif service == "mock-agentcore":
                        async with aiohttp.ClientSession() as session:
                            async with session.get("http://localhost:8000/health", timeout=2) as response:
                                accessible = response.status == 200
                        communication_tests.append({"service": service, "allowed": True, "accessible": accessible})
                        
                except Exception:
                    communication_tests.append({"service": service, "allowed": True, "accessible": False})
            
            # Check if allowed communications work
            allowed_working = sum(1 for test in communication_tests if test["allowed"] and test["accessible"])
            total_allowed = sum(1 for test in communication_tests if test["allowed"])
            
            details = {
                "communication_tests": communication_tests,
                "allowed_working": allowed_working,
                "total_allowed": total_allowed
            }
            
            if allowed_working >= total_allowed * 0.8:  # 80% of allowed services should work
                return True, "low", "Inter-container communication properly configured", details, []
            else:
                return False, "medium", "Inter-container communication issues detected", details, [
                    "Review container network configuration",
                    "Check service discovery settings",
                    "Verify firewall rules for internal communication"
                ]
                
        except Exception as e:
            return False, "medium", f"Inter-container communication test failed: {str(e)}", {}, []