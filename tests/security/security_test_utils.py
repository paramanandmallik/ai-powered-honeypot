"""
Security testing utilities and mock implementations
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, List, Any, Optional


class SecurityTestMixin:
    """Mixin class to add security testing methods to honeypot classes"""
    
    async def simulate_login(self, username: str, password: str) -> Dict[str, Any]:
        """Mock login simulation for security testing"""
        # Detect SQL injection patterns
        sql_patterns = ["'", "union", "select", "drop", "insert", "delete", "--", "/*", "*/"]
        injection_detected = any(pattern.lower() in username.lower() for pattern in sql_patterns)
        
        # Simulate authentication
        success = username == "admin" and password == "password123" and not injection_detected
        
        result = {
            "success": success,
            "synthetic": True,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if injection_detected:
            result.update({
                "injection_detected": True,
                "security_alert": True,
                "attack_vector": "sql_injection",
                "confidence_score": 0.9
            })
        
        return result
    
    async def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Mock SSH authentication for security testing"""
        # Common weak credentials
        weak_creds = [
            ("root", "password"), ("admin", "admin"), ("root", "123456"),
            ("admin", "password123"), ("user", "user"), ("test", "test")
        ]
        
        success = (username, password) in weak_creds
        
        return {
            "success": success,
            "synthetic": True,
            "session_id": f"session_{random.randint(1000, 9999)}",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def execute_command(self, session_id: str, command: str) -> str:
        """Mock command execution for security testing"""
        # Detect malicious patterns
        malicious_patterns = [
            "rm -rf", "dd if=/dev/zero", ":(){ :|:& };:", "nc -e", "curl", "wget",
            "sudo", "su -", "chmod +s", "/etc/passwd", "/etc/shadow"
        ]
        
        blocked_patterns = ["Permission denied", "Command not found", "Operation not permitted"]
        
        # Check for malicious patterns
        if any(pattern in command for pattern in malicious_patterns):
            return random.choice(blocked_patterns)
        
        # Simulate normal command output
        if command == "whoami":
            return "user"
        elif command == "id":
            return "uid=1000(user) gid=1000(user) groups=1000(user)"
        elif command.startswith("ls"):
            return "file1.txt  file2.txt  directory1/"
        else:
            return f"Executed: {command}"
    
    async def execute_query(self, connection_id: str, query: str) -> Dict[str, Any]:
        """Mock database query execution for security testing"""
        # Detect SQL injection patterns
        injection_patterns = [
            "union select", "drop table", "insert into", "load_file",
            "into outfile", "exec xp_cmdshell", "information_schema"
        ]
        
        injection_detected = any(pattern.lower() in query.lower() for pattern in injection_patterns)
        
        result = {
            "success": not injection_detected,
            "synthetic": True,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if injection_detected:
            result.update({
                "injection_detected": True,
                "security_alert": True,
                "blocked": True,
                "attack_type": "sql_injection",
                "risk_level": "high"
            })
        else:
            result["data"] = [{"id": 1, "name": "synthetic_user", "synthetic": True}]
        
        return result
    
    async def simulate_connection(self, username: str, password: str, database: str) -> Dict[str, Any]:
        """Mock database connection simulation"""
        return {
            "success": True,
            "synthetic": True,
            "connection_id": f"conn_{random.randint(1000, 9999)}",
            "database": database
        }
    
    async def analyze_email_for_phishing(self, email: Dict[str, Any]) -> Dict[str, Any]:
        """Mock email phishing analysis"""
        # Phishing indicators
        phishing_indicators = [
            "click here", "verify account", "urgent", "suspended",
            "phishing", "malicious", "evil.com", "attacker.com"
        ]
        
        content = f"{email.get('subject', '')} {email.get('body', '')} {email.get('from', '')}"
        
        phishing_score = sum(1 for indicator in phishing_indicators if indicator.lower() in content.lower())
        is_phishing = phishing_score > 0
        confidence = min(phishing_score * 0.3, 1.0)
        
        result = {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "synthetic": True
        }
        
        if is_phishing:
            result.update({
                "phishing_indicators": [indicator for indicator in phishing_indicators 
                                     if indicator.lower() in content.lower()],
                "risk_score": confidence
            })
        
        return result
    
    async def simulate_search(self, query: str) -> Dict[str, Any]:
        """Mock search functionality for XSS testing"""
        xss_patterns = ["<script", "<img", "<svg", "javascript:", "onerror", "onload"]
        
        xss_detected = any(pattern.lower() in query.lower() for pattern in xss_patterns)
        
        result = {
            "success": not xss_detected,
            "synthetic": True,
            "query": query
        }
        
        if xss_detected:
            result.update({
                "xss_detected": True,
                "security_alert": True,
                "blocked": True
            })
        
        return result
    
    async def handle_unknown_request(self, payload: str) -> Dict[str, Any]:
        """Mock handling of unknown requests for zero-day testing"""
        # Simple anomaly detection based on payload characteristics
        anomaly_score = 0.0
        
        # Check for unusual patterns
        if len(payload) > 1000:
            anomaly_score += 0.3
        if any(char in payload for char in ['\x00', '\x90', '\xff']):
            anomaly_score += 0.4
        if payload.count('A') > 100:  # Buffer overflow pattern
            anomaly_score += 0.5
        
        return {
            "anomaly_detected": anomaly_score > 0.5,
            "unknown_attack_pattern": anomaly_score > 0.7,
            "behavioral_analysis": {"pattern_type": "unknown", "complexity": "high"},
            "anomaly_score": anomaly_score,
            "synthetic": True
        }
    
    async def handle_unknown_protocol_data(self, data: str) -> Dict[str, Any]:
        """Mock handling of unknown protocol data"""
        return await self.handle_unknown_request(data)
    
    async def analyze_command_patterns(self, session_id: str) -> Dict[str, Any]:
        """Mock command pattern analysis for AI detection"""
        # Simulate AI-based pattern detection
        patterns = ["reconnaissance", "privilege_escalation", "data_collection"]
        detected_pattern = random.choice(patterns)
        
        return {
            "malicious_pattern_detected": True,
            "pattern_type": detected_pattern,
            "confidence_score": random.uniform(0.7, 0.95),
            "synthetic": True
        }


def add_security_test_methods(honeypot_class):
    """Add security testing methods to a honeypot class"""
    # Add all methods from SecurityTestMixin to the honeypot class
    for method_name in dir(SecurityTestMixin):
        if not method_name.startswith('_') and callable(getattr(SecurityTestMixin, method_name)):
            method = getattr(SecurityTestMixin, method_name)
            setattr(honeypot_class, method_name, method)
    
    return honeypot_class


# Apply security test methods to existing honeypot classes
try:
    from honeypots.web_admin.web_admin_honeypot import WebAdminHoneypot
    from honeypots.ssh.ssh_honeypot import SSHHoneypot
    from honeypots.database.database_honeypot import DatabaseHoneypot
    from honeypots.email.email_honeypot import EmailHoneypot
    
    # Add security testing methods to existing classes
    for cls in [WebAdminHoneypot, SSHHoneypot, DatabaseHoneypot, EmailHoneypot]:
        for method_name in dir(SecurityTestMixin):
            if not method_name.startswith('_') and callable(getattr(SecurityTestMixin, method_name)):
                if not hasattr(cls, method_name):
                    method = getattr(SecurityTestMixin, method_name)
                    setattr(cls, method_name, method)

except ImportError:
    # If honeypot classes are not available, we'll handle this in the tests
    pass

# Mock security system components for testing
class MockSecurityManager:
    """Mock Security Manager for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.incidents = {}
        self.breach_simulations = {}
    
    async def start(self):
        pass
    
    async def stop(self):
        pass
    
    async def report_isolation_breach(self, honeypot_id: str, breach_type: str, details: Dict[str, Any]):
        return {"breach_reported": True, "breach_id": f"breach_{random.randint(1000, 9999)}"}
    
    async def detect_container_escape(self, session_id: str, command: str, response: str):
        escape_patterns = ["docker", "runc", "unshare", "nsenter", "capsh"]
        escape_detected = any(pattern in command for pattern in escape_patterns)
        
        return {
            "escape_detected": escape_detected,
            "containment_action": "block_command" if escape_detected else "allow"
        }
    
    async def check_process_isolation_breach(self, session_id: str, command: str, response: str):
        violation_patterns = ["kill -9 1", "ps aux", "pgrep", "lsof -p 1"]
        violation_detected = any(pattern in command for pattern in violation_patterns)
        
        return {"violation_detected": violation_detected}
    
    async def detect_filesystem_breach(self, session_id: str, command: str, response: str):
        breach_patterns = ["chroot", "mount", "umount", "pivot_root"]
        breach_detected = any(pattern in command for pattern in breach_patterns)
        
        return {"breach_detected": breach_detected}
    
    async def check_resource_limit_breach(self, session_id: str, command: str, response: str):
        limit_patterns = [":(){ :|:& };:", "dd if=/dev/zero", "while true"]
        limit_exceeded = any(pattern in command for pattern in limit_patterns)
        
        return {"limit_exceeded": limit_exceeded}
    
    async def detect_privilege_escalation(self, session_id: str, command: str, response: str):
        escalation_patterns = ["sudo", "su ", "pkexec", "runuser"]
        escalation_detected = any(pattern in command for pattern in escalation_patterns)
        
        return {"escalation_detected": escalation_detected}
    
    async def report_namespace_breach(self, namespace: str, attempt: Dict[str, Any]):
        return {"breach_reported": True}
    
    async def detect_syscall_bypass(self, session_id: str, command: str, response: str):
        bypass_patterns = ["syscall", "ctypes", "fiddle", "strace"]
        bypass_detected = any(pattern in command for pattern in bypass_patterns)
        
        return {"bypass_detected": bypass_detected}
    
    async def get_breach_response_status(self, honeypot_id: str):
        return {
            "containment_applied": True,
            "breach_count": 3,
            "emergency_shutdown": True
        }


class MockNetworkIsolation:
    """Mock Network Isolation for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
    
    async def configure_isolation(self, honeypot_id: str, config: Dict[str, Any]):
        return {"configured": True}
    
    async def check_traffic_violation(self, honeypot_id: str, traffic: Dict[str, Any]):
        # Check if traffic is external
        dst = traffic.get("dst", "")
        external_ips = ["8.8.8.8", "1.1.1.1", "malicious.com"]
        
        violation = any(ip in dst for ip in external_ips)
        
        return {
            "violation": violation,
            "action": "block" if violation else "allow"
        }
    
    async def setup_network_namespace(self, namespace: str, config: Dict[str, Any]):
        return {"namespace_created": True}
    
    async def check_namespace_breach(self, namespace: str, attempt: Dict[str, Any]):
        breach_actions = ["create_interface", "bind_port", "raw_socket"]
        breach_detected = attempt.get("action") in breach_actions
        
        return {"breach_detected": breach_detected}
    
    async def check_lateral_movement(self, source: str, target: str):
        return {"movement_blocked": True}


class MockDataProtection:
    """Mock Data Protection for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
    
    async def detect_real_data(self, data: str):
        # Simple real data detection patterns
        real_patterns = [
            "@company.com", "AKIA", "sk_live_", "prod-", "/etc/", "8.8.8.8",
            "mysql://", "postgresql://"
        ]
        
        is_real = any(pattern in data for pattern in real_patterns)
        
        result = {"is_real": is_real}
        
        if is_real:
            result.update({
                "confidence": 0.9,
                "pattern_type": "sensitive_data"
            })
        
        return result
    
    async def validate_synthetic_data(self, data: Dict[str, Any]):
        return {
            "is_synthetic": data.get("synthetic", False),
            "fingerprint_valid": "fingerprint" in data
        }
    
    async def quarantine_data(self, data: str, source: str, context: str):
        return {
            "status": "quarantined",
            "quarantine_id": f"q_{random.randint(1000, 9999)}",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def list_quarantined_data(self):
        return [{"quarantine_id": "q_1234", "status": "quarantined"}]
    
    async def get_quarantine_details(self, quarantine_id: str):
        return {
            "status": "quarantined",
            "access_restricted": True
        }


class MockAuditLogger:
    """Mock Audit Logger for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
    
    async def log_quarantine_event(self, quarantine_result: Dict[str, Any]):
        return {
            "event_type": "data_quarantine",
            "data_hash": "mock_hash_value"
        }
    
    async def log_audit_event(self, event_type: str, actor: str, resource: str, action: str, details: Dict[str, Any]):
        return {
            "audit_id": f"audit_{random.randint(1000, 9999)}",
            "timestamp": datetime.utcnow().isoformat(),
            "digital_signature": "mock_signature",
            "integrity_hash": "mock_hash"
        }


class MockCoordinatorAgent:
    """Mock Coordinator Agent for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.honeypots = {}
    
    async def start(self):
        pass
    
    async def stop(self):
        pass
    
    async def create_honeypot(self, request: Dict[str, Any]):
        honeypot_id = f"hp_{random.randint(1000, 9999)}"
        self.honeypots[honeypot_id] = {
            "honeypot_id": honeypot_id,
            "type": request.get("honeypot_type", "ssh"),
            "status": "active"
        }
        return self.honeypots[honeypot_id]
    
    async def destroy_honeypot(self, honeypot_id: str):
        if honeypot_id in self.honeypots:
            self.honeypots[honeypot_id]["status"] = "destroyed"
        return {"destroyed": True}
    
    async def get_honeypot_status(self, honeypot_id: str):
        return self.honeypots.get(honeypot_id, {"status": "not_found"})


class MockAlertingService:
    """Mock Alerting Service for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.alerts = []
    
    async def get_active_alerts(self):
        return self.alerts
    
    async def send_emergency_communication(self, message: Dict[str, Any]):
        return {
            "sent": True,
            "channels_used": [
                {"type": "email", "priority": "critical"},
                {"type": "sms", "priority": "critical"}
            ]
        }


# Add more methods to MockSecurityManager
def add_security_manager_methods():
    """Add additional methods to MockSecurityManager"""
    
    async def start_breach_simulation(self, config: Dict[str, Any]):
        simulation_id = f"sim_{random.randint(1000, 9999)}"
        self.breach_simulations[simulation_id] = config
        return {"simulation_id": simulation_id}
    
    async def simulate_breach_activity(self, simulation_id: str, activity: Dict[str, Any]):
        # Mock breach activity simulation
        detected = random.choice([True, False])
        return {
            "detected": detected,
            "detection_method": "behavioral_analysis" if detected else None,
            "confidence_score": random.uniform(0.6, 0.95) if detected else 0.0
        }
    
    async def get_simulation_results(self, simulation_id: str):
        return {
            "breach_type": "data_exfiltration",
            "activities_executed": 5,
            "activities_detected": 3
        }
    
    async def stop_breach_simulation(self, simulation_id: str):
        if simulation_id in self.breach_simulations:
            del self.breach_simulations[simulation_id]
        return {"stopped": True}
    
    async def create_incident(self, incident_type: str, severity: str, details: Dict[str, Any]):
        incident_id = f"inc_{random.randint(1000, 9999)}"
        self.incidents[incident_id] = {
            "incident_id": incident_id,
            "type": incident_type,
            "severity": severity,
            "documented": True
        }
        return self.incidents[incident_id]
    
    async def escalate_incident(self, incident_id: str, escalation_level: int):
        return {
            "escalated": True,
            "escalation_level": escalation_level,
            "escalation_contacts": ["security_team", "management"]
        }
    
    async def get_escalation_notifications(self, incident_id: str):
        return [{"recipient": "security_team", "status": "sent"}]
    
    async def trigger_automated_response(self, incident_data: Dict[str, Any]):
        workflow_id = f"wf_{random.randint(1000, 9999)}"
        return {
            "workflow_triggered": True,
            "workflow_id": workflow_id
        }
    
    async def get_workflow_status(self, workflow_id: str):
        return {
            "status": "completed",
            "completed_steps": [
                {"action": "isolate", "status": "completed"},
                {"action": "analyze", "status": "completed"}
            ]
        }
    
    async def execute_comprehensive_security_test(self, scenario: Dict[str, Any]):
        return {
            "scenario_executed": True,
            "honeypots_tested": len(scenario["honeypot_types"]),
            "attack_vectors_tested": len(scenario["attack_vectors"]),
            "security_control_effectiveness": {
                control: {"effectiveness_score": random.uniform(0.7, 0.95)}
                for control in scenario["security_controls"]
            },
            "overall_security_score": random.uniform(0.8, 0.95)
        }
    
    async def validate_security_control_matrix(self, matrix: Dict[str, Any]):
        return {
            "matrix_complete": True,
            "control_coverage": 0.95,
            "threat_coverage": 0.85,
            "control_categories": {
                category: {
                    "implemented": True,
                    "effectiveness": random.uniform(0.7, 0.95),
                    "threats_covered": details["threat_coverage"]
                }
                for category, details in matrix.items()
            }
        }
    
    async def analyze_attack_surface(self, honeypot_ids: List[str]):
        return {
            "exposed_services": [
                {
                    "service_type": "http",
                    "port": 80,
                    "risk_level": "medium",
                    "mitigation_recommendations": ["Enable HTTPS", "Input validation"]
                }
            ],
            "potential_vulnerabilities": ["XSS", "SQL Injection"],
            "risk_assessment": {
                "overall_risk_score": 0.6,
                "critical_vulnerabilities": 0,
                "recommended_actions": ["Security hardening"]
            }
        }
    
    # Add all these methods to MockSecurityManager
    for method_name, method in locals().items():
        if callable(method) and not method_name.startswith('_'):
            setattr(MockSecurityManager, method_name, method)

# Apply the additional methods
add_security_manager_methods()