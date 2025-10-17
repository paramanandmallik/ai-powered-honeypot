"""
Tests for real data protection and quarantine validation
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from tests.security.security_test_utils import (
    MockDataProtection as DataProtection,
    MockAuditLogger as AuditLogger
)

# Mock agents
class InteractionAgent:
    def __init__(self, config=None):
        self.config = config or {}
    
    async def start(self):
        pass
    
    async def stop(self):
        pass
    
    async def initialize_session(self, session_id: str, config: Dict[str, Any]):
        return {"session_initialized": True}
    
    async def generate_synthetic_data(self, request: Dict[str, Any]):
        return [
            {
                "synthetic": True,
                "fingerprint": "mock_fingerprint",
                "creation_time": datetime.utcnow().isoformat(),
                "data": f"synthetic_{request['type']}_data"
            }
            for _ in range(request.get('count', 1))
        ]
    
    async def simulate_command(self, session_id: str, command: str):
        return f"Command output: {command}"

class IntelligenceAgent:
    def __init__(self, config=None):
        self.config = config or {}
    
    async def start(self):
        pass
    
    async def stop(self):
        pass


@pytest.mark.security
@pytest.mark.asyncio
class TestDataProtectionValidation:
    """Test real data protection and quarantine mechanisms"""

    @pytest.fixture
    async def data_protection_system(self, test_config):
        """Setup data protection testing system"""
        config = {
            **test_config,
            "data_protection_mode": "strict",
            "real_data_detection": True,
            "auto_quarantine": True,
            "audit_all_data": True
        }
        
        data_protection = DataProtection(config=config)
        audit_logger = AuditLogger(config=config)
        interaction = InteractionAgent(config=config)
        intelligence = IntelligenceAgent(config=config)
        
        await interaction.start()
        await intelligence.start()
        
        system = {
            "data_protection": data_protection,
            "audit_logger": audit_logger,
            "interaction": interaction,
            "intelligence": intelligence
        }
        
        yield system
        
        await interaction.stop()
        await intelligence.stop()

    async def test_real_data_pattern_detection(self, data_protection_system):
        """Test detection of real data patterns"""
        data_protection = data_protection_system["data_protection"]
        
        # Test cases with real data patterns
        real_data_patterns = [
            # Email addresses
            {"data": "john.doe@company.com", "type": "email", "should_detect": True},
            {"data": "admin@production-server.com", "type": "email", "should_detect": True},
            {"data": "synthetic_user@fake-domain.local", "type": "email", "should_detect": False},
            
            # API Keys and Secrets
            {"data": "YOUR_AWS_ACCESS_KEY_ID", "type": "aws_key", "should_detect": True},
            {"data": "sk_live_1234567890abcdef", "type": "stripe_key", "should_detect": True},
            {"data": "ghp_1234567890abcdef1234567890abcdef12345678", "type": "github_token", "should_detect": True},
            {"data": "synthetic_key_12345", "type": "synthetic_key", "should_detect": False},
            
            # Hostnames and Servers
            {"data": "prod-database-01.company.com", "type": "hostname", "should_detect": True},
            {"data": "production-web-server", "type": "hostname", "should_detect": True},
            {"data": "synthetic-server-123", "type": "hostname", "should_detect": False},
            
            # File Paths
            {"data": "/etc/shadow", "type": "system_file", "should_detect": True},
            {"data": "/var/log/auth.log", "type": "system_file", "should_detect": True},
            {"data": "/tmp/synthetic_file.txt", "type": "synthetic_file", "should_detect": False},
            
            # IP Addresses
            {"data": "8.8.8.8", "type": "public_ip", "should_detect": True},
            {"data": "1.1.1.1", "type": "public_ip", "should_detect": True},
            {"data": "192.168.1.100", "type": "private_ip", "should_detect": False},
            
            # Database Connection Strings
            {"data": "mysql://user:pass@prod-db.company.com:3306/customers", "type": "db_connection", "should_detect": True},
            {"data": "postgresql://admin:secret@production:5432/orders", "type": "db_connection", "should_detect": True},
            {"data": "sqlite:///tmp/synthetic_test.db", "type": "db_connection", "should_detect": False},
        ]
        
        detection_accuracy = 0
        total_tests = len(real_data_patterns)
        
        for test_case in real_data_patterns:
            detection_result = await data_protection.detect_real_data(test_case["data"])
            
            if detection_result["is_real"] == test_case["should_detect"]:
                detection_accuracy += 1
            
            # Verify detection metadata
            if detection_result["is_real"]:
                assert "confidence" in detection_result
                assert "pattern_type" in detection_result
                assert detection_result["confidence"] > 0.5
        
        # Should achieve high detection accuracy
        accuracy_rate = detection_accuracy / total_tests
        assert accuracy_rate >= 0.85  # 85% accuracy threshold

    async def test_synthetic_data_validation(self, data_protection_system):
        """Test validation of synthetic data tagging"""
        data_protection = data_protection_system["data_protection"]
        interaction = data_protection_system["interaction"]
        
        session_id = "synthetic-validation-test"
        
        # Generate synthetic data
        synthetic_data_types = [
            "user_credentials",
            "file_system_structure", 
            "database_records",
            "network_configuration",
            "system_information"
        ]
        
        generated_data = {}
        
        for data_type in synthetic_data_types:
            data = await interaction.generate_synthetic_data({
                "type": data_type,
                "session_id": session_id,
                "count": 5
            })
            generated_data[data_type] = data
        
        # Validate synthetic data tagging
        for data_type, data_items in generated_data.items():
            for item in data_items:
                # Verify synthetic tagging
                assert item["synthetic"] is True
                assert "fingerprint" in item
                assert "creation_time" in item
                
                # Verify data protection recognizes as synthetic
                protection_check = await data_protection.validate_synthetic_data(item)
                assert protection_check["is_synthetic"] is True
                assert protection_check["fingerprint_valid"] is True

    async def test_quarantine_procedures(self, data_protection_system):
        """Test data quarantine procedures"""
        data_protection = data_protection_system["data_protection"]
        audit_logger = data_protection_system["audit_logger"]
        
        # Test data that should be quarantined
        quarantine_candidates = [
            {
                "data": "john.smith@company.com",
                "source": "ssh_session_123",
                "context": "user enumeration"
            },
            {
                "data": "YOUR_AWS_ACCESS_KEY_ID",
                "source": "web_session_456", 
                "context": "credential harvesting"
            },
            {
                "data": "prod-server-01.company.com",
                "source": "db_session_789",
                "context": "lateral movement attempt"
            }
        ]
        
        quarantined_items = []
        
        for candidate in quarantine_candidates:
            # Detect real data
            detection_result = await data_protection.detect_real_data(candidate["data"])
            
            if detection_result["is_real"]:
                # Quarantine the data
                quarantine_result = await data_protection.quarantine_data(
                    candidate["data"],
                    candidate["source"],
                    candidate["context"]
                )
                
                quarantined_items.append(quarantine_result)
                
                # Verify quarantine metadata
                assert quarantine_result["status"] == "quarantined"
                assert quarantine_result["quarantine_id"] is not None
                assert quarantine_result["timestamp"] is not None
                
                # Verify audit logging
                audit_entry = await audit_logger.log_quarantine_event(quarantine_result)
                assert audit_entry["event_type"] == "data_quarantine"
                assert audit_entry["data_hash"] is not None  # Should not log actual data
        
        # Verify quarantine storage
        quarantine_list = await data_protection.list_quarantined_data()
        assert len(quarantine_list) >= len(quarantined_items)
        
        for item in quarantined_items:
            quarantine_details = await data_protection.get_quarantine_details(
                item["quarantine_id"]
            )
            assert quarantine_details["status"] == "quarantined"
            assert quarantine_details["access_restricted"] is True

    async def test_data_leakage_prevention(self, data_protection_system):
        """Test prevention of data leakage"""
        data_protection = data_protection_system["data_protection"]
        interaction = data_protection_system["interaction"]
        
        session_id = "leakage-prevention-test"
        
        # Initialize session with data protection
        await interaction.initialize_session(session_id, {
            "data_protection": "strict",
            "leakage_prevention": True,
            "output_filtering": True
        })
        
        # Commands that might leak real data
        potentially_leaky_commands = [
            "cat /etc/passwd",
            "grep -r 'password' /etc/",
            "find /home -name '*.key'",
            "ps aux | grep -i prod",
            "netstat -an | grep :3306",
            "env | grep -i secret",
            "history | grep ssh",
            "cat ~/.ssh/config"
        ]
        
        leakage_prevented = 0
        
        for command in potentially_leaky_commands:
            response = await interaction.simulate_command(session_id, command)
            
            # Check response for real data leakage
            leakage_check = await data_protection.scan_output_for_real_data(response)
            
            if leakage_check["real_data_detected"]:
                # Verify data was filtered/redacted
                filtered_response = await data_protection.filter_real_data_from_output(response)
                
                assert filtered_response != response  # Should be modified
                assert "[REDACTED]" in filtered_response or "[FILTERED]" in filtered_response
                leakage_prevented += 1
        
        # Should prevent some data leakage
        assert leakage_prevented >= len(potentially_leaky_commands) * 0.3

    async def test_cross_session_data_isolation(self, data_protection_system):
        """Test data isolation between sessions"""
        interaction = data_protection_system["interaction"]
        data_protection = data_protection_system["data_protection"]
        
        # Create multiple isolated sessions
        sessions = []
        for i in range(3):
            session_id = f"isolation-test-session-{i}"
            await interaction.initialize_session(session_id, {
                "data_isolation": "strict",
                "cross_session_access": False
            })
            sessions.append(session_id)
        
        # Generate session-specific synthetic data
        session_data = {}
        
        for i, session_id in enumerate(sessions):
            data = await interaction.generate_synthetic_data({
                "type": "user_credentials",
                "session_id": session_id,
                "count": 3,
                "session_specific": True
            })
            session_data[session_id] = data
        
        # Test cross-session data access
        isolation_violations = 0
        
        for i, session_id in enumerate(sessions):
            # Try to access data from other sessions
            for j, other_session in enumerate(sessions):
                if i != j:
                    access_attempt = await data_protection.check_cross_session_data_access(
                        session_id, other_session
                    )
                    
                    if access_attempt["access_granted"]:
                        isolation_violations += 1
        
        # Should prevent all cross-session data access
        assert isolation_violations == 0

    async def test_data_retention_and_cleanup(self, data_protection_system):
        """Test data retention policies and cleanup procedures"""
        data_protection = data_protection_system["data_protection"]
        
        # Create test data with different retention policies
        test_data_items = [
            {
                "data": "test_data_1",
                "retention_policy": "session_only",
                "created": datetime.utcnow()
            },
            {
                "data": "test_data_2", 
                "retention_policy": "24_hours",
                "created": datetime.utcnow()
            },
            {
                "data": "test_data_3",
                "retention_policy": "7_days",
                "created": datetime.utcnow()
            }
        ]
        
        # Store data with retention policies
        stored_items = []
        for item in test_data_items:
            storage_result = await data_protection.store_with_retention_policy(
                item["data"],
                item["retention_policy"],
                item["created"]
            )
            stored_items.append(storage_result)
        
        # Test retention policy enforcement
        retention_check = await data_protection.check_retention_policies()
        
        assert "items_checked" in retention_check
        assert "items_expired" in retention_check
        assert "cleanup_scheduled" in retention_check
        
        # Test manual cleanup
        cleanup_result = await data_protection.cleanup_expired_data()
        
        assert cleanup_result["status"] == "completed"
        assert "items_removed" in cleanup_result
        assert "storage_freed" in cleanup_result

    async def test_encryption_and_data_integrity(self, data_protection_system):
        """Test data encryption and integrity validation"""
        data_protection = data_protection_system["data_protection"]
        
        # Test data encryption
        sensitive_data = [
            "user_password_hash_12345",
            "api_key_synthetic_67890", 
            "session_token_abcdef",
            "synthetic_credit_card_1234567890123456"
        ]
        
        encrypted_data = []
        
        for data in sensitive_data:
            encryption_result = await data_protection.encrypt_sensitive_data(data)
            
            assert encryption_result["encrypted"] is True
            assert encryption_result["ciphertext"] != data  # Should be encrypted
            assert "encryption_key_id" in encryption_result
            assert "integrity_hash" in encryption_result
            
            encrypted_data.append(encryption_result)
        
        # Test decryption and integrity validation
        for i, encrypted_item in enumerate(encrypted_data):
            # Verify integrity
            integrity_check = await data_protection.verify_data_integrity(encrypted_item)
            assert integrity_check["integrity_valid"] is True
            
            # Decrypt data
            decryption_result = await data_protection.decrypt_sensitive_data(encrypted_item)
            assert decryption_result["decrypted"] is True
            assert decryption_result["plaintext"] == sensitive_data[i]

    async def test_compliance_reporting(self, data_protection_system):
        """Test data protection compliance reporting"""
        data_protection = data_protection_system["data_protection"]
        audit_logger = data_protection_system["audit_logger"]
        
        # Generate compliance report
        compliance_report = await data_protection.generate_compliance_report()
        
        # Verify required compliance elements
        required_elements = [
            "synthetic_data_percentage",
            "real_data_detection_rate",
            "quarantine_effectiveness",
            "data_leakage_incidents",
            "encryption_coverage",
            "retention_policy_compliance",
            "audit_trail_completeness"
        ]
        
        for element in required_elements:
            assert element in compliance_report
        
        # Verify compliance thresholds
        assert compliance_report["synthetic_data_percentage"] >= 95  # 95% synthetic
        assert compliance_report["real_data_detection_rate"] >= 85  # 85% detection
        assert compliance_report["quarantine_effectiveness"] >= 90  # 90% effective
        assert compliance_report["data_leakage_incidents"] == 0  # No leakage
        assert compliance_report["encryption_coverage"] >= 100  # Full encryption
        
        # Verify audit trail
        audit_completeness = await audit_logger.verify_audit_completeness()
        assert audit_completeness["completeness_percentage"] >= 95

    async def test_emergency_data_protection_procedures(self, data_protection_system):
        """Test emergency data protection procedures"""
        data_protection = data_protection_system["data_protection"]
        
        # Simulate data protection emergency
        emergency_scenarios = [
            {
                "type": "mass_real_data_detection",
                "severity": "critical",
                "affected_sessions": ["session-1", "session-2", "session-3"]
            },
            {
                "type": "quarantine_system_failure",
                "severity": "high", 
                "affected_systems": ["quarantine_storage", "audit_logger"]
            },
            {
                "type": "encryption_key_compromise",
                "severity": "critical",
                "affected_keys": ["key-1", "key-2"]
            }
        ]
        
        emergency_responses = []
        
        for scenario in emergency_scenarios:
            response = await data_protection.handle_data_protection_emergency(scenario)
            emergency_responses.append(response)
            
            # Verify emergency response
            assert response["status"] == "emergency_handled"
            assert response["containment_applied"] is True
            
            if scenario["severity"] == "critical":
                assert response["immediate_shutdown"] is True
                assert response["escalation_triggered"] is True
        
        # Verify all emergencies were handled
        assert len(emergency_responses) == len(emergency_scenarios)
        
        # Verify system recovery procedures
        recovery_status = await data_protection.get_emergency_recovery_status()
        assert recovery_status["recovery_in_progress"] is True
        assert "estimated_recovery_time" in recovery_status

    async def test_data_protection_performance(self, data_protection_system):
        """Test data protection performance under load"""
        data_protection = data_protection_system["data_protection"]
        
        # Generate high volume of data for protection testing
        test_data_volume = 1000
        test_data = []
        
        for i in range(test_data_volume):
            # Mix of real and synthetic data
            if i % 3 == 0:
                data = f"real_email_{i}@company.com"  # Real-looking data
            else:
                data = f"synthetic_data_{i}_fingerprint_xyz"  # Synthetic data
            
            test_data.append(data)
        
        # Measure protection processing time
        start_time = datetime.utcnow()
        
        # Process data protection checks concurrently
        protection_tasks = [
            data_protection.detect_real_data(data) for data in test_data
        ]
        
        results = await asyncio.gather(*protection_tasks)
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        # Verify performance requirements
        throughput = test_data_volume / processing_time
        assert throughput >= 100  # Should process at least 100 items per second
        
        # Verify all data was processed
        assert len(results) == test_data_volume
        
        # Verify detection accuracy under load
        real_data_count = sum(1 for i in range(test_data_volume) if i % 3 == 0)
        detected_real_count = sum(1 for result in results if result["is_real"])
        
        detection_accuracy = detected_real_count / real_data_count if real_data_count > 0 else 1
        assert detection_accuracy >= 0.8  # 80% accuracy under load