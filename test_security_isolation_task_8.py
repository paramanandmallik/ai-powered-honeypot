"""
Comprehensive test suite for Task 8: Security and Isolation Controls

Tests network isolation, data protection, and audit logging components
implemented in task 8.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from security.network_isolation import (
    NetworkSecurityManager, VPCIsolationManager, NetworkMonitor,
    EgressFilter, NetworkAttackDetector, NetworkThreatLevel
)
from security.data_protection import (
    DataProtectionManager, SyntheticDataTagger, RealDataDetector,
    DataEncryption, DataRetentionManager, DataClassification, DataSensitivity
)
from security.audit_logging import (
    AuditComplianceManager, AuditLogger, ComplianceReporter,
    LogAnomalyDetector, TamperDetectionSystem, ComplianceMonitor,
    AuditEventType, AuditSeverity, ComplianceFramework
)


class TestNetworkIsolation:
    """Test network isolation and security architecture"""
    
    @pytest.fixture
    def network_config(self):
        return {
            'vpc_config': {
                'cidr': '10.0.0.0/16'
            },
            'monitoring_enabled': True,
            'egress_filtering': True
        }
    
    @pytest.fixture
    def network_manager(self, network_config):
        return NetworkSecurityManager(network_config)
    
    @pytest.mark.asyncio
    async def test_vpc_isolation_manager(self, network_config):
        """Test VPC isolation manager functionality"""
        vpc_manager = VPCIsolationManager(network_config)
        
        # Test subnet creation
        honeypot_id = "test_honeypot_001"
        subnet_cidr = "10.0.1.0/24"
        
        created_subnet = await vpc_manager.create_isolated_subnet(honeypot_id, subnet_cidr)
        assert created_subnet == subnet_cidr
        assert subnet_cidr in vpc_manager.isolated_subnets
        assert honeypot_id in vpc_manager.honeypot_networks
        
        # Test subnet conflict detection
        with pytest.raises(ValueError, match="conflicts with existing networks"):
            await vpc_manager.create_isolated_subnet("test_honeypot_002", subnet_cidr)
        
        # Test subnet destruction
        success = await vpc_manager.destroy_isolated_subnet(honeypot_id)
        assert success is True
        assert subnet_cidr not in vpc_manager.isolated_subnets
        assert honeypot_id not in vpc_manager.honeypot_networks    

    @pytest.mark.asyncio
    async def test_network_monitor(self, network_config):
        """Test network monitoring and anomaly detection"""
        monitor = NetworkMonitor(network_config)
        
        # Start monitoring
        await monitor.start_monitoring()
        assert monitor.monitoring_active is True
        
        # Test event logging
        from security.network_isolation import NetworkEvent
        test_event = NetworkEvent(
            event_id="test_event_001",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="10.0.1.50",
            protocol="tcp",
            port=22,
            action="ALLOW",
            rule_id="test_rule",
            threat_level=NetworkThreatLevel.LOW
        )
        
        await monitor.log_network_event(test_event)
        assert len(monitor.network_events) == 1
        assert monitor.network_events[0].event_id == "test_event_001"
        
        # Stop monitoring
        await monitor.stop_monitoring()
        assert monitor.monitoring_active is False
    
    @pytest.mark.asyncio
    async def test_egress_filter(self, network_config):
        """Test egress filtering functionality"""
        egress_filter = EgressFilter(network_config)
        
        # Test allowed internal traffic
        allowed, reason = await egress_filter.check_egress_allowed(
            "10.0.1.10", "10.0.1.20", 80, "tcp"
        )
        assert allowed is True
        assert "allow list" in reason.lower()
        
        # Test blocked external traffic
        allowed, reason = await egress_filter.check_egress_allowed(
            "10.0.1.10", "8.8.8.8", 53, "tcp"
        )
        assert allowed is False
        assert "blocked" in reason.lower()
        
        # Test dynamic blocking
        await egress_filter.add_dynamic_block("192.168.1.0/24", 30)
        assert "192.168.1.0/24" in egress_filter.dynamic_blocks
        
        # Test cleanup of expired blocks
        await egress_filter.cleanup_expired_blocks()
    
    @pytest.mark.asyncio
    async def test_attack_detector(self, network_config):
        """Test network attack detection"""
        detector = NetworkAttackDetector(network_config)
        
        # Create test events simulating port scan
        from security.network_isolation import NetworkEvent
        events = []
        for port in range(20, 35):  # Simulate port scanning
            event = NetworkEvent(
                event_id=f"scan_event_{port}",
                timestamp=datetime.utcnow(),
                source_ip="192.168.1.100",
                destination_ip="10.0.1.50",
                protocol="tcp",
                port=port,
                action="DENY",
                rule_id="test_rule",
                threat_level=NetworkThreatLevel.MEDIUM
            )
            events.append(event)
        
        # Analyze for attack patterns
        anomalies = await detector.analyze_network_activity(events)
        
        # Should detect port scanning pattern
        port_scan_anomalies = [a for a in anomalies if a.anomaly_type == "port_scan"]
        assert len(port_scan_anomalies) > 0
        assert port_scan_anomalies[0].threat_level == NetworkThreatLevel.MEDIUM


class TestDataProtection:
    """Test data protection and synthetic data controls"""
    
    @pytest.fixture
    def data_config(self):
        return {
            'tagging_secret': 'test_secret_key',
            'master_encryption_key': 'test_master_key',
            'quarantine_key': 'test_quarantine_key'
        }
    
    @pytest.fixture
    def data_manager(self, data_config):
        return DataProtectionManager(data_config)
    
    @pytest.mark.asyncio
    async def test_synthetic_data_tagger(self, data_config):
        """Test synthetic data tagging and tracking"""
        tagger = SyntheticDataTagger(data_config)
        
        # Test tag creation
        test_data = {"username": "test_user", "password": "fake_password"}
        tag = tagger.create_synthetic_tag(test_data, "test_creator")
        
        assert tag.classification == DataClassification.SYNTHETIC
        assert tag.created_by == "test_creator"
        assert tag.fingerprint is not None
        assert tag.tag_id in tagger.tag_registry
        
        # Test data verification
        is_valid = tagger.verify_synthetic_data(test_data, tag.tag_id)
        assert is_valid is True
        
        # Test access tracking
        success = tagger.track_data_access(tag.tag_id)
        assert success is True
        
        # Test usage report
        report = tagger.get_synthetic_data_usage_report()
        assert report['total_synthetic_tags'] == 1
        assert 'test_creator' in report['by_creator'] 
   
    @pytest.mark.asyncio
    async def test_real_data_detector(self, data_config):
        """Test real data detection and quarantine"""
        detector = RealDataDetector(data_config)
        
        # Test detection of real data patterns
        real_data = "My SSN is 123-45-6789 and email is john@company.com"
        has_real_data, alerts = await detector.scan_for_real_data(real_data, "test_source")
        
        assert has_real_data is True
        assert len(alerts) >= 2  # Should detect SSN and email
        
        # Test quarantine functionality
        quarantine_id = await detector.quarantine_data(
            real_data, "Real data detected", "test_source"
        )
        assert quarantine_id is not None
        assert quarantine_id in detector.quarantine_storage
        
        # Test review of quarantined data
        success = await detector.review_quarantined_data(
            quarantine_id, "security_reviewer", "approved_for_deletion"
        )
        assert success is True
        
        # Test synthetic data (should not trigger alerts)
        synthetic_data = "Username: synthetic_user_001, Password: SYNTHETIC_PASS_123"
        has_real_data, alerts = await detector.scan_for_real_data(synthetic_data, "test_source")
        assert has_real_data is False or len(alerts) == 0
    
    @pytest.mark.asyncio
    async def test_data_encryption(self, data_config):
        """Test data encryption functionality"""
        encryption = DataEncryption(data_config)
        
        # Test data encryption
        test_data = {"sensitive": "information", "user_id": 12345}
        encrypted = encryption.encrypt_data(test_data, "session_data")
        assert encrypted is not None
        assert isinstance(encrypted, str)
        
        # Test data decryption
        decrypted = encryption.decrypt_data(encrypted, "session_data")
        assert decrypted == test_data
        
        # Test key rotation
        success = encryption.rotate_encryption_key("session_data")
        assert success is True
    
    @pytest.mark.asyncio
    async def test_data_retention_manager(self, data_config):
        """Test data retention and lifecycle management"""
        retention_manager = DataRetentionManager(data_config)
        
        # Test record registration
        from security.data_protection import DataTag
        test_tag = DataTag(
            tag_id="test_tag_001",
            classification=DataClassification.SYNTHETIC,
            sensitivity=DataSensitivity.INTERNAL,
            created_at=datetime.utcnow(),
            created_by="test_user",
            fingerprint="test_fingerprint"
        )
        
        record = retention_manager.register_data_record(
            "test_record_001",
            {"test": "data"},
            "synthetic_data",
            [test_tag]
        )
        
        assert record.record_id == "test_record_001"
        assert record.retention_policy == "synthetic_data"
        
        # Test retention status
        status = retention_manager.get_retention_status()
        assert status['total_records'] == 1
        assert 'synthetic_data' in status['by_policy']
    
    @pytest.mark.asyncio
    async def test_data_protection_pipeline(self, data_manager):
        """Test complete data protection pipeline"""
        await data_manager.initialize()
        
        # Test processing synthetic data
        synthetic_data = {"username": "synthetic_user", "role": "admin"}
        result = await data_manager.process_data(
            synthetic_data, "test_honeypot", "interaction_agent"
        )
        
        assert result['status'] == 'processed'
        assert 'tag_id' in result
        assert result['encrypted'] is True
        
        # Test processing real data (should be quarantined)
        real_data = "My SSN is 123-45-6789 and credit card is 4532-1234-5678-9012"
        result = await data_manager.process_data(
            real_data, "test_honeypot", "interaction_agent"
        )
        
        # Should be quarantined due to SSN and credit card detection
        assert result['status'] == 'quarantined'
        assert 'quarantine_id' in result
        assert len(result['alerts']) > 0


class TestAuditLogging:
    """Test audit logging and compliance framework"""
    
    @pytest.fixture
    def audit_config(self):
        return {
            'audit_log_path': '/tmp/test_audit',
            'compliance_frameworks': ['sox', 'gdpr', 'iso27001']
        }
    
    @pytest.fixture
    def audit_manager(self, audit_config):
        return AuditComplianceManager(audit_config)
    
    @pytest.mark.asyncio
    async def test_audit_logger(self, audit_config):
        """Test audit logging with digital signatures"""
        audit_logger = AuditLogger(audit_config)
        
        # Test event logging
        from security.audit_logging import AuditEvent
        test_event = AuditEvent(
            event_id="test_audit_001",
            timestamp=datetime.utcnow(),
            event_type=AuditEventType.SYSTEM_START,
            severity=AuditSeverity.INFO,
            source_component="test_component",
            user_id="test_user",
            session_id="test_session",
            resource_id="test_resource",
            action="test_action",
            description="Test audit event"
        )
        
        event_id = await audit_logger.log_event(test_event)
        assert event_id == test_event.event_id
        assert len(audit_logger.log_entries) == 1
        
        # Test log integrity verification
        integrity_result = await audit_logger.verify_log_integrity()
        assert integrity_result['overall_status'] == 'VALID'
        assert integrity_result['verified_signatures'] == 1
        assert integrity_result['verified_chain'] == 1 
   
    @pytest.mark.asyncio
    async def test_compliance_reporter(self, audit_config):
        """Test compliance reporting functionality"""
        reporter = ComplianceReporter(audit_config)
        
        # Create test events
        from security.audit_logging import AuditEvent
        events = []
        for i in range(5):
            event = AuditEvent(
                event_id=f"compliance_test_{i}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                event_type=AuditEventType.DATA_ACCESS,
                severity=AuditSeverity.INFO,
                source_component="test_component",
                user_id=f"user_{i}",
                session_id=f"session_{i}",
                resource_id=f"resource_{i}",
                action="data_access",
                description=f"Test data access event {i}"
            )
            events.append(event)
        
        # Generate compliance report
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=1)
        
        report = await reporter.generate_compliance_report(
            ComplianceFramework.GDPR, start_date, end_date, events
        )
        
        assert report.framework == ComplianceFramework.GDPR
        assert report.total_events == 5
        assert report.status in ['COMPLIANT', 'NON_COMPLIANT', 'PARTIAL']
    
    @pytest.mark.asyncio
    async def test_anomaly_detector(self, audit_config):
        """Test log anomaly detection"""
        detector = LogAnomalyDetector(audit_config)
        
        # Create events with volume anomaly
        from security.audit_logging import AuditEvent
        events = []
        
        # Normal volume (1 event per hour for 10 hours)
        base_time = datetime.utcnow() - timedelta(hours=10)
        for i in range(10):
            event = AuditEvent(
                event_id=f"normal_{i}",
                timestamp=base_time + timedelta(hours=i),
                event_type=AuditEventType.AUTHENTICATION,
                severity=AuditSeverity.INFO,
                source_component="auth_system",
                user_id=f"user_{i}",
                session_id=f"session_{i}",
                resource_id="auth_resource",
                action="login",
                description=f"Normal login event {i}"
            )
            events.append(event)
        
        # Volume spike (20 events in one hour)
        spike_time = datetime.utcnow()
        for i in range(20):
            event = AuditEvent(
                event_id=f"spike_{i}",
                timestamp=spike_time,
                event_type=AuditEventType.AUTHENTICATION,
                severity=AuditSeverity.INFO,
                source_component="auth_system",
                user_id=f"spike_user_{i}",
                session_id=f"spike_session_{i}",
                resource_id="auth_resource",
                action="login",
                description=f"Spike login event {i}"
            )
            events.append(event)
        
        # Analyze for anomalies
        anomalies = await detector.analyze_logs(events)
        
        # Should detect volume anomaly
        volume_anomalies = [a for a in anomalies if a.anomaly_type == "volume_spike"]
        assert len(volume_anomalies) > 0
    
    @pytest.mark.asyncio
    async def test_tamper_detection(self, audit_config):
        """Test tamper detection system"""
        tamper_detector = TamperDetectionSystem(audit_config)
        
        await tamper_detector.initialize()
        assert tamper_detector.monitoring_active is True
        
        # Get tamper status
        status = tamper_detector.get_tamper_status()
        assert 'monitoring_active' in status
        assert 'total_alerts' in status
        assert status['monitoring_active'] is True
    
    @pytest.mark.asyncio
    async def test_compliance_monitor(self, audit_config):
        """Test real-time compliance monitoring"""
        compliance_monitor = ComplianceMonitor(audit_config)
        
        await compliance_monitor.initialize()
        assert compliance_monitor.monitoring_active is True
        
        # Get compliance status
        status = compliance_monitor.get_compliance_status()
        assert 'monitoring_active' in status
        assert 'total_violations' in status
        assert 'compliance_rules' in status
        assert status['monitoring_active'] is True
    
    @pytest.mark.asyncio
    async def test_audit_compliance_manager(self, audit_manager):
        """Test complete audit and compliance management"""
        await audit_manager.initialize()
        
        # Test audit event logging
        event_id = await audit_manager.log_audit_event(
            AuditEventType.HONEYPOT_CREATE,
            'security_manager',
            'create_honeypot',
            'Test honeypot creation',
            severity=AuditSeverity.INFO,
            resource_id='test_honeypot_001',
            metadata={'honeypot_type': 'ssh'}
        )
        
        assert event_id is not None
        
        # Test compliance report generation
        report = await audit_manager.generate_compliance_report(
            ComplianceFramework.ISO27001, days_back=1
        )
        
        assert report.framework == ComplianceFramework.ISO27001
        
        # Test audit status
        status = await audit_manager.get_audit_status()
        assert 'audit_logging' in status
        assert 'compliance_monitoring' in status
        assert 'tamper_detection' in status
        assert 'overall_health' in status
        
        # Test comprehensive audit report
        comprehensive_report = await audit_manager.generate_comprehensive_audit_report(days_back=1)
        assert 'report_id' in comprehensive_report
        assert 'compliance_reports' in comprehensive_report
        assert 'recommendations' in comprehensive_report


@pytest.mark.asyncio
async def test_integrated_security_system():
    """Test integrated security and isolation system"""
    
    # Configuration for all components
    config = {
        'vpc_config': {'cidr': '10.0.0.0/16'},
        'monitoring_enabled': True,
        'egress_filtering': True,
        'tagging_secret': 'integrated_test_secret',
        'master_encryption_key': 'integrated_test_key',
        'audit_log_path': '/tmp/integrated_test_audit'
    }
    
    # Initialize all managers
    network_manager = NetworkSecurityManager(config)
    data_manager = DataProtectionManager(config)
    audit_manager = AuditComplianceManager(config)
    
    # Initialize systems
    await network_manager.initialize()
    await data_manager.initialize()
    await audit_manager.initialize()
    
    # Test integrated workflow: Create secure honeypot
    honeypot_id = "integrated_test_honeypot"
    
    # 1. Create secure network
    subnet = await network_manager.create_secure_honeypot_network(honeypot_id)
    assert subnet is not None
    
    # 2. Process synthetic data
    synthetic_data = {"username": "test_admin", "password": "synthetic_pass_123"}
    data_result = await data_manager.process_data(
        synthetic_data, honeypot_id, "interaction_agent"
    )
    assert data_result['status'] == 'processed'
    
    # 3. Log audit events
    event_id = await audit_manager.log_audit_event(
        AuditEventType.HONEYPOT_CREATE,
        'integrated_test',
        'create_secure_honeypot',
        f'Created secure honeypot: {honeypot_id}',
        resource_id=honeypot_id,
        metadata={'subnet': subnet, 'data_tag': data_result['tag_id']}
    )
    assert event_id is not None
    
    # 4. Check security status
    network_status = await network_manager.get_security_status()
    data_status = await data_manager.get_protection_status()
    audit_status = await audit_manager.get_audit_status()
    
    assert network_status['active_honeypots'] == 1
    assert data_status['synthetic_tags'] >= 1
    assert audit_status['overall_health'] in ['HEALTHY', 'WARNING']
    
    # 5. Cleanup
    cleanup_success = await network_manager.destroy_honeypot_network(honeypot_id)
    assert cleanup_success is True


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])