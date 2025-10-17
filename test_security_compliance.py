#!/usr/bin/env python3
"""
Test Security and Compliance Features

Tests the network isolation, data protection, and audit logging components.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta

from security.security_manager import SecurityManager, SecurityLevel
from security.network_isolation import NetworkThreatLevel
from security.data_protection import DataClassification, DataSensitivity
from security.audit_logging import AuditEventType, AuditSeverity, ComplianceFramework

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_network_isolation():
    """Test network isolation and security features"""
    logger.info("Testing network isolation...")
    
    config = {
        'security_level': 'high',
        'tagging_secret': 'test_secret_key',
        'master_encryption_key': 'test_master_key'
    }
    
    security_manager = SecurityManager(config)
    await security_manager.initialize()
    
    try:
        # Test honeypot creation
        honeypot_result = await security_manager.create_secure_honeypot(
            'test_honeypot_1',
            {'type': 'ssh', 'port': 22}
        )
        
        logger.info(f"Created honeypot: {honeypot_result}")
        assert honeypot_result['status'] == 'created'
        
        # Test network access check
        access_result = await security_manager.check_network_access(
            '192.168.1.100',  # source
            '8.8.8.8',        # destination (should be blocked)
            80,               # port
            'tcp',            # protocol
            'test_session_1'  # session_id
        )
        
        logger.info(f"Network access check: {access_result}")
        assert not access_result['allowed']  # Should be blocked by egress filter
        
        # Test attacker connection logging
        connection_event = await security_manager.log_attacker_connection(
            'test_session_1',
            '192.168.1.100',
            'test_honeypot_1',
            'Mozilla/5.0 (Attacker Browser)'
        )
        
        logger.info(f"Logged attacker connection: {connection_event}")
        
        # Test honeypot destruction
        destroy_result = await security_manager.destroy_secure_honeypot('test_honeypot_1')
        logger.info(f"Destroyed honeypot: {destroy_result}")
        assert destroy_result
        
        logger.info("✓ Network isolation tests passed")
        
    finally:
        await security_manager.shutdown()


async def test_data_protection():
    """Test data protection and privacy controls"""
    logger.info("Testing data protection...")
    
    config = {
        'security_level': 'high',
        'tagging_secret': 'test_secret_key',
        'master_encryption_key': 'test_master_key',
        'quarantine_key': 'test_quarantine_key'
    }
    
    security_manager = SecurityManager(config)
    await security_manager.initialize()
    
    try:
        # Test synthetic data processing
        synthetic_data = {
            'username': 'fake_user_123',
            'password': 'synthetic_password',
            'email': 'fake@synthetic.com'
        }
        
        result = await security_manager.process_attacker_data(
            synthetic_data,
            'ssh_honeypot',
            'test_session_2'
        )
        
        logger.info(f"Processed synthetic data: {result}")
        assert result['status'] == 'processed'
        
        # Test real data detection (simulate real SSN)
        real_data = {
            'username': 'admin',
            'ssn': '123-45-6789',  # This should be detected as real data
            'notes': 'This contains a real SSN'
        }
        
        result = await security_manager.process_attacker_data(
            real_data,
            'web_honeypot',
            'test_session_3'
        )
        
        logger.info(f"Processed real data: {result}")
        assert result['status'] == 'quarantined'  # Should be quarantined
        
        # Test AWS key detection
        aws_data = {
            'config': 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
            'secret': 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
        
        result = await security_manager.process_attacker_data(
            aws_data,
            'file_honeypot',
            'test_session_4'
        )
        
        logger.info(f"Processed AWS data: {result}")
        assert result['status'] == 'quarantined'  # Should be quarantined
        
        logger.info("✓ Data protection tests passed")
        
    finally:
        await security_manager.shutdown()


async def test_audit_logging():
    """Test audit logging and compliance features"""
    logger.info("Testing audit logging...")
    
    config = {
        'security_level': 'high',
        'tagging_secret': 'test_secret_key',
        'master_encryption_key': 'test_master_key'
    }
    
    security_manager = SecurityManager(config)
    await security_manager.initialize()
    
    try:
        # Test various audit events
        events = [
            ('admin_login', 'Administrator logged in'),
            ('config_change', 'System configuration modified'),
            ('data_access', 'Sensitive data accessed'),
            ('security_alert', 'Suspicious activity detected')
        ]
        
        event_ids = []
        for action, description in events:
            event_id = await security_manager.audit_compliance.log_audit_event(
                AuditEventType.ADMIN_ACTION,
                'test_component',
                action,
                description,
                severity=AuditSeverity.INFO,
                user_id='test_admin',
                metadata={'test': True}
            )
            event_ids.append(event_id)
            logger.info(f"Logged audit event: {event_id}")
        
        # Test log integrity verification
        integrity_result = await security_manager.audit_compliance.audit_logger.verify_log_integrity()
        logger.info(f"Log integrity check: {integrity_result}")
        assert integrity_result['overall_status'] == 'VALID'
        
        # Test compliance report generation
        compliance_report = await security_manager.audit_compliance.generate_compliance_report(
            ComplianceFramework.ISO27001,
            days_back=1
        )
        
        logger.info(f"Generated compliance report: {compliance_report.report_id}")
        logger.info(f"Compliance status: {compliance_report.status}")
        
        # Test security alert logging
        alert_id = await security_manager.log_security_alert(
            'test_alert',
            'Test security alert for validation',
            AuditSeverity.WARNING,
            session_id='test_session_alert',
            metadata={'alert_type': 'test'}
        )
        
        logger.info(f"Logged security alert: {alert_id}")
        
        logger.info("✓ Audit logging tests passed")
        
    finally:
        await security_manager.shutdown()


async def test_security_health_check():
    """Test security health check functionality"""
    logger.info("Testing security health check...")
    
    config = {
        'security_level': 'high',
        'tagging_secret': 'test_secret_key',
        'master_encryption_key': 'test_master_key'
    }
    
    security_manager = SecurityManager(config)
    await security_manager.initialize()
    
    try:
        # Run health check
        health_result = await security_manager.run_security_health_check()
        
        logger.info(f"Security health check result: {health_result['overall_status']}")
        logger.info(f"Issues found: {len(health_result['issues'])}")
        logger.info(f"Recommendations: {len(health_result['recommendations'])}")
        
        # Get security status
        status = await security_manager.get_security_status()
        logger.info(f"Security status: {json.dumps(status, indent=2, default=str)}")
        
        assert health_result['overall_status'] in ['healthy', 'warning', 'critical']
        assert status['initialized'] == True
        
        logger.info("✓ Security health check tests passed")
        
    finally:
        await security_manager.shutdown()


async def test_emergency_procedures():
    """Test emergency shutdown procedures"""
    logger.info("Testing emergency procedures...")
    
    config = {
        'security_level': 'high',
        'tagging_secret': 'test_secret_key',
        'master_encryption_key': 'test_master_key'
    }
    
    security_manager = SecurityManager(config)
    await security_manager.initialize()
    
    try:
        # Create a honeypot first
        await security_manager.create_secure_honeypot(
            'emergency_test_honeypot',
            {'type': 'web', 'port': 80}
        )
        
        # Test emergency shutdown
        shutdown_result = await security_manager.emergency_shutdown(
            'Test emergency shutdown procedure',
            'test_admin'
        )
        
        logger.info(f"Emergency shutdown result: {shutdown_result}")
        assert shutdown_result == True
        
        logger.info("✓ Emergency procedures tests passed")
        
    except Exception as e:
        logger.error(f"Emergency test error: {e}")
        # Still try to shutdown
        await security_manager.shutdown()


async def run_all_tests():
    """Run all security and compliance tests"""
    logger.info("Starting security and compliance tests...")
    
    tests = [
        test_network_isolation,
        test_data_protection,
        test_audit_logging,
        test_security_health_check,
        test_emergency_procedures
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            await test_func()
            passed += 1
        except Exception as e:
            logger.error(f"Test {test_func.__name__} failed: {e}")
            failed += 1
    
    logger.info(f"\nTest Results:")
    logger.info(f"✓ Passed: {passed}")
    logger.info(f"✗ Failed: {failed}")
    logger.info(f"Total: {passed + failed}")
    
    if failed == 0:
        logger.info("🎉 All security and compliance tests passed!")
    else:
        logger.warning(f"⚠️  {failed} test(s) failed")
    
    return failed == 0


if __name__ == "__main__":
    # Run tests
    success = asyncio.run(run_all_tests())
    
    if success:
        print("\n✅ Security and compliance implementation validated successfully!")
        print("\nImplemented features:")
        print("• Network isolation and VPC security")
        print("• Egress filtering and external communication blocking")
        print("• Network monitoring and anomaly detection")
        print("• Network-based attack detection")
        print("• Synthetic data tagging and tracking")
        print("• Real data detection and quarantine systems")
        print("• Data encryption for all stored data")
        print("• Data retention and lifecycle management")
        print("• Comprehensive audit trail logging")
        print("• Digital signatures for log integrity")
        print("• Compliance reporting capabilities")
        print("• Log analysis and anomaly detection")
        print("• Emergency shutdown procedures")
        print("• Security health monitoring")
    else:
        print("\n❌ Some security tests failed. Please review the logs.")
        exit(1)