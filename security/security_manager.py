"""
Security Manager Module

Main security and compliance manager that integrates network isolation,
data protection, and audit logging components.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

from .network_isolation import NetworkSecurityManager
from .data_protection import DataProtectionManager
from .audit_logging import AuditComplianceManager, AuditEventType, AuditSeverity

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security levels for the system"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityManager:
    """Main security and compliance manager"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.security_level = SecurityLevel(config.get('security_level', 'high'))
        
        # Initialize security components
        self.network_security = NetworkSecurityManager(config)
        self.data_protection = DataProtectionManager(config)
        self.audit_compliance = AuditComplianceManager(config)
        
        self.initialized = False
        
    async def initialize(self):
        """Initialize all security components"""
        try:
            logger.info("Initializing security manager...")
            
            # Initialize components
            await self.network_security.initialize()
            await self.data_protection.initialize()
            await self.audit_compliance.initialize()
            
            # Log system initialization
            await self.audit_compliance.log_audit_event(
                AuditEventType.SYSTEM_START,
                'security_manager',
                'initialize',
                'Security manager initialized',
                severity=AuditSeverity.INFO,
                metadata={
                    'security_level': self.security_level.value,
                    'components': ['network_security', 'data_protection', 'audit_compliance']
                }
            )
            
            self.initialized = True
            logger.info("Security manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize security manager: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown all security components"""
        try:
            logger.info("Shutting down security manager...")
            
            # Log system shutdown
            if self.initialized:
                await self.audit_compliance.log_audit_event(
                    AuditEventType.SYSTEM_STOP,
                    'security_manager',
                    'shutdown',
                    'Security manager shutting down',
                    severity=AuditSeverity.INFO
                )
            
            # Shutdown components
            await self.network_security.shutdown()
            
            logger.info("Security manager shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during security manager shutdown: {e}")
    
    async def create_secure_honeypot(self, honeypot_id: str, honeypot_config: Dict) -> Dict:
        """Create a secure honeypot environment"""
        try:
            logger.info(f"Creating secure honeypot: {honeypot_id}")
            
            # Create isolated network
            network_subnet = await self.network_security.create_secure_honeypot_network(honeypot_id)
            
            # Log honeypot creation
            await self.audit_compliance.log_audit_event(
                AuditEventType.HONEYPOT_CREATE,
                'security_manager',
                'create_honeypot',
                f'Created secure honeypot: {honeypot_id}',
                severity=AuditSeverity.INFO,
                resource_id=honeypot_id,
                metadata={
                    'network_subnet': network_subnet,
                    'honeypot_config': honeypot_config
                }
            )
            
            return {
                'honeypot_id': honeypot_id,
                'network_subnet': network_subnet,
                'security_level': self.security_level.value,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'created'
            }
            
        except Exception as e:
            logger.error(f"Failed to create secure honeypot: {e}")
            
            # Log failure
            await self.audit_compliance.log_audit_event(
                AuditEventType.HONEYPOT_CREATE,
                'security_manager',
                'create_honeypot',
                f'Failed to create honeypot: {honeypot_id}',
                severity=AuditSeverity.ERROR,
                resource_id=honeypot_id,
                success=False,
                error_message=str(e)
            )
            
            raise
    
    async def destroy_secure_honeypot(self, honeypot_id: str) -> bool:
        """Destroy a secure honeypot environment"""
        try:
            logger.info(f"Destroying secure honeypot: {honeypot_id}")
            
            # Destroy network isolation
            success = await self.network_security.destroy_honeypot_network(honeypot_id)
            
            # Log honeypot destruction
            await self.audit_compliance.log_audit_event(
                AuditEventType.HONEYPOT_DESTROY,
                'security_manager',
                'destroy_honeypot',
                f'Destroyed honeypot: {honeypot_id}',
                severity=AuditSeverity.INFO,
                resource_id=honeypot_id,
                success=success
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to destroy secure honeypot: {e}")
            
            # Log failure
            await self.audit_compliance.log_audit_event(
                AuditEventType.HONEYPOT_DESTROY,
                'security_manager',
                'destroy_honeypot',
                f'Failed to destroy honeypot: {honeypot_id}',
                severity=AuditSeverity.ERROR,
                resource_id=honeypot_id,
                success=False,
                error_message=str(e)
            )
            
            return False
    
    async def process_attacker_data(self, data: Any, source_location: str, 
                                  session_id: str, user_id: Optional[str] = None) -> Dict:
        """Process data from attacker interactions through security pipeline"""
        try:
            # Process through data protection pipeline
            protection_result = await self.data_protection.process_data(
                data, source_location, 'interaction_agent'
            )
            
            # Log data processing
            await self.audit_compliance.log_audit_event(
                AuditEventType.DATA_ACCESS,
                'security_manager',
                'process_attacker_data',
                f'Processed attacker data from {source_location}',
                severity=AuditSeverity.INFO,
                session_id=session_id,
                user_id=user_id,
                metadata={
                    'source_location': source_location,
                    'protection_result': protection_result
                }
            )
            
            # If data was quarantined, log security alert
            if protection_result.get('status') == 'quarantined':
                await self.audit_compliance.log_audit_event(
                    AuditEventType.SECURITY_ALERT,
                    'security_manager',
                    'data_quarantined',
                    f'Real data detected and quarantined from {source_location}',
                    severity=AuditSeverity.WARNING,
                    session_id=session_id,
                    user_id=user_id,
                    metadata={
                        'quarantine_id': protection_result.get('quarantine_id'),
                        'alerts': protection_result.get('alerts', [])
                    }
                )
            
            return protection_result
            
        except Exception as e:
            logger.error(f"Failed to process attacker data: {e}")
            
            # Log failure
            await self.audit_compliance.log_audit_event(
                AuditEventType.DATA_ACCESS,
                'security_manager',
                'process_attacker_data',
                f'Failed to process attacker data from {source_location}',
                severity=AuditSeverity.ERROR,
                session_id=session_id,
                user_id=user_id,
                success=False,
                error_message=str(e)
            )
            
            raise
    
    async def check_network_access(self, source_ip: str, destination_ip: str, 
                                 port: int, protocol: str, session_id: str) -> Dict:
        """Check if network access should be allowed"""
        try:
            # Check through network security
            security_result = await self.network_security.check_network_security(
                source_ip, destination_ip, port, protocol
            )
            
            # Log network access attempt
            event_type = AuditEventType.AUTHORIZATION if security_result['allowed'] else AuditEventType.POLICY_VIOLATION
            severity = AuditSeverity.INFO if security_result['allowed'] else AuditSeverity.WARNING
            
            await self.audit_compliance.log_audit_event(
                event_type,
                'security_manager',
                'check_network_access',
                f'Network access {"allowed" if security_result["allowed"] else "denied"}: {source_ip} -> {destination_ip}:{port}',
                severity=severity,
                session_id=session_id,
                success=security_result['allowed'],
                metadata={
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'port': port,
                    'protocol': protocol,
                    'reason': security_result['reason']
                }
            )
            
            return security_result
            
        except Exception as e:
            logger.error(f"Failed to check network access: {e}")
            
            # Log failure
            await self.audit_compliance.log_audit_event(
                AuditEventType.AUTHORIZATION,
                'security_manager',
                'check_network_access',
                f'Failed to check network access: {source_ip} -> {destination_ip}:{port}',
                severity=AuditSeverity.ERROR,
                session_id=session_id,
                success=False,
                error_message=str(e)
            )
            
            return {
                'allowed': False,
                'reason': 'Security check error',
                'error': str(e)
            }
    
    async def log_attacker_connection(self, session_id: str, source_ip: str, 
                                   honeypot_id: str, user_agent: Optional[str] = None) -> str:
        """Log attacker connection to honeypot"""
        try:
            event_id = await self.audit_compliance.log_audit_event(
                AuditEventType.ATTACKER_CONNECT,
                'security_manager',
                'attacker_connect',
                f'Attacker connected to honeypot {honeypot_id}',
                severity=AuditSeverity.INFO,
                session_id=session_id,
                resource_id=honeypot_id,
                ip_address=source_ip,
                user_agent=user_agent,
                metadata={
                    'honeypot_id': honeypot_id,
                    'connection_time': datetime.utcnow().isoformat()
                }
            )
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to log attacker connection: {e}")
            raise
    
    async def log_attacker_disconnection(self, session_id: str, honeypot_id: str, 
                                       duration_seconds: int) -> str:
        """Log attacker disconnection from honeypot"""
        try:
            event_id = await self.audit_compliance.log_audit_event(
                AuditEventType.ATTACKER_DISCONNECT,
                'security_manager',
                'attacker_disconnect',
                f'Attacker disconnected from honeypot {honeypot_id}',
                severity=AuditSeverity.INFO,
                session_id=session_id,
                resource_id=honeypot_id,
                metadata={
                    'honeypot_id': honeypot_id,
                    'session_duration_seconds': duration_seconds,
                    'disconnection_time': datetime.utcnow().isoformat()
                }
            )
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to log attacker disconnection: {e}")
            raise
    
    async def log_security_alert(self, alert_type: str, description: str, 
                               severity: AuditSeverity, **kwargs) -> str:
        """Log a security alert"""
        try:
            event_id = await self.audit_compliance.log_audit_event(
                AuditEventType.SECURITY_ALERT,
                'security_manager',
                alert_type,
                description,
                severity=severity,
                **kwargs
            )
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to log security alert: {e}")
            raise
    
    async def emergency_shutdown(self, reason: str, initiated_by: str) -> bool:
        """Emergency shutdown of all security systems"""
        try:
            logger.critical(f"Emergency shutdown initiated: {reason}")
            
            # Log emergency shutdown
            await self.audit_compliance.log_audit_event(
                AuditEventType.SYSTEM_STOP,
                'security_manager',
                'emergency_shutdown',
                f'Emergency shutdown: {reason}',
                severity=AuditSeverity.CRITICAL,
                user_id=initiated_by,
                metadata={
                    'reason': reason,
                    'initiated_by': initiated_by,
                    'shutdown_time': datetime.utcnow().isoformat()
                }
            )
            
            # Shutdown all components
            await self.shutdown()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed emergency shutdown: {e}")
            return False
    
    async def get_security_status(self) -> Dict:
        """Get comprehensive security status"""
        try:
            network_status = await self.network_security.get_security_status()
            protection_status = await self.data_protection.get_protection_status()
            audit_status = await self.audit_compliance.get_audit_status()
            
            return {
                'security_level': self.security_level.value,
                'initialized': self.initialized,
                'network_security': network_status,
                'data_protection': protection_status,
                'audit_compliance': audit_status,
                'status_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get security status: {e}")
            return {
                'error': str(e),
                'status_timestamp': datetime.utcnow().isoformat()
            }
    
    async def run_security_health_check(self) -> Dict:
        """Run comprehensive security health check"""
        try:
            health_results = {
                'overall_status': 'healthy',
                'checks': {},
                'issues': [],
                'recommendations': []
            }
            
            # Check network security
            network_status = await self.network_security.get_security_status()
            health_results['checks']['network_security'] = {
                'status': 'healthy' if network_status.get('monitoring_active') else 'unhealthy',
                'details': network_status
            }
            
            if not network_status.get('monitoring_active'):
                health_results['issues'].append('Network monitoring is not active')
                health_results['recommendations'].append('Restart network monitoring service')
            
            # Check data protection
            protection_status = await self.data_protection.get_protection_status()
            quarantined_items = protection_status.get('quarantined_items', 0)
            
            health_results['checks']['data_protection'] = {
                'status': 'healthy' if quarantined_items < 10 else 'warning',
                'details': protection_status
            }
            
            if quarantined_items > 0:
                health_results['issues'].append(f'{quarantined_items} items in quarantine')
                health_results['recommendations'].append('Review quarantined items')
            
            # Check audit compliance
            audit_status = await self.audit_compliance.get_audit_status()
            integrity_violations = audit_status.get('integrity_violations', 0)
            
            health_results['checks']['audit_compliance'] = {
                'status': 'healthy' if integrity_violations == 0 else 'critical',
                'details': audit_status
            }
            
            if integrity_violations > 0:
                health_results['issues'].append(f'{integrity_violations} audit integrity violations')
                health_results['recommendations'].append('Investigate audit log integrity issues immediately')
                health_results['overall_status'] = 'critical'
            
            # Determine overall status
            if health_results['issues'] and health_results['overall_status'] != 'critical':
                health_results['overall_status'] = 'warning'
            
            # Log health check
            await self.audit_compliance.log_audit_event(
                AuditEventType.COMPLIANCE_CHECK,
                'security_manager',
                'health_check',
                f'Security health check completed: {health_results["overall_status"]}',
                severity=AuditSeverity.INFO if health_results['overall_status'] == 'healthy' else AuditSeverity.WARNING,
                metadata={
                    'health_results': health_results,
                    'issues_count': len(health_results['issues'])
                }
            )
            
            return health_results
            
        except Exception as e:
            logger.error(f"Failed to run security health check: {e}")
            return {
                'overall_status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }