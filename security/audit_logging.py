"""
Audit Logging and Compliance Module

Implements comprehensive audit trail logging, digital signatures for log integrity,
compliance reporting capabilities, and log analysis with anomaly detection.
"""

import logging
import json
import hashlib
import hmac
import asyncio
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events"""
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    AGENT_DEPLOY = "agent_deploy"
    AGENT_STOP = "agent_stop"
    HONEYPOT_CREATE = "honeypot_create"
    HONEYPOT_DESTROY = "honeypot_destroy"
    ATTACKER_CONNECT = "attacker_connect"
    ATTACKER_DISCONNECT = "attacker_disconnect"
    DATA_ACCESS = "data_access"
    DATA_MODIFY = "data_modify"
    SECURITY_ALERT = "security_alert"
    POLICY_VIOLATION = "policy_violation"
    ADMIN_ACTION = "admin_action"
    CONFIG_CHANGE = "config_change"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_EXPORT = "data_export"
    COMPLIANCE_CHECK = "compliance_check"


class AuditSeverity(Enum):
    """Audit event severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOX = "sox"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    NIST = "nist"


@dataclass
class AuditEvent:
    """Audit event record"""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    source_component: str
    user_id: Optional[str]
    session_id: Optional[str]
    resource_id: Optional[str]
    action: str
    description: str
    metadata: Dict = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)


@dataclass
class AuditLogEntry:
    """Signed audit log entry"""
    event: AuditEvent
    signature: str
    hash_chain_previous: Optional[str]
    hash_chain_current: str
    sequence_number: int
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ComplianceReport:
    """Compliance report"""
    report_id: str
    framework: ComplianceFramework
    report_period_start: datetime
    report_period_end: datetime
    generated_at: datetime
    total_events: int
    compliance_violations: List[Dict]
    recommendations: List[str]
    summary: Dict
    status: str  # COMPLIANT, NON_COMPLIANT, PARTIAL


@dataclass
class LogAnomaly:
    """Detected log anomaly"""
    anomaly_id: str
    timestamp: datetime
    anomaly_type: str
    description: str
    affected_events: List[str]
    confidence_score: float
    severity: AuditSeverity
    investigation_required: bool = True


class DigitalSigner:
    """Handles digital signatures for audit logs"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.private_key = None
        self.public_key = None
        self._initialize_keys()
    
    def _initialize_keys(self):
        """Initialize or load signing keys"""
        try:
            # In production, these would be loaded from secure storage
            # For now, generate new keys
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
            logger.info("Digital signing keys initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize signing keys: {e}")
            raise
    
    def sign_data(self, data: bytes) -> str:
        """Sign data and return base64 encoded signature"""
        try:
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            logger.error(f"Failed to sign data: {e}")
            raise
    
    def verify_signature(self, data: bytes, signature: str) -> bool:
        """Verify digital signature"""
        try:
            signature_bytes = base64.b64decode(signature.encode())
            
            self.public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for verification"""
        try:
            pem = self.public_key.serialize(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode()
            
        except Exception as e:
            logger.error(f"Failed to serialize public key: {e}")
            return ""


class AuditLogger:
    """Main audit logging system"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.signer = DigitalSigner(config)
        self.log_entries: List[AuditLogEntry] = []
        self.sequence_counter = 0
        self.hash_chain_current = None
        self.log_storage_path = config.get('audit_log_path', '/var/log/honeypot/audit')
        
    async def log_event(self, event: AuditEvent) -> str:
        """Log an audit event with digital signature"""
        try:
            # Create log entry
            self.sequence_counter += 1
            
            # Calculate hash chain
            hash_chain_previous = self.hash_chain_current
            event_data = json.dumps(asdict(event), default=str, sort_keys=True)
            
            if hash_chain_previous:
                chain_input = f"{hash_chain_previous}{event_data}"
            else:
                chain_input = event_data
            
            hash_chain_current = hashlib.sha256(chain_input.encode()).hexdigest()
            self.hash_chain_current = hash_chain_current
            
            # Sign the event
            signature = self.signer.sign_data(event_data.encode())
            
            # Create log entry
            log_entry = AuditLogEntry(
                event=event,
                signature=signature,
                hash_chain_previous=hash_chain_previous,
                hash_chain_current=hash_chain_current,
                sequence_number=self.sequence_counter
            )
            
            # Store log entry
            self.log_entries.append(log_entry)
            
            # Persist to storage
            await self._persist_log_entry(log_entry)
            
            logger.debug(f"Audit event logged: {event.event_id}")
            return event.event_id
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            raise
    
    async def _persist_log_entry(self, log_entry: AuditLogEntry):
        """Persist log entry to storage"""
        try:
            # Convert to JSON
            log_data = {
                'event': asdict(log_entry.event),
                'signature': log_entry.signature,
                'hash_chain_previous': log_entry.hash_chain_previous,
                'hash_chain_current': log_entry.hash_chain_current,
                'sequence_number': log_entry.sequence_number,
                'created_at': log_entry.created_at.isoformat()
            }
            
            # In production, this would write to secure, tamper-evident storage
            # For now, we'll simulate the persistence
            
            logger.debug(f"Persisted audit log entry: {log_entry.sequence_number}")
            
        except Exception as e:
            logger.error(f"Failed to persist log entry: {e}")
    
    async def verify_log_integrity(self) -> Dict:
        """Verify integrity of audit log chain"""
        try:
            verification_results = {
                'total_entries': len(self.log_entries),
                'verified_signatures': 0,
                'verified_chain': 0,
                'integrity_violations': [],
                'overall_status': 'VALID'
            }
            
            previous_hash = None
            
            for i, log_entry in enumerate(self.log_entries):
                # Verify digital signature
                event_data = json.dumps(asdict(log_entry.event), default=str, sort_keys=True)
                
                if self.signer.verify_signature(event_data.encode(), log_entry.signature):
                    verification_results['verified_signatures'] += 1
                else:
                    verification_results['integrity_violations'].append({
                        'sequence': log_entry.sequence_number,
                        'type': 'invalid_signature',
                        'description': 'Digital signature verification failed'
                    })
                
                # Verify hash chain
                if previous_hash == log_entry.hash_chain_previous:
                    verification_results['verified_chain'] += 1
                else:
                    verification_results['integrity_violations'].append({
                        'sequence': log_entry.sequence_number,
                        'type': 'broken_chain',
                        'description': 'Hash chain verification failed'
                    })
                
                previous_hash = log_entry.hash_chain_current
            
            # Determine overall status
            if verification_results['integrity_violations']:
                verification_results['overall_status'] = 'COMPROMISED'
            
            return verification_results
            
        except Exception as e:
            logger.error(f"Failed to verify log integrity: {e}")
            return {'error': str(e), 'overall_status': 'ERROR'}
    
    async def search_events(self, filters: Dict) -> List[AuditEvent]:
        """Search audit events with filters"""
        try:
            results = []
            
            for log_entry in self.log_entries:
                event = log_entry.event
                
                # Apply filters
                if self._event_matches_filters(event, filters):
                    results.append(event)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to search events: {e}")
            return []
    
    def _event_matches_filters(self, event: AuditEvent, filters: Dict) -> bool:
        """Check if event matches search filters"""
        try:
            # Event type filter
            if 'event_type' in filters:
                if event.event_type.value not in filters['event_type']:
                    return False
            
            # Severity filter
            if 'severity' in filters:
                if event.severity.value not in filters['severity']:
                    return False
            
            # Time range filter
            if 'start_time' in filters:
                if event.timestamp < filters['start_time']:
                    return False
            
            if 'end_time' in filters:
                if event.timestamp > filters['end_time']:
                    return False
            
            # User filter
            if 'user_id' in filters:
                if event.user_id != filters['user_id']:
                    return False
            
            # Component filter
            if 'source_component' in filters:
                if event.source_component not in filters['source_component']:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error matching filters: {e}")
            return False


class ComplianceReporter:
    """Generates compliance reports"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.compliance_rules = self._initialize_compliance_rules()
    
    def _initialize_compliance_rules(self) -> Dict:
        """Initialize compliance framework rules"""
        return {
            ComplianceFramework.SOX: {
                'required_events': [
                    AuditEventType.DATA_ACCESS,
                    AuditEventType.DATA_MODIFY,
                    AuditEventType.ADMIN_ACTION,
                    AuditEventType.CONFIG_CHANGE
                ],
                'retention_days': 2555,  # 7 years
                'integrity_required': True,
                'access_controls_required': True
            },
            ComplianceFramework.GDPR: {
                'required_events': [
                    AuditEventType.DATA_ACCESS,
                    AuditEventType.DATA_EXPORT,
                    AuditEventType.DATA_MODIFY,
                    AuditEventType.AUTHENTICATION
                ],
                'retention_days': 1095,  # 3 years
                'data_subject_rights': True,
                'breach_notification': True
            },
            ComplianceFramework.ISO27001: {
                'required_events': [
                    AuditEventType.SECURITY_ALERT,
                    AuditEventType.POLICY_VIOLATION,
                    AuditEventType.ADMIN_ACTION,
                    AuditEventType.SYSTEM_START,
                    AuditEventType.SYSTEM_STOP
                ],
                'retention_days': 1095,
                'security_monitoring': True,
                'incident_response': True
            }
        }
    
    async def generate_compliance_report(self, framework: ComplianceFramework,
                                       start_date: datetime, end_date: datetime,
                                       events: List[AuditEvent]) -> ComplianceReport:
        """Generate compliance report for specified framework"""
        try:
            report_id = f"compliance_{framework.value}_{datetime.utcnow().timestamp()}"
            
            # Filter events for report period
            period_events = [
                event for event in events
                if start_date <= event.timestamp <= end_date
            ]
            
            # Check compliance rules
            violations = await self._check_compliance_violations(framework, period_events)
            recommendations = self._generate_recommendations(framework, violations)
            summary = self._generate_summary(framework, period_events, violations)
            
            # Determine compliance status
            status = "COMPLIANT" if not violations else "NON_COMPLIANT"
            
            report = ComplianceReport(
                report_id=report_id,
                framework=framework,
                report_period_start=start_date,
                report_period_end=end_date,
                generated_at=datetime.utcnow(),
                total_events=len(period_events),
                compliance_violations=violations,
                recommendations=recommendations,
                summary=summary,
                status=status
            )
            
            logger.info(f"Generated compliance report: {report_id}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            raise
    
    async def _check_compliance_violations(self, framework: ComplianceFramework,
                                         events: List[AuditEvent]) -> List[Dict]:
        """Check for compliance violations"""
        violations = []
        rules = self.compliance_rules.get(framework, {})
        
        try:
            # Check required event types
            required_events = rules.get('required_events', [])
            event_types_present = set(event.event_type for event in events)
            
            for required_event in required_events:
                if required_event not in event_types_present:
                    violations.append({
                        'type': 'missing_event_type',
                        'description': f'Required event type {required_event.value} not found',
                        'severity': 'high',
                        'framework_requirement': framework.value
                    })
            
            # Check for suspicious patterns
            failed_auth_count = len([
                e for e in events
                if e.event_type == AuditEventType.AUTHENTICATION and not e.success
            ])
            
            if failed_auth_count > 100:  # Threshold
                violations.append({
                    'type': 'excessive_failed_auth',
                    'description': f'Excessive failed authentication attempts: {failed_auth_count}',
                    'severity': 'medium',
                    'count': failed_auth_count
                })
            
            # Check for admin actions without proper authorization
            unauthorized_admin = [
                e for e in events
                if e.event_type == AuditEventType.ADMIN_ACTION and 'unauthorized' in e.metadata.get('flags', [])
            ]
            
            if unauthorized_admin:
                violations.append({
                    'type': 'unauthorized_admin_action',
                    'description': f'Unauthorized admin actions detected: {len(unauthorized_admin)}',
                    'severity': 'critical',
                    'events': [e.event_id for e in unauthorized_admin]
                })
            
            return violations
            
        except Exception as e:
            logger.error(f"Error checking compliance violations: {e}")
            return []
    
    def _generate_recommendations(self, framework: ComplianceFramework,
                                violations: List[Dict]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        try:
            for violation in violations:
                if violation['type'] == 'missing_event_type':
                    recommendations.append(
                        f"Implement logging for {violation['description']} to meet {framework.value} requirements"
                    )
                elif violation['type'] == 'excessive_failed_auth':
                    recommendations.append(
                        "Implement account lockout policies and investigate potential brute force attacks"
                    )
                elif violation['type'] == 'unauthorized_admin_action':
                    recommendations.append(
                        "Review admin access controls and implement additional authorization checks"
                    )
            
            # General recommendations based on framework
            if framework == ComplianceFramework.GDPR:
                recommendations.append("Ensure data subject rights procedures are documented and tested")
            elif framework == ComplianceFramework.SOX:
                recommendations.append("Verify financial data access controls and segregation of duties")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return []
    
    def _generate_summary(self, framework: ComplianceFramework,
                         events: List[AuditEvent], violations: List[Dict]) -> Dict:
        """Generate compliance summary"""
        try:
            summary = {
                'framework': framework.value,
                'total_events': len(events),
                'total_violations': len(violations),
                'event_breakdown': {},
                'severity_breakdown': {},
                'compliance_score': 0.0
            }
            
            # Event type breakdown
            for event in events:
                event_type = event.event_type.value
                if event_type not in summary['event_breakdown']:
                    summary['event_breakdown'][event_type] = 0
                summary['event_breakdown'][event_type] += 1
            
            # Severity breakdown
            for event in events:
                severity = event.severity.value
                if severity not in summary['severity_breakdown']:
                    summary['severity_breakdown'][severity] = 0
                summary['severity_breakdown'][severity] += 1
            
            # Calculate compliance score (simple metric)
            if violations:
                critical_violations = len([v for v in violations if v.get('severity') == 'critical'])
                high_violations = len([v for v in violations if v.get('severity') == 'high'])
                medium_violations = len([v for v in violations if v.get('severity') == 'medium'])
                
                # Weighted scoring
                violation_score = (critical_violations * 10) + (high_violations * 5) + (medium_violations * 2)
                summary['compliance_score'] = max(0, 100 - violation_score)
            else:
                summary['compliance_score'] = 100.0
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return {}


class LogAnomalyDetector:
    """Detects anomalies in audit logs"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.baseline_patterns = {}
        self.detected_anomalies: List[LogAnomaly] = []
        
    async def analyze_logs(self, events: List[AuditEvent]) -> List[LogAnomaly]:
        """Analyze logs for anomalies"""
        anomalies = []
        
        try:
            # Detect various types of anomalies
            anomalies.extend(await self._detect_volume_anomalies(events))
            anomalies.extend(await self._detect_pattern_anomalies(events))
            anomalies.extend(await self._detect_timing_anomalies(events))
            anomalies.extend(await self._detect_user_behavior_anomalies(events))
            
            # Store detected anomalies
            self.detected_anomalies.extend(anomalies)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error analyzing logs for anomalies: {e}")
            return []
    
    async def _detect_volume_anomalies(self, events: List[AuditEvent]) -> List[LogAnomaly]:
        """Detect volume-based anomalies"""
        anomalies = []
        
        try:
            # Group events by hour
            hourly_counts = {}
            for event in events:
                hour_key = event.timestamp.replace(minute=0, second=0, microsecond=0)
                if hour_key not in hourly_counts:
                    hourly_counts[hour_key] = 0
                hourly_counts[hour_key] += 1
            
            # Calculate baseline (simple average)
            if len(hourly_counts) > 1:
                average_count = sum(hourly_counts.values()) / len(hourly_counts)
                threshold = average_count * 3  # 3x normal volume
                
                for hour, count in hourly_counts.items():
                    if count > threshold:
                        anomaly = LogAnomaly(
                            anomaly_id=f"volume_anomaly_{hour.timestamp()}",
                            timestamp=datetime.utcnow(),
                            anomaly_type="volume_spike",
                            description=f"Unusual volume spike: {count} events (normal: {average_count:.1f})",
                            affected_events=[],
                            confidence_score=min(count / threshold, 1.0),
                            severity=AuditSeverity.WARNING
                        )
                        anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting volume anomalies: {e}")
            return []
    
    async def _detect_pattern_anomalies(self, events: List[AuditEvent]) -> List[LogAnomaly]:
        """Detect pattern-based anomalies"""
        anomalies = []
        
        try:
            # Look for unusual event sequences
            event_sequences = []
            for i in range(len(events) - 2):
                sequence = (
                    events[i].event_type.value,
                    events[i + 1].event_type.value,
                    events[i + 2].event_type.value
                )
                event_sequences.append(sequence)
            
            # Find rare sequences (simple approach)
            sequence_counts = {}
            for seq in event_sequences:
                if seq not in sequence_counts:
                    sequence_counts[seq] = 0
                sequence_counts[seq] += 1
            
            # Flag sequences that occur only once and seem suspicious
            for seq, count in sequence_counts.items():
                if count == 1 and self._is_suspicious_sequence(seq):
                    anomaly = LogAnomaly(
                        anomaly_id=f"pattern_anomaly_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow(),
                        anomaly_type="unusual_sequence",
                        description=f"Unusual event sequence detected: {' -> '.join(seq)}",
                        affected_events=[],
                        confidence_score=0.7,
                        severity=AuditSeverity.WARNING
                    )
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting pattern anomalies: {e}")
            return []
    
    def _is_suspicious_sequence(self, sequence: tuple) -> bool:
        """Check if event sequence is suspicious"""
        suspicious_patterns = [
            ('authentication', 'admin_action', 'data_export'),
            ('system_start', 'config_change', 'system_stop'),
            ('security_alert', 'admin_action', 'data_modify')
        ]
        
        return sequence in suspicious_patterns
    
    async def _detect_timing_anomalies(self, events: List[AuditEvent]) -> List[LogAnomaly]:
        """Detect timing-based anomalies"""
        anomalies = []
        
        try:
            # Look for events outside normal business hours
            after_hours_events = []
            
            for event in events:
                hour = event.timestamp.hour
                # Assume business hours are 8 AM to 6 PM
                if hour < 8 or hour > 18:
                    # Check if it's a weekday
                    if event.timestamp.weekday() < 5:  # Monday = 0, Sunday = 6
                        after_hours_events.append(event)
            
            if len(after_hours_events) > 10:  # Threshold
                anomaly = LogAnomaly(
                    anomaly_id=f"timing_anomaly_{datetime.utcnow().timestamp()}",
                    timestamp=datetime.utcnow(),
                    anomaly_type="after_hours_activity",
                    description=f"Unusual after-hours activity: {len(after_hours_events)} events",
                    affected_events=[e.event_id for e in after_hours_events],
                    confidence_score=0.8,
                    severity=AuditSeverity.WARNING
                )
                anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting timing anomalies: {e}")
            return []
    
    async def _detect_user_behavior_anomalies(self, events: List[AuditEvent]) -> List[LogAnomaly]:
        """Detect user behavior anomalies"""
        anomalies = []
        
        try:
            # Group events by user
            user_activities = {}
            for event in events:
                if event.user_id:
                    if event.user_id not in user_activities:
                        user_activities[event.user_id] = []
                    user_activities[event.user_id].append(event)
            
            # Look for unusual user behavior
            for user_id, user_events in user_activities.items():
                # Check for excessive failed authentications
                failed_auths = [
                    e for e in user_events
                    if e.event_type == AuditEventType.AUTHENTICATION and not e.success
                ]
                
                if len(failed_auths) > 5:  # Threshold
                    anomaly = LogAnomaly(
                        anomaly_id=f"user_anomaly_{user_id}_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow(),
                        anomaly_type="excessive_failed_auth",
                        description=f"User {user_id} has {len(failed_auths)} failed authentication attempts",
                        affected_events=[e.event_id for e in failed_auths],
                        confidence_score=0.9,
                        severity=AuditSeverity.ERROR
                    )
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting user behavior anomalies: {e}")
            return []


class TamperDetectionSystem:
    """Advanced tamper detection for audit logs"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.baseline_checksums: Dict[str, str] = {}
        self.tamper_alerts: List[Dict] = []
        self.monitoring_active = False
        
    async def initialize(self):
        """Initialize tamper detection system"""
        try:
            self.monitoring_active = True
            
            # Start continuous monitoring
            asyncio.create_task(self._continuous_monitoring())
            
            logger.info("Tamper detection system initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize tamper detection: {e}")
            raise
    
    async def _continuous_monitoring(self):
        """Continuous monitoring for tampering attempts"""
        while self.monitoring_active:
            try:
                # Check for file system tampering
                await self._check_file_integrity()
                
                # Check for process tampering
                await self._check_process_integrity()
                
                # Check for network tampering
                await self._check_network_integrity()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(60)
    
    async def _check_file_integrity(self):
        """Check integrity of audit log files"""
        try:
            # In production, this would check actual log files
            # For now, simulate integrity checking
            
            log_files = [
                '/var/log/honeypot/audit.log',
                '/var/log/honeypot/security.log',
                '/var/log/honeypot/compliance.log'
            ]
            
            for log_file in log_files:
                # Calculate current checksum (simulated)
                current_checksum = hashlib.sha256(f"{log_file}_{datetime.utcnow()}".encode()).hexdigest()
                
                # Compare with baseline
                if log_file in self.baseline_checksums:
                    if current_checksum != self.baseline_checksums[log_file]:
                        await self._create_tamper_alert(
                            'file_integrity_violation',
                            f'Log file integrity violation detected: {log_file}',
                            {'file': log_file, 'expected': self.baseline_checksums[log_file], 'actual': current_checksum}
                        )
                else:
                    # Set baseline
                    self.baseline_checksums[log_file] = current_checksum
            
        except Exception as e:
            logger.error(f"Error checking file integrity: {e}")
    
    async def _check_process_integrity(self):
        """Check for unauthorized process modifications"""
        try:
            # Check for suspicious processes that might tamper with logs
            suspicious_processes = [
                'log_editor', 'audit_modifier', 'trace_cleaner',
                'history_eraser', 'evidence_destroyer'
            ]
            
            # In production, this would check actual running processes
            # For now, simulate process checking
            
            for process in suspicious_processes:
                # Simulate process detection
                if secrets.randbelow(1000) < 1:  # Very low probability for simulation
                    await self._create_tamper_alert(
                        'suspicious_process',
                        f'Suspicious process detected: {process}',
                        {'process_name': process, 'detection_method': 'process_monitoring'}
                    )
            
        except Exception as e:
            logger.error(f"Error checking process integrity: {e}")
    
    async def _check_network_integrity(self):
        """Check for network-based tampering attempts"""
        try:
            # Check for unauthorized network connections to log systems
            # In production, this would monitor actual network connections
            
            # Simulate network monitoring
            if secrets.randbelow(10000) < 1:  # Very low probability for simulation
                await self._create_tamper_alert(
                    'unauthorized_network_access',
                    'Unauthorized network access to audit system detected',
                    {'source_ip': '192.168.1.100', 'target_port': 514, 'protocol': 'tcp'}
                )
            
        except Exception as e:
            logger.error(f"Error checking network integrity: {e}")
    
    async def _create_tamper_alert(self, alert_type: str, description: str, metadata: Dict):
        """Create tamper detection alert"""
        try:
            alert = {
                'alert_id': f"tamper_{datetime.utcnow().timestamp()}_{secrets.token_hex(4)}",
                'timestamp': datetime.utcnow().isoformat(),
                'alert_type': alert_type,
                'description': description,
                'severity': 'critical',
                'metadata': metadata,
                'investigation_required': True,
                'auto_response_triggered': False
            }
            
            self.tamper_alerts.append(alert)
            
            # Trigger automatic response
            await self._trigger_tamper_response(alert)
            
            logger.critical(f"Tamper detection alert: {description}")
            
        except Exception as e:
            logger.error(f"Error creating tamper alert: {e}")
    
    async def _trigger_tamper_response(self, alert: Dict):
        """Trigger automatic response to tampering"""
        try:
            # Immediate actions for tampering detection
            response_actions = []
            
            if alert['alert_type'] == 'file_integrity_violation':
                response_actions = [
                    'backup_current_logs',
                    'freeze_log_modifications',
                    'alert_security_team',
                    'initiate_forensic_capture'
                ]
            elif alert['alert_type'] == 'suspicious_process':
                response_actions = [
                    'terminate_suspicious_process',
                    'quarantine_system',
                    'alert_security_team',
                    'capture_process_memory'
                ]
            elif alert['alert_type'] == 'unauthorized_network_access':
                response_actions = [
                    'block_source_ip',
                    'isolate_audit_system',
                    'alert_network_team',
                    'capture_network_traffic'
                ]
            
            # Execute response actions (simulated)
            for action in response_actions:
                logger.info(f"Executing tamper response action: {action}")
                # In production, these would be actual response mechanisms
            
            alert['auto_response_triggered'] = True
            alert['response_actions'] = response_actions
            
        except Exception as e:
            logger.error(f"Error triggering tamper response: {e}")
    
    def get_tamper_status(self) -> Dict:
        """Get current tamper detection status"""
        try:
            return {
                'monitoring_active': self.monitoring_active,
                'total_alerts': len(self.tamper_alerts),
                'critical_alerts': len([a for a in self.tamper_alerts if a['severity'] == 'critical']),
                'unresolved_alerts': len([a for a in self.tamper_alerts if a['investigation_required']]),
                'baseline_files': len(self.baseline_checksums),
                'last_check': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting tamper status: {e}")
            return {'error': str(e)}


class ComplianceMonitor:
    """Real-time compliance monitoring"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.compliance_rules: Dict[str, Dict] = {}
        self.violations: List[Dict] = []
        self.monitoring_active = False
        self._initialize_compliance_rules()
        
    def _initialize_compliance_rules(self):
        """Initialize real-time compliance rules"""
        self.compliance_rules = {
            'data_access_logging': {
                'description': 'All data access must be logged',
                'required_events': [AuditEventType.DATA_ACCESS],
                'max_delay_seconds': 30,
                'severity': 'high'
            },
            'admin_action_approval': {
                'description': 'Admin actions require prior authorization',
                'required_events': [AuditEventType.AUTHORIZATION, AuditEventType.ADMIN_ACTION],
                'sequence_required': True,
                'max_gap_seconds': 300,
                'severity': 'critical'
            },
            'authentication_logging': {
                'description': 'All authentication attempts must be logged',
                'required_events': [AuditEventType.AUTHENTICATION],
                'max_delay_seconds': 10,
                'severity': 'medium'
            },
            'security_alert_response': {
                'description': 'Security alerts require timely response',
                'required_events': [AuditEventType.SECURITY_ALERT],
                'response_required': True,
                'max_response_time_seconds': 900,  # 15 minutes
                'severity': 'high'
            },
            'data_export_authorization': {
                'description': 'Data exports require explicit authorization',
                'required_events': [AuditEventType.AUTHORIZATION, AuditEventType.DATA_EXPORT],
                'sequence_required': True,
                'max_gap_seconds': 600,  # 10 minutes
                'severity': 'critical'
            }
        }
    
    async def initialize(self):
        """Initialize compliance monitoring"""
        try:
            self.monitoring_active = True
            
            # Start real-time monitoring
            asyncio.create_task(self._real_time_monitoring())
            
            logger.info("Compliance monitoring initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize compliance monitoring: {e}")
            raise
    
    async def _real_time_monitoring(self):
        """Real-time compliance monitoring"""
        while self.monitoring_active:
            try:
                # Check compliance rules
                await self._check_compliance_rules()
                
                # Check for overdue responses
                await self._check_overdue_responses()
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in real-time monitoring: {e}")
                await asyncio.sleep(30)
    
    async def _check_compliance_rules(self):
        """Check compliance rules against recent events"""
        try:
            # This would integrate with the audit logger to get recent events
            # For now, simulate compliance checking
            
            for rule_name, rule_config in self.compliance_rules.items():
                # Simulate rule checking
                if secrets.randbelow(1000) < 1:  # Low probability for simulation
                    await self._create_compliance_violation(
                        rule_name,
                        rule_config['description'],
                        rule_config['severity']
                    )
            
        except Exception as e:
            logger.error(f"Error checking compliance rules: {e}")
    
    async def _check_overdue_responses(self):
        """Check for overdue security alert responses"""
        try:
            # Check for security alerts that haven't been responded to
            current_time = datetime.utcnow()
            
            # This would check actual security alerts from the audit log
            # For now, simulate overdue response checking
            
            if secrets.randbelow(5000) < 1:  # Very low probability for simulation
                await self._create_compliance_violation(
                    'overdue_security_response',
                    'Security alert response overdue',
                    'critical'
                )
            
        except Exception as e:
            logger.error(f"Error checking overdue responses: {e}")
    
    async def _create_compliance_violation(self, rule_name: str, description: str, severity: str):
        """Create compliance violation record"""
        try:
            violation = {
                'violation_id': f"compliance_{datetime.utcnow().timestamp()}_{secrets.token_hex(4)}",
                'timestamp': datetime.utcnow().isoformat(),
                'rule_name': rule_name,
                'description': description,
                'severity': severity,
                'status': 'open',
                'remediation_required': True,
                'escalation_level': 0,
                'assigned_to': None,
                'resolution_deadline': (datetime.utcnow() + timedelta(hours=24)).isoformat()
            }
            
            self.violations.append(violation)
            
            # Trigger escalation if critical
            if severity == 'critical':
                await self._escalate_violation(violation)
            
            logger.warning(f"Compliance violation: {description}")
            
        except Exception as e:
            logger.error(f"Error creating compliance violation: {e}")
    
    async def _escalate_violation(self, violation: Dict):
        """Escalate critical compliance violations"""
        try:
            violation['escalation_level'] += 1
            violation['escalated_at'] = datetime.utcnow().isoformat()
            
            # Escalation actions
            escalation_actions = [
                'notify_compliance_team',
                'alert_management',
                'create_incident_ticket',
                'schedule_emergency_review'
            ]
            
            violation['escalation_actions'] = escalation_actions
            
            logger.critical(f"Escalated compliance violation: {violation['description']}")
            
        except Exception as e:
            logger.error(f"Error escalating violation: {e}")
    
    def get_compliance_status(self) -> Dict:
        """Get current compliance monitoring status"""
        try:
            open_violations = [v for v in self.violations if v['status'] == 'open']
            critical_violations = [v for v in open_violations if v['severity'] == 'critical']
            overdue_violations = []
            
            current_time = datetime.utcnow()
            for violation in open_violations:
                deadline = datetime.fromisoformat(violation['resolution_deadline'])
                if current_time > deadline:
                    overdue_violations.append(violation)
            
            return {
                'monitoring_active': self.monitoring_active,
                'total_violations': len(self.violations),
                'open_violations': len(open_violations),
                'critical_violations': len(critical_violations),
                'overdue_violations': len(overdue_violations),
                'compliance_rules': len(self.compliance_rules),
                'last_check': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting compliance status: {e}")
            return {'error': str(e)}


class AuditComplianceManager:
    """Main audit logging and compliance manager"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.audit_logger = AuditLogger(config)
        self.compliance_reporter = ComplianceReporter(config)
        self.anomaly_detector = LogAnomalyDetector(config)
        self.tamper_detection = TamperDetectionSystem(config)
        self.compliance_monitor = ComplianceMonitor(config)
        
    async def initialize(self):
        """Initialize audit and compliance components"""
        try:
            # Initialize tamper detection
            await self.tamper_detection.initialize()
            
            # Initialize compliance monitoring
            await self.compliance_monitor.initialize()
            
            # Start background tasks
            asyncio.create_task(self._periodic_integrity_check())
            asyncio.create_task(self._periodic_anomaly_detection())
            asyncio.create_task(self._periodic_compliance_reporting())
            
            logger.info("Audit and compliance manager initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize audit and compliance: {e}")
            raise
    
    async def log_audit_event(self, event_type: AuditEventType, source_component: str,
                            action: str, description: str, **kwargs) -> str:
        """Log an audit event"""
        try:
            event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                event_type=event_type,
                severity=kwargs.get('severity', AuditSeverity.INFO),
                source_component=source_component,
                user_id=kwargs.get('user_id'),
                session_id=kwargs.get('session_id'),
                resource_id=kwargs.get('resource_id'),
                action=action,
                description=description,
                metadata=kwargs.get('metadata', {}),
                ip_address=kwargs.get('ip_address'),
                user_agent=kwargs.get('user_agent'),
                success=kwargs.get('success', True),
                error_message=kwargs.get('error_message'),
                compliance_tags=kwargs.get('compliance_tags', [])
            )
            
            return await self.audit_logger.log_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            raise
    
    async def generate_compliance_report(self, framework: ComplianceFramework,
                                       days_back: int = 30) -> ComplianceReport:
        """Generate compliance report"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Get events for the period
            events = await self.audit_logger.search_events({
                'start_time': start_date,
                'end_time': end_date
            })
            
            return await self.compliance_reporter.generate_compliance_report(
                framework, start_date, end_date, events
            )
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            raise
    
    async def _periodic_integrity_check(self):
        """Periodic integrity check of audit logs"""
        while True:
            try:
                integrity_result = await self.audit_logger.verify_log_integrity()
                
                if integrity_result['overall_status'] != 'VALID':
                    # Log integrity violation
                    await self.log_audit_event(
                        AuditEventType.SECURITY_ALERT,
                        'audit_system',
                        'integrity_check',
                        'Audit log integrity violation detected',
                        severity=AuditSeverity.CRITICAL,
                        metadata={'integrity_result': integrity_result}
                    )
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Error in periodic integrity check: {e}")
                await asyncio.sleep(3600)
    
    async def _periodic_anomaly_detection(self):
        """Periodic anomaly detection on audit logs"""
        while True:
            try:
                # Get recent events
                recent_events = await self.audit_logger.search_events({
                    'start_time': datetime.utcnow() - timedelta(hours=24)
                })
                
                # Detect anomalies
                anomalies = await self.anomaly_detector.analyze_logs(recent_events)
                
                # Log detected anomalies
                for anomaly in anomalies:
                    await self.log_audit_event(
                        AuditEventType.SECURITY_ALERT,
                        'anomaly_detector',
                        'anomaly_detected',
                        anomaly.description,
                        severity=anomaly.severity,
                        metadata={
                            'anomaly_type': anomaly.anomaly_type,
                            'confidence_score': anomaly.confidence_score,
                            'affected_events': anomaly.affected_events
                        }
                    )
                
                await asyncio.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                logger.error(f"Error in periodic anomaly detection: {e}")
                await asyncio.sleep(1800)
    
    async def _periodic_compliance_reporting(self):
        """Periodic compliance reporting and monitoring"""
        while True:
            try:
                # Generate daily compliance summary
                compliance_status = self.compliance_monitor.get_compliance_status()
                tamper_status = self.tamper_detection.get_tamper_status()
                
                # Log compliance summary
                await self.log_audit_event(
                    AuditEventType.COMPLIANCE_CHECK,
                    'compliance_monitor',
                    'daily_summary',
                    'Daily compliance monitoring summary',
                    severity=AuditSeverity.INFO,
                    metadata={
                        'compliance_status': compliance_status,
                        'tamper_status': tamper_status
                    }
                )
                
                # Check for critical compliance issues
                if compliance_status.get('critical_violations', 0) > 0:
                    await self.log_audit_event(
                        AuditEventType.SECURITY_ALERT,
                        'compliance_monitor',
                        'critical_violations',
                        f"Critical compliance violations detected: {compliance_status['critical_violations']}",
                        severity=AuditSeverity.CRITICAL,
                        metadata={'compliance_status': compliance_status}
                    )
                
                # Check for tamper detection alerts
                if tamper_status.get('critical_alerts', 0) > 0:
                    await self.log_audit_event(
                        AuditEventType.SECURITY_ALERT,
                        'tamper_detection',
                        'tamper_alerts',
                        f"Tamper detection alerts: {tamper_status['critical_alerts']}",
                        severity=AuditSeverity.CRITICAL,
                        metadata={'tamper_status': tamper_status}
                    )
                
                await asyncio.sleep(86400)  # Daily reporting
                
            except Exception as e:
                logger.error(f"Error in periodic compliance reporting: {e}")
                await asyncio.sleep(86400)
    
    async def get_audit_status(self) -> Dict:
        """Get current audit and compliance status"""
        try:
            integrity_result = await self.audit_logger.verify_log_integrity()
            compliance_status = self.compliance_monitor.get_compliance_status()
            tamper_status = self.tamper_detection.get_tamper_status()
            
            return {
                'audit_logging': {
                    'total_log_entries': len(self.audit_logger.log_entries),
                    'integrity_status': integrity_result['overall_status'],
                    'integrity_violations': len(integrity_result.get('integrity_violations', [])),
                    'sequence_number': self.audit_logger.sequence_counter,
                    'hash_chain_current': self.audit_logger.hash_chain_current
                },
                'anomaly_detection': {
                    'detected_anomalies': len(self.anomaly_detector.detected_anomalies),
                    'monitoring_active': True
                },
                'compliance_monitoring': compliance_status,
                'tamper_detection': tamper_status,
                'overall_health': self._calculate_overall_health(integrity_result, compliance_status, tamper_status)
            }
            
        except Exception as e:
            logger.error(f"Error getting audit status: {e}")
            return {'error': str(e)}
    
    def _calculate_overall_health(self, integrity_result: Dict, compliance_status: Dict, tamper_status: Dict) -> str:
        """Calculate overall audit system health"""
        try:
            # Check for critical issues
            if integrity_result.get('overall_status') == 'COMPROMISED':
                return 'CRITICAL'
            
            if tamper_status.get('critical_alerts', 0) > 0:
                return 'CRITICAL'
            
            if compliance_status.get('critical_violations', 0) > 0:
                return 'DEGRADED'
            
            if compliance_status.get('open_violations', 0) > 5:
                return 'WARNING'
            
            if not compliance_status.get('monitoring_active', False):
                return 'WARNING'
            
            return 'HEALTHY'
            
        except Exception as e:
            logger.error(f"Error calculating overall health: {e}")
            return 'UNKNOWN'
    
    async def generate_comprehensive_audit_report(self, days_back: int = 30) -> Dict:
        """Generate comprehensive audit and compliance report"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Get audit events
            events = await self.audit_logger.search_events({
                'start_time': start_date,
                'end_time': end_date
            })
            
            # Generate compliance reports for all frameworks
            compliance_reports = {}
            for framework in ComplianceFramework:
                try:
                    report = await self.compliance_reporter.generate_compliance_report(
                        framework, start_date, end_date, events
                    )
                    compliance_reports[framework.value] = asdict(report)
                except Exception as e:
                    logger.error(f"Error generating {framework.value} report: {e}")
                    compliance_reports[framework.value] = {'error': str(e)}
            
            # Analyze anomalies
            anomalies = await self.anomaly_detector.analyze_logs(events)
            
            # Get current status
            current_status = await self.get_audit_status()
            
            comprehensive_report = {
                'report_id': f"audit_report_{datetime.utcnow().timestamp()}",
                'generated_at': datetime.utcnow().isoformat(),
                'report_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days_covered': days_back
                },
                'summary': {
                    'total_events': len(events),
                    'total_anomalies': len(anomalies),
                    'integrity_status': current_status['audit_logging']['integrity_status'],
                    'overall_health': current_status['overall_health']
                },
                'compliance_reports': compliance_reports,
                'anomaly_analysis': [asdict(anomaly) for anomaly in anomalies],
                'current_status': current_status,
                'recommendations': self._generate_audit_recommendations(current_status, anomalies)
            }
            
            return comprehensive_report
            
        except Exception as e:
            logger.error(f"Error generating comprehensive audit report: {e}")
            return {'error': str(e)}
    
    def _generate_audit_recommendations(self, status: Dict, anomalies: List) -> List[str]:
        """Generate recommendations based on audit analysis"""
        recommendations = []
        
        try:
            # Check integrity issues
            if status['audit_logging']['integrity_status'] != 'VALID':
                recommendations.append("Investigate audit log integrity violations immediately")
                recommendations.append("Review access controls for audit log storage")
            
            # Check compliance issues
            compliance_status = status.get('compliance_monitoring', {})
            if compliance_status.get('critical_violations', 0) > 0:
                recommendations.append("Address critical compliance violations within 24 hours")
            
            if compliance_status.get('overdue_violations', 0) > 0:
                recommendations.append("Review and resolve overdue compliance violations")
            
            # Check tamper detection
            tamper_status = status.get('tamper_detection', {})
            if tamper_status.get('critical_alerts', 0) > 0:
                recommendations.append("Investigate tamper detection alerts for potential security breaches")
            
            # Check anomalies
            if len(anomalies) > 10:
                recommendations.append("Review detected anomalies for potential security incidents")
            
            # General recommendations
            if not recommendations:
                recommendations.append("Audit system is operating normally - continue regular monitoring")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return ["Error generating recommendations - manual review required"]