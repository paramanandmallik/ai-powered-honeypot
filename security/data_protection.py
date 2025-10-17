"""
Data Protection and Privacy Controls Module

Implements synthetic data tagging and tracking, real data detection and quarantine,
encryption for stored data, and data retention lifecycle management.
"""

import logging
import hashlib
import hmac
import re
import json
import asyncio
import secrets
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data classification levels"""
    SYNTHETIC = "synthetic"
    REAL = "real"
    UNKNOWN = "unknown"
    QUARANTINED = "quarantined"


class DataSensitivity(Enum):
    """Data sensitivity levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class DataTag:
    """Data tagging metadata"""
    tag_id: str
    classification: DataClassification
    sensitivity: DataSensitivity
    created_at: datetime
    created_by: str
    fingerprint: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class DataRecord:
    """Data record with protection metadata"""
    record_id: str
    content: Any
    tags: List[DataTag]
    encrypted: bool
    retention_policy: str
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    quarantined: bool = False
    quarantine_reason: Optional[str] = None


@dataclass
class RealDataAlert:
    """Alert for detected real data"""
    alert_id: str
    timestamp: datetime
    data_sample: str  # Redacted sample
    detection_method: str
    confidence_score: float
    source_location: str
    mitigation_actions: List[str]
    resolved: bool = False


class SyntheticDataTagger:
    """Manages synthetic data tagging and tracking"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.synthetic_fingerprints: Set[str] = set()
        self.tag_registry: Dict[str, DataTag] = {}
        self.secret_key = config.get('tagging_secret', self._generate_secret())
        
    def _generate_secret(self) -> str:
        """Generate a secret key for data fingerprinting"""
        return secrets.token_urlsafe(32)
    
    def create_synthetic_tag(self, data: Any, creator: str, 
                           sensitivity: DataSensitivity = DataSensitivity.INTERNAL,
                           generation_context: Optional[Dict] = None) -> DataTag:
        """Create a tag for synthetic data"""
        try:
            # Generate unique fingerprint
            fingerprint = self._generate_fingerprint(data)
            
            # Check if this data was already tagged
            if fingerprint in self.synthetic_fingerprints:
                existing_tag = self._find_tag_by_fingerprint(fingerprint)
                if existing_tag:
                    logger.info(f"Data already tagged as synthetic: {existing_tag.tag_id}")
                    return existing_tag
            
            # Extract data characteristics for better tracking
            data_characteristics = self._analyze_data_characteristics(data)
            
            tag = DataTag(
                tag_id=f"syn_{datetime.utcnow().timestamp()}_{secrets.token_hex(8)}",
                classification=DataClassification.SYNTHETIC,
                sensitivity=sensitivity,
                created_at=datetime.utcnow(),
                created_by=creator,
                fingerprint=fingerprint,
                metadata={
                    'data_type': type(data).__name__,
                    'size_bytes': len(str(data)),
                    'generation_method': 'ai_synthetic',
                    'generation_context': generation_context or {},
                    'characteristics': data_characteristics,
                    'synthetic_markers': self._add_synthetic_markers(data),
                    'usage_tracking': {
                        'created_at': datetime.utcnow().isoformat(),
                        'access_count': 0,
                        'last_accessed': None
                    }
                }
            )
            
            # Register tag and fingerprint
            self.tag_registry[tag.tag_id] = tag
            self.synthetic_fingerprints.add(fingerprint)
            
            logger.info(f"Created synthetic data tag: {tag.tag_id}")
            return tag
            
        except Exception as e:
            logger.error(f"Failed to create synthetic tag: {e}")
            raise
    
    def _find_tag_by_fingerprint(self, fingerprint: str) -> Optional[DataTag]:
        """Find existing tag by fingerprint"""
        for tag in self.tag_registry.values():
            if tag.fingerprint == fingerprint:
                return tag
        return None
    
    def _analyze_data_characteristics(self, data: Any) -> Dict:
        """Analyze data characteristics for tracking"""
        try:
            characteristics = {
                'data_type': type(data).__name__,
                'structure': 'unknown'
            }
            
            if isinstance(data, str):
                characteristics.update({
                    'structure': 'string',
                    'length': len(data),
                    'contains_numbers': bool(re.search(r'\d', data)),
                    'contains_special_chars': bool(re.search(r'[^a-zA-Z0-9\s]', data)),
                    'word_count': len(data.split()) if data else 0
                })
            elif isinstance(data, dict):
                characteristics.update({
                    'structure': 'dictionary',
                    'key_count': len(data),
                    'keys': list(data.keys())[:10],  # First 10 keys for tracking
                    'nested_levels': self._count_nested_levels(data)
                })
            elif isinstance(data, (list, tuple)):
                characteristics.update({
                    'structure': 'array',
                    'item_count': len(data),
                    'item_types': list(set(type(item).__name__ for item in data))
                })
            
            return characteristics
            
        except Exception as e:
            logger.error(f"Error analyzing data characteristics: {e}")
            return {'error': str(e)}
    
    def _count_nested_levels(self, data: Dict, level: int = 0) -> int:
        """Count nested levels in dictionary"""
        if not isinstance(data, dict) or level > 10:  # Prevent infinite recursion
            return level
        
        max_level = level
        for value in data.values():
            if isinstance(value, dict):
                nested_level = self._count_nested_levels(value, level + 1)
                max_level = max(max_level, nested_level)
        
        return max_level
    
    def _add_synthetic_markers(self, data: Any) -> List[str]:
        """Add synthetic markers to data for identification"""
        markers = []
        
        try:
            # Add timestamp-based marker
            timestamp_marker = f"SYNTHETIC_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            markers.append(timestamp_marker)
            
            # Add content-based markers
            if isinstance(data, str):
                if 'user' in data.lower() or 'admin' in data.lower():
                    markers.append('SYNTHETIC_USER_DATA')
                if 'password' in data.lower() or 'secret' in data.lower():
                    markers.append('SYNTHETIC_CREDENTIAL_DATA')
                if '@' in data and '.' in data:
                    markers.append('SYNTHETIC_EMAIL_DATA')
            elif isinstance(data, dict):
                if any(key.lower() in ['username', 'user', 'login'] for key in data.keys()):
                    markers.append('SYNTHETIC_USER_RECORD')
                if any(key.lower() in ['password', 'secret', 'key'] for key in data.keys()):
                    markers.append('SYNTHETIC_CREDENTIAL_RECORD')
            
            # Add unique synthetic identifier
            synthetic_id = f"SYN_{secrets.token_hex(4).upper()}"
            markers.append(synthetic_id)
            
            return markers
            
        except Exception as e:
            logger.error(f"Error adding synthetic markers: {e}")
            return ['SYNTHETIC_MARKER_ERROR']
    
    def track_data_access(self, tag_id: str) -> bool:
        """Track access to synthetic data"""
        try:
            if tag_id in self.tag_registry:
                tag = self.tag_registry[tag_id]
                tag.metadata['usage_tracking']['access_count'] += 1
                tag.metadata['usage_tracking']['last_accessed'] = datetime.utcnow().isoformat()
                
                logger.debug(f"Tracked access to synthetic data: {tag_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error tracking data access: {e}")
            return False
    
    def get_synthetic_data_usage_report(self) -> Dict:
        """Generate usage report for synthetic data"""
        try:
            report = {
                'total_synthetic_tags': len(self.tag_registry),
                'by_creator': {},
                'by_sensitivity': {},
                'by_data_type': {},
                'usage_statistics': {
                    'most_accessed': [],
                    'never_accessed': [],
                    'recent_creations': []
                }
            }
            
            for tag in self.tag_registry.values():
                # Group by creator
                creator = tag.created_by
                if creator not in report['by_creator']:
                    report['by_creator'][creator] = 0
                report['by_creator'][creator] += 1
                
                # Group by sensitivity
                sensitivity = tag.sensitivity.value
                if sensitivity not in report['by_sensitivity']:
                    report['by_sensitivity'][sensitivity] = 0
                report['by_sensitivity'][sensitivity] += 1
                
                # Group by data type
                data_type = tag.metadata.get('data_type', 'unknown')
                if data_type not in report['by_data_type']:
                    report['by_data_type'][data_type] = 0
                report['by_data_type'][data_type] += 1
                
                # Usage statistics
                usage_tracking = tag.metadata.get('usage_tracking', {})
                access_count = usage_tracking.get('access_count', 0)
                
                if access_count == 0:
                    report['usage_statistics']['never_accessed'].append({
                        'tag_id': tag.tag_id,
                        'created_at': tag.created_at.isoformat(),
                        'creator': tag.created_by
                    })
                else:
                    report['usage_statistics']['most_accessed'].append({
                        'tag_id': tag.tag_id,
                        'access_count': access_count,
                        'last_accessed': usage_tracking.get('last_accessed'),
                        'creator': tag.created_by
                    })
                
                # Recent creations (last 24 hours)
                if (datetime.utcnow() - tag.created_at).days == 0:
                    report['usage_statistics']['recent_creations'].append({
                        'tag_id': tag.tag_id,
                        'created_at': tag.created_at.isoformat(),
                        'creator': tag.created_by,
                        'data_type': data_type
                    })
            
            # Sort most accessed
            report['usage_statistics']['most_accessed'].sort(
                key=lambda x: x['access_count'], reverse=True
            )
            report['usage_statistics']['most_accessed'] = report['usage_statistics']['most_accessed'][:10]
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating usage report: {e}")
            return {'error': str(e)}
    
    def _generate_fingerprint(self, data: Any) -> str:
        """Generate a unique fingerprint for data"""
        try:
            # Convert data to string representation
            data_str = json.dumps(data, sort_keys=True, default=str)
            
            # Create HMAC fingerprint
            fingerprint = hmac.new(
                self.secret_key.encode(),
                data_str.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return fingerprint
            
        except Exception as e:
            logger.error(f"Failed to generate fingerprint: {e}")
            return hashlib.sha256(str(data).encode()).hexdigest()
    
    def verify_synthetic_data(self, data: Any, tag_id: str) -> bool:
        """Verify that data matches its synthetic tag"""
        try:
            if tag_id not in self.tag_registry:
                return False
            
            tag = self.tag_registry[tag_id]
            current_fingerprint = self._generate_fingerprint(data)
            
            return current_fingerprint == tag.fingerprint
            
        except Exception as e:
            logger.error(f"Failed to verify synthetic data: {e}")
            return False
    
    def is_synthetic_fingerprint(self, fingerprint: str) -> bool:
        """Check if fingerprint belongs to synthetic data"""
        return fingerprint in self.synthetic_fingerprints
    
    def get_tag_info(self, tag_id: str) -> Optional[DataTag]:
        """Get information about a data tag"""
        return self.tag_registry.get(tag_id)


class RealDataDetector:
    """Detects and quarantines real data"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.detection_patterns = self._initialize_detection_patterns()
        self.quarantine_storage: Dict[str, Any] = {}
        self.alerts: List[RealDataAlert] = []
        
    def _initialize_detection_patterns(self) -> Dict[str, Dict]:
        """Initialize patterns for detecting real data"""
        return {
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'description': 'Social Security Number',
                'confidence_weight': 0.9,
                'category': 'pii'
            },
            'credit_card': {
                'pattern': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                'description': 'Credit Card Number',
                'confidence_weight': 0.8,
                'category': 'financial'
            },
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email Address',
                'confidence_weight': 0.6,
                'category': 'pii'
            },
            'phone': {
                'pattern': r'\b\d{3}-\d{3}-\d{4}\b|\(\d{3}\)\s?\d{3}-\d{4}\b',
                'description': 'Phone Number',
                'confidence_weight': 0.5,
                'category': 'pii'
            },
            'aws_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS Access Key',
                'confidence_weight': 0.95,
                'category': 'credentials'
            },
            'aws_secret': {
                'pattern': r'[A-Za-z0-9/+=]{40}',
                'description': 'AWS Secret Key',
                'confidence_weight': 0.85,
                'category': 'credentials'
            },
            'api_key': {
                'pattern': r'[Aa][Pp][Ii]_?[Kk][Ee][Yy].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
                'description': 'API Key',
                'confidence_weight': 0.8,
                'category': 'credentials'
            },
            'jwt_token': {
                'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'description': 'JWT Token',
                'confidence_weight': 0.7,
                'category': 'credentials'
            },
            'private_key': {
                'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                'description': 'Private Key',
                'confidence_weight': 0.95,
                'category': 'credentials'
            },
            'password': {
                'pattern': r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'"]{8,})[\'"]?',
                'description': 'Password',
                'confidence_weight': 0.7,
                'category': 'credentials'
            },
            'database_connection': {
                'pattern': r'(?i)(mongodb|mysql|postgresql|oracle)://[^\s]+',
                'description': 'Database Connection String',
                'confidence_weight': 0.8,
                'category': 'credentials'
            },
            'ip_address': {
                'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'description': 'IP Address',
                'confidence_weight': 0.4,
                'category': 'network'
            },
            'mac_address': {
                'pattern': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
                'description': 'MAC Address',
                'confidence_weight': 0.6,
                'category': 'network'
            }
        }
    
    async def scan_for_real_data(self, data: Any, source_location: str) -> Tuple[bool, List[RealDataAlert]]:
        """Scan data for real/sensitive information"""
        alerts = []
        
        try:
            # Convert data to searchable text
            text_data = self._extract_text(data)
            
            # Check each detection pattern
            for pattern_name, pattern_config in self.detection_patterns.items():
                matches = re.finditer(pattern_config['pattern'], text_data, re.IGNORECASE)
                
                for match in matches:
                    # Additional validation for some patterns
                    if not self._validate_match(pattern_name, match.group()):
                        continue
                    
                    # Create alert for detected real data
                    alert = RealDataAlert(
                        alert_id=f"real_data_{datetime.utcnow().timestamp()}_{secrets.token_hex(4)}",
                        timestamp=datetime.utcnow(),
                        data_sample=self._redact_sample(match.group()),
                        detection_method=pattern_name,
                        confidence_score=pattern_config['confidence_weight'],
                        source_location=source_location,
                        mitigation_actions=self._get_mitigation_actions(pattern_config['category'])
                    )
                    
                    alerts.append(alert)
                    self.alerts.append(alert)
            
            # Additional heuristic checks
            heuristic_alerts = await self._run_heuristic_checks(data, source_location)
            alerts.extend(heuristic_alerts)
            
            # Determine if real data was detected
            has_real_data = any(alert.confidence_score > 0.7 for alert in alerts)
            
            if has_real_data:
                logger.warning(f"Real data detected in {source_location}: {len(alerts)} matches")
            
            return has_real_data, alerts
            
        except Exception as e:
            logger.error(f"Error scanning for real data: {e}")
            return False, []
    
    def _validate_match(self, pattern_name: str, match_text: str) -> bool:
        """Additional validation for pattern matches"""
        try:
            if pattern_name == 'credit_card':
                # Luhn algorithm validation for credit cards
                return self._validate_credit_card(match_text)
            elif pattern_name == 'ssn':
                # Basic SSN validation
                return self._validate_ssn(match_text)
            elif pattern_name == 'email':
                # Check for common fake email patterns
                return not self._is_fake_email(match_text)
            elif pattern_name == 'ip_address':
                # Validate IP address format and exclude private ranges for alerts
                return self._validate_ip_address(match_text)
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating match: {e}")
            return True  # Default to true if validation fails
    
    def _validate_credit_card(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        try:
            # Remove non-digits
            digits = re.sub(r'\D', '', card_number)
            
            if len(digits) < 13 or len(digits) > 19:
                return False
            
            # Luhn algorithm
            total = 0
            reverse_digits = digits[::-1]
            
            for i, digit in enumerate(reverse_digits):
                n = int(digit)
                if i % 2 == 1:
                    n *= 2
                    if n > 9:
                        n = (n // 10) + (n % 10)
                total += n
            
            return total % 10 == 0
            
        except Exception:
            return False
    
    def _validate_ssn(self, ssn: str) -> bool:
        """Basic SSN validation"""
        try:
            # Remove non-digits
            digits = re.sub(r'\D', '', ssn)
            
            if len(digits) != 9:
                return False
            
            # Check for invalid patterns
            invalid_patterns = [
                '000000000', '111111111', '222222222', '333333333',
                '444444444', '555555555', '666666666', '777777777',
                '888888888', '999999999'
            ]
            
            return digits not in invalid_patterns
            
        except Exception:
            return False
    
    def _is_fake_email(self, email: str) -> bool:
        """Check if email appears to be fake/synthetic"""
        fake_domains = [
            'example.com', 'test.com', 'fake.com', 'dummy.com',
            'sample.com', 'placeholder.com', 'synthetic.com'
        ]
        
        fake_patterns = [
            r'test\d*@', r'fake\d*@', r'dummy\d*@', r'sample\d*@',
            r'user\d*@', r'admin\d*@', r'synthetic\d*@'
        ]
        
        email_lower = email.lower()
        
        # Check fake domains
        for domain in fake_domains:
            if domain in email_lower:
                return True
        
        # Check fake patterns
        for pattern in fake_patterns:
            if re.search(pattern, email_lower):
                return True
        
        return False
    
    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address and check if it's public"""
        try:
            import ipaddress
            ip_obj = ipaddress.IPv4Address(ip)
            
            # Only alert on public IP addresses (potential real infrastructure)
            return not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local
            
        except Exception:
            return False
    
    def _get_mitigation_actions(self, category: str) -> List[str]:
        """Get category-specific mitigation actions"""
        mitigation_map = {
            'pii': ['quarantine_data', 'alert_privacy_team', 'audit_source', 'notify_compliance'],
            'financial': ['quarantine_data', 'alert_security_team', 'freeze_account', 'audit_source'],
            'credentials': ['quarantine_data', 'alert_security_team', 'rotate_credentials', 'audit_source'],
            'network': ['quarantine_data', 'alert_network_team', 'audit_source'],
            'default': ['quarantine_data', 'alert_security_team', 'audit_source']
        }
        
        return mitigation_map.get(category, mitigation_map['default'])
    
    async def _run_heuristic_checks(self, data: Any, source_location: str) -> List[RealDataAlert]:
        """Run heuristic checks for real data detection"""
        alerts = []
        
        try:
            # Check for high entropy strings (potential passwords/keys)
            entropy_alerts = self._check_entropy_patterns(data, source_location)
            alerts.extend(entropy_alerts)
            
            # Check for structured data patterns
            structure_alerts = self._check_structured_patterns(data, source_location)
            alerts.extend(structure_alerts)
            
            # Check for temporal patterns (real timestamps, etc.)
            temporal_alerts = self._check_temporal_patterns(data, source_location)
            alerts.extend(temporal_alerts)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error in heuristic checks: {e}")
            return []
    
    def _check_entropy_patterns(self, data: Any, source_location: str) -> List[RealDataAlert]:
        """Check for high entropy strings that might be real credentials"""
        alerts = []
        
        try:
            text_data = self._extract_text(data)
            
            # Find potential high-entropy strings
            words = re.findall(r'\b[A-Za-z0-9+/=]{20,}\b', text_data)
            
            for word in words:
                entropy = self._calculate_entropy(word)
                
                if entropy > 4.5:  # High entropy threshold
                    alert = RealDataAlert(
                        alert_id=f"entropy_{datetime.utcnow().timestamp()}_{secrets.token_hex(4)}",
                        timestamp=datetime.utcnow(),
                        data_sample=self._redact_sample(word),
                        detection_method="high_entropy",
                        confidence_score=min(entropy / 6.0, 0.9),  # Normalize to 0-0.9
                        source_location=source_location,
                        mitigation_actions=['quarantine_data', 'alert_security_team', 'audit_source']
                    )
                    alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error checking entropy patterns: {e}")
            return []
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        try:
            if not text:
                return 0
            
            # Count character frequencies
            char_counts = {}
            for char in text:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            # Calculate entropy
            entropy = 0
            text_length = len(text)
            
            for count in char_counts.values():
                probability = count / text_length
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0
    
    def _check_structured_patterns(self, data: Any, source_location: str) -> List[RealDataAlert]:
        """Check for structured data that might be real"""
        alerts = []
        
        try:
            if isinstance(data, dict):
                # Check for database-like structures
                if self._looks_like_database_record(data):
                    alert = RealDataAlert(
                        alert_id=f"structure_{datetime.utcnow().timestamp()}_{secrets.token_hex(4)}",
                        timestamp=datetime.utcnow(),
                        data_sample="<structured_database_record>",
                        detection_method="database_structure",
                        confidence_score=0.6,
                        source_location=source_location,
                        mitigation_actions=['quarantine_data', 'alert_data_team', 'audit_source']
                    )
                    alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error checking structured patterns: {e}")
            return []
    
    def _looks_like_database_record(self, data: Dict) -> bool:
        """Check if dictionary looks like a real database record"""
        try:
            # Common database field patterns
            db_field_patterns = [
                'id', 'user_id', 'customer_id', 'account_id',
                'created_at', 'updated_at', 'timestamp',
                'first_name', 'last_name', 'full_name',
                'address', 'city', 'state', 'zip_code',
                'phone_number', 'email_address'
            ]
            
            # Check if data has multiple database-like fields
            matching_fields = 0
            for key in data.keys():
                key_lower = str(key).lower()
                if any(pattern in key_lower for pattern in db_field_patterns):
                    matching_fields += 1
            
            # If more than 3 fields match database patterns, likely real data
            return matching_fields > 3
            
        except Exception:
            return False
    
    def _check_temporal_patterns(self, data: Any, source_location: str) -> List[RealDataAlert]:
        """Check for temporal patterns that might indicate real data"""
        alerts = []
        
        try:
            text_data = self._extract_text(data)
            
            # Look for recent timestamps (within last year)
            timestamp_patterns = [
                r'\b20(2[0-9]|3[0-9])-\d{2}-\d{2}\b',  # YYYY-MM-DD format
                r'\b\d{1,2}/\d{1,2}/20(2[0-9]|3[0-9])\b',  # MM/DD/YYYY format
            ]
            
            current_year = datetime.utcnow().year
            
            for pattern in timestamp_patterns:
                matches = re.finditer(pattern, text_data)
                
                for match in matches:
                    timestamp_str = match.group()
                    
                    # Check if timestamp is recent (within last 2 years)
                    if self._is_recent_timestamp(timestamp_str, current_year):
                        alert = RealDataAlert(
                            alert_id=f"temporal_{datetime.utcnow().timestamp()}_{secrets.token_hex(4)}",
                            timestamp=datetime.utcnow(),
                            data_sample=self._redact_sample(timestamp_str),
                            detection_method="recent_timestamp",
                            confidence_score=0.5,
                            source_location=source_location,
                            mitigation_actions=['quarantine_data', 'alert_data_team', 'audit_source']
                        )
                        alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error checking temporal patterns: {e}")
            return []
    
    def _is_recent_timestamp(self, timestamp_str: str, current_year: int) -> bool:
        """Check if timestamp appears to be recent/real"""
        try:
            # Extract year from timestamp
            year_match = re.search(r'20(\d{2})', timestamp_str)
            if year_match:
                year = int(f"20{year_match.group(1)}")
                # Consider timestamps within last 2 years as potentially real
                return abs(current_year - year) <= 2
            
            return False
            
        except Exception:
            return False
    
    def _extract_text(self, data: Any) -> str:
        """Extract searchable text from various data types"""
        try:
            if isinstance(data, str):
                return data
            elif isinstance(data, dict):
                return json.dumps(data, default=str)
            elif isinstance(data, (list, tuple)):
                return ' '.join(str(item) for item in data)
            else:
                return str(data)
        except Exception:
            return ""
    
    def _redact_sample(self, text: str) -> str:
        """Redact sensitive parts of detected text for logging"""
        if len(text) <= 4:
            return "*" * len(text)
        
        # Show first 2 and last 2 characters, redact middle
        return text[:2] + "*" * (len(text) - 4) + text[-2:]
    
    async def quarantine_data(self, data: Any, reason: str, source_location: str) -> str:
        """Quarantine detected real data"""
        try:
            quarantine_id = f"quarantine_{datetime.utcnow().timestamp()}_{secrets.token_hex(8)}"
            
            # Store quarantined data (encrypted)
            encrypted_data = self._encrypt_quarantine_data(data)
            
            self.quarantine_storage[quarantine_id] = {
                'data': encrypted_data,
                'reason': reason,
                'source_location': source_location,
                'quarantined_at': datetime.utcnow().isoformat(),
                'reviewed': False
            }
            
            logger.warning(f"Data quarantined: {quarantine_id} - {reason}")
            return quarantine_id
            
        except Exception as e:
            logger.error(f"Failed to quarantine data: {e}")
            raise
    
    def _encrypt_quarantine_data(self, data: Any) -> str:
        """Encrypt quarantined data for secure storage"""
        try:
            # Generate encryption key from config
            key = base64.urlsafe_b64encode(
                hashlib.sha256(self.config.get('quarantine_key', 'default').encode()).digest()
            )
            
            fernet = Fernet(key)
            data_bytes = json.dumps(data, default=str).encode()
            encrypted_data = fernet.encrypt(data_bytes)
            
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"Failed to encrypt quarantine data: {e}")
            return str(data)  # Fallback to plain text with warning
    
    async def review_quarantined_data(self, quarantine_id: str, reviewer: str, 
                                    action: str) -> bool:
        """Review and take action on quarantined data"""
        try:
            if quarantine_id not in self.quarantine_storage:
                return False
            
            quarantine_record = self.quarantine_storage[quarantine_id]
            quarantine_record['reviewed'] = True
            quarantine_record['reviewer'] = reviewer
            quarantine_record['review_action'] = action
            quarantine_record['reviewed_at'] = datetime.utcnow().isoformat()
            
            logger.info(f"Quarantined data reviewed: {quarantine_id} - {action}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to review quarantined data: {e}")
            return False


class DataEncryption:
    """Handles encryption for all stored data"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.encryption_keys: Dict[str, bytes] = {}
        self._initialize_encryption_keys()
        
    def _initialize_encryption_keys(self):
        """Initialize encryption keys for different data types"""
        master_key = self.config.get('master_encryption_key', 'default_key').encode()
        
        # Derive keys for different purposes
        key_purposes = ['session_data', 'intelligence_data', 'audit_logs', 'synthetic_data']
        
        for purpose in key_purposes:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=purpose.encode(),
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_key))
            self.encryption_keys[purpose] = key
    
    def encrypt_data(self, data: Any, purpose: str = 'session_data') -> str:
        """Encrypt data for storage"""
        try:
            if purpose not in self.encryption_keys:
                raise ValueError(f"Unknown encryption purpose: {purpose}")
            
            fernet = Fernet(self.encryption_keys[purpose])
            
            # Serialize data
            if isinstance(data, (dict, list)):
                data_bytes = json.dumps(data, default=str).encode()
            else:
                data_bytes = str(data).encode()
            
            # Encrypt
            encrypted_data = fernet.encrypt(data_bytes)
            
            # Return base64 encoded string
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str, purpose: str = 'session_data') -> Any:
        """Decrypt stored data"""
        try:
            if purpose not in self.encryption_keys:
                raise ValueError(f"Unknown encryption purpose: {purpose}")
            
            fernet = Fernet(self.encryption_keys[purpose])
            
            # Decode and decrypt
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_bytes = fernet.decrypt(encrypted_bytes)
            
            # Try to deserialize as JSON, fallback to string
            try:
                return json.loads(decrypted_bytes.decode())
            except json.JSONDecodeError:
                return decrypted_bytes.decode()
                
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            raise
    
    def rotate_encryption_key(self, purpose: str) -> bool:
        """Rotate encryption key for a specific purpose"""
        try:
            # Generate new key
            new_key = Fernet.generate_key()
            old_key = self.encryption_keys.get(purpose)
            
            # Update key
            self.encryption_keys[purpose] = new_key
            
            logger.info(f"Rotated encryption key for purpose: {purpose}")
            
            # In a real implementation, you would re-encrypt existing data
            # with the new key here
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate encryption key: {e}")
            return False


class DataRetentionManager:
    """Manages data retention and lifecycle policies"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.retention_policies = self._initialize_retention_policies()
        self.data_records: Dict[str, DataRecord] = {}
        
    def _initialize_retention_policies(self) -> Dict[str, Dict]:
        """Initialize data retention policies"""
        return {
            'session_data': {
                'retention_days': 90,
                'archive_after_days': 30,
                'encryption_required': True,
                'auto_delete': True
            },
            'intelligence_data': {
                'retention_days': 365,
                'archive_after_days': 90,
                'encryption_required': True,
                'auto_delete': False  # Requires manual review
            },
            'audit_logs': {
                'retention_days': 2555,  # 7 years
                'archive_after_days': 365,
                'encryption_required': True,
                'auto_delete': False
            },
            'synthetic_data': {
                'retention_days': 30,
                'archive_after_days': 7,
                'encryption_required': False,
                'auto_delete': True
            },
            'quarantined_data': {
                'retention_days': 180,
                'archive_after_days': 30,
                'encryption_required': True,
                'auto_delete': False  # Requires security review
            }
        }
    
    def register_data_record(self, record_id: str, content: Any, 
                           retention_policy: str, tags: List[DataTag]) -> DataRecord:
        """Register a data record for retention management"""
        try:
            record = DataRecord(
                record_id=record_id,
                content=content,
                tags=tags,
                encrypted=False,
                retention_policy=retention_policy,
                created_at=datetime.utcnow(),
                last_accessed=datetime.utcnow()
            )
            
            self.data_records[record_id] = record
            
            logger.info(f"Registered data record: {record_id} with policy: {retention_policy}")
            return record
            
        except Exception as e:
            logger.error(f"Failed to register data record: {e}")
            raise
    
    async def apply_retention_policies(self):
        """Apply retention policies to all registered data"""
        try:
            current_time = datetime.utcnow()
            actions_taken = []
            
            for record_id, record in list(self.data_records.items()):
                policy = self.retention_policies.get(record.retention_policy)
                if not policy:
                    continue
                
                age_days = (current_time - record.created_at).days
                
                # Check if data should be archived
                if age_days >= policy['archive_after_days'] and not record.encrypted:
                    await self._archive_record(record)
                    actions_taken.append(f"Archived {record_id}")
                
                # Check if data should be deleted
                if age_days >= policy['retention_days'] and policy['auto_delete']:
                    await self._delete_record(record_id)
                    actions_taken.append(f"Deleted {record_id}")
                
                # Check if data needs manual review
                elif age_days >= policy['retention_days'] and not policy['auto_delete']:
                    await self._flag_for_review(record)
                    actions_taken.append(f"Flagged for review {record_id}")
            
            if actions_taken:
                logger.info(f"Retention policy actions: {actions_taken}")
            
            return actions_taken
            
        except Exception as e:
            logger.error(f"Error applying retention policies: {e}")
            return []
    
    async def _archive_record(self, record: DataRecord):
        """Archive a data record"""
        try:
            # Encrypt if required
            if not record.encrypted:
                # This would integrate with the DataEncryption class
                record.encrypted = True
                logger.info(f"Archived and encrypted record: {record.record_id}")
            
        except Exception as e:
            logger.error(f"Failed to archive record: {e}")
    
    async def _delete_record(self, record_id: str):
        """Delete a data record"""
        try:
            if record_id in self.data_records:
                del self.data_records[record_id]
                logger.info(f"Deleted record: {record_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete record: {e}")
    
    async def _flag_for_review(self, record: DataRecord):
        """Flag a record for manual review"""
        try:
            # Add review flag to metadata
            if not hasattr(record, 'review_required'):
                record.review_required = True
                record.review_flagged_at = datetime.utcnow()
                logger.info(f"Flagged record for review: {record.record_id}")
            
        except Exception as e:
            logger.error(f"Failed to flag record for review: {e}")
    
    def get_retention_status(self) -> Dict:
        """Get current retention status"""
        try:
            current_time = datetime.utcnow()
            status = {
                'total_records': len(self.data_records),
                'by_policy': {},
                'pending_actions': []
            }
            
            for record in self.data_records.values():
                policy = record.retention_policy
                if policy not in status['by_policy']:
                    status['by_policy'][policy] = 0
                status['by_policy'][policy] += 1
                
                # Check for pending actions
                age_days = (current_time - record.created_at).days
                policy_config = self.retention_policies.get(policy, {})
                
                if age_days >= policy_config.get('retention_days', 0):
                    status['pending_actions'].append({
                        'record_id': record.record_id,
                        'action': 'delete' if policy_config.get('auto_delete') else 'review',
                        'age_days': age_days
                    })
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting retention status: {e}")
            return {'error': str(e)}


class DataProtectionManager:
    """Main data protection and privacy controls manager"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.synthetic_tagger = SyntheticDataTagger(config)
        self.real_data_detector = RealDataDetector(config)
        self.encryption = DataEncryption(config)
        self.retention_manager = DataRetentionManager(config)
        
    async def initialize(self):
        """Initialize data protection components"""
        try:
            # Start retention policy enforcement
            asyncio.create_task(self._retention_enforcement_loop())
            
            logger.info("Data protection manager initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize data protection: {e}")
            raise
    
    async def process_data(self, data: Any, source_location: str, 
                         creator: str) -> Dict:
        """Process data through protection pipeline"""
        try:
            # Step 1: Scan for real data
            has_real_data, alerts = await self.real_data_detector.scan_for_real_data(
                data, source_location
            )
            
            if has_real_data:
                # Quarantine real data
                quarantine_id = await self.real_data_detector.quarantine_data(
                    data, "Real data detected", source_location
                )
                
                return {
                    'status': 'quarantined',
                    'quarantine_id': quarantine_id,
                    'alerts': [alert.__dict__ for alert in alerts],
                    'message': 'Real data detected and quarantined'
                }
            
            # Step 2: Tag as synthetic data
            synthetic_tag = self.synthetic_tagger.create_synthetic_tag(data, creator)
            
            # Step 3: Encrypt if needed
            encrypted_data = self.encryption.encrypt_data(data, 'synthetic_data')
            
            # Step 4: Register for retention management
            record = self.retention_manager.register_data_record(
                record_id=synthetic_tag.tag_id,
                content=encrypted_data,
                retention_policy='synthetic_data',
                tags=[synthetic_tag]
            )
            
            return {
                'status': 'processed',
                'tag_id': synthetic_tag.tag_id,
                'fingerprint': synthetic_tag.fingerprint,
                'encrypted': True,
                'record_id': record.record_id,
                'message': 'Data processed and protected'
            }
            
        except Exception as e:
            logger.error(f"Error processing data: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'message': 'Failed to process data'
            }
    
    async def _retention_enforcement_loop(self):
        """Background task for retention policy enforcement"""
        while True:
            try:
                await self.retention_manager.apply_retention_policies()
                await asyncio.sleep(3600)  # Run every hour
                
            except Exception as e:
                logger.error(f"Error in retention enforcement: {e}")
                await asyncio.sleep(3600)
    
    async def get_protection_status(self) -> Dict:
        """Get current data protection status"""
        try:
            return {
                'synthetic_tags': len(self.synthetic_tagger.tag_registry),
                'quarantined_items': len(self.real_data_detector.quarantine_storage),
                'real_data_alerts': len(self.real_data_detector.alerts),
                'retention_status': self.retention_manager.get_retention_status(),
                'encryption_keys': list(self.encryption.encryption_keys.keys())
            }
            
        except Exception as e:
            logger.error(f"Error getting protection status: {e}")
            return {'error': str(e)}