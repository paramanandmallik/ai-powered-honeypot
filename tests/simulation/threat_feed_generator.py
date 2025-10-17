"""
Synthetic Threat Feed Generator for Local Development
Generates realistic threat data for testing detection logic
"""

import asyncio
import json
import logging
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatIndicator:
    indicator_type: str
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    tags: List[str]

@dataclass
class ThreatEvent:
    event_id: str
    timestamp: datetime
    threat_type: ThreatType
    severity: ThreatSeverity
    source_ip: str
    target_ip: str
    target_port: int
    protocol: str
    description: str
    indicators: List[ThreatIndicator]
    mitre_techniques: List[str]
    confidence_score: float
    raw_data: Dict[str, Any]

class SyntheticThreatGenerator:
    """Generates synthetic threat events for testing"""
    
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.ip_ranges = self._generate_ip_ranges()
        self.user_agents = self._load_user_agents()
        self.malware_families = self._load_malware_families()
        
    def _load_threat_patterns(self) -> Dict[ThreatType, Dict[str, Any]]:
        """Load threat patterns and templates"""
        return {
            ThreatType.BRUTE_FORCE: {
                "ports": [22, 3389, 21, 23, 25, 110, 143, 993, 995],
                "protocols": ["ssh", "rdp", "ftp", "telnet", "smtp", "pop3", "imap"],
                "techniques": ["T1110", "T1078", "T1021"],
                "patterns": [
                    "Multiple failed login attempts",
                    "Dictionary attack detected",
                    "Credential stuffing attempt",
                    "Password spraying activity"
                ]
            },
            ThreatType.SQL_INJECTION: {
                "ports": [80, 443, 8080, 8443],
                "protocols": ["http", "https"],
                "techniques": ["T1190", "T1505.003"],
                "patterns": [
                    "SQL injection attempt in parameter",
                    "Union-based SQL injection",
                    "Blind SQL injection probe",
                    "Time-based SQL injection"
                ]
            },
            ThreatType.RECONNAISSANCE: {
                "ports": [80, 443, 22, 21, 25, 53, 135, 139, 445],
                "protocols": ["http", "https", "ssh", "ftp", "smtp", "dns", "smb"],
                "techniques": ["T1595", "T1590", "T1046", "T1018"],
                "patterns": [
                    "Port scanning activity detected",
                    "Service enumeration attempt",
                    "Directory traversal probe",
                    "Banner grabbing detected"
                ]
            },
            ThreatType.MALWARE: {
                "ports": [80, 443, 8080, 4444, 6666, 9999],
                "protocols": ["http", "https", "tcp"],
                "techniques": ["T1071", "T1105", "T1059", "T1055"],
                "patterns": [
                    "Malware communication detected",
                    "Command and control traffic",
                    "Suspicious file download",
                    "Process injection attempt"
                ]
            },
            ThreatType.LATERAL_MOVEMENT: {
                "ports": [135, 139, 445, 3389, 5985, 5986],
                "protocols": ["smb", "rdp", "winrm"],
                "techniques": ["T1021", "T1570", "T1563", "T1210"],
                "patterns": [
                    "Lateral movement via SMB",
                    "Remote desktop session",
                    "WinRM connection attempt",
                    "Service exploitation"
                ]
            }
        }
    
    def _generate_ip_ranges(self) -> Dict[str, List[str]]:
        """Generate IP address ranges for different threat actors"""
        return {
            "tor_exit_nodes": [
                "185.220.100.0/24",
                "185.220.101.0/24",
                "199.87.154.0/24"
            ],
            "known_malicious": [
                "192.168.100.0/24",
                "10.0.100.0/24",
                "172.16.100.0/24"
            ],
            "suspicious": [
                "203.0.113.0/24",
                "198.51.100.0/24",
                "192.0.2.0/24"
            ]
        }
    
    def _load_user_agents(self) -> List[str]:
        """Load realistic user agent strings"""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "wget/1.20.3",
            "python-requests/2.25.1",
            "Nmap Scripting Engine",
            "sqlmap/1.5.2",
            "Nikto/2.1.6"
        ]
    
    def _load_malware_families(self) -> List[str]:
        """Load malware family names"""
        return [
            "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Metasploit",
            "Mimikatz", "PowerShell Empire", "Covenant", "PoshC2",
            "Sliver", "Havoc", "Mythic", "Koadic", "Pupy"
        ]
    
    def generate_random_ip(self, category: str = "suspicious") -> str:
        """Generate a random IP address from specified category"""
        ip_ranges = self.ip_ranges.get(category, self.ip_ranges["suspicious"])
        selected_range = random.choice(ip_ranges)
        network = ipaddress.ip_network(selected_range)
        return str(random.choice(list(network.hosts())))
    
    def generate_threat_indicators(self, threat_type: ThreatType, 
                                 source_ip: str) -> List[ThreatIndicator]:
        """Generate threat indicators for a specific threat type"""
        indicators = []
        base_time = datetime.utcnow()
        
        # IP indicator
        indicators.append(ThreatIndicator(
            indicator_type="ip",
            value=source_ip,
            confidence=random.uniform(0.7, 0.95),
            first_seen=base_time - timedelta(hours=random.randint(1, 24)),
            last_seen=base_time,
            tags=[threat_type.value, "malicious", "synthetic"]
        ))
        
        # URL indicators for web-based threats
        if threat_type in [ThreatType.SQL_INJECTION, ThreatType.XSS, ThreatType.RECONNAISSANCE]:
            malicious_urls = [
                "/admin/login.php",
                "/wp-admin/",
                "/phpmyadmin/",
                "/.env",
                "/config.php",
                "/backup.sql",
                "/admin.php?id=1' OR '1'='1",
                "/search.php?q=<script>alert(1)</script>"
            ]
            
            for _ in range(random.randint(1, 3)):
                url = random.choice(malicious_urls)
                indicators.append(ThreatIndicator(
                    indicator_type="url",
                    value=f"http://{source_ip}{url}",
                    confidence=random.uniform(0.6, 0.9),
                    first_seen=base_time - timedelta(minutes=random.randint(5, 60)),
                    last_seen=base_time,
                    tags=[threat_type.value, "web", "synthetic"]
                ))
        
        # File hash indicators for malware
        if threat_type == ThreatType.MALWARE:
            for _ in range(random.randint(1, 2)):
                file_hash = uuid.uuid4().hex
                indicators.append(ThreatIndicator(
                    indicator_type="file_hash",
                    value=file_hash,
                    confidence=random.uniform(0.8, 0.95),
                    first_seen=base_time - timedelta(hours=random.randint(1, 12)),
                    last_seen=base_time,
                    tags=[threat_type.value, "malware", "synthetic"]
                ))
        
        return indicators
    
    def generate_single_threat(self, threat_type: Optional[ThreatType] = None,
                             severity: Optional[ThreatSeverity] = None) -> ThreatEvent:
        """Generate a single synthetic threat event"""
        
        # Select random threat type if not specified
        if not threat_type:
            threat_type = random.choice(list(ThreatType))
        
        # Select random severity if not specified
        if not severity:
            severity = random.choice(list(ThreatSeverity))
        
        # Get threat pattern
        pattern = self.threat_patterns.get(threat_type, {})
        
        # Generate IPs
        source_ip = self.generate_random_ip("known_malicious")
        target_ip = self.generate_random_ip("suspicious")  # Honeypot IP
        
        # Select port and protocol
        target_port = random.choice(pattern.get("ports", [80, 443, 22]))
        protocol = random.choice(pattern.get("protocols", ["tcp"]))
        
        # Generate description
        description_patterns = pattern.get("patterns", ["Suspicious activity detected"])
        description = random.choice(description_patterns)
        
        # Generate MITRE techniques
        mitre_techniques = pattern.get("techniques", [])
        selected_techniques = random.sample(
            mitre_techniques, 
            min(len(mitre_techniques), random.randint(1, 3))
        )
        
        # Generate confidence score
        base_confidence = {
            ThreatSeverity.LOW: (0.3, 0.6),
            ThreatSeverity.MEDIUM: (0.5, 0.8),
            ThreatSeverity.HIGH: (0.7, 0.9),
            ThreatSeverity.CRITICAL: (0.8, 0.95)
        }
        conf_range = base_confidence.get(severity, (0.5, 0.8))
        confidence_score = random.uniform(*conf_range)
        
        # Generate indicators
        indicators = self.generate_threat_indicators(threat_type, source_ip)
        
        # Generate raw data
        raw_data = {
            "user_agent": random.choice(self.user_agents),
            "request_count": random.randint(1, 100),
            "bytes_transferred": random.randint(100, 10000),
            "session_duration": random.randint(1, 3600),
            "geolocation": {
                "country": random.choice(["US", "CN", "RU", "KP", "IR", "DE", "FR"]),
                "city": random.choice(["Unknown", "Beijing", "Moscow", "Pyongyang"])
            }
        }
        
        # Add threat-specific raw data
        if threat_type == ThreatType.BRUTE_FORCE:
            raw_data.update({
                "failed_attempts": random.randint(10, 1000),
                "usernames_tried": random.randint(5, 50),
                "passwords_tried": random.randint(10, 500)
            })
        elif threat_type == ThreatType.MALWARE:
            raw_data.update({
                "malware_family": random.choice(self.malware_families),
                "c2_domain": f"malicious{random.randint(1, 999)}.com",
                "payload_size": random.randint(1024, 1048576)
            })
        
        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow() - timedelta(
                seconds=random.randint(0, 3600)
            ),
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            protocol=protocol,
            description=description,
            indicators=indicators,
            mitre_techniques=selected_techniques,
            confidence_score=confidence_score,
            raw_data=raw_data
        )
    
    def generate_threat_campaign(self, campaign_size: int = 10,
                               threat_type: Optional[ThreatType] = None) -> List[ThreatEvent]:
        """Generate a coordinated threat campaign"""
        campaign = []
        
        # Use same source IP for campaign
        source_ip = self.generate_random_ip("known_malicious")
        
        # Generate related threats over time
        base_time = datetime.utcnow() - timedelta(hours=2)
        
        for i in range(campaign_size):
            # Use specified threat type or escalate through different types
            if threat_type:
                current_threat_type = threat_type
            else:
                # Simulate attack progression
                progression = [
                    ThreatType.RECONNAISSANCE,
                    ThreatType.BRUTE_FORCE,
                    ThreatType.LATERAL_MOVEMENT,
                    ThreatType.PRIVILEGE_ESCALATION,
                    ThreatType.PERSISTENCE,
                    ThreatType.DATA_EXFILTRATION
                ]
                current_threat_type = progression[min(i, len(progression) - 1)]
            
            threat = self.generate_single_threat(current_threat_type)
            
            # Override source IP to maintain campaign consistency
            threat.source_ip = source_ip
            
            # Adjust timestamp for campaign timeline
            threat.timestamp = base_time + timedelta(
                minutes=i * random.randint(5, 30)
            )
            
            campaign.append(threat)
        
        return campaign
    
    def generate_threat_feed(self, count: int = 100,
                           time_range_hours: int = 24) -> List[ThreatEvent]:
        """Generate a complete threat feed with diverse threats"""
        threats = []
        
        # Generate individual threats
        for _ in range(int(count * 0.7)):  # 70% individual threats
            threats.append(self.generate_single_threat())
        
        # Generate threat campaigns
        remaining = count - len(threats)
        while remaining > 0:
            campaign_size = min(random.randint(3, 8), remaining)
            campaign = self.generate_threat_campaign(campaign_size)
            threats.extend(campaign)
            remaining -= len(campaign)
        
        # Sort by timestamp
        threats.sort(key=lambda x: x.timestamp)
        
        return threats[:count]  # Ensure exact count
    
    def export_to_json(self, threats: List[ThreatEvent], 
                      filename: str = "synthetic_threats.json") -> str:
        """Export threats to JSON format"""
        threat_data = []
        
        for threat in threats:
            threat_dict = asdict(threat)
            
            # Convert datetime objects to ISO strings
            threat_dict["timestamp"] = threat.timestamp.isoformat()
            threat_dict["threat_type"] = threat.threat_type.value
            threat_dict["severity"] = threat.severity.value
            
            # Convert indicator datetimes
            for indicator in threat_dict["indicators"]:
                indicator["first_seen"] = indicator["first_seen"].isoformat()
                indicator["last_seen"] = indicator["last_seen"].isoformat()
            
            threat_data.append(threat_dict)
        
        with open(filename, 'w') as f:
            json.dump(threat_data, f, indent=2)
        
        logger.info(f"Exported {len(threats)} threats to {filename}")
        return filename
    
    def export_to_stix(self, threats: List[ThreatEvent],
                      filename: str = "synthetic_threats.stix") -> str:
        """Export threats to STIX format (simplified)"""
        stix_objects = []
        
        for threat in threats:
            # Create STIX indicator object
            stix_object = {
                "type": "indicator",
                "id": f"indicator--{threat.event_id}",
                "created": threat.timestamp.isoformat(),
                "modified": threat.timestamp.isoformat(),
                "pattern": f"[ipv4-addr:value = '{threat.source_ip}']",
                "labels": [threat.threat_type.value],
                "confidence": int(threat.confidence_score * 100),
                "description": threat.description,
                "x_mitre_techniques": threat.mitre_techniques
            }
            stix_objects.append(stix_object)
        
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }
        
        with open(filename, 'w') as f:
            json.dump(stix_bundle, f, indent=2)
        
        logger.info(f"Exported {len(threats)} threats to STIX format: {filename}")
        return filename

# Convenience functions for testing
def generate_test_threats(count: int = 50) -> List[ThreatEvent]:
    """Generate threats for testing"""
    generator = SyntheticThreatGenerator()
    return generator.generate_threat_feed(count)

def generate_brute_force_campaign(size: int = 10) -> List[ThreatEvent]:
    """Generate a brute force campaign for testing"""
    generator = SyntheticThreatGenerator()
    return generator.generate_threat_campaign(size, ThreatType.BRUTE_FORCE)

def generate_malware_campaign(size: int = 5) -> List[ThreatEvent]:
    """Generate a malware campaign for testing"""
    generator = SyntheticThreatGenerator()
    return generator.generate_threat_campaign(size, ThreatType.MALWARE)

if __name__ == "__main__":
    # Example usage
    generator = SyntheticThreatGenerator()
    
    # Generate diverse threat feed
    threats = generator.generate_threat_feed(100)
    generator.export_to_json(threats, "test_threats.json")
    generator.export_to_stix(threats, "test_threats.stix")
    
    # Generate specific campaigns
    brute_force_campaign = generator.generate_threat_campaign(
        10, ThreatType.BRUTE_FORCE
    )
    generator.export_to_json(brute_force_campaign, "brute_force_campaign.json")
    
    print(f"Generated {len(threats)} total threats")
    print(f"Generated {len(brute_force_campaign)} brute force threats")