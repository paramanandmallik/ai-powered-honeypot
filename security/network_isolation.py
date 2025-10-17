"""
Network Isolation and Security Module

Implements VPC isolation, network monitoring, egress filtering,
and network-based attack detection for honeypot environments.
"""

import logging
import ipaddress
import asyncio
import secrets
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json

logger = logging.getLogger(__name__)


class NetworkThreatLevel(Enum):
    """Network threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NetworkRule:
    """Network security rule definition"""
    rule_id: str
    name: str
    source_cidr: str
    destination_cidr: str
    protocol: str
    port_range: str
    action: str  # ALLOW, DENY, LOG
    priority: int
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class NetworkEvent:
    """Network security event"""
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    action: str
    rule_id: Optional[str]
    threat_level: NetworkThreatLevel
    metadata: Dict = field(default_factory=dict)


@dataclass
class NetworkAnomaly:
    """Detected network anomaly"""
    anomaly_id: str
    timestamp: datetime
    anomaly_type: str
    source_ip: str
    destination_ip: str
    confidence_score: float
    description: str
    threat_level: NetworkThreatLevel
    mitigation_actions: List[str] = field(default_factory=list)


class VPCIsolationManager:
    """Manages VPC and subnet isolation for honeypots"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.isolated_subnets: Set[str] = set()
        self.honeypot_networks: Dict[str, str] = {}
        self.network_rules: Dict[str, NetworkRule] = {}
        self.vpc_config = config.get('vpc_config', {})
        self.security_groups: Dict[str, Dict] = {}
        self.route_tables: Dict[str, Dict] = {}
        
    async def create_isolated_subnet(self, honeypot_id: str, subnet_cidr: str) -> str:
        """Create an isolated subnet for a honeypot"""
        try:
            # Validate CIDR
            network = ipaddress.IPv4Network(subnet_cidr, strict=False)
            
            # Check for conflicts with existing subnets
            if self._check_subnet_conflict(subnet_cidr):
                raise ValueError(f"Subnet {subnet_cidr} conflicts with existing networks")
            
            # Create VPC if not exists
            vpc_id = await self._ensure_vpc_exists()
            
            # Create subnet configuration
            subnet_config = {
                'honeypot_id': honeypot_id,
                'cidr': subnet_cidr,
                'vpc_id': vpc_id,
                'isolation_level': 'STRICT',
                'egress_filtering': True,
                'monitoring_enabled': True,
                'created_at': datetime.utcnow().isoformat(),
                'availability_zone': self._select_availability_zone(),
                'public_ip_assignment': False  # Never assign public IPs to honeypot subnets
            }
            
            # Create security group for this honeypot
            security_group_id = await self._create_security_group(honeypot_id, vpc_id)
            subnet_config['security_group_id'] = security_group_id
            
            # Create route table for isolation
            route_table_id = await self._create_isolated_route_table(honeypot_id, vpc_id)
            subnet_config['route_table_id'] = route_table_id
            
            # Register subnet
            self.isolated_subnets.add(subnet_cidr)
            self.honeypot_networks[honeypot_id] = subnet_config
            
            # Apply default security rules
            await self._apply_default_security_rules(honeypot_id, subnet_cidr)
            
            # Configure network ACLs for additional isolation
            await self._configure_network_acls(honeypot_id, subnet_cidr)
            
            logger.info(f"Created isolated subnet {subnet_cidr} for honeypot {honeypot_id}")
            return subnet_cidr
            
        except Exception as e:
            logger.error(f"Failed to create isolated subnet: {e}")
            raise
    
    def _check_subnet_conflict(self, new_cidr: str) -> bool:
        """Check if new subnet conflicts with existing ones"""
        new_network = ipaddress.IPv4Network(new_cidr, strict=False)
        
        for existing_cidr in self.isolated_subnets:
            existing_network = ipaddress.IPv4Network(existing_cidr, strict=False)
            if new_network.overlaps(existing_network):
                return True
        return False
    
    async def _apply_default_security_rules(self, honeypot_id: str, subnet_cidr: str):
        """Apply default security rules to isolated subnet"""
        default_rules = [
            NetworkRule(
                rule_id=f"{honeypot_id}_deny_all_egress",
                name="Deny All Egress Traffic",
                source_cidr=subnet_cidr,
                destination_cidr="0.0.0.0/0",
                protocol="*",
                port_range="*",
                action="DENY",
                priority=1000
            ),
            NetworkRule(
                rule_id=f"{honeypot_id}_allow_internal",
                name="Allow Internal Communication",
                source_cidr=subnet_cidr,
                destination_cidr=subnet_cidr,
                protocol="*",
                port_range="*",
                action="ALLOW",
                priority=100
            ),
            NetworkRule(
                rule_id=f"{honeypot_id}_log_all_attempts",
                name="Log All Connection Attempts",
                source_cidr="0.0.0.0/0",
                destination_cidr=subnet_cidr,
                protocol="*",
                port_range="*",
                action="LOG",
                priority=50
            )
        ]
        
        for rule in default_rules:
            self.network_rules[rule.rule_id] = rule
    
    async def destroy_isolated_subnet(self, honeypot_id: str) -> bool:
        """Destroy isolated subnet and cleanup resources"""
        try:
            if honeypot_id not in self.honeypot_networks:
                logger.warning(f"Honeypot {honeypot_id} not found in network registry")
                return False
            
            subnet_config = self.honeypot_networks[honeypot_id]
            subnet_cidr = subnet_config.get('cidr') if isinstance(subnet_config, dict) else subnet_config
            
            # Cleanup AWS resources
            if isinstance(subnet_config, dict):
                # Delete security group
                if 'security_group_id' in subnet_config:
                    await self._delete_security_group(subnet_config['security_group_id'])
                
                # Delete route table
                if 'route_table_id' in subnet_config:
                    await self._delete_route_table(subnet_config['route_table_id'])
            
            # Remove security rules
            rules_to_remove = [
                rule_id for rule_id, rule in self.network_rules.items()
                if rule_id.startswith(honeypot_id)
            ]
            
            for rule_id in rules_to_remove:
                del self.network_rules[rule_id]
            
            # Remove from security groups and route tables
            if honeypot_id in self.security_groups:
                del self.security_groups[honeypot_id]
            if honeypot_id in self.route_tables:
                del self.route_tables[honeypot_id]
            
            # Remove subnet registration
            self.isolated_subnets.discard(subnet_cidr)
            del self.honeypot_networks[honeypot_id]
            
            logger.info(f"Destroyed isolated subnet for honeypot {honeypot_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to destroy isolated subnet: {e}")
            return False
    
    async def _ensure_vpc_exists(self) -> str:
        """Ensure VPC exists for honeypot isolation"""
        try:
            vpc_id = self.vpc_config.get('vpc_id')
            if vpc_id:
                return vpc_id
            
            # Create new VPC for honeypot isolation
            vpc_cidr = self.vpc_config.get('cidr', '10.0.0.0/16')
            vpc_config = {
                'cidr_block': vpc_cidr,
                'enable_dns_hostnames': True,
                'enable_dns_support': True,
                'tags': {
                    'Name': 'honeypot-isolation-vpc',
                    'Purpose': 'AI-Honeypot-Isolation',
                    'CreatedBy': 'SecurityManager'
                }
            }
            
            # In production, this would create actual AWS VPC
            # For now, simulate VPC creation
            vpc_id = f"vpc-{secrets.token_hex(8)}"
            self.vpc_config['vpc_id'] = vpc_id
            
            logger.info(f"Created VPC for honeypot isolation: {vpc_id}")
            return vpc_id
            
        except Exception as e:
            logger.error(f"Failed to ensure VPC exists: {e}")
            raise
    
    def _select_availability_zone(self) -> str:
        """Select availability zone for subnet"""
        # In production, this would query AWS for available AZs
        available_azs = ['us-west-2a', 'us-west-2b', 'us-west-2c']
        return available_azs[len(self.isolated_subnets) % len(available_azs)]
    
    async def _create_security_group(self, honeypot_id: str, vpc_id: str) -> str:
        """Create security group for honeypot isolation"""
        try:
            security_group_config = {
                'group_name': f'honeypot-{honeypot_id}-sg',
                'description': f'Security group for honeypot {honeypot_id}',
                'vpc_id': vpc_id,
                'ingress_rules': [
                    {
                        'protocol': 'tcp',
                        'port_range': '22-22',
                        'source': '0.0.0.0/0',
                        'description': 'SSH access for honeypot'
                    },
                    {
                        'protocol': 'tcp',
                        'port_range': '80-80',
                        'source': '0.0.0.0/0',
                        'description': 'HTTP access for honeypot'
                    },
                    {
                        'protocol': 'tcp',
                        'port_range': '443-443',
                        'source': '0.0.0.0/0',
                        'description': 'HTTPS access for honeypot'
                    }
                ],
                'egress_rules': [
                    {
                        'protocol': 'tcp',
                        'port_range': '53-53',
                        'destination': '0.0.0.0/0',
                        'description': 'DNS queries only'
                    }
                    # No other egress allowed - strict isolation
                ]
            }
            
            # In production, this would create actual AWS Security Group
            security_group_id = f"sg-{secrets.token_hex(8)}"
            self.security_groups[honeypot_id] = security_group_config
            
            logger.info(f"Created security group for honeypot {honeypot_id}: {security_group_id}")
            return security_group_id
            
        except Exception as e:
            logger.error(f"Failed to create security group: {e}")
            raise
    
    async def _create_isolated_route_table(self, honeypot_id: str, vpc_id: str) -> str:
        """Create isolated route table for honeypot"""
        try:
            route_table_config = {
                'vpc_id': vpc_id,
                'routes': [
                    {
                        'destination': '10.0.0.0/16',
                        'target': 'local',
                        'description': 'Local VPC traffic only'
                    }
                    # No internet gateway route - complete isolation
                ],
                'tags': {
                    'Name': f'honeypot-{honeypot_id}-rt',
                    'Purpose': 'Honeypot-Isolation'
                }
            }
            
            # In production, this would create actual AWS Route Table
            route_table_id = f"rtb-{secrets.token_hex(8)}"
            self.route_tables[honeypot_id] = route_table_config
            
            logger.info(f"Created isolated route table for honeypot {honeypot_id}: {route_table_id}")
            return route_table_id
            
        except Exception as e:
            logger.error(f"Failed to create route table: {e}")
            raise
    
    async def _configure_network_acls(self, honeypot_id: str, subnet_cidr: str):
        """Configure Network ACLs for additional security layer"""
        try:
            nacl_config = {
                'honeypot_id': honeypot_id,
                'subnet_cidr': subnet_cidr,
                'inbound_rules': [
                    {
                        'rule_number': 100,
                        'protocol': 'tcp',
                        'port_range': '22-22',
                        'source': '0.0.0.0/0',
                        'action': 'ALLOW'
                    },
                    {
                        'rule_number': 110,
                        'protocol': 'tcp',
                        'port_range': '80-80',
                        'source': '0.0.0.0/0',
                        'action': 'ALLOW'
                    },
                    {
                        'rule_number': 120,
                        'protocol': 'tcp',
                        'port_range': '443-443',
                        'source': '0.0.0.0/0',
                        'action': 'ALLOW'
                    },
                    {
                        'rule_number': 32767,
                        'protocol': 'all',
                        'port_range': 'all',
                        'source': '0.0.0.0/0',
                        'action': 'DENY'
                    }
                ],
                'outbound_rules': [
                    {
                        'rule_number': 100,
                        'protocol': 'tcp',
                        'port_range': '53-53',
                        'destination': '0.0.0.0/0',
                        'action': 'ALLOW'
                    },
                    {
                        'rule_number': 32767,
                        'protocol': 'all',
                        'port_range': 'all',
                        'destination': '0.0.0.0/0',
                        'action': 'DENY'
                    }
                ]
            }
            
            logger.info(f"Configured Network ACLs for honeypot {honeypot_id}")
            
        except Exception as e:
            logger.error(f"Failed to configure Network ACLs: {e}")
    
    async def _delete_security_group(self, security_group_id: str):
        """Delete security group"""
        try:
            # In production, this would delete actual AWS Security Group
            logger.info(f"Deleted security group: {security_group_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete security group: {e}")
    
    async def _delete_route_table(self, route_table_id: str):
        """Delete route table"""
        try:
            # In production, this would delete actual AWS Route Table
            logger.info(f"Deleted route table: {route_table_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete route table: {e}")


class NetworkMonitor:
    """Network monitoring and anomaly detection"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.monitoring_active = False
        self.network_events: List[NetworkEvent] = []
        self.anomalies: List[NetworkAnomaly] = []
        self.baseline_traffic: Dict[str, Dict] = {}
        
    async def start_monitoring(self):
        """Start network monitoring"""
        self.monitoring_active = True
        logger.info("Network monitoring started")
        
        # Start monitoring tasks
        asyncio.create_task(self._monitor_traffic())
        asyncio.create_task(self._detect_anomalies())
        asyncio.create_task(self._cleanup_old_events())
    
    async def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring_active = False
        logger.info("Network monitoring stopped")
    
    async def _monitor_traffic(self):
        """Monitor network traffic patterns"""
        while self.monitoring_active:
            try:
                # Simulate traffic monitoring (in real implementation, this would
                # integrate with VPC Flow Logs, CloudWatch, or network sensors)
                await self._collect_network_metrics()
                await asyncio.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in traffic monitoring: {e}")
                await asyncio.sleep(30)
    
    async def _collect_network_metrics(self):
        """Collect network metrics and events"""
        # This would integrate with actual network monitoring tools
        # For now, we'll simulate the collection process
        pass
    
    async def _detect_anomalies(self):
        """Detect network anomalies using pattern analysis"""
        while self.monitoring_active:
            try:
                await self._analyze_traffic_patterns()
                await asyncio.sleep(60)  # Analyze every minute
                
            except Exception as e:
                logger.error(f"Error in anomaly detection: {e}")
                await asyncio.sleep(60)
    
    async def _analyze_traffic_patterns(self):
        """Analyze traffic patterns for anomalies"""
        try:
            # Analyze recent network events for patterns
            recent_events = [
                event for event in self.network_events
                if (datetime.utcnow() - event.timestamp).seconds < 300  # Last 5 minutes
            ]
            
            if not recent_events:
                return
            
            # Detect port scanning patterns
            await self._detect_port_scanning(recent_events)
            
            # Detect brute force patterns
            await self._detect_brute_force_attempts(recent_events)
            
            # Detect lateral movement attempts
            await self._detect_lateral_movement(recent_events)
            
            # Detect data exfiltration patterns
            await self._detect_data_exfiltration(recent_events)
            
        except Exception as e:
            logger.error(f"Error analyzing traffic patterns: {e}")
    
    async def _detect_port_scanning(self, events: List[NetworkEvent]):
        """Detect port scanning activities"""
        try:
            # Group events by source IP
            source_activities = {}
            for event in events:
                if event.source_ip not in source_activities:
                    source_activities[event.source_ip] = []
                source_activities[event.source_ip].append(event)
            
            # Check for port scanning patterns
            for source_ip, source_events in source_activities.items():
                unique_ports = set(event.port for event in source_events)
                
                # If source accessed many different ports, likely port scan
                if len(unique_ports) > 10:
                    anomaly = NetworkAnomaly(
                        anomaly_id=f"port_scan_{source_ip}_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow(),
                        anomaly_type="port_scanning",
                        source_ip=source_ip,
                        destination_ip="multiple",
                        confidence_score=min(len(unique_ports) / 20, 1.0),
                        description=f"Port scanning detected from {source_ip}: {len(unique_ports)} ports accessed",
                        threat_level=NetworkThreatLevel.HIGH,
                        mitigation_actions=['block_source_ip', 'increase_monitoring', 'alert_security_team']
                    )
                    self.anomalies.append(anomaly)
                    logger.warning(f"Port scanning detected from {source_ip}")
            
        except Exception as e:
            logger.error(f"Error detecting port scanning: {e}")
    
    async def _detect_brute_force_attempts(self, events: List[NetworkEvent]):
        """Detect brute force authentication attempts"""
        try:
            # Look for repeated connection attempts to authentication ports
            auth_ports = {22, 21, 23, 3389, 5900}  # SSH, FTP, Telnet, RDP, VNC
            
            source_auth_attempts = {}
            for event in events:
                if event.port in auth_ports:
                    if event.source_ip not in source_auth_attempts:
                        source_auth_attempts[event.source_ip] = []
                    source_auth_attempts[event.source_ip].append(event)
            
            # Check for excessive attempts
            for source_ip, attempts in source_auth_attempts.items():
                if len(attempts) > 5:  # Threshold for brute force
                    anomaly = NetworkAnomaly(
                        anomaly_id=f"brute_force_{source_ip}_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow(),
                        anomaly_type="brute_force",
                        source_ip=source_ip,
                        destination_ip="multiple",
                        confidence_score=min(len(attempts) / 10, 1.0),
                        description=f"Brute force attempt detected from {source_ip}: {len(attempts)} authentication attempts",
                        threat_level=NetworkThreatLevel.HIGH,
                        mitigation_actions=['block_source_ip', 'alert_security_team', 'lockout_account']
                    )
                    self.anomalies.append(anomaly)
                    logger.warning(f"Brute force attempt detected from {source_ip}")
            
        except Exception as e:
            logger.error(f"Error detecting brute force attempts: {e}")
    
    async def _detect_lateral_movement(self, events: List[NetworkEvent]):
        """Detect lateral movement attempts"""
        try:
            # Look for internal network scanning patterns
            internal_networks = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
            
            lateral_activities = {}
            for event in events:
                # Check if both source and destination are internal
                source_internal = any(
                    ipaddress.IPv4Address(event.source_ip) in ipaddress.IPv4Network(net, strict=False)
                    for net in internal_networks
                )
                dest_internal = any(
                    ipaddress.IPv4Address(event.destination_ip) in ipaddress.IPv4Network(net, strict=False)
                    for net in internal_networks
                )
                
                if source_internal and dest_internal:
                    if event.source_ip not in lateral_activities:
                        lateral_activities[event.source_ip] = set()
                    lateral_activities[event.source_ip].add(event.destination_ip)
            
            # Check for scanning multiple internal hosts
            for source_ip, destinations in lateral_activities.items():
                if len(destinations) > 5:  # Threshold for lateral movement
                    anomaly = NetworkAnomaly(
                        anomaly_id=f"lateral_movement_{source_ip}_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow(),
                        anomaly_type="lateral_movement",
                        source_ip=source_ip,
                        destination_ip="multiple_internal",
                        confidence_score=min(len(destinations) / 10, 1.0),
                        description=f"Lateral movement detected from {source_ip}: scanning {len(destinations)} internal hosts",
                        threat_level=NetworkThreatLevel.CRITICAL,
                        mitigation_actions=['isolate_source', 'emergency_alert', 'forensic_capture']
                    )
                    self.anomalies.append(anomaly)
                    logger.critical(f"Lateral movement detected from {source_ip}")
            
        except Exception as e:
            logger.error(f"Error detecting lateral movement: {e}")
    
    async def _detect_data_exfiltration(self, events: List[NetworkEvent]):
        """Detect data exfiltration attempts"""
        try:
            # Look for large data transfers to external destinations
            external_transfers = {}
            
            for event in events:
                # Check if destination is external
                try:
                    dest_ip = ipaddress.IPv4Address(event.destination_ip)
                    if not dest_ip.is_private:
                        if event.source_ip not in external_transfers:
                            external_transfers[event.source_ip] = []
                        external_transfers[event.source_ip].append(event)
                except ValueError:
                    continue
            
            # Check for excessive external connections (potential exfiltration)
            for source_ip, transfers in external_transfers.items():
                if len(transfers) > 3:  # Threshold for data exfiltration
                    anomaly = NetworkAnomaly(
                        anomaly_id=f"data_exfiltration_{source_ip}_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow(),
                        anomaly_type="data_exfiltration",
                        source_ip=source_ip,
                        destination_ip="external",
                        confidence_score=min(len(transfers) / 5, 1.0),
                        description=f"Potential data exfiltration from {source_ip}: {len(transfers)} external connections",
                        threat_level=NetworkThreatLevel.CRITICAL,
                        mitigation_actions=['block_all_traffic', 'emergency_shutdown', 'immediate_investigation']
                    )
                    self.anomalies.append(anomaly)
                    logger.critical(f"Potential data exfiltration detected from {source_ip}")
            
        except Exception as e:
            logger.error(f"Error detecting data exfiltration: {e}")
    
    async def log_network_event(self, event: NetworkEvent):
        """Log a network security event"""
        self.network_events.append(event)
        
        # Check if event indicates potential threat
        if event.threat_level in [NetworkThreatLevel.HIGH, NetworkThreatLevel.CRITICAL]:
            await self._handle_high_threat_event(event)
        
        logger.info(f"Network event logged: {event.event_id}")
    
    async def _handle_high_threat_event(self, event: NetworkEvent):
        """Handle high-threat network events"""
        # Implement immediate response actions
        logger.warning(f"High-threat network event detected: {event.event_id}")
        
        # Could trigger automatic blocking, alerting, etc.
    
    async def _cleanup_old_events(self):
        """Cleanup old network events"""
        while self.monitoring_active:
            try:
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                
                # Remove events older than 24 hours
                self.network_events = [
                    event for event in self.network_events
                    if event.timestamp > cutoff_time
                ]
                
                # Remove old anomalies
                self.anomalies = [
                    anomaly for anomaly in self.anomalies
                    if anomaly.timestamp > cutoff_time
                ]
                
                await asyncio.sleep(3600)  # Cleanup every hour
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
                await asyncio.sleep(3600)


class EgressFilter:
    """Egress filtering and external communication blocking"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.blocked_destinations: Set[str] = set()
        self.allowed_destinations: Set[str] = set()
        self.filter_rules: Dict[str, Dict] = {}
        
        # Initialize default blocked destinations
        self._initialize_default_blocks()
    
    def _initialize_default_blocks(self):
        """Initialize default blocked destinations"""
        # Block common external services that attackers might try to reach
        default_blocks = [
            "0.0.0.0/0",  # Block all by default
        ]
        
        # Allow specific internal services only
        default_allows = [
            "10.0.0.0/8",     # Private networks
            "172.16.0.0/12",  # Private networks
            "192.168.0.0/16", # Private networks
            "127.0.0.0/8",    # Loopback
            "169.254.0.0/16", # Link-local
        ]
        
        # Specific high-risk destinations to explicitly block
        high_risk_blocks = [
            "8.8.8.8/32",      # Google DNS (commonly used for exfiltration)
            "1.1.1.1/32",      # Cloudflare DNS
            "208.67.222.222/32", # OpenDNS
        ]
        
        self.blocked_destinations.update(default_blocks)
        self.blocked_destinations.update(high_risk_blocks)
        self.allowed_destinations.update(default_allows)
        
        # Initialize dynamic blocking lists
        self.dynamic_blocks: Set[str] = set()
        self.temporary_blocks: Dict[str, datetime] = {}
    
    async def check_egress_allowed(self, source_ip: str, destination_ip: str, 
                                 port: int, protocol: str) -> Tuple[bool, str]:
        """Check if egress traffic is allowed"""
        try:
            # Check against allow list first
            if self._is_destination_allowed(destination_ip):
                return True, "Destination in allow list"
            
            # Check against block list
            if self._is_destination_blocked(destination_ip):
                await self._log_blocked_attempt(source_ip, destination_ip, port, protocol)
                return False, "Destination blocked by policy"
            
            # Default deny
            await self._log_blocked_attempt(source_ip, destination_ip, port, protocol)
            return False, "Default deny policy"
            
        except Exception as e:
            logger.error(f"Error checking egress: {e}")
            return False, "Error in policy check"
    
    def _is_destination_allowed(self, destination_ip: str) -> bool:
        """Check if destination is in allow list"""
        dest_addr = ipaddress.IPv4Address(destination_ip)
        
        for allowed_cidr in self.allowed_destinations:
            if dest_addr in ipaddress.IPv4Network(allowed_cidr, strict=False):
                return True
        return False
    
    def _is_destination_blocked(self, destination_ip: str) -> bool:
        """Check if destination is in block list"""
        dest_addr = ipaddress.IPv4Address(destination_ip)
        
        for blocked_cidr in self.blocked_destinations:
            if dest_addr in ipaddress.IPv4Network(blocked_cidr, strict=False):
                return True
        return False
    
    async def _log_blocked_attempt(self, source_ip: str, destination_ip: str, 
                                 port: int, protocol: str):
        """Log blocked egress attempt"""
        event = NetworkEvent(
            event_id=f"egress_block_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            action="BLOCKED",
            rule_id="egress_filter",
            threat_level=NetworkThreatLevel.MEDIUM,
            metadata={
                'reason': 'Egress filtering policy',
                'filter_type': 'automatic'
            }
        )
        
        logger.warning(f"Blocked egress attempt: {source_ip} -> {destination_ip}:{port}")
    
    async def add_dynamic_block(self, destination: str, duration_minutes: int = 60):
        """Add a destination to dynamic block list"""
        try:
            self.dynamic_blocks.add(destination)
            
            # Add to temporary blocks with expiration
            if duration_minutes > 0:
                expiry_time = datetime.utcnow() + timedelta(minutes=duration_minutes)
                self.temporary_blocks[destination] = expiry_time
            
            logger.info(f"Added dynamic block for {destination} (duration: {duration_minutes} minutes)")
            
        except Exception as e:
            logger.error(f"Failed to add dynamic block: {e}")
    
    async def remove_dynamic_block(self, destination: str):
        """Remove a destination from dynamic block list"""
        try:
            self.dynamic_blocks.discard(destination)
            self.temporary_blocks.pop(destination, None)
            
            logger.info(f"Removed dynamic block for {destination}")
            
        except Exception as e:
            logger.error(f"Failed to remove dynamic block: {e}")
    
    async def cleanup_expired_blocks(self):
        """Remove expired temporary blocks"""
        try:
            current_time = datetime.utcnow()
            expired_blocks = [
                dest for dest, expiry in self.temporary_blocks.items()
                if current_time > expiry
            ]
            
            for dest in expired_blocks:
                await self.remove_dynamic_block(dest)
            
            if expired_blocks:
                logger.info(f"Cleaned up {len(expired_blocks)} expired blocks")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired blocks: {e}")
    
    def _is_destination_blocked(self, destination_ip: str) -> bool:
        """Check if destination is in block list"""
        dest_addr = ipaddress.IPv4Address(destination_ip)
        
        # Check static blocks
        for blocked_cidr in self.blocked_destinations:
            if dest_addr in ipaddress.IPv4Network(blocked_cidr, strict=False):
                return True
        
        # Check dynamic blocks
        for blocked_cidr in self.dynamic_blocks:
            try:
                if dest_addr in ipaddress.IPv4Network(blocked_cidr, strict=False):
                    return True
            except ValueError:
                # Handle single IP addresses
                if str(dest_addr) == blocked_cidr:
                    return True
        
        return False


class NetworkAttackDetector:
    """Network-based attack detection"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.attack_patterns: Dict[str, Dict] = {}
        self.detection_rules: Dict[str, Dict] = {}
        
        # Initialize attack detection patterns
        self._initialize_attack_patterns()
    
    def _initialize_attack_patterns(self):
        """Initialize network attack detection patterns"""
        self.attack_patterns = {
            'port_scan': {
                'description': 'Port scanning activity',
                'indicators': ['multiple_ports', 'rapid_connections', 'connection_failures'],
                'threshold': 10,
                'time_window': 60,  # seconds
                'threat_level': NetworkThreatLevel.MEDIUM
            },
            'brute_force': {
                'description': 'Brute force authentication attempts',
                'indicators': ['repeated_auth_failures', 'multiple_usernames'],
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'threat_level': NetworkThreatLevel.HIGH
            },
            'lateral_movement': {
                'description': 'Lateral movement attempts',
                'indicators': ['internal_scanning', 'privilege_escalation'],
                'threshold': 3,
                'time_window': 600,  # 10 minutes
                'threat_level': NetworkThreatLevel.CRITICAL
            },
            'data_exfiltration': {
                'description': 'Data exfiltration attempts',
                'indicators': ['large_data_transfer', 'external_connections'],
                'threshold': 1,
                'time_window': 60,
                'threat_level': NetworkThreatLevel.CRITICAL
            }
        }
    
    async def analyze_network_activity(self, events: List[NetworkEvent]) -> List[NetworkAnomaly]:
        """Analyze network events for attack patterns"""
        detected_anomalies = []
        
        try:
            for pattern_name, pattern_config in self.attack_patterns.items():
                anomalies = await self._detect_pattern(pattern_name, pattern_config, events)
                detected_anomalies.extend(anomalies)
            
            return detected_anomalies
            
        except Exception as e:
            logger.error(f"Error in network attack detection: {e}")
            return []
    
    async def _detect_pattern(self, pattern_name: str, pattern_config: Dict, 
                            events: List[NetworkEvent]) -> List[NetworkAnomaly]:
        """Detect specific attack pattern in network events"""
        anomalies = []
        
        # Group events by source IP and time window
        time_window = pattern_config['time_window']
        threshold = pattern_config['threshold']
        
        # Simple pattern detection (in real implementation, this would be more sophisticated)
        source_activity = {}
        
        for event in events:
            source_ip = event.source_ip
            if source_ip not in source_activity:
                source_activity[source_ip] = []
            source_activity[source_ip].append(event)
        
        # Analyze activity per source
        for source_ip, source_events in source_activity.items():
            if len(source_events) >= threshold:
                # Create anomaly
                anomaly = NetworkAnomaly(
                    anomaly_id=f"{pattern_name}_{source_ip}_{datetime.utcnow().timestamp()}",
                    timestamp=datetime.utcnow(),
                    anomaly_type=pattern_name,
                    source_ip=source_ip,
                    destination_ip="multiple",
                    confidence_score=min(len(source_events) / threshold, 1.0),
                    description=pattern_config['description'],
                    threat_level=pattern_config['threat_level'],
                    mitigation_actions=self._get_mitigation_actions(pattern_name)
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _get_mitigation_actions(self, pattern_name: str) -> List[str]:
        """Get recommended mitigation actions for attack pattern"""
        mitigation_map = {
            'port_scan': ['block_source_ip', 'increase_monitoring'],
            'brute_force': ['block_source_ip', 'alert_security_team', 'lockout_account'],
            'lateral_movement': ['isolate_source', 'emergency_alert', 'forensic_capture'],
            'data_exfiltration': ['block_all_traffic', 'emergency_shutdown', 'immediate_investigation']
        }
        
        return mitigation_map.get(pattern_name, ['log_incident', 'manual_review'])


class NetworkSecurityManager:
    """Main network security management class"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.vpc_manager = VPCIsolationManager(config)
        self.network_monitor = NetworkMonitor(config)
        self.egress_filter = EgressFilter(config)
        self.attack_detector = NetworkAttackDetector(config)
        
    async def initialize(self):
        """Initialize network security components"""
        try:
            await self.network_monitor.start_monitoring()
            logger.info("Network security manager initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize network security: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown network security components"""
        try:
            await self.network_monitor.stop_monitoring()
            logger.info("Network security manager shutdown")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    async def create_secure_honeypot_network(self, honeypot_id: str) -> str:
        """Create a secure, isolated network for a honeypot"""
        try:
            # Generate unique subnet CIDR
            subnet_cidr = f"10.{hash(honeypot_id) % 255}.0.0/24"
            
            # Create isolated subnet
            subnet = await self.vpc_manager.create_isolated_subnet(honeypot_id, subnet_cidr)
            
            logger.info(f"Created secure network for honeypot {honeypot_id}: {subnet}")
            return subnet
            
        except Exception as e:
            logger.error(f"Failed to create secure honeypot network: {e}")
            raise
    
    async def destroy_honeypot_network(self, honeypot_id: str) -> bool:
        """Destroy honeypot network and cleanup"""
        try:
            success = await self.vpc_manager.destroy_isolated_subnet(honeypot_id)
            
            if success:
                logger.info(f"Destroyed network for honeypot {honeypot_id}")
            else:
                logger.warning(f"Failed to destroy network for honeypot {honeypot_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error destroying honeypot network: {e}")
            return False
    
    async def check_network_security(self, source_ip: str, destination_ip: str, 
                                   port: int, protocol: str) -> Dict:
        """Comprehensive network security check"""
        try:
            # Check egress filtering
            egress_allowed, egress_reason = await self.egress_filter.check_egress_allowed(
                source_ip, destination_ip, port, protocol
            )
            
            # Log the attempt
            event = NetworkEvent(
                event_id=f"security_check_{datetime.utcnow().timestamp()}",
                timestamp=datetime.utcnow(),
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                action="ALLOW" if egress_allowed else "DENY",
                rule_id="security_check",
                threat_level=NetworkThreatLevel.LOW if egress_allowed else NetworkThreatLevel.MEDIUM
            )
            
            await self.network_monitor.log_network_event(event)
            
            return {
                'allowed': egress_allowed,
                'reason': egress_reason,
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in network security check: {e}")
            return {
                'allowed': False,
                'reason': 'Security check error',
                'error': str(e)
            }
    
    async def get_security_status(self) -> Dict:
        """Get current network security status"""
        try:
            return {
                'monitoring_active': self.network_monitor.monitoring_active,
                'isolated_subnets': len(self.vpc_manager.isolated_subnets),
                'active_honeypots': len(self.vpc_manager.honeypot_networks),
                'recent_events': len(self.network_monitor.network_events),
                'detected_anomalies': len(self.network_monitor.anomalies),
                'network_rules': len(self.vpc_manager.network_rules)
            }
            
        except Exception as e:
            logger.error(f"Error getting security status: {e}")
            return {'error': str(e)}