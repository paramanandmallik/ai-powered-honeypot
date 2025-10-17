"""
Detection Agent - AI-Powered Threat Detection and Engagement Decision Making

This agent analyzes incoming threat data and makes intelligent decisions about whether
to engage with potential attackers using honeypots. It uses AI to evaluate threat
confidence, map to MITRE ATT&CK framework, and recommend appropriate honeypot types.

Key Features:
- AI-powered threat analysis with confidence scoring
- MITRE ATT&CK framework integration for threat classification
- Configurable engagement decision logic with thresholds
- AgentCore Runtime messaging for publishing engagement decisions
- Real-time threat intelligence processing
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from uuid import uuid4

# Import base agent with fallback for testing
try:
    from ..base_agent import BaseAgent
except ImportError:
    from agents.base_agent import BaseAgent

# Import AgentCore SDK with fallback for testing
try:
    from ...config.agentcore_sdk import AgentCoreSDK, create_agent_sdk
except ImportError:
    try:
        from config.agentcore_sdk import AgentCoreSDK, create_agent_sdk
    except ImportError:
        # Mock for testing when AgentCore SDK is not available
        AgentCoreSDK = None
        create_agent_sdk = None

logger = logging.getLogger(__name__)

# MITRE ATT&CK Technique Mappings
MITRE_ATTACK_TECHNIQUES = {
    "brute_force": ["T1110", "T1110.001", "T1110.002", "T1110.003"],
    "credential_stuffing": ["T1110.004", "T1078"],
    "port_scan": ["T1046", "T1595.001"],
    "reconnaissance": ["T1595", "T1590", "T1591", "T1592", "T1593", "T1594"],
    "malware": ["T1203", "T1055", "T1059", "T1105"],
    "exploit": ["T1203", "T1068", "T1190"],
    "sql_injection": ["T1190", "T1213"],
    "web_attack": ["T1190", "T1505.003"],
    "lateral_movement": ["T1021", "T1570", "T1563"],
    "privilege_escalation": ["T1068", "T1055", "T1134"],
    "persistence": ["T1053", "T1547", "T1543"],
    "data_exfiltration": ["T1041", "T1048", "T1567"],
    "command_injection": ["T1059", "T1190"],
    "file_access": ["T1005", "T1039", "T1083"],
    "network_discovery": ["T1018", "T1040", "T1049"],
    "system_discovery": ["T1082", "T1033", "T1057"]
}

# Threat severity mappings
THREAT_SEVERITY_MAPPING = {
    "brute_force": "HIGH",
    "credential_stuffing": "HIGH", 
    "malware": "CRITICAL",
    "exploit": "CRITICAL",
    "sql_injection": "HIGH",
    "lateral_movement": "CRITICAL",
    "privilege_escalation": "CRITICAL",
    "data_exfiltration": "CRITICAL",
    "port_scan": "MEDIUM",
    "reconnaissance": "MEDIUM",
    "web_attack": "HIGH",
    "command_injection": "HIGH",
    "file_access": "MEDIUM",
    "network_discovery": "LOW",
    "system_discovery": "LOW"
}

class ThreatAssessment:
    """Threat assessment data structure"""
    
    def __init__(self, threat_data: Dict[str, Any]):
        self.threat_id = str(uuid4())
        self.source_ip = threat_data.get("source_ip", "unknown")
        self.destination_ip = threat_data.get("destination_ip", "unknown")
        self.threat_type = threat_data.get("threat_type", "unknown")
        self.indicators = threat_data.get("indicators", [])
        self.timestamp = threat_data.get("timestamp", datetime.utcnow().isoformat())
        self.raw_data = threat_data
        
        # Analysis results (to be populated)
        self.confidence_score = 0.0
        self.severity = "UNKNOWN"
        self.mitre_techniques = []
        self.attack_vector = "unknown"
        self.potential_impact = "unknown"
        self.engagement_decision = "MONITOR"
        self.reasoning = ""
        self.recommended_honeypots = []

class DetectionAgent(BaseAgent):
    """AI-Powered Threat Detection Agent for Honeypot System"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        capabilities = [
            "threat_analysis",
            "engagement_decision", 
            "mitre_mapping",
            "confidence_scoring",
            "ioc_extraction",
            "reputation_analysis",
            "behavioral_analysis",
            "pattern_recognition"
        ]
        
        super().__init__("detection", capabilities, config)
        
        # Configuration
        self.confidence_threshold = float(self.config.get("confidence_threshold", 0.75))
        self.enable_mitre_mapping = self.config.get("enable_mitre_mapping", True)
        self.max_concurrent_assessments = int(self.config.get("max_concurrent_assessments", 10))
        self.engagement_cooldown_minutes = int(self.config.get("engagement_cooldown_minutes", 5))
        self.reputation_cache_ttl = int(self.config.get("reputation_cache_ttl", 3600))
        
        # AgentCore Runtime SDK
        self.agentcore_sdk: Optional[AgentCoreSDK] = None
        
        # State tracking
        self.active_assessments: Dict[str, ThreatAssessment] = {}
        self.assessment_history: List[Dict[str, Any]] = []
        self.reputation_cache: Dict[str, Dict[str, Any]] = {}
        self.engagement_history: Dict[str, datetime] = {}  # IP -> last engagement time
        
        # Threat intelligence feeds (mock for foundation)
        self.threat_feeds: List[str] = [
            "internal_siem",
            "threat_intelligence_platform", 
            "network_monitoring",
            "endpoint_detection"
        ]
        
        self.logger.info(f"Detection Agent initialized with confidence threshold: {self.confidence_threshold}")
    
    async def initialize(self):
        """Initialize the Detection Agent"""
        try:
            self.logger.info("Initializing Detection Agent...")
            
            # Initialize AgentCore Runtime SDK
            await self._initialize_agentcore_sdk()
            
            # Initialize AI models and threat intelligence feeds
            await self._initialize_threat_intelligence()
            
            # Set up message handlers for AgentCore Runtime
            await self._setup_message_handlers()
            
            # Set up monitoring
            self.state["initialized"] = True
            self.state["confidence_threshold"] = self.confidence_threshold
            self.state["active_assessments"] = 0
            self.state["threat_feeds_connected"] = len(self.threat_feeds)
            
            self.logger.info("Detection Agent initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Detection Agent: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup Detection Agent resources"""
        try:
            self.logger.info("Cleaning up Detection Agent...")
            
            # Complete any active assessments
            if self.active_assessments:
                self.logger.info(f"Completing {len(self.active_assessments)} active assessments...")
                await self._complete_active_assessments()
            
            # Stop AgentCore SDK
            if self.agentcore_sdk:
                await self.agentcore_sdk.stop()
            
            self.logger.info("Detection Agent cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during Detection Agent cleanup: {e}")
    
    async def _initialize_agentcore_sdk(self):
        """Initialize AgentCore Runtime SDK"""
        try:
            if create_agent_sdk is None:
                self.logger.info("AgentCore SDK not available, running in standalone mode")
                self.agentcore_sdk = None
                return
                
            self.agentcore_sdk = await create_agent_sdk(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                capabilities=self.capabilities
            )
            
            await self.agentcore_sdk.start()
            self.logger.info("AgentCore Runtime SDK initialized")
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize AgentCore SDK, running in standalone mode: {e}")
            self.agentcore_sdk = None
    
    async def _setup_message_handlers(self):
        """Set up message handlers for AgentCore Runtime"""
        if not self.agentcore_sdk:
            return
        
        # Register message handlers
        self.agentcore_sdk.register_message_handler("threat_detected", self._handle_threat_detected)
        self.agentcore_sdk.register_message_handler("reputation_check", self._handle_reputation_check)
        self.agentcore_sdk.register_message_handler("ioc_extraction", self._handle_ioc_extraction)
        self.agentcore_sdk.register_message_handler("engagement_feedback", self._handle_engagement_feedback)
        self.agentcore_sdk.register_message_handler("health_check", self._handle_health_check)
        
        self.logger.info("Message handlers registered with AgentCore Runtime")
    
    async def _handle_threat_detected(self, message):
        """Handle threat detection messages from AgentCore Runtime"""
        try:
            payload = message.payload
            result = await self.evaluate_threat(payload)
            
            # Send response back through AgentCore messaging
            if result.get("decision") == "ENGAGE":
                await self._publish_engagement_decision(result)
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection message: {e}")
    
    async def _handle_reputation_check(self, message):
        """Handle reputation check messages from AgentCore Runtime"""
        try:
            payload = message.payload
            result = await self.check_reputation(payload)
            
            # Send response back to requesting agent
            await self.agentcore_sdk.send_message(
                message.from_agent,
                "reputation_response",
                result
            )
            
        except Exception as e:
            self.logger.error(f"Error handling reputation check message: {e}")
    
    async def _handle_ioc_extraction(self, message):
        """Handle IOC extraction messages from AgentCore Runtime"""
        try:
            payload = message.payload
            result = await self.extract_iocs(payload)
            
            # Send response back to requesting agent
            await self.agentcore_sdk.send_message(
                message.from_agent,
                "ioc_extraction_response", 
                result
            )
            
        except Exception as e:
            self.logger.error(f"Error handling IOC extraction message: {e}")
    
    async def _handle_engagement_feedback(self, message):
        """Handle engagement feedback from Coordinator Agent"""
        try:
            payload = message.payload
            threat_id = payload.get("threat_id")
            engagement_status = payload.get("status")
            
            self.logger.info(f"Received engagement feedback for {threat_id}: {engagement_status}")
            
            # Update assessment history with feedback
            for assessment in self.assessment_history:
                if assessment["threat_id"] == threat_id:
                    assessment["engagement_status"] = engagement_status
                    assessment["engagement_feedback_time"] = datetime.utcnow().isoformat()
                    break
            
        except Exception as e:
            self.logger.error(f"Error handling engagement feedback: {e}")
    
    async def _handle_health_check(self, message):
        """Handle health check messages from AgentCore Runtime"""
        try:
            health_status = await self.get_health_status()
            
            # Send response back to requesting agent
            await self.agentcore_sdk.send_message(
                message.from_agent,
                "health_check_response",
                health_status
            )
            
        except Exception as e:
            self.logger.error(f"Error handling health check message: {e}")
    
    async def _publish_engagement_decision(self, decision_data: Dict[str, Any]):
        """Publish engagement decision to Coordinator Agent via AgentCore messaging"""
        try:
            if not self.agentcore_sdk:
                self.logger.warning("AgentCore SDK not available, cannot publish engagement decision")
                return
            
            # Send engagement decision to Coordinator Agent
            await self.agentcore_sdk.send_message(
                "coordinator",
                "engagement_decision",
                decision_data
            )
            
            self.logger.info(f"Published engagement decision for threat {decision_data['threat_id']}")
            
        except Exception as e:
            self.logger.error(f"Failed to publish engagement decision: {e}")
    
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process incoming messages"""
        try:
            message_type = message.get("type", "unknown")
            payload = message.get("payload", {})
            
            self.increment_message_count(message_type)
            
            if message_type == "threat_detected":
                return await self.evaluate_threat(payload)
            elif message_type == "reputation_check":
                return await self.check_reputation(payload)
            elif message_type == "ioc_extraction":
                return await self.extract_iocs(payload)
            elif message_type == "health_check":
                return await self.get_health_status()
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return {"error": f"Unknown message type: {message_type}"}
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            self.error_count += 1
            return {"error": str(e)}
    
    async def evaluate_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate threat data and make engagement decision"""
        try:
            # Create threat assessment
            assessment = ThreatAssessment(threat_data)
            self.active_assessments[assessment.threat_id] = assessment
            self.state["active_assessments"] = len(self.active_assessments)
            
            self.logger.info(f"Evaluating threat {assessment.threat_id} from {assessment.source_ip}")
            
            # Perform AI-powered threat analysis
            analysis_result = await self._analyze_threat_with_ai(assessment)
            
            # Update assessment with analysis results
            assessment.confidence_score = analysis_result.get("confidence_score", 0.0)
            assessment.severity = analysis_result.get("severity", "UNKNOWN")
            assessment.mitre_techniques = analysis_result.get("mitre_techniques", [])
            assessment.attack_vector = analysis_result.get("attack_vector", "unknown")
            assessment.potential_impact = analysis_result.get("potential_impact", "unknown")
            assessment.reasoning = analysis_result.get("reasoning", "")
            
            # Make engagement decision
            engagement_decision = await self._make_engagement_decision(assessment)
            assessment.engagement_decision = engagement_decision["decision"]
            assessment.recommended_honeypots = engagement_decision["recommended_honeypots"]
            
            # Store in history and clean up
            self.assessment_history.append(self._assessment_to_dict(assessment))
            if len(self.assessment_history) > 1000:  # Keep last 1000 assessments
                self.assessment_history = self.assessment_history[-1000:]
            
            del self.active_assessments[assessment.threat_id]
            self.state["active_assessments"] = len(self.active_assessments)
            
            # Prepare response
            response = {
                "threat_id": assessment.threat_id,
                "decision": assessment.engagement_decision,
                "confidence": assessment.confidence_score,
                "reasoning": assessment.reasoning,
                "mitre_techniques": assessment.mitre_techniques,
                "recommended_honeypots": assessment.recommended_honeypots,
                "threat_assessment": {
                    "severity": assessment.severity,
                    "attack_vector": assessment.attack_vector,
                    "potential_impact": assessment.potential_impact
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Threat {assessment.threat_id} evaluation complete: {assessment.engagement_decision} (confidence: {assessment.confidence_score:.2f})")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error evaluating threat: {e}")
            self.error_count += 1
            raise
    
    async def check_reputation(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check IP reputation using enhanced threat intelligence"""
        try:
            ip_address = request_data.get("ip_address")
            if not ip_address:
                return {"error": "IP address required"}
            
            # Check cache first
            cached_reputation = await self._get_cached_reputation(ip_address)
            if cached_reputation:
                self.logger.debug(f"Returning cached reputation for {ip_address}")
                return cached_reputation
            
            # Get historical patterns
            historical_patterns = await self._get_historical_patterns(ip_address)
            
            # Enhanced AI reputation analysis
            prompt = f"""Analyze the reputation of IP address {ip_address} with comprehensive threat intelligence:

=== IP ADDRESS ANALYSIS ===
IP Address: {ip_address}

=== HISTORICAL PATTERNS ===
Previous Attacks: {historical_patterns.get('previous_attacks', 0)}
Attack Types: {', '.join(historical_patterns.get('attack_types', []))}
Last Seen: {historical_patterns.get('last_seen', 'Never')}
Attack Frequency: {historical_patterns.get('frequency', 'Unknown')}

=== ANALYSIS REQUIREMENTS ===
Provide a comprehensive reputation assessment considering:

1. **Geolocation Analysis**: Country, region, ISP, and hosting provider reputation
2. **ASN Information**: Autonomous System Number and associated reputation
3. **Historical Attack Patterns**: Based on the provided historical data
4. **Threat Intelligence Feeds**: Known malicious indicators and associations
5. **Behavioral Patterns**: Automation likelihood and attack sophistication

=== OUTPUT REQUIREMENTS ===
Provide assessment with:
- Risk Level: LOW/MEDIUM/HIGH/CRITICAL
- Confidence Score: 0-100 (based on data quality and indicators)
- Threat Categories: List of applicable threat types
- Geolocation Risk: Assessment of geographic risk factors
- ASN Reputation: Autonomous System reputation assessment
- Indicators: Specific indicators of compromise or suspicious activity
- Recommendations: Actionable recommendations for handling this IP
- Reasoning: Detailed explanation of the risk assessment

Format as JSON with all requested fields."""
            
            result_str = await self.process_with_ai(prompt)
            
            # Try to parse AI response, fallback to enhanced analysis
            try:
                reputation_data = json.loads(result_str)
            except json.JSONDecodeError:
                reputation_data = await self._enhanced_reputation_analysis(ip_address, historical_patterns)
            
            # Validate and enhance reputation data
            reputation_data = await self._validate_reputation_data(reputation_data, ip_address)
            
            # Cache the result
            self.reputation_cache[ip_address] = {
                "data": reputation_data,
                "cached_at": datetime.utcnow().isoformat()
            }
            
            return reputation_data
            
        except Exception as e:
            self.logger.error(f"Error checking reputation: {e}")
            return {"error": str(e), "ip_address": ip_address}
    
    async def _enhanced_reputation_analysis(self, ip_address: str, historical_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced fallback reputation analysis"""
        try:
            # Base risk assessment
            risk_level = "LOW"
            confidence_score = 50
            threat_categories = []
            indicators = []
            
            # Analyze historical patterns
            previous_attacks = historical_patterns.get("previous_attacks", 0)
            attack_types = historical_patterns.get("attack_types", [])
            frequency = historical_patterns.get("frequency", "unknown")
            
            if previous_attacks > 0:
                indicators.append(f"Previously seen {previous_attacks} times")
                threat_categories.extend(attack_types)
                
                if previous_attacks >= 5:
                    risk_level = "HIGH"
                    confidence_score = 85
                elif previous_attacks >= 2:
                    risk_level = "MEDIUM"
                    confidence_score = 70
                else:
                    risk_level = "MEDIUM"
                    confidence_score = 60
            
            # Analyze frequency patterns
            if frequency == "high":
                risk_level = "HIGH"
                confidence_score = min(95, confidence_score + 15)
                indicators.append("High frequency attack pattern")
            elif frequency == "medium":
                confidence_score = min(90, confidence_score + 10)
                indicators.append("Medium frequency attack pattern")
            
            # Basic geolocation analysis (simplified)
            geolocation_risk = "MEDIUM"  # Default
            asn_reputation = "UNKNOWN"   # Default
            
            # Generate recommendations
            recommendations = []
            if risk_level in ["HIGH", "CRITICAL"]:
                recommendations.extend(["Block or monitor closely", "Consider immediate engagement"])
            elif risk_level == "MEDIUM":
                recommendations.extend(["Monitor activity", "Consider engagement if patterns continue"])
            else:
                recommendations.append("Standard monitoring")
            
            return {
                "ip_address": ip_address,
                "risk_level": risk_level,
                "confidence_score": confidence_score,
                "threat_categories": list(set(threat_categories)),
                "geolocation_risk": geolocation_risk,
                "asn_reputation": asn_reputation,
                "indicators": indicators,
                "recommendations": recommendations,
                "reasoning": f"Analysis based on {previous_attacks} previous attacks with {frequency} frequency",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error in enhanced reputation analysis: {e}")
            return {
                "ip_address": ip_address,
                "risk_level": "MEDIUM",
                "confidence_score": 50,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _validate_reputation_data(self, reputation_data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Validate and ensure reputation data has required fields"""
        try:
            # Ensure required fields
            required_fields = {
                "ip_address": ip_address,
                "risk_level": "MEDIUM",
                "confidence_score": 50,
                "threat_categories": [],
                "indicators": [],
                "recommendations": [],
                "timestamp": datetime.utcnow().isoformat()
            }
            
            for field, default_value in required_fields.items():
                if field not in reputation_data:
                    reputation_data[field] = default_value
            
            # Validate risk level
            if reputation_data["risk_level"] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                reputation_data["risk_level"] = "MEDIUM"
            
            # Validate confidence score
            if not isinstance(reputation_data["confidence_score"], (int, float)) or not (0 <= reputation_data["confidence_score"] <= 100):
                reputation_data["confidence_score"] = 50
            
            # Ensure lists are actually lists
            for list_field in ["threat_categories", "indicators", "recommendations"]:
                if not isinstance(reputation_data.get(list_field), list):
                    reputation_data[list_field] = []
            
            return reputation_data
            
        except Exception as e:
            self.logger.error(f"Error validating reputation data: {e}")
            return reputation_data
    
    async def extract_iocs(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Indicators of Compromise from text data with enhanced pattern recognition"""
        try:
            text_data = request_data.get("text", "")
            source_type = request_data.get("source_type", "unknown")
            
            if not text_data:
                return {"error": "Text data required"}
            
            # Enhanced AI IOC extraction
            prompt = f"""Extract Indicators of Compromise (IOCs) from the following {source_type} data:

=== SOURCE DATA ===
{text_data}

=== EXTRACTION REQUIREMENTS ===
Identify and extract all potential IOCs with high precision:

1. **Network Indicators**:
   - IPv4 and IPv6 addresses
   - Domain names and subdomains
   - URLs and URIs
   - Email addresses
   - Network ports and protocols

2. **File Indicators**:
   - MD5, SHA1, SHA256, SHA512 hashes
   - File names and extensions
   - File paths (Windows and Unix)
   - File sizes and timestamps

3. **System Indicators**:
   - Registry keys and values
   - Process names and PIDs
   - Service names
   - User accounts and groups
   - Scheduled tasks

4. **Attack Indicators**:
   - Command line arguments
   - PowerShell commands
   - SQL injection patterns
   - XSS payloads
   - Malware signatures

=== OUTPUT FORMAT ===
Provide JSON with:
- Each IOC category as an array
- Confidence score (0-100) for each extracted IOC
- Context information where the IOC was found
- MITRE ATT&CK technique associations where applicable
- Overall extraction confidence score

Be precise and avoid false positives. Only extract clear indicators."""
            
            result_str = await self.process_with_ai(prompt)
            
            # Try to parse AI response, fallback to regex-based extraction
            try:
                iocs = json.loads(result_str)
                iocs = await self._validate_ioc_data(iocs)
            except json.JSONDecodeError:
                iocs = await self._regex_based_ioc_extraction(text_data)
            
            # Add metadata
            iocs["source_type"] = source_type
            iocs["text_length"] = len(text_data)
            iocs["timestamp"] = datetime.utcnow().isoformat()
            
            # Calculate total IOCs found
            total_iocs = sum(len(iocs.get(category, [])) for category in [
                "ip_addresses", "domains", "file_hashes", "urls", "email_addresses",
                "file_paths", "registry_keys", "process_names", "command_lines"
            ])
            iocs["total_iocs_found"] = total_iocs
            
            self.logger.info(f"Extracted {total_iocs} IOCs from {source_type} data")
            
            return iocs
            
        except Exception as e:
            self.logger.error(f"Error extracting IOCs: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
    
    async def _regex_based_ioc_extraction(self, text_data: str) -> Dict[str, Any]:
        """Fallback regex-based IOC extraction"""
        try:
            iocs = {
                "ip_addresses": [],
                "domains": [],
                "file_hashes": [],
                "urls": [],
                "email_addresses": [],
                "file_paths": [],
                "registry_keys": [],
                "process_names": [],
                "command_lines": [],
                "extraction_confidence": 70
            }
            
            # IP address pattern (IPv4)
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ip_matches = re.findall(ip_pattern, text_data)
            for ip in ip_matches:
                # Validate IP format
                parts = ip.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    iocs["ip_addresses"].append({
                        "value": ip,
                        "confidence": 90,
                        "context": "regex_extraction"
                    })
            
            # Domain pattern
            domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
            domain_matches = re.findall(domain_pattern, text_data)
            for match in domain_matches:
                domain = ''.join(match) if isinstance(match, tuple) else match
                if '.' in domain and len(domain) > 4:  # Basic validation
                    iocs["domains"].append({
                        "value": domain,
                        "confidence": 80,
                        "context": "regex_extraction"
                    })
            
            # Hash patterns
            hash_patterns = {
                "md5": r'\b[a-fA-F0-9]{32}\b',
                "sha1": r'\b[a-fA-F0-9]{40}\b',
                "sha256": r'\b[a-fA-F0-9]{64}\b'
            }
            
            for hash_type, pattern in hash_patterns.items():
                hash_matches = re.findall(pattern, text_data)
                for hash_value in hash_matches:
                    iocs["file_hashes"].append({
                        "value": hash_value,
                        "type": hash_type,
                        "confidence": 95,
                        "context": "regex_extraction"
                    })
            
            # URL pattern
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            url_matches = re.findall(url_pattern, text_data)
            for url in url_matches:
                iocs["urls"].append({
                    "value": url,
                    "confidence": 85,
                    "context": "regex_extraction"
                })
            
            # Email pattern
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            email_matches = re.findall(email_pattern, text_data)
            for email in email_matches:
                iocs["email_addresses"].append({
                    "value": email,
                    "confidence": 85,
                    "context": "regex_extraction"
                })
            
            # File path patterns
            file_path_patterns = [
                r'[A-Za-z]:\\[^<>:"|?*\n\r]+',  # Windows paths
                r'/[^<>:"|?*\n\r\s]+',          # Unix paths
            ]
            
            for pattern in file_path_patterns:
                path_matches = re.findall(pattern, text_data)
                for path in path_matches:
                    if len(path) > 3:  # Basic validation
                        iocs["file_paths"].append({
                            "value": path,
                            "confidence": 75,
                            "context": "regex_extraction"
                        })
            
            # Registry key pattern
            registry_pattern = r'HKEY_[A-Z_]+\\[^<>:"|?*\n\r]+'
            registry_matches = re.findall(registry_pattern, text_data)
            for reg_key in registry_matches:
                iocs["registry_keys"].append({
                    "value": reg_key,
                    "confidence": 90,
                    "context": "regex_extraction"
                })
            
            # Process name pattern (simple)
            process_pattern = r'\b[a-zA-Z0-9_-]+\.exe\b'
            process_matches = re.findall(process_pattern, text_data)
            for process in process_matches:
                iocs["process_names"].append({
                    "value": process,
                    "confidence": 70,
                    "context": "regex_extraction"
                })
            
            return iocs
            
        except Exception as e:
            self.logger.error(f"Error in regex-based IOC extraction: {e}")
            return {
                "ip_addresses": [],
                "domains": [],
                "file_hashes": [],
                "urls": [],
                "email_addresses": [],
                "file_paths": [],
                "registry_keys": [],
                "process_names": [],
                "command_lines": [],
                "extraction_confidence": 0,
                "error": str(e)
            }
    
    async def _validate_ioc_data(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and standardize IOC extraction results"""
        try:
            # Ensure all required categories exist
            required_categories = [
                "ip_addresses", "domains", "file_hashes", "urls", "email_addresses",
                "file_paths", "registry_keys", "process_names", "command_lines"
            ]
            
            for category in required_categories:
                if category not in iocs:
                    iocs[category] = []
            
            # Ensure extraction_confidence exists and is valid
            if "extraction_confidence" not in iocs or not isinstance(iocs["extraction_confidence"], (int, float)):
                iocs["extraction_confidence"] = 70
            
            # Validate confidence score range
            iocs["extraction_confidence"] = max(0, min(100, iocs["extraction_confidence"]))
            
            # Standardize IOC format (ensure each IOC has value and confidence)
            for category in required_categories:
                standardized_iocs = []
                for ioc in iocs[category]:
                    if isinstance(ioc, str):
                        # Convert string to standard format
                        standardized_iocs.append({
                            "value": ioc,
                            "confidence": 80,
                            "context": "ai_extraction"
                        })
                    elif isinstance(ioc, dict) and "value" in ioc:
                        # Ensure confidence exists
                        if "confidence" not in ioc:
                            ioc["confidence"] = 80
                        standardized_iocs.append(ioc)
                
                iocs[category] = standardized_iocs
            
            return iocs
            
        except Exception as e:
            self.logger.error(f"Error validating IOC data: {e}")
            return iocs
    
    async def _analyze_threat_with_ai(self, assessment: ThreatAssessment) -> Dict[str, Any]:
        """Analyze threat using AI capabilities with enhanced MITRE ATT&CK mapping"""
        try:
            # Check reputation cache first
            reputation_data = await self._get_cached_reputation(assessment.source_ip)
            
            # Prepare enhanced context for AI analysis
            context = {
                "threat_data": assessment.raw_data,
                "source_ip": assessment.source_ip,
                "destination_ip": assessment.destination_ip,
                "threat_type": assessment.threat_type,
                "indicators": assessment.indicators,
                "reputation_data": reputation_data,
                "mitre_techniques": MITRE_ATTACK_TECHNIQUES.get(assessment.threat_type.lower(), []),
                "historical_patterns": await self._get_historical_patterns(assessment.source_ip)
            }
            
            prompt = f"""Analyze this cybersecurity threat with advanced threat intelligence:

=== THREAT DETAILS ===
Threat Type: {assessment.threat_type}
Source IP: {assessment.source_ip}
Destination IP: {assessment.destination_ip}
Indicators: {', '.join(assessment.indicators)}
Timestamp: {assessment.timestamp}

=== REPUTATION DATA ===
{json.dumps(reputation_data, indent=2) if reputation_data else "No cached reputation data"}

=== MITRE ATT&CK CONTEXT ===
Potential Techniques: {', '.join(MITRE_ATTACK_TECHNIQUES.get(assessment.threat_type.lower(), []))}

=== ANALYSIS REQUIREMENTS ===
Provide a comprehensive threat assessment with:

1. **Confidence Score** (0.0-1.0): Based on indicator quality, reputation, and pattern matching
2. **Severity Level** (LOW/MEDIUM/HIGH/CRITICAL): Considering potential impact and exploitability
3. **MITRE ATT&CK Techniques**: Specific technique IDs that match this threat pattern
4. **Attack Vector**: Detailed description of the attack method and entry point
5. **Potential Impact**: Assessment of what could be compromised or affected
6. **Behavioral Indicators**: Patterns that suggest automated vs manual attack
7. **Engagement Recommendation**: Whether this threat warrants honeypot engagement
8. **Reasoning**: Detailed explanation of the assessment logic

=== ANALYSIS FACTORS ===
Consider these factors in your assessment:
- IP geolocation and ASN reputation
- Attack timing and frequency patterns
- Indicator of Compromise (IOC) quality and freshness
- Potential for lateral movement and persistence
- Data exfiltration and system compromise risks
- Sophistication level of the attack
- Likelihood of human vs automated attack

=== OUTPUT FORMAT ===
Respond with valid JSON containing all requested fields. Use precise MITRE technique IDs."""
            
            result_str = await self.process_with_ai(prompt, context)
            
            # Try to parse JSON response, fallback to enhanced structured data
            try:
                result = json.loads(result_str)
                # Validate and enhance the result
                result = await self._validate_and_enhance_analysis(result, assessment)
            except json.JSONDecodeError:
                # Enhanced fallback analysis
                result = await self._enhanced_fallback_analysis(assessment, context)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in AI threat analysis: {e}")
            return await self._enhanced_fallback_analysis(assessment, {})
    
    async def _validate_and_enhance_analysis(self, result: Dict[str, Any], assessment: ThreatAssessment) -> Dict[str, Any]:
        """Validate and enhance AI analysis results"""
        try:
            # Ensure required fields exist
            required_fields = ["confidence_score", "severity", "mitre_techniques", "attack_vector", "potential_impact", "reasoning"]
            for field in required_fields:
                if field not in result:
                    result[field] = "Not provided"
            
            # Validate confidence score
            if not isinstance(result.get("confidence_score"), (int, float)) or not (0 <= result["confidence_score"] <= 1):
                result["confidence_score"] = 0.5
            
            # Validate severity
            if result.get("severity") not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                result["severity"] = THREAT_SEVERITY_MAPPING.get(assessment.threat_type.lower(), "MEDIUM")
            
            # Validate MITRE techniques
            if not isinstance(result.get("mitre_techniques"), list):
                result["mitre_techniques"] = MITRE_ATTACK_TECHNIQUES.get(assessment.threat_type.lower(), [])
            
            # Add behavioral analysis
            result["behavioral_indicators"] = await self._analyze_behavioral_patterns(assessment)
            
            # Add engagement recommendation
            result["engagement_recommendation"] = await self._calculate_engagement_recommendation(result, assessment)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error validating analysis results: {e}")
            return result
    
    async def _enhanced_fallback_analysis(self, assessment: ThreatAssessment, context: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced fallback threat analysis with better logic"""
        try:
            # Base confidence and severity from threat type
            base_confidence = 0.5
            severity = THREAT_SEVERITY_MAPPING.get(assessment.threat_type.lower(), "MEDIUM")
            mitre_techniques = MITRE_ATTACK_TECHNIQUES.get(assessment.threat_type.lower(), [])
            
            # Adjust confidence based on indicators
            confidence_adjustments = 0.0
            
            # Check for high-quality indicators
            if assessment.indicators:
                for indicator in assessment.indicators:
                    if any(keyword in indicator.lower() for keyword in ["malware", "exploit", "backdoor"]):
                        confidence_adjustments += 0.2
                    elif any(keyword in indicator.lower() for keyword in ["suspicious", "anomaly", "unusual"]):
                        confidence_adjustments += 0.1
            
            # Check reputation data
            reputation_data = context.get("reputation_data", {})
            if reputation_data:
                risk_level = reputation_data.get("risk_level", "MEDIUM")
                if risk_level in ["HIGH", "CRITICAL"]:
                    confidence_adjustments += 0.2
                elif risk_level == "LOW":
                    confidence_adjustments -= 0.1
            
            # Check for repeat offender
            if assessment.source_ip in self.engagement_history:
                last_engagement = self.engagement_history[assessment.source_ip]
                if datetime.utcnow() - last_engagement < timedelta(hours=24):
                    confidence_adjustments += 0.15  # Recent repeat activity
            
            final_confidence = min(1.0, max(0.0, base_confidence + confidence_adjustments))
            
            # Behavioral analysis
            behavioral_indicators = await self._analyze_behavioral_patterns(assessment)
            
            result = {
                "confidence_score": final_confidence,
                "severity": severity,
                "mitre_techniques": mitre_techniques,
                "attack_vector": f"{assessment.threat_type} attack from {assessment.source_ip}",
                "potential_impact": f"Potential {severity.lower()} impact system compromise",
                "behavioral_indicators": behavioral_indicators,
                "reasoning": f"Enhanced rule-based analysis: confidence adjusted by {confidence_adjustments:.2f} based on indicators and reputation",
                "engagement_recommendation": final_confidence >= self.confidence_threshold
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in enhanced fallback analysis: {e}")
            return self._fallback_threat_analysis(assessment)
    
    async def _analyze_behavioral_patterns(self, assessment: ThreatAssessment) -> Dict[str, Any]:
        """Analyze behavioral patterns in the threat"""
        try:
            patterns = {
                "automation_likelihood": "unknown",
                "sophistication_level": "medium",
                "persistence_indicators": [],
                "lateral_movement_risk": "medium"
            }
            
            # Analyze automation likelihood
            if assessment.threat_type.lower() in ["brute_force", "credential_stuffing", "port_scan"]:
                patterns["automation_likelihood"] = "high"
            elif assessment.threat_type.lower() in ["lateral_movement", "privilege_escalation"]:
                patterns["automation_likelihood"] = "low"
            
            # Analyze sophistication
            if assessment.threat_type.lower() in ["exploit", "malware", "lateral_movement"]:
                patterns["sophistication_level"] = "high"
            elif assessment.threat_type.lower() in ["brute_force", "port_scan"]:
                patterns["sophistication_level"] = "low"
            
            # Check for persistence indicators
            if any(keyword in str(assessment.indicators).lower() for keyword in ["scheduled", "startup", "registry", "service"]):
                patterns["persistence_indicators"].append("system_modification")
            
            if any(keyword in str(assessment.indicators).lower() for keyword in ["backdoor", "remote", "shell"]):
                patterns["persistence_indicators"].append("remote_access")
            
            # Assess lateral movement risk
            if assessment.threat_type.lower() in ["lateral_movement", "privilege_escalation", "credential_stuffing"]:
                patterns["lateral_movement_risk"] = "high"
            elif assessment.threat_type.lower() in ["port_scan", "reconnaissance"]:
                patterns["lateral_movement_risk"] = "medium"
            else:
                patterns["lateral_movement_risk"] = "low"
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error analyzing behavioral patterns: {e}")
            return {"automation_likelihood": "unknown", "sophistication_level": "medium"}
    
    async def _calculate_engagement_recommendation(self, analysis: Dict[str, Any], assessment: ThreatAssessment) -> bool:
        """Calculate whether to recommend engagement based on analysis"""
        try:
            confidence = analysis.get("confidence_score", 0.0)
            severity = analysis.get("severity", "MEDIUM")
            
            # Base recommendation on confidence threshold
            if confidence < self.confidence_threshold:
                return False
            
            # Check engagement cooldown
            if assessment.source_ip in self.engagement_history:
                last_engagement = self.engagement_history[assessment.source_ip]
                cooldown_period = timedelta(minutes=self.engagement_cooldown_minutes)
                if datetime.utcnow() - last_engagement < cooldown_period:
                    return False
            
            # High severity threats should be engaged if above threshold
            if severity in ["HIGH", "CRITICAL"] and confidence >= self.confidence_threshold:
                return True
            
            # Medium severity requires higher confidence
            if severity == "MEDIUM" and confidence >= (self.confidence_threshold + 0.1):
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error calculating engagement recommendation: {e}")
            return False
    
    async def _get_cached_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get cached reputation data for an IP address"""
        try:
            cached_data = self.reputation_cache.get(ip_address)
            if cached_data:
                cache_time = datetime.fromisoformat(cached_data["cached_at"])
                if datetime.utcnow() - cache_time < timedelta(seconds=self.reputation_cache_ttl):
                    return cached_data["data"]
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting cached reputation: {e}")
            return None
    
    async def _get_historical_patterns(self, ip_address: str) -> Dict[str, Any]:
        """Get historical attack patterns for an IP address"""
        try:
            patterns = {
                "previous_attacks": 0,
                "attack_types": [],
                "last_seen": None,
                "frequency": "unknown"
            }
            
            # Check assessment history
            for assessment in self.assessment_history:
                if assessment.get("source_ip") == ip_address:
                    patterns["previous_attacks"] += 1
                    threat_type = assessment.get("threat_type")
                    if threat_type and threat_type not in patterns["attack_types"]:
                        patterns["attack_types"].append(threat_type)
                    
                    # Update last seen
                    assessment_time = assessment.get("timestamp")
                    if assessment_time:
                        if not patterns["last_seen"] or assessment_time > patterns["last_seen"]:
                            patterns["last_seen"] = assessment_time
            
            # Calculate frequency
            if patterns["previous_attacks"] > 0 and patterns["last_seen"]:
                try:
                    last_seen_dt = datetime.fromisoformat(patterns["last_seen"])
                    days_since = (datetime.utcnow() - last_seen_dt).days
                    if days_since > 0:
                        attacks_per_day = patterns["previous_attacks"] / days_since
                        if attacks_per_day > 1:
                            patterns["frequency"] = "high"
                        elif attacks_per_day > 0.1:
                            patterns["frequency"] = "medium"
                        else:
                            patterns["frequency"] = "low"
                except:
                    patterns["frequency"] = "unknown"
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error getting historical patterns: {e}")
            return {"previous_attacks": 0, "attack_types": [], "frequency": "unknown"}
    
    def _fallback_threat_analysis(self, assessment: ThreatAssessment) -> Dict[str, Any]:
        """Fallback threat analysis when AI is unavailable"""
        # Simple rule-based analysis for foundation
        confidence_score = 0.5  # Default medium confidence
        severity = "MEDIUM"
        mitre_techniques = []
        
        # Adjust based on threat type
        if assessment.threat_type.lower() in ["brute_force", "credential_stuffing"]:
            confidence_score = 0.8
            severity = "HIGH"
            mitre_techniques = ["T1110", "T1078"]
        elif assessment.threat_type.lower() in ["port_scan", "reconnaissance"]:
            confidence_score = 0.7
            severity = "MEDIUM"
            mitre_techniques = ["T1595", "T1046"]
        elif assessment.threat_type.lower() in ["malware", "exploit"]:
            confidence_score = 0.9
            severity = "CRITICAL"
            mitre_techniques = ["T1203", "T1055"]
        
        return {
            "confidence_score": confidence_score,
            "severity": severity,
            "mitre_techniques": mitre_techniques,
            "attack_vector": f"{assessment.threat_type} from {assessment.source_ip}",
            "potential_impact": f"Potential {severity.lower()} impact system compromise",
            "reasoning": f"Rule-based analysis of {assessment.threat_type} threat pattern"
        }
    
    async def _make_engagement_decision(self, assessment: ThreatAssessment) -> Dict[str, Any]:
        """Make enhanced engagement decision based on threat assessment"""
        try:
            decision = "MONITOR"  # Default decision
            recommended_honeypots = []
            decision_factors = []
            
            # Check engagement cooldown
            cooldown_active = False
            if assessment.source_ip in self.engagement_history:
                last_engagement = self.engagement_history[assessment.source_ip]
                cooldown_period = timedelta(minutes=self.engagement_cooldown_minutes)
                if datetime.utcnow() - last_engagement < cooldown_period:
                    cooldown_active = True
                    decision_factors.append(f"Engagement cooldown active ({self.engagement_cooldown_minutes}min)")
            
            # Enhanced decision logic
            if cooldown_active:
                decision = "MONITOR"
                decision_factors.append("Cooldown period prevents engagement")
            elif assessment.confidence_score >= self.confidence_threshold:
                if assessment.severity in ["HIGH", "CRITICAL"]:
                    decision = "ENGAGE"
                    decision_factors.append(f"High confidence ({assessment.confidence_score:.2f}) and {assessment.severity} severity")
                    
                    # Enhanced honeypot recommendation based on MITRE techniques
                    recommended_honeypots = await self._recommend_honeypots_by_techniques(
                        assessment.threat_type, 
                        assessment.mitre_techniques
                    )
                    
                elif assessment.severity == "MEDIUM" and assessment.confidence_score >= (self.confidence_threshold + 0.1):
                    decision = "ENGAGE"
                    decision_factors.append(f"Very high confidence ({assessment.confidence_score:.2f}) for MEDIUM severity")
                    recommended_honeypots = await self._recommend_honeypots_by_techniques(
                        assessment.threat_type,
                        assessment.mitre_techniques
                    )
                else:
                    decision = "MONITOR"
                    decision_factors.append(f"Confidence above threshold but severity is {assessment.severity}")
            else:
                if assessment.confidence_score < 0.3:
                    decision = "IGNORE"
                    decision_factors.append(f"Low confidence ({assessment.confidence_score:.2f})")
                else:
                    decision = "MONITOR"
                    decision_factors.append(f"Medium confidence ({assessment.confidence_score:.2f})")
            
            # Record engagement decision
            if decision == "ENGAGE":
                self.engagement_history[assessment.source_ip] = datetime.utcnow()
            
            reasoning = "; ".join(decision_factors)
            
            self.logger.info(f"Engagement decision for {assessment.threat_id}: {decision} - {reasoning}")
            
            return {
                "decision": decision,
                "recommended_honeypots": recommended_honeypots,
                "decision_reasoning": reasoning,
                "decision_factors": decision_factors,
                "cooldown_active": cooldown_active
            }
            
        except Exception as e:
            self.logger.error(f"Error making engagement decision: {e}")
            return {
                "decision": "MONITOR",
                "recommended_honeypots": [],
                "decision_reasoning": f"Error in decision making: {str(e)}",
                "decision_factors": ["Error occurred"],
                "cooldown_active": False
            }
    
    async def _recommend_honeypots_by_techniques(self, threat_type: str, mitre_techniques: List[str]) -> List[str]:
        """Recommend honeypots based on threat type and MITRE ATT&CK techniques"""
        try:
            recommended = set()
            
            # Base recommendations by threat type
            threat_type_lower = threat_type.lower()
            if threat_type_lower in ["brute_force", "credential_stuffing"]:
                recommended.update(["ssh", "web_admin"])
            elif threat_type_lower in ["sql_injection", "database_attack"]:
                recommended.update(["database", "web_admin"])
            elif threat_type_lower in ["file_access", "smb_attack"]:
                recommended.update(["file_share"])
            elif threat_type_lower in ["phishing", "email_attack"]:
                recommended.update(["email"])
            elif threat_type_lower in ["web_attack", "command_injection"]:
                recommended.update(["web_admin"])
            elif threat_type_lower in ["lateral_movement", "privilege_escalation"]:
                recommended.update(["ssh", "web_admin", "database"])
            
            # Enhanced recommendations based on MITRE techniques
            for technique in mitre_techniques:
                if technique in ["T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004"]:  # Brute Force
                    recommended.update(["ssh", "web_admin"])
                elif technique in ["T1021", "T1021.001", "T1021.002"]:  # Remote Services
                    recommended.update(["ssh", "database"])
                elif technique in ["T1190"]:  # Exploit Public-Facing Application
                    recommended.update(["web_admin"])
                elif technique in ["T1213", "T1213.001", "T1213.002"]:  # Data from Information Repositories
                    recommended.update(["database", "file_share"])
                elif technique in ["T1005", "T1039", "T1083"]:  # Data from Local System
                    recommended.update(["file_share", "ssh"])
                elif technique in ["T1566", "T1566.001", "T1566.002"]:  # Phishing
                    recommended.update(["email"])
                elif technique in ["T1059", "T1059.001", "T1059.003"]:  # Command and Scripting Interpreter
                    recommended.update(["ssh", "web_admin"])
            
            # Default fallback
            if not recommended:
                recommended = {"web_admin", "ssh"}
            
            # Limit to maximum 3 honeypots for resource efficiency
            return list(recommended)[:3]
            
        except Exception as e:
            self.logger.error(f"Error recommending honeypots: {e}")
            return ["web_admin", "ssh"]  # Safe default
    
    async def _initialize_threat_intelligence(self):
        """Initialize threat intelligence feeds and models"""
        try:
            self.logger.info("Initializing threat intelligence systems...")
            
            # In a real implementation, this would:
            # 1. Connect to threat intelligence feeds
            # 2. Load ML models for threat detection
            # 3. Initialize reputation databases
            # 4. Set up MITRE ATT&CK framework mappings
            
            # For foundation, we'll simulate this
            await asyncio.sleep(0.1)  # Simulate initialization time
            
            self.logger.info("Threat intelligence systems initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize threat intelligence: {e}")
            raise
    
    async def _complete_active_assessments(self):
        """Complete any active threat assessments"""
        try:
            for threat_id, assessment in list(self.active_assessments.items()):
                self.logger.info(f"Completing assessment {threat_id}")
                
                # Mark as completed with default decision
                assessment.engagement_decision = "MONITOR"
                assessment.reasoning = "Assessment completed during shutdown"
                
                # Move to history
                self.assessment_history.append(self._assessment_to_dict(assessment))
                del self.active_assessments[threat_id]
            
            self.state["active_assessments"] = 0
            
        except Exception as e:
            self.logger.error(f"Error completing active assessments: {e}")
    
    def _assessment_to_dict(self, assessment: ThreatAssessment) -> Dict[str, Any]:
        """Convert threat assessment to dictionary"""
        return {
            "threat_id": assessment.threat_id,
            "source_ip": assessment.source_ip,
            "destination_ip": assessment.destination_ip,
            "threat_type": assessment.threat_type,
            "confidence_score": assessment.confidence_score,
            "severity": assessment.severity,
            "engagement_decision": assessment.engagement_decision,
            "mitre_techniques": assessment.mitre_techniques,
            "recommended_honeypots": assessment.recommended_honeypots,
            "reasoning": assessment.reasoning,
            "timestamp": assessment.timestamp
        }
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get Detection Agent specific metrics"""
        base_metrics = await super().get_metrics()
        
        # Calculate engagement statistics
        engagement_stats = {"engage": 0, "monitor": 0, "ignore": 0}
        threat_type_stats = {}
        severity_stats = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        
        for assessment in self.assessment_history:
            decision = assessment.get("engagement_decision", "monitor").lower()
            if decision in engagement_stats:
                engagement_stats[decision] += 1
            
            threat_type = assessment.get("threat_type", "unknown")
            threat_type_stats[threat_type] = threat_type_stats.get(threat_type, 0) + 1
            
            severity = assessment.get("severity", "MEDIUM")
            if severity in severity_stats:
                severity_stats[severity] += 1
        
        # Calculate average confidence
        confidences = [a.get("confidence_score", 0) for a in self.assessment_history if "confidence_score" in a]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        detection_metrics = {
            "active_assessments": len(self.active_assessments),
            "total_assessments": len(self.assessment_history),
            "confidence_threshold": self.confidence_threshold,
            "average_confidence": round(avg_confidence, 3),
            "engagement_decisions": engagement_stats,
            "threat_type_distribution": threat_type_stats,
            "severity_distribution": severity_stats,
            "reputation_cache_size": len(self.reputation_cache),
            "engagement_history_size": len(self.engagement_history),
            "threat_feeds_connected": self.state.get("threat_feeds_connected", 0),
            "agentcore_connected": self.agentcore_sdk is not None
        }
        
        return {**base_metrics, **detection_metrics}
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get Detection Agent health status"""
        base_health = await super().get_health_status()
        
        # Check specific health indicators
        health_indicators = {
            "agentcore_sdk_connected": self.agentcore_sdk is not None,
            "active_assessments_within_limit": len(self.active_assessments) <= self.max_concurrent_assessments,
            "recent_activity": len(self.assessment_history) > 0,
            "error_rate_acceptable": self.error_count / max(self.message_count, 1) < 0.1
        }
        
        # Overall health status
        all_healthy = all(health_indicators.values())
        health_status = "healthy" if all_healthy else "degraded"
        
        detection_health = {
            "detection_agent_status": health_status,
            "health_indicators": health_indicators,
            "active_assessments": len(self.active_assessments),
            "max_concurrent_assessments": self.max_concurrent_assessments,
            "cache_status": {
                "reputation_cache_entries": len(self.reputation_cache),
                "engagement_history_entries": len(self.engagement_history)
            }
        }
        
        return {**base_health, **detection_health}
    
    # Additional utility methods for enhanced functionality
    async def get_threat_statistics(self) -> Dict[str, Any]:
        """Get comprehensive threat statistics"""
        try:
            stats = {
                "total_threats_analyzed": len(self.assessment_history),
                "threats_by_type": {},
                "threats_by_severity": {},
                "engagement_rate": 0,
                "average_confidence": 0,
                "top_source_ips": {},
                "mitre_techniques_seen": set(),
                "recent_activity": []
            }
            
            if not self.assessment_history:
                return stats
            
            # Analyze assessment history
            engaged_count = 0
            confidences = []
            
            for assessment in self.assessment_history:
                # Count by type
                threat_type = assessment.get("threat_type", "unknown")
                stats["threats_by_type"][threat_type] = stats["threats_by_type"].get(threat_type, 0) + 1
                
                # Count by severity
                severity = assessment.get("severity", "MEDIUM")
                stats["threats_by_severity"][severity] = stats["threats_by_severity"].get(severity, 0) + 1
                
                # Count engagements
                if assessment.get("engagement_decision") == "ENGAGE":
                    engaged_count += 1
                
                # Collect confidences
                if "confidence_score" in assessment:
                    confidences.append(assessment["confidence_score"])
                
                # Count source IPs
                source_ip = assessment.get("source_ip", "unknown")
                stats["top_source_ips"][source_ip] = stats["top_source_ips"].get(source_ip, 0) + 1
                
                # Collect MITRE techniques
                techniques = assessment.get("mitre_techniques", [])
                stats["mitre_techniques_seen"].update(techniques)
            
            # Calculate rates and averages
            stats["engagement_rate"] = engaged_count / len(self.assessment_history)
            stats["average_confidence"] = sum(confidences) / len(confidences) if confidences else 0
            
            # Get recent activity (last 10 assessments)
            stats["recent_activity"] = self.assessment_history[-10:] if len(self.assessment_history) > 10 else self.assessment_history
            
            # Convert set to list for JSON serialization
            stats["mitre_techniques_seen"] = list(stats["mitre_techniques_seen"])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting threat statistics: {e}")
            return {"error": str(e)}
    
    async def update_configuration(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update Detection Agent configuration"""
        try:
            old_config = self.config.copy()
            
            # Update configuration
            self.config.update(new_config)
            
            # Update specific settings
            if "confidence_threshold" in new_config:
                self.confidence_threshold = float(new_config["confidence_threshold"])
                self.state["confidence_threshold"] = self.confidence_threshold
            
            if "max_concurrent_assessments" in new_config:
                self.max_concurrent_assessments = int(new_config["max_concurrent_assessments"])
            
            if "engagement_cooldown_minutes" in new_config:
                self.engagement_cooldown_minutes = int(new_config["engagement_cooldown_minutes"])
            
            self.logger.info(f"Configuration updated: {new_config}")
            
            return {
                "status": "success",
                "old_config": old_config,
                "new_config": self.config,
                "updated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error updating configuration: {e}")
            return {"status": "error", "error": str(e)}