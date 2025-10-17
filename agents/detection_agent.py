"""
Detection Agent Implementation
AI-powered threat detection agent for the honeypot system.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import hashlib

from strands import tool
from agents.base_agent import BaseAgent
from config.agentcore_sdk import AgentCoreSDK, create_agent_sdk, Message

class DetectionAgent(BaseAgent):
    """AI-powered threat detection agent"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        capabilities = [
            "threat_analysis",
            "anomaly_detection", 
            "risk_assessment",
            "mitre_mapping",
            "confidence_scoring",
            "behavioral_analysis",
            "pattern_recognition",
            "threat_feed_integration",
            "agentcore_messaging"
        ]
        
        super().__init__(
            agent_type="detection",
            capabilities=capabilities,
            config=config
        )
        
        # Detection-specific configuration
        self.threat_threshold = self.config.get("threat_threshold", 0.75)
        self.confidence_threshold = self.config.get("confidence_threshold", 0.6)
        self.engagement_threshold = self.config.get("engagement_threshold", 0.75)
        
        # Threat analysis models and data
        self.threat_patterns = {}
        self.behavioral_baselines = {}
        self.active_sessions = {}
        self.threat_intelligence = {}
        self.mitre_mappings = {}
        
        # AgentCore messaging integration
        self.agentcore_sdk: Optional[AgentCoreSDK] = None
        self.message_retry_count = {}
        self.max_retry_attempts = self.config.get("max_retry_attempts", 3)
        self.retry_delay = self.config.get("retry_delay", 5)  # seconds
        
        # Message state management
        self.threat_analysis_state = {}
        self.engagement_decisions = {}
        self.message_handlers_registered = False
        
        # Initialize MITRE ATT&CK framework data
        self._initialize_mitre_framework()
    
    def _initialize_mitre_framework(self):
        """Initialize MITRE ATT&CK framework mappings"""
        self.mitre_mappings = {
            # Initial Access
            "T1078": {"name": "Valid Accounts", "tactic": "initial-access", "description": "Use of valid credentials"},
            "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access", "description": "Exploitation of internet-facing services"},
            "T1566": {"name": "Phishing", "tactic": "initial-access", "description": "Spearphishing and phishing attacks"},
            
            # Execution
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "description": "Command line and scripting"},
            "T1053": {"name": "Scheduled Task/Job", "tactic": "execution", "description": "Scheduled tasks and cron jobs"},
            
            # Persistence
            "T1098": {"name": "Account Manipulation", "tactic": "persistence", "description": "Modification of user accounts"},
            "T1136": {"name": "Create Account", "tactic": "persistence", "description": "Creation of new accounts"},
            
            # Privilege Escalation
            "T1055": {"name": "Process Injection", "tactic": "privilege-escalation", "description": "Process injection techniques"},
            "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation", "description": "Privilege escalation exploits"},
            
            # Defense Evasion
            "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion", "description": "File and data obfuscation"},
            "T1070": {"name": "Indicator Removal on Host", "tactic": "defense-evasion", "description": "Log and artifact deletion"},
            
            # Credential Access
            "T1110": {"name": "Brute Force", "tactic": "credential-access", "description": "Brute force attacks"},
            "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access", "description": "Credential extraction"},
            
            # Discovery
            "T1083": {"name": "File and Directory Discovery", "tactic": "discovery", "description": "File system enumeration"},
            "T1057": {"name": "Process Discovery", "tactic": "discovery", "description": "Process enumeration"},
            "T1018": {"name": "Remote System Discovery", "tactic": "discovery", "description": "Network reconnaissance"},
            
            # Lateral Movement
            "T1021": {"name": "Remote Services", "tactic": "lateral-movement", "description": "Remote service exploitation"},
            "T1105": {"name": "Ingress Tool Transfer", "tactic": "lateral-movement", "description": "Tool and file transfer"},
            
            # Collection
            "T1005": {"name": "Data from Local System", "tactic": "collection", "description": "Local data collection"},
            "T1039": {"name": "Data from Network Shared Drive", "tactic": "collection", "description": "Network share access"},
            
            # Exfiltration
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "description": "Data exfiltration via C2"},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration", "description": "Alternative exfiltration methods"}
        }
        
        # Technique detection patterns
        self.technique_patterns = {
            "T1110": ["failed_login", "brute_force", "password_spray"],
            "T1078": ["valid_credentials", "account_reuse", "credential_stuffing"],
            "T1059": ["command_execution", "shell_access", "script_execution"],
            "T1083": ["directory_listing", "file_enumeration", "find_command"],
            "T1057": ["process_listing", "ps_command", "task_enumeration"],
            "T1021": ["ssh_connection", "rdp_access", "remote_login"],
            "T1105": ["file_transfer", "wget", "curl", "scp"]
        }
        
    async def initialize(self):
        """Initialize the detection agent"""
        self.logger.info("Initializing Detection Agent")
        
        # Initialize AgentCore SDK
        await self._initialize_agentcore_messaging()
        
        # Load threat intelligence feeds
        await self._load_threat_feeds()
        
        # Initialize ML models
        await self._initialize_models()
        
        # Register message handlers
        await self._register_message_handlers()
        
        self.logger.info("Detection Agent initialized successfully")
    
    async def cleanup(self):
        """Cleanup detection agent resources"""
        self.logger.info("Cleaning up Detection Agent")
        
        # Cleanup AgentCore SDK
        if self.agentcore_sdk:
            await self.agentcore_sdk.stop()
            self.agentcore_sdk = None
        
        # Clear state
        self.threat_analysis_state.clear()
        self.engagement_decisions.clear()
        self.message_retry_count.clear()
    
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process detection-specific messages"""
        message_type = message.get("type")
        
        if message_type == "analyze_threat":
            return await self._analyze_threat(message.get("data", {}))
        elif message_type == "update_threat_feeds":
            return await self._update_threat_feeds(message.get("feeds", []))
        else:
            return None
    
    # AgentCore Messaging Integration Methods
    
    async def _initialize_agentcore_messaging(self):
        """Initialize AgentCore SDK for messaging"""
        try:
            # Check if we're in test mode (no AgentCore server available)
            test_mode = self.config.get("test_mode", False)
            
            if test_mode:
                self.logger.info("Running in test mode - skipping AgentCore messaging initialization")
                self.agentcore_sdk = None
                return
            
            self.agentcore_sdk = await create_agent_sdk(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                capabilities=self.capabilities
            )
            
            await self.agentcore_sdk.start()
            
            self.logger.info("AgentCore messaging initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize AgentCore messaging: {e}")
            self.logger.info("Continuing without AgentCore messaging (development mode)")
            self.agentcore_sdk = None
    
    async def _register_message_handlers(self):
        """Register message handlers for different message types"""
        if not self.agentcore_sdk:
            self.logger.info("AgentCore SDK not initialized, skipping message handler registration")
            self.message_handlers_registered = False
            return
        
        try:
            # Register handlers for different message types
            self.agentcore_sdk.register_message_handler("threat_feed_update", self._handle_threat_feed_message)
            self.agentcore_sdk.register_message_handler("threat_analysis_request", self._handle_threat_analysis_request)
            self.agentcore_sdk.register_message_handler("engagement_feedback", self._handle_engagement_feedback)
            self.agentcore_sdk.register_message_handler("system_alert", self._handle_system_alert)
            self.agentcore_sdk.register_message_handler("state_sync_request", self._handle_state_sync_request)
            
            self.message_handlers_registered = True
            self.logger.info("Message handlers registered successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to register message handlers: {e}")
            self.message_handlers_registered = False
    
    async def _handle_threat_feed_message(self, message: Message):
        """Handle threat feed update messages"""
        try:
            self.logger.info(f"Processing threat feed update from {message.from_agent}")
            
            feed_data = message.payload.get("feed_data", {})
            feed_type = message.payload.get("feed_type", "unknown")
            
            # Update threat feeds
            result = await self._update_threat_feeds([{
                "type": feed_type,
                "data": feed_data,
                "source": message.from_agent,
                "timestamp": message.timestamp
            }])
            
            # Send acknowledgment
            await self._send_message_with_retry(
                to_agent=message.from_agent,
                message_type="threat_feed_ack",
                payload={
                    "original_message_id": message.message_id,
                    "status": "processed",
                    "result": result
                }
            )
            
            self.log_activity("threat_feed_processed", {
                "feed_type": feed_type,
                "source_agent": message.from_agent,
                "indicators_added": result.get("added_indicators", 0)
            })
            
        except Exception as e:
            self.logger.error(f"Error handling threat feed message: {e}")
            await self._handle_message_error(message, e)
    
    async def _handle_threat_analysis_request(self, message: Message):
        """Handle threat analysis requests from other agents"""
        try:
            self.logger.info(f"Processing threat analysis request from {message.from_agent}")
            
            threat_data = message.payload.get("threat_data", {})
            analysis_id = message.payload.get("analysis_id", f"analysis-{datetime.utcnow().timestamp()}")
            
            # Store analysis state
            self.threat_analysis_state[analysis_id] = {
                "status": "processing",
                "started_at": datetime.utcnow().isoformat(),
                "requesting_agent": message.from_agent,
                "original_message_id": message.message_id
            }
            
            # Perform threat analysis
            analysis_result = await self._analyze_threat(threat_data)
            analysis_result["analysis_id"] = analysis_id
            
            # Update state
            self.threat_analysis_state[analysis_id].update({
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "result": analysis_result
            })
            
            # Send analysis result
            await self._send_message_with_retry(
                to_agent=message.from_agent,
                message_type="threat_analysis_result",
                payload={
                    "analysis_id": analysis_id,
                    "original_message_id": message.message_id,
                    "analysis_result": analysis_result
                }
            )
            
            # If engagement threshold is met, notify coordinator
            if analysis_result.get("threshold_met", False):
                await self._publish_engagement_decision(analysis_result)
            
            self.log_activity("threat_analysis_completed", {
                "analysis_id": analysis_id,
                "requesting_agent": message.from_agent,
                "threat_level": analysis_result.get("threat_level"),
                "confidence": analysis_result.get("overall_confidence")
            })
            
        except Exception as e:
            self.logger.error(f"Error handling threat analysis request: {e}")
            await self._handle_message_error(message, e)
    
    async def _handle_engagement_feedback(self, message: Message):
        """Handle engagement feedback from coordinator agent"""
        try:
            self.logger.info(f"Processing engagement feedback from {message.from_agent}")
            
            engagement_id = message.payload.get("engagement_id")
            feedback = message.payload.get("feedback", {})
            
            if engagement_id in self.engagement_decisions:
                # Update engagement decision with feedback
                self.engagement_decisions[engagement_id].update({
                    "feedback_received": True,
                    "feedback": feedback,
                    "feedback_timestamp": datetime.utcnow().isoformat()
                })
                
                # Update threat intelligence based on feedback
                await self._update_threat_intelligence_from_feedback(engagement_id, feedback)
                
                self.log_activity("engagement_feedback_processed", {
                    "engagement_id": engagement_id,
                    "feedback_type": feedback.get("type"),
                    "success": feedback.get("success", False)
                })
            
        except Exception as e:
            self.logger.error(f"Error handling engagement feedback: {e}")
            await self._handle_message_error(message, e)
    
    async def _handle_system_alert(self, message: Message):
        """Handle system alerts from other agents"""
        try:
            self.logger.info(f"Processing system alert from {message.from_agent}")
            
            alert_type = message.payload.get("alert_type")
            alert_data = message.payload.get("alert_data", {})
            
            # Process different types of alerts
            if alert_type == "emergency_shutdown":
                await self._handle_emergency_shutdown(alert_data)
            elif alert_type == "threat_escalation":
                await self._handle_threat_escalation(alert_data)
            elif alert_type == "system_compromise":
                await self._handle_system_compromise(alert_data)
            
            self.log_activity("system_alert_processed", {
                "alert_type": alert_type,
                "source_agent": message.from_agent
            })
            
        except Exception as e:
            self.logger.error(f"Error handling system alert: {e}")
            await self._handle_message_error(message, e)
    
    async def _handle_state_sync_request(self, message: Message):
        """Handle state synchronization requests"""
        try:
            self.logger.info(f"Processing state sync request from {message.from_agent}")
            
            # Prepare current state
            current_state = {
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "status": self.state["status"],
                "threat_analysis_state": self.threat_analysis_state,
                "engagement_decisions": self.engagement_decisions,
                "active_sessions_count": len(self.active_sessions),
                "last_updated": datetime.utcnow().isoformat()
            }
            
            # Send state response
            await self._send_message_with_retry(
                to_agent=message.from_agent,
                message_type="state_sync_response",
                payload={
                    "original_message_id": message.message_id,
                    "state": current_state
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error handling state sync request: {e}")
            await self._handle_message_error(message, e)
    
    async def _publish_engagement_decision(self, analysis_result: Dict[str, Any]):
        """Publish engagement decision to coordinator agent"""
        try:
            engagement_id = f"engagement-{datetime.utcnow().timestamp()}"
            
            engagement_decision = {
                "engagement_id": engagement_id,
                "analysis_result": analysis_result,
                "decision": analysis_result["engagement_decision"]["decision"],
                "confidence": analysis_result["overall_confidence"],
                "threat_level": analysis_result["threat_level"],
                "mitre_techniques": analysis_result["mitre_techniques"],
                "recommended_honeypots": self._recommend_honeypots(analysis_result),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Store engagement decision
            self.engagement_decisions[engagement_id] = engagement_decision
            
            # Send to coordinator agent
            await self._send_message_with_retry(
                to_agent="coordinator",
                message_type="engagement_decision",
                payload=engagement_decision
            )
            
            # Update AgentCore state
            await self._update_agentcore_state()
            
            self.log_activity("engagement_decision_published", {
                "engagement_id": engagement_id,
                "decision": engagement_decision["decision"],
                "confidence": engagement_decision["confidence"],
                "threat_level": engagement_decision["threat_level"]
            })
            
        except Exception as e:
            self.logger.error(f"Error publishing engagement decision: {e}")
            raise
    
    async def _send_message_with_retry(self, to_agent: str, message_type: str, payload: Dict[str, Any]):
        """Send message with retry logic"""
        message_key = f"{to_agent}:{message_type}:{hash(json.dumps(payload, sort_keys=True))}"
        retry_count = self.message_retry_count.get(message_key, 0)
        
        try:
            if not self.agentcore_sdk:
                self.logger.warning(f"AgentCore SDK not initialized - simulating message send: {message_type} to {to_agent}")
                return f"simulated-{message_type}-{to_agent}"
            
            message_id = await self.agentcore_sdk.send_message(to_agent, message_type, payload)
            
            # Clear retry count on success
            if message_key in self.message_retry_count:
                del self.message_retry_count[message_key]
            
            self.logger.debug(f"Message sent successfully: {message_type} to {to_agent}")
            return message_id
            
        except Exception as e:
            self.logger.error(f"Failed to send message (attempt {retry_count + 1}): {e}")
            
            if retry_count < self.max_retry_attempts:
                self.message_retry_count[message_key] = retry_count + 1
                
                # Schedule retry
                await asyncio.sleep(self.retry_delay * (retry_count + 1))  # Exponential backoff
                return await self._send_message_with_retry(to_agent, message_type, payload)
            else:
                # Max retries exceeded
                self.logger.error(f"Max retry attempts exceeded for message: {message_type} to {to_agent}")
                if message_key in self.message_retry_count:
                    del self.message_retry_count[message_key]
                raise
    
    async def _update_agentcore_state(self):
        """Update agent state in AgentCore Runtime"""
        try:
            if not self.agentcore_sdk:
                return
            
            state_data = {
                "agent_status": self.state["status"],
                "processed_messages": self.message_count,
                "active_analyses": len(self.threat_analysis_state),
                "pending_engagements": len([e for e in self.engagement_decisions.values() 
                                          if not e.get("feedback_received", False)]),
                "error_count": self.error_count,
                "last_updated": datetime.utcnow().isoformat()
            }
            
            await self.agentcore_sdk.update_state(state_data)
            
        except Exception as e:
            self.logger.error(f"Failed to update AgentCore state: {e}")
    
    async def _handle_message_error(self, message: Message, error: Exception):
        """Handle message processing errors"""
        try:
            error_response = {
                "original_message_id": message.message_id,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Send error response to sender
            await self._send_message_with_retry(
                to_agent=message.from_agent,
                message_type="message_error",
                payload=error_response
            )
            
            self.log_activity("message_error", {
                "original_message_type": message.message_type,
                "from_agent": message.from_agent,
                "error_type": type(error).__name__
            })
            
        except Exception as e:
            self.logger.error(f"Failed to handle message error: {e}")
    
    def _recommend_honeypots(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Recommend appropriate honeypots based on analysis"""
        recommended = []
        mitre_techniques = analysis_result.get("mitre_techniques", [])
        
        # Map MITRE techniques to honeypot types
        technique_ids = [t.get("technique_id") for t in mitre_techniques]
        
        if any(tid in ["T1078", "T1110"] for tid in technique_ids):  # Credential attacks
            recommended.extend(["web_admin", "ssh"])
        
        if any(tid in ["T1083", "T1057"] for tid in technique_ids):  # Discovery
            recommended.extend(["ssh", "file_share"])
        
        if any(tid in ["T1021", "T1105"] for tid in technique_ids):  # Lateral movement
            recommended.extend(["ssh", "database"])
        
        if any(tid in ["T1566"] for tid in technique_ids):  # Phishing
            recommended.append("email")
        
        # Default recommendations if no specific techniques detected
        if not recommended:
            recommended = ["web_admin", "ssh"]
        
        return list(set(recommended))  # Remove duplicates
    
    async def _update_threat_intelligence_from_feedback(self, engagement_id: str, feedback: Dict[str, Any]):
        """Update threat intelligence based on engagement feedback"""
        try:
            engagement = self.engagement_decisions.get(engagement_id)
            if not engagement:
                return
            
            success = feedback.get("success", False)
            intelligence_gathered = feedback.get("intelligence", {})
            
            # Update threat patterns based on success/failure
            analysis_result = engagement.get("analysis_result", {})
            mitre_techniques = analysis_result.get("mitre_techniques", [])
            
            for technique in mitre_techniques:
                technique_id = technique.get("technique_id")
                if technique_id:
                    # Adjust confidence based on feedback
                    if success:
                        # Increase confidence for successful engagements
                        self.mitre_mappings[technique_id]["success_rate"] = \
                            self.mitre_mappings[technique_id].get("success_rate", 0.5) + 0.1
                    else:
                        # Decrease confidence for failed engagements
                        self.mitre_mappings[technique_id]["success_rate"] = \
                            self.mitre_mappings[technique_id].get("success_rate", 0.5) - 0.05
            
            # Update threat intelligence with new IOCs
            if intelligence_gathered:
                await self._update_threat_feeds([{
                    "type": "engagement_intelligence",
                    "data": intelligence_gathered,
                    "source": "engagement_feedback",
                    "engagement_id": engagement_id
                }])
            
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence from feedback: {e}")
    
    async def _handle_emergency_shutdown(self, alert_data: Dict[str, Any]):
        """Handle emergency shutdown alert"""
        try:
            self.logger.critical("Emergency shutdown alert received")
            
            # Stop processing new threats
            self.state["status"] = "emergency_shutdown"
            
            # Clear active sessions
            self.active_sessions.clear()
            self.threat_analysis_state.clear()
            
            # Notify all connected agents
            await self.agentcore_sdk.broadcast_message(
                message_type="emergency_shutdown_ack",
                payload={
                    "agent_id": self.agent_id,
                    "status": "shutdown_initiated",
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error handling emergency shutdown: {e}")
    
    async def _handle_threat_escalation(self, alert_data: Dict[str, Any]):
        """Handle threat escalation alert"""
        try:
            threat_level = alert_data.get("threat_level", "unknown")
            threat_data = alert_data.get("threat_data", {})
            
            self.logger.warning(f"Threat escalation received: {threat_level}")
            
            # Adjust detection thresholds for escalated threats
            if threat_level == "Critical":
                self.engagement_threshold = max(0.5, self.engagement_threshold - 0.2)
            elif threat_level == "High":
                self.engagement_threshold = max(0.6, self.engagement_threshold - 0.1)
            
            # Re-analyze recent threat data with new thresholds
            for analysis_id, analysis_state in self.threat_analysis_state.items():
                if analysis_state.get("status") == "completed":
                    result = analysis_state.get("result", {})
                    if result.get("overall_confidence", 0) >= self.engagement_threshold:
                        await self._publish_engagement_decision(result)
            
        except Exception as e:
            self.logger.error(f"Error handling threat escalation: {e}")
    
    async def _handle_system_compromise(self, alert_data: Dict[str, Any]):
        """Handle system compromise alert"""
        try:
            compromised_component = alert_data.get("component", "unknown")
            
            self.logger.critical(f"System compromise detected: {compromised_component}")
            
            # Increase threat detection sensitivity
            self.threat_threshold = max(0.3, self.threat_threshold - 0.3)
            self.engagement_threshold = max(0.4, self.engagement_threshold - 0.3)
            
            # Send high-priority alert
            await self.agentcore_sdk.broadcast_message(
                message_type="system_compromise_alert",
                payload={
                    "source_agent": self.agent_id,
                    "compromised_component": compromised_component,
                    "new_thresholds": {
                        "threat_threshold": self.threat_threshold,
                        "engagement_threshold": self.engagement_threshold
                    },
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error handling system compromise: {e}")
    
    async def _load_threat_feeds(self):
        """Load threat intelligence feeds"""
        try:
            # Initialize threat intelligence feeds
            self.threat_feeds = {
                "malicious_ips": [
                    "192.168.1.100", "10.0.0.50", "172.16.0.25",
                    "203.0.113.0", "198.51.100.0", "192.0.2.0"
                ],
                "known_malware": [
                    {"name": "Mimikatz", "hash": "a1b2c3d4e5f6", "family": "credential_dumper"},
                    {"name": "Cobalt Strike", "hash": "f6e5d4c3b2a1", "family": "backdoor"},
                    {"name": "PowerShell Empire", "hash": "1a2b3c4d5e6f", "family": "post_exploitation"}
                ],
                "attack_patterns": [
                    {"pattern": "brute_force_ssh", "indicators": ["multiple_failed_logins", "sequential_attempts"]},
                    {"pattern": "credential_stuffing", "indicators": ["username_enumeration", "password_spraying"]},
                    {"pattern": "lateral_movement", "indicators": ["smb_enumeration", "rdp_attempts", "wmi_execution"]}
                ],
                "suspicious_domains": [
                    "malicious-domain.com", "phishing-site.net", "c2-server.org"
                ],
                "threat_actors": [
                    {"name": "APT29", "ttps": ["T1078", "T1055", "T1027"], "confidence": 0.8},
                    {"name": "Lazarus", "ttps": ["T1566", "T1059", "T1105"], "confidence": 0.9}
                ]
            }
            
            # Load behavioral patterns for anomaly detection
            self.behavioral_patterns = {
                "normal_login_times": {"start": 8, "end": 18},  # Business hours
                "typical_session_duration": {"min": 300, "max": 3600},  # 5min to 1hr
                "common_commands": ["ls", "cd", "pwd", "cat", "grep", "ps", "top"],
                "suspicious_commands": ["nc", "ncat", "wget", "curl", "base64", "powershell"]
            }
            
            self.logger.info(f"Loaded {len(self.threat_feeds)} threat feed categories")
            
        except Exception as e:
            self.logger.error(f"Failed to load threat feeds: {e}")
            raise
    
    async def _initialize_models(self):
        """Initialize AI models for threat detection"""
        try:
            # Initialize threat analysis algorithms
            self.threat_algorithms = {
                "behavioral_analyzer": self._analyze_behavioral_patterns,
                "network_analyzer": self._analyze_network_patterns,
                "command_analyzer": self._analyze_command_patterns,
                "temporal_analyzer": self._analyze_temporal_patterns,
                "reputation_analyzer": self._analyze_reputation_data
            }
            
            # Initialize confidence scoring models
            self.confidence_models = {
                "threat_confidence": self._calculate_threat_confidence,
                "engagement_confidence": self._calculate_engagement_confidence,
                "attribution_confidence": self._calculate_attribution_confidence
            }
            
            # Initialize decision making framework
            self.decision_framework = {
                "engagement_criteria": {
                    "min_confidence": 0.75,
                    "threat_indicators": 3,
                    "behavioral_anomalies": 2
                },
                "escalation_criteria": {
                    "high_confidence": 0.9,
                    "known_threat_actor": True,
                    "critical_assets_targeted": True
                }
            }
            
            self.logger.info("AI threat detection models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize AI models: {e}")
            raise
    
    async def _analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze potential threat using comprehensive AI-powered analysis"""
        try:
            analysis_start_time = datetime.utcnow()
            
            # Step 1: Multi-algorithm threat analysis
            algorithm_results = {}
            for algorithm_name, algorithm_func in self.threat_algorithms.items():
                try:
                    result = await algorithm_func(threat_data)
                    algorithm_results[algorithm_name] = result
                except Exception as e:
                    self.logger.warning(f"Algorithm {algorithm_name} failed: {e}")
                    algorithm_results[algorithm_name] = {"confidence": 0.0, "indicators": []}
            
            # Step 2: MITRE ATT&CK technique mapping
            mitre_techniques = await self._map_to_mitre_attack(threat_data, algorithm_results)
            
            # Step 3: Confidence scoring using multiple models
            confidence_scores = {}
            for model_name, model_func in self.confidence_models.items():
                confidence_scores[model_name] = model_func(threat_data, algorithm_results, mitre_techniques)
            
            # Step 4: Overall threat assessment
            overall_confidence = self._calculate_overall_confidence(confidence_scores)
            threat_level = self._determine_threat_level(overall_confidence, algorithm_results)
            
            # Step 5: Engagement decision
            engagement_decision = await self._make_engagement_decision(
                threat_data, overall_confidence, threat_level, mitre_techniques
            )
            
            # Step 6: AI-powered contextual analysis
            ai_analysis = await self._perform_ai_analysis(threat_data, algorithm_results, mitre_techniques)
            
            # Compile comprehensive analysis result
            analysis_result = {
                "agent_id": self.agent_id,
                "analysis_timestamp": analysis_start_time.isoformat(),
                "processing_time_ms": (datetime.utcnow() - analysis_start_time).total_seconds() * 1000,
                
                # Core assessment
                "threat_level": threat_level,
                "overall_confidence": overall_confidence,
                "confidence_breakdown": confidence_scores,
                
                # Technical analysis
                "algorithm_results": algorithm_results,
                "mitre_techniques": mitre_techniques,
                "indicators_of_compromise": self._extract_iocs(threat_data),
                
                # Decision making
                "engagement_decision": engagement_decision,
                "engagement_rationale": engagement_decision.get("rationale", ""),
                "threshold_met": overall_confidence >= self.engagement_threshold,
                
                # AI insights
                "ai_analysis": ai_analysis,
                "recommendations": self._generate_recommendations(threat_level, mitre_techniques, engagement_decision),
                
                # Metadata
                "threat_data_hash": hashlib.md5(json.dumps(threat_data, sort_keys=True).encode()).hexdigest(),
                "analysis_version": "2.1.0"
            }
            
            # Log the analysis
            self.log_activity("comprehensive_threat_analysis", {
                "threat_level": threat_level,
                "confidence": overall_confidence,
                "engagement_decision": engagement_decision.get("decision"),
                "mitre_techniques_count": len(mitre_techniques),
                "processing_time_ms": analysis_result["processing_time_ms"]
            })
            
            # Send engagement alert if threshold is met
            if analysis_result["threshold_met"]:
                await self._send_engagement_alert(analysis_result)
            
            # Update threat intelligence with new patterns
            await self._update_threat_intelligence(threat_data, analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive threat analysis: {e}")
            self.error_count += 1
            raise
    
    async def _analyze_behavioral_patterns(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral patterns for anomalies"""
        indicators = []
        confidence = 0.0
        
        # Analyze login patterns
        if "login_attempts" in threat_data:
            failed_attempts = threat_data.get("failed_login_attempts", 0)
            if failed_attempts > 10:
                indicators.append("excessive_failed_logins")
                confidence += 0.3
        
        # Analyze session timing
        if "session_start_time" in threat_data:
            session_hour = datetime.fromisoformat(threat_data["session_start_time"]).hour
            normal_hours = self.behavioral_patterns["normal_login_times"]
            if not (normal_hours["start"] <= session_hour <= normal_hours["end"]):
                indicators.append("off_hours_activity")
                confidence += 0.2
        
        # Analyze command patterns
        if "commands" in threat_data:
            commands = threat_data["commands"]
            suspicious_count = sum(1 for cmd in commands if any(sus in cmd.lower() 
                                 for sus in self.behavioral_patterns["suspicious_commands"]))
            if suspicious_count > 0:
                indicators.append("suspicious_commands")
                confidence += min(suspicious_count * 0.15, 0.4)
        
        return {
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
            "analysis_type": "behavioral"
        }
    
    async def _analyze_network_patterns(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network traffic patterns"""
        indicators = []
        confidence = 0.0
        
        # Check source IP reputation
        source_ip = threat_data.get("source_ip")
        if source_ip and source_ip in self.threat_feeds["malicious_ips"]:
            indicators.append("known_malicious_ip")
            confidence += 0.6
        
        # Analyze connection patterns
        if "connection_count" in threat_data:
            conn_count = threat_data["connection_count"]
            if conn_count > 100:
                indicators.append("high_connection_volume")
                confidence += 0.3
        
        # Check for port scanning behavior
        if "destination_ports" in threat_data:
            ports = threat_data["destination_ports"]
            if len(ports) > 20:
                indicators.append("port_scanning")
                confidence += 0.4
        
        return {
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
            "analysis_type": "network"
        }
    
    async def _analyze_command_patterns(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze command execution patterns"""
        indicators = []
        confidence = 0.0
        
        commands = threat_data.get("commands", [])
        if not commands:
            return {"confidence": 0.0, "indicators": [], "analysis_type": "command"}
        
        # Check for reconnaissance commands
        recon_commands = ["whoami", "id", "uname", "ps", "netstat", "ifconfig", "ls -la"]
        recon_count = sum(1 for cmd in commands if any(recon in cmd.lower() for recon in recon_commands))
        if recon_count >= 3:
            indicators.append("reconnaissance_activity")
            confidence += 0.4
        
        # Check for privilege escalation attempts
        privesc_commands = ["sudo", "su", "chmod +s", "find / -perm"]
        privesc_count = sum(1 for cmd in commands if any(priv in cmd.lower() for priv in privesc_commands))
        if privesc_count > 0:
            indicators.append("privilege_escalation_attempts")
            confidence += 0.5
        
        # Check for persistence mechanisms
        persistence_commands = ["crontab", "systemctl", "service", "rc.local"]
        persistence_count = sum(1 for cmd in commands if any(pers in cmd.lower() for pers in persistence_commands))
        if persistence_count > 0:
            indicators.append("persistence_mechanisms")
            confidence += 0.3
        
        return {
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
            "analysis_type": "command",
            "command_count": len(commands)
        }
    
    async def _analyze_temporal_patterns(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal patterns and timing"""
        indicators = []
        confidence = 0.0
        
        # Analyze session duration
        if "session_duration" in threat_data:
            duration = threat_data["session_duration"]
            typical_range = self.behavioral_patterns["typical_session_duration"]
            if duration < typical_range["min"] or duration > typical_range["max"]:
                indicators.append("unusual_session_duration")
                confidence += 0.2
        
        # Analyze activity frequency
        if "activity_timestamps" in threat_data:
            timestamps = threat_data["activity_timestamps"]
            if len(timestamps) > 1:
                intervals = []
                for i in range(1, len(timestamps)):
                    prev_time = datetime.fromisoformat(timestamps[i-1])
                    curr_time = datetime.fromisoformat(timestamps[i])
                    intervals.append((curr_time - prev_time).total_seconds())
                
                # Check for automated/scripted behavior
                if len(set(intervals)) == 1:  # All intervals are identical
                    indicators.append("automated_behavior")
                    confidence += 0.4
        
        return {
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
            "analysis_type": "temporal"
        }
    
    async def _analyze_reputation_data(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze reputation and threat intelligence data"""
        indicators = []
        confidence = 0.0
        
        # Check IP reputation
        source_ip = threat_data.get("source_ip")
        if source_ip:
            if source_ip in self.threat_feeds["malicious_ips"]:
                indicators.append("known_malicious_ip")
                confidence += 0.7
        
        # Check for known malware signatures
        if "file_hashes" in threat_data:
            for file_hash in threat_data["file_hashes"]:
                for malware in self.threat_feeds["known_malware"]:
                    if malware["hash"] == file_hash:
                        indicators.append(f"known_malware_{malware['family']}")
                        confidence += 0.8
        
        # Check domain reputation
        if "domains" in threat_data:
            for domain in threat_data["domains"]:
                if domain in self.threat_feeds["suspicious_domains"]:
                    indicators.append("suspicious_domain")
                    confidence += 0.5
        
        return {
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
            "analysis_type": "reputation"
        }
    
    async def _map_to_mitre_attack(self, threat_data: Dict[str, Any], algorithm_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map detected behaviors to MITRE ATT&CK techniques"""
        detected_techniques = []
        
        # Collect all indicators from algorithm results
        all_indicators = []
        for result in algorithm_results.values():
            all_indicators.extend(result.get("indicators", []))
        
        # Map indicators to MITRE techniques
        technique_matches = defaultdict(list)
        
        for technique_id, patterns in self.technique_patterns.items():
            for pattern in patterns:
                for indicator in all_indicators:
                    if pattern in indicator:
                        technique_matches[technique_id].append(indicator)
        
        # Create technique objects with confidence scores
        for technique_id, matched_indicators in technique_matches.items():
            if technique_id in self.mitre_mappings:
                technique_info = self.mitre_mappings[technique_id]
                confidence = min(len(matched_indicators) * 0.3, 1.0)
                
                detected_techniques.append({
                    "technique_id": technique_id,
                    "technique_name": technique_info["name"],
                    "tactic": technique_info["tactic"],
                    "description": technique_info["description"],
                    "confidence": confidence,
                    "matched_indicators": matched_indicators,
                    "evidence": self._extract_technique_evidence(threat_data, matched_indicators)
                })
        
        # Sort by confidence
        detected_techniques.sort(key=lambda x: x["confidence"], reverse=True)
        
        return detected_techniques
    
    def _extract_technique_evidence(self, threat_data: Dict[str, Any], indicators: List[str]) -> Dict[str, Any]:
        """Extract evidence supporting MITRE technique detection"""
        evidence = {}
        
        # Extract relevant data based on indicators
        if "reconnaissance_activity" in indicators:
            evidence["commands"] = threat_data.get("commands", [])
        
        if "brute_force" in indicators or "failed_login" in indicators:
            evidence["failed_attempts"] = threat_data.get("failed_login_attempts", 0)
            evidence["login_timeline"] = threat_data.get("login_attempts", [])
        
        if "suspicious_commands" in indicators:
            evidence["suspicious_commands"] = [
                cmd for cmd in threat_data.get("commands", [])
                if any(sus in cmd.lower() for sus in self.behavioral_patterns["suspicious_commands"])
            ]
        
        return evidence
    
    def _calculate_threat_confidence(self, threat_data: Dict[str, Any], algorithm_results: Dict[str, Any], mitre_techniques: List[Dict[str, Any]]) -> float:
        """Calculate threat confidence score"""
        # Base confidence from algorithms
        algorithm_confidences = [result.get("confidence", 0.0) for result in algorithm_results.values()]
        base_confidence = sum(algorithm_confidences) / len(algorithm_confidences) if algorithm_confidences else 0.0
        
        # Boost from MITRE technique matches
        mitre_boost = min(len(mitre_techniques) * 0.1, 0.3)
        
        # Boost from high-confidence techniques
        high_conf_techniques = [t for t in mitre_techniques if t.get("confidence", 0) > 0.7]
        high_conf_boost = min(len(high_conf_techniques) * 0.15, 0.4)
        
        return min(base_confidence + mitre_boost + high_conf_boost, 1.0)
    
    def _calculate_engagement_confidence(self, threat_data: Dict[str, Any], algorithm_results: Dict[str, Any], mitre_techniques: List[Dict[str, Any]]) -> float:
        """Calculate confidence for engagement decision"""
        # Start with threat confidence
        threat_conf = self._calculate_threat_confidence(threat_data, algorithm_results, mitre_techniques)
        
        # Adjust based on engagement-specific factors
        engagement_factors = 0.0
        
        # Known threat actor patterns
        if any("known_malicious" in indicator for result in algorithm_results.values() 
               for indicator in result.get("indicators", [])):
            engagement_factors += 0.2
        
        # Multiple attack techniques
        if len(mitre_techniques) >= 3:
            engagement_factors += 0.15
        
        # Active reconnaissance
        if any("reconnaissance" in indicator for result in algorithm_results.values() 
               for indicator in result.get("indicators", [])):
            engagement_factors += 0.1
        
        return min(threat_conf + engagement_factors, 1.0)
    
    def _calculate_attribution_confidence(self, threat_data: Dict[str, Any], algorithm_results: Dict[str, Any], mitre_techniques: List[Dict[str, Any]]) -> float:
        """Calculate confidence for threat actor attribution"""
        attribution_confidence = 0.0
        
        # Check for known threat actor TTPs
        detected_technique_ids = [t["technique_id"] for t in mitre_techniques]
        
        for actor in self.threat_feeds["threat_actors"]:
            matching_ttps = set(actor["ttps"]) & set(detected_technique_ids)
            if matching_ttps:
                match_ratio = len(matching_ttps) / len(actor["ttps"])
                attribution_confidence = max(attribution_confidence, match_ratio * actor["confidence"])
        
        return attribution_confidence
    
    def _calculate_overall_confidence(self, confidence_scores: Dict[str, float]) -> float:
        """Calculate overall confidence from multiple models"""
        # Weighted average of confidence scores
        weights = {
            "threat_confidence": 0.4,
            "engagement_confidence": 0.4,
            "attribution_confidence": 0.2
        }
        
        weighted_sum = sum(confidence_scores.get(model, 0.0) * weight 
                          for model, weight in weights.items())
        
        return min(weighted_sum, 1.0)
    
    def _determine_threat_level(self, confidence: float, algorithm_results: Dict[str, Any]) -> str:
        """Determine threat level based on confidence and indicators"""
        # Count high-confidence indicators
        high_conf_indicators = sum(1 for result in algorithm_results.values() 
                                 if result.get("confidence", 0) > 0.7)
        
        if confidence >= 0.9 or high_conf_indicators >= 4:
            return "Critical"
        elif confidence >= 0.75 or high_conf_indicators >= 3:
            return "High"
        elif confidence >= 0.5 or high_conf_indicators >= 2:
            return "Medium"
        else:
            return "Low"
    
    async def _make_engagement_decision(self, threat_data: Dict[str, Any], confidence: float, 
                                      threat_level: str, mitre_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make intelligent engagement decision"""
        decision_factors = []
        decision_score = 0.0
        
        # Factor 1: Confidence threshold
        if confidence >= self.engagement_threshold:
            decision_factors.append("confidence_threshold_met")
            decision_score += 0.4
        
        # Factor 2: Threat level assessment
        threat_level_scores = {"Critical": 0.4, "High": 0.3, "Medium": 0.2, "Low": 0.1}
        decision_score += threat_level_scores.get(threat_level, 0.0)
        decision_factors.append(f"threat_level_{threat_level.lower()}")
        
        # Factor 3: Number of MITRE techniques
        technique_count = len(mitre_techniques)
        if technique_count >= 3:
            decision_factors.append("multiple_attack_techniques")
            decision_score += 0.2
        
        # Factor 4: Known threat actor indicators
        if any("known_malicious" in str(technique) for technique in mitre_techniques):
            decision_factors.append("known_threat_indicators")
            decision_score += 0.3
        
        # Factor 5: Active attack progression
        attack_progression_techniques = ["T1083", "T1057", "T1018", "T1021"]  # Discovery and lateral movement
        if any(t["technique_id"] in attack_progression_techniques for t in mitre_techniques):
            decision_factors.append("active_attack_progression")
            decision_score += 0.25
        
        # Make final decision
        engage = decision_score >= 0.6 and confidence >= self.engagement_threshold
        
        return {
            "decision": "engage" if engage else "monitor",
            "confidence": confidence,
            "decision_score": min(decision_score, 1.0),
            "factors": decision_factors,
            "rationale": self._generate_decision_rationale(engage, decision_factors, confidence, threat_level),
            "recommended_honeypot_types": self._recommend_honeypot_types(mitre_techniques) if engage else [],
            "monitoring_duration": 3600 if not engage else 0  # Monitor for 1 hour if not engaging
        }
    
    def _generate_decision_rationale(self, engage: bool, factors: List[str], confidence: float, threat_level: str) -> str:
        """Generate human-readable rationale for engagement decision"""
        if engage:
            return (f"Engagement recommended based on {threat_level} threat level "
                   f"with {confidence:.2f} confidence. Key factors: {', '.join(factors[:3])}")
        else:
            return (f"Monitoring recommended. Threat level: {threat_level}, "
                   f"confidence: {confidence:.2f}. Factors: {', '.join(factors[:3])}")
    
    def _recommend_honeypot_types(self, mitre_techniques: List[Dict[str, Any]]) -> List[str]:
        """Recommend appropriate honeypot types based on detected techniques"""
        honeypot_recommendations = []
        
        technique_ids = [t["technique_id"] for t in mitre_techniques]
        
        # SSH honeypot for command execution and lateral movement
        if any(tid in ["T1059", "T1021", "T1105"] for tid in technique_ids):
            honeypot_recommendations.append("ssh_honeypot")
        
        # Web admin portal for credential attacks
        if any(tid in ["T1078", "T1110", "T1190"] for tid in technique_ids):
            honeypot_recommendations.append("web_admin_portal")
        
        # Database honeypot for data access attempts
        if any(tid in ["T1005", "T1039", "T1041"] for tid in technique_ids):
            honeypot_recommendations.append("database_honeypot")
        
        # File share honeypot for discovery and collection
        if any(tid in ["T1083", "T1005", "T1039"] for tid in technique_ids):
            honeypot_recommendations.append("file_share_honeypot")
        
        return honeypot_recommendations or ["ssh_honeypot"]  # Default to SSH honeypot
    
    async def _perform_ai_analysis(self, threat_data: Dict[str, Any], algorithm_results: Dict[str, Any], 
                                 mitre_techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform AI-powered contextual analysis"""
        try:
            # Create comprehensive analysis prompt
            analysis_prompt = f"""
            Perform advanced threat analysis on the following security event:
            
            Threat Data: {json.dumps(threat_data, indent=2)}
            
            Algorithm Analysis Results: {json.dumps(algorithm_results, indent=2)}
            
            Detected MITRE ATT&CK Techniques: {json.dumps(mitre_techniques, indent=2)}
            
            Please provide:
            1. Threat actor profiling and attribution assessment
            2. Attack campaign analysis and objectives
            3. Risk assessment for potential damage
            4. Tactical recommendations for engagement
            5. Intelligence value assessment
            
            Format as JSON with fields: threat_actor_profile, campaign_analysis, risk_assessment, tactical_recommendations, intelligence_value
            """
            
            ai_result = await self.process_with_ai(analysis_prompt)
            
            # Parse AI response
            try:
                ai_analysis = json.loads(ai_result)
            except json.JSONDecodeError:
                ai_analysis = {
                    "threat_actor_profile": "Unknown - requires manual analysis",
                    "campaign_analysis": "Insufficient data for campaign attribution",
                    "risk_assessment": "Medium risk based on detected techniques",
                    "tactical_recommendations": ["Deploy appropriate honeypots", "Monitor for escalation"],
                    "intelligence_value": "Medium - standard attack patterns detected"
                }
            
            return ai_analysis
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return {
                "error": "AI analysis unavailable",
                "fallback_analysis": "Manual review recommended"
            }
    
    def _extract_iocs(self, threat_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract indicators of compromise from threat data"""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": [],
            "user_agents": [],
            "command_signatures": []
        }
        
        # Extract IP addresses
        if "source_ip" in threat_data:
            iocs["ip_addresses"].append(threat_data["source_ip"])
        
        # Extract domains
        if "domains" in threat_data:
            iocs["domains"].extend(threat_data["domains"])
        
        # Extract file hashes
        if "file_hashes" in threat_data:
            iocs["file_hashes"].extend(threat_data["file_hashes"])
        
        # Extract user agents
        if "user_agent" in threat_data:
            iocs["user_agents"].append(threat_data["user_agent"])
        
        # Extract command signatures
        if "commands" in threat_data:
            suspicious_commands = [
                cmd for cmd in threat_data["commands"]
                if any(sus in cmd.lower() for sus in self.behavioral_patterns["suspicious_commands"])
            ]
            iocs["command_signatures"].extend(suspicious_commands)
        
        return iocs
    
    def _generate_recommendations(self, threat_level: str, mitre_techniques: List[Dict[str, Any]], 
                                engagement_decision: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if engagement_decision["decision"] == "engage":
            recommendations.append("Deploy recommended honeypot environments")
            recommendations.append("Activate real-time monitoring and alerting")
            recommendations.append("Prepare incident response team for potential escalation")
        else:
            recommendations.append("Continue monitoring for 1 hour")
            recommendations.append("Update threat intelligence feeds")
            recommendations.append("Review detection rules for potential tuning")
        
        # Technique-specific recommendations
        technique_ids = [t["technique_id"] for t in mitre_techniques]
        
        if "T1110" in technique_ids:  # Brute Force
            recommendations.append("Implement account lockout policies")
        
        if "T1078" in technique_ids:  # Valid Accounts
            recommendations.append("Review account access logs")
        
        if "T1059" in technique_ids:  # Command and Scripting
            recommendations.append("Monitor command execution patterns")
        
        return recommendations
    
    async def _send_engagement_alert(self, analysis_result: Dict[str, Any]):
        """Send engagement alert to coordinator agent via AgentCore messaging"""
        try:
            # Use the new messaging system to publish engagement decision
            await self._publish_engagement_decision(analysis_result)
            
            # Also send traditional alert for logging
            alert_data = self.send_alert_tool(
                alert_type="engagement_decision",
                alert_message=f"Engagement decision: {analysis_result['engagement_decision']['decision']} "
                             f"(confidence: {analysis_result['overall_confidence']:.2f}, "
                             f"threat level: {analysis_result['threat_level']})",
                severity=analysis_result['threat_level'].lower()
            )
            
            self.logger.info(f"Engagement alert sent via AgentCore messaging: {alert_data['alert_id']}")
            return alert_data
            
        except Exception as e:
            self.logger.error(f"Failed to send engagement alert: {e}")
            # Fallback to traditional alert only
            alert_data = self.send_alert_tool(
                alert_type="engagement_decision_fallback",
                alert_message=f"Engagement decision (fallback): {analysis_result['engagement_decision']['decision']}",
                severity="high"
            )
            return alert_data
    
    async def _update_threat_intelligence(self, threat_data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Update threat intelligence with new patterns"""
        try:
            # Update behavioral baselines
            if analysis_result["overall_confidence"] > 0.8:
                threat_signature = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "threat_level": analysis_result["threat_level"],
                    "mitre_techniques": [t["technique_id"] for t in analysis_result["mitre_techniques"]],
                    "indicators": [],
                    "source_data_hash": analysis_result["threat_data_hash"]
                }
                
                # Collect indicators from all algorithms
                for result in analysis_result["algorithm_results"].values():
                    threat_signature["indicators"].extend(result.get("indicators", []))
                
                # Store in threat intelligence
                signature_id = hashlib.md5(json.dumps(threat_signature, sort_keys=True).encode()).hexdigest()
                self.threat_intelligence[signature_id] = threat_signature
                
                self.logger.info(f"Updated threat intelligence with signature: {signature_id}")
                
        except Exception as e:
            self.logger.error(f"Failed to update threat intelligence: {e}")
    
    async def _update_threat_feeds(self, feeds: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Update threat intelligence feeds with new data"""
        updated_count = 0
        new_indicators = 0
        
        try:
            for feed in feeds:
                feed_type = feed.get("type")
                feed_data = feed.get("data", [])
                feed_source = feed.get("source", "unknown")
                
                if feed_type in self.threat_feeds:
                    # Handle different data types for deduplication
                    existing_data = self.threat_feeds[feed_type]
                    
                    if feed_type in ["malicious_ips", "suspicious_domains"]:
                        # Simple string lists - use set for deduplication
                        existing_set = set(existing_data)
                        new_data = [item for item in feed_data if item not in existing_set]
                    else:
                        # Complex objects - use different deduplication logic
                        if feed_type == "known_malware":
                            existing_hashes = {item.get("hash") for item in existing_data if isinstance(item, dict)}
                            new_data = [item for item in feed_data 
                                      if isinstance(item, dict) and item.get("hash") not in existing_hashes]
                        elif feed_type == "attack_patterns":
                            existing_patterns = {item.get("pattern") for item in existing_data if isinstance(item, dict)}
                            new_data = [item for item in feed_data 
                                      if isinstance(item, dict) and item.get("pattern") not in existing_patterns]
                        else:
                            # Default: just append new data
                            new_data = feed_data
                    
                    if new_data:
                        self.threat_feeds[feed_type].extend(new_data)
                        new_indicators += len(new_data)
                        updated_count += 1
                        
                        self.logger.info(f"Added {len(new_data)} new indicators to {feed_type} from {feed_source}")
                
                # Update threat actor intelligence
                elif feed_type == "threat_actors":
                    for actor_data in feed_data:
                        actor_name = actor_data.get("name")
                        if actor_name:
                            # Update or add threat actor
                            existing_actor = next((a for a in self.threat_feeds["threat_actors"] 
                                                 if a["name"] == actor_name), None)
                            if existing_actor:
                                existing_actor.update(actor_data)
                            else:
                                self.threat_feeds["threat_actors"].append(actor_data)
                            updated_count += 1
            
            # Update feed metadata
            feed_update_info = {
                "updated_feeds": updated_count,
                "new_indicators": new_indicators,
                "total_feed_categories": len(self.threat_feeds),
                "last_update": datetime.utcnow().isoformat(),
                "feed_sizes": {k: len(v) for k, v in self.threat_feeds.items()}
            }
            
            self.logger.info(f"Threat feed update complete: {updated_count} feeds updated, {new_indicators} new indicators")
            
            return feed_update_info
            
        except Exception as e:
            self.logger.error(f"Failed to update threat feeds: {e}")
            raise
    
    def _get_agent_tools(self) -> List:
        """Get detection-specific tools"""
        base_tools = super()._get_agent_tools()
        detection_tools = [
            self.analyze_network_traffic_tool,
            self.check_reputation_tool,
            self.extract_iocs_tool,
            self.analyze_threat_comprehensive_tool,
            self.map_mitre_techniques_tool,
            self.calculate_threat_confidence_tool,
            self.make_engagement_decision_tool,
            self.update_threat_feeds_tool
        ]
        return base_tools + detection_tools
    
    @tool
    def analyze_network_traffic_tool(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network traffic for anomalies"""
        # Simplified analysis - in reality would use ML models
        suspicious_indicators = []
        
        # Check for suspicious patterns
        if traffic_data.get("packet_count", 0) > 10000:
            suspicious_indicators.append("High packet volume")
        
        if traffic_data.get("unique_destinations", 0) > 100:
            suspicious_indicators.append("High destination diversity")
        
        risk_score = len(suspicious_indicators) * 25
        
        return {
            "risk_score": min(risk_score, 100),
            "suspicious_indicators": suspicious_indicators,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def check_reputation_tool(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address reputation"""
        # In a real implementation, this would query threat intelligence APIs
        is_malicious = ip_address in ["192.168.1.100", "10.0.0.50"]  # Mock malicious IPs
        
        return {
            "ip_address": ip_address,
            "is_malicious": is_malicious,
            "reputation_score": 10 if is_malicious else 90,
            "sources": ["mock_threat_feed"],
            "check_timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def extract_iocs_tool(self, text_data: str) -> Dict[str, Any]:
        """Extract indicators of compromise from text"""
        import re
        
        # Simple regex patterns for IOCs
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b'
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        
        ips = re.findall(ip_pattern, text_data)
        domains = re.findall(domain_pattern, text_data)
        hashes = re.findall(hash_pattern, text_data)
        
        return {
            "ip_addresses": list(set(ips)),
            "domains": list(set(domains)),
            "hashes": list(set(hashes)),
            "extraction_timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def analyze_threat_comprehensive_tool(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive threat analysis using all available algorithms"""
        try:
            # Run the comprehensive analysis synchronously
            import asyncio
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self._analyze_threat(threat_data))
            return result
        except Exception as e:
            return {
                "error": f"Analysis failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    @tool
    def map_mitre_techniques_tool(self, threat_indicators: List[str]) -> List[Dict[str, Any]]:
        """Map threat indicators to MITRE ATT&CK techniques"""
        mapped_techniques = []
        
        for technique_id, patterns in self.technique_patterns.items():
            matches = [indicator for indicator in threat_indicators 
                      if any(pattern in indicator for pattern in patterns)]
            
            if matches and technique_id in self.mitre_mappings:
                technique_info = self.mitre_mappings[technique_id]
                mapped_techniques.append({
                    "technique_id": technique_id,
                    "technique_name": technique_info["name"],
                    "tactic": technique_info["tactic"],
                    "matched_indicators": matches,
                    "confidence": min(len(matches) * 0.3, 1.0)
                })
        
        return sorted(mapped_techniques, key=lambda x: x["confidence"], reverse=True)
    
    @tool
    def calculate_threat_confidence_tool(self, threat_data: Dict[str, Any], 
                                       algorithm_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat confidence score"""
        # Simplified confidence calculation for tool use
        confidences = [result.get("confidence", 0.0) for result in algorithm_results.values()]
        base_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        # Boost factors
        indicator_count = sum(len(result.get("indicators", [])) for result in algorithm_results.values())
        indicator_boost = min(indicator_count * 0.1, 0.3)
        
        final_confidence = min(base_confidence + indicator_boost, 1.0)
        
        return {
            "confidence_score": final_confidence,
            "base_confidence": base_confidence,
            "indicator_boost": indicator_boost,
            "total_indicators": indicator_count,
            "calculation_timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def make_engagement_decision_tool(self, confidence: float, threat_level: str, 
                                    technique_count: int) -> Dict[str, Any]:
        """Make engagement decision based on threat analysis"""
        decision_score = 0.0
        factors = []
        
        # Confidence factor
        if confidence >= self.engagement_threshold:
            decision_score += 0.4
            factors.append("confidence_threshold_met")
        
        # Threat level factor
        level_scores = {"Critical": 0.4, "High": 0.3, "Medium": 0.2, "Low": 0.1}
        decision_score += level_scores.get(threat_level, 0.0)
        factors.append(f"threat_level_{threat_level.lower()}")
        
        # Technique count factor
        if technique_count >= 3:
            decision_score += 0.2
            factors.append("multiple_techniques")
        
        engage = decision_score >= 0.6 and confidence >= self.engagement_threshold
        
        return {
            "decision": "engage" if engage else "monitor",
            "decision_score": decision_score,
            "confidence": confidence,
            "factors": factors,
            "rationale": f"{'Engage' if engage else 'Monitor'} based on {confidence:.2f} confidence and {threat_level} threat level",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def update_threat_feeds_tool(self, feed_type: str, new_indicators: List[str], 
                               source: str = "manual") -> Dict[str, Any]:
        """Update threat intelligence feeds with new indicators"""
        if feed_type not in self.threat_feeds:
            return {
                "error": f"Unknown feed type: {feed_type}",
                "available_types": list(self.threat_feeds.keys())
            }
        
        # Deduplicate and add new indicators
        if feed_type in ["malicious_ips", "suspicious_domains"]:
            existing_indicators = set(self.threat_feeds[feed_type])
            new_unique_indicators = [ind for ind in new_indicators if ind not in existing_indicators]
        else:
            # For complex feed types, just add all indicators
            new_unique_indicators = new_indicators
        
        if new_unique_indicators:
            self.threat_feeds[feed_type].extend(new_unique_indicators)
            
            self.logger.info(f"Added {len(new_unique_indicators)} new indicators to {feed_type} from {source}")
            
            return {
                "feed_type": feed_type,
                "added_indicators": len(new_unique_indicators),
                "total_indicators": len(self.threat_feeds[feed_type]),
                "source": source,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            return {
                "feed_type": feed_type,
                "added_indicators": 0,
                "message": "No new indicators to add",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # AgentCore Messaging Tools
    
    @tool
    def send_engagement_decision_tool(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Send engagement decision to coordinator agent via AgentCore messaging"""
        try:
            # This will be executed asynchronously
            asyncio.create_task(self._publish_engagement_decision(analysis_result))
            
            return {
                "status": "engagement_decision_sent",
                "decision": analysis_result["engagement_decision"]["decision"],
                "confidence": analysis_result["overall_confidence"],
                "threat_level": analysis_result["threat_level"],
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    @tool
    def get_messaging_status_tool(self) -> Dict[str, Any]:
        """Get AgentCore messaging system status"""
        return {
            "agentcore_sdk_initialized": self.agentcore_sdk is not None,
            "message_handlers_registered": self.message_handlers_registered,
            "active_analyses": len(self.threat_analysis_state),
            "pending_engagements": len([e for e in self.engagement_decisions.values() 
                                      if not e.get("feedback_received", False)]),
            "retry_queue_size": len(self.message_retry_count),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def send_threat_feed_update_tool(self, target_agent: str, feed_type: str, 
                                   feed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send threat feed update to another agent"""
        try:
            # This will be executed asynchronously
            asyncio.create_task(self._send_message_with_retry(
                to_agent=target_agent,
                message_type="threat_feed_update",
                payload={
                    "feed_type": feed_type,
                    "feed_data": feed_data,
                    "source_agent": self.agent_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ))
            
            return {
                "status": "threat_feed_update_sent",
                "target_agent": target_agent,
                "feed_type": feed_type,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    @tool
    def request_state_sync_tool(self, target_agent: str) -> Dict[str, Any]:
        """Request state synchronization from another agent"""
        try:
            # This will be executed asynchronously
            asyncio.create_task(self._send_message_with_retry(
                to_agent=target_agent,
                message_type="state_sync_request",
                payload={
                    "requesting_agent": self.agent_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ))
            
            return {
                "status": "state_sync_requested",
                "target_agent": target_agent,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    @tool
    def broadcast_system_alert_tool(self, alert_type: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Broadcast system alert to all agents"""
        try:
            # This will be executed asynchronously
            asyncio.create_task(self.agentcore_sdk.broadcast_message(
                message_type="system_alert",
                payload={
                    "alert_type": alert_type,
                    "alert_data": alert_data,
                    "source_agent": self.agent_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ) if self.agentcore_sdk else None)
            
            return {
                "status": "system_alert_broadcasted",
                "alert_type": alert_type,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

# AgentCore Runtime entry point
def create_detection_agent_app():
    """Create AgentCore Runtime app for the Detection Agent"""
    agent = DetectionAgent()
    return agent.create_agentcore_app()

if __name__ == "__main__":
    # For local testing
    async def main():
        agent = DetectionAgent()
        await agent.start()
        
        # Test threat analysis
        test_threat = {
            "source_ip": "192.168.1.100",
            "destination_port": 22,
            "protocol": "SSH",
            "failed_attempts": 50,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await agent._analyze_threat(test_threat)
        print(f"Analysis result: {json.dumps(result, indent=2)}")
        
        await agent.stop()
    
    asyncio.run(main())