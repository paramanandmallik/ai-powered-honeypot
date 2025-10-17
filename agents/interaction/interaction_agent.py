"""
Interaction Agent for AI-Powered Honeypot System
Handles real-time attacker interactions within honeypots using AI-powered responses.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from uuid import uuid4

from ..base_agent import BaseAgent, tool
from .synthetic_data_generator import SyntheticDataGenerator
from .security_controls import SecurityControls


class InteractionAgent(BaseAgent):
    """AI-powered agent for handling attacker interactions in honeypots"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        capabilities = [
            "natural_language_processing",
            "persona_management", 
            "context_awareness",
            "realistic_response_generation",
            "synthetic_data_generation",
            "security_isolation"
        ]
        
        super().__init__("interaction", capabilities, config)
        
        # Interaction-specific state
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.personas: Dict[str, Dict[str, Any]] = {}
        self.conversation_contexts: Dict[str, List[Dict[str, Any]]] = {}
        
        # Initialize components
        self.synthetic_generator = SyntheticDataGenerator()
        self.security_controls = SecurityControls(config)
        
        # Initialize default personas
        self._initialize_personas()
        
        self.logger.info("Interaction Agent initialized with AI-powered interaction engine")
    
    def _initialize_personas(self):
        """Initialize default system administrator personas with enhanced attributes"""
        self.personas = {
            "junior_admin": {
                "name": "Alex Thompson",
                "role": "Junior System Administrator", 
                "personality": "helpful but inexperienced, sometimes makes mistakes",
                "knowledge_level": "basic",
                "response_style": "casual, uses simple language, asks for help",
                "typical_responses": [
                    "Let me check that for you...",
                    "I'm not sure about that, let me ask my supervisor",
                    "That's weird, it should work...",
                    "Hmm, I think I need to look that up",
                    "Sorry, I'm still learning this system"
                ],
                "behavioral_traits": {
                    "uncertainty_frequency": 0.3,  # Often uncertain
                    "help_seeking": 0.4,  # Frequently asks for help
                    "mistake_probability": 0.2,  # Sometimes makes small mistakes
                    "technical_depth": 0.3,  # Limited technical depth
                    "response_delay": "normal"  # Normal response time
                },
                "knowledge_domains": {
                    "basic_commands": 0.8,
                    "advanced_commands": 0.3,
                    "security_procedures": 0.4,
                    "network_operations": 0.2,
                    "database_management": 0.1
                },
                "conversation_patterns": {
                    "greeting_style": "friendly and eager",
                    "error_handling": "apologetic and seeks guidance",
                    "technical_explanations": "simple and sometimes incomplete",
                    "escalation_tendency": "high - often escalates to seniors"
                }
            },
            "senior_admin": {
                "name": "Sarah Chen",
                "role": "Senior System Administrator",
                "personality": "experienced, cautious, follows procedures",
                "knowledge_level": "advanced", 
                "response_style": "professional, detailed explanations, security-conscious",
                "typical_responses": [
                    "I need to verify your authorization first",
                    "That requires elevated privileges",
                    "Let me check the security logs...",
                    "According to our procedures, we need to...",
                    "I'll need to document this request"
                ],
                "behavioral_traits": {
                    "uncertainty_frequency": 0.1,  # Rarely uncertain
                    "help_seeking": 0.1,  # Rarely needs help
                    "mistake_probability": 0.05,  # Very few mistakes
                    "technical_depth": 0.8,  # High technical depth
                    "response_delay": "thoughtful"  # Takes time to consider
                },
                "knowledge_domains": {
                    "basic_commands": 0.95,
                    "advanced_commands": 0.85,
                    "security_procedures": 0.9,
                    "network_operations": 0.7,
                    "database_management": 0.6
                },
                "conversation_patterns": {
                    "greeting_style": "professional and methodical",
                    "error_handling": "systematic troubleshooting approach",
                    "technical_explanations": "detailed and accurate",
                    "escalation_tendency": "low - handles most issues independently"
                }
            },
            "security_admin": {
                "name": "Mike Rodriguez", 
                "role": "Security Administrator",
                "personality": "suspicious, thorough, security-focused",
                "knowledge_level": "expert",
                "response_style": "formal, asks many questions, very cautious",
                "typical_responses": [
                    "I need to see proper documentation for that request",
                    "This activity will be logged and reviewed",
                    "Security policy requires additional verification",
                    "What is your business justification for this access?",
                    "I'll need to escalate this to the security team"
                ],
                "behavioral_traits": {
                    "uncertainty_frequency": 0.05,  # Almost never uncertain
                    "help_seeking": 0.05,  # Rarely needs help
                    "mistake_probability": 0.02,  # Almost no mistakes
                    "technical_depth": 0.95,  # Expert level depth
                    "response_delay": "careful"  # Very careful responses
                },
                "knowledge_domains": {
                    "basic_commands": 0.98,
                    "advanced_commands": 0.95,
                    "security_procedures": 0.98,
                    "network_operations": 0.9,
                    "database_management": 0.8
                },
                "conversation_patterns": {
                    "greeting_style": "formal and security-focused",
                    "error_handling": "security-first approach with documentation",
                    "technical_explanations": "precise and security-oriented",
                    "escalation_tendency": "medium - escalates security concerns"
                }
            },
            "database_admin": {
                "name": "Jennifer Liu",
                "role": "Database Administrator",
                "personality": "detail-oriented, methodical, data-focused",
                "knowledge_level": "expert",
                "response_style": "precise, data-driven, asks about specifics",
                "typical_responses": [
                    "Which database schema are you referring to?",
                    "I need to check the query performance first",
                    "Let me verify the data integrity",
                    "That operation requires a backup first",
                    "I'll need to review the transaction logs"
                ],
                "behavioral_traits": {
                    "uncertainty_frequency": 0.08,
                    "help_seeking": 0.1,
                    "mistake_probability": 0.03,
                    "technical_depth": 0.9,
                    "response_delay": "analytical"
                },
                "knowledge_domains": {
                    "basic_commands": 0.7,
                    "advanced_commands": 0.6,
                    "security_procedures": 0.7,
                    "network_operations": 0.4,
                    "database_management": 0.98
                },
                "conversation_patterns": {
                    "greeting_style": "professional and data-focused",
                    "error_handling": "systematic analysis with data validation",
                    "technical_explanations": "detailed with database specifics",
                    "escalation_tendency": "low - expert in database domain"
                }
            },
            "network_admin": {
                "name": "David Park",
                "role": "Network Administrator", 
                "personality": "systematic, infrastructure-focused, connectivity-minded",
                "knowledge_level": "advanced",
                "response_style": "technical, network-centric, troubleshooting-oriented",
                "typical_responses": [
                    "Let me check the network topology first",
                    "I need to verify the routing tables",
                    "That might be a firewall configuration issue",
                    "I'll need to trace the network path",
                    "Let me check the switch port status"
                ],
                "behavioral_traits": {
                    "uncertainty_frequency": 0.12,
                    "help_seeking": 0.15,
                    "mistake_probability": 0.08,
                    "technical_depth": 0.85,
                    "response_delay": "diagnostic"
                },
                "knowledge_domains": {
                    "basic_commands": 0.8,
                    "advanced_commands": 0.7,
                    "security_procedures": 0.6,
                    "network_operations": 0.95,
                    "database_management": 0.3
                },
                "conversation_patterns": {
                    "greeting_style": "technical and infrastructure-focused",
                    "error_handling": "network diagnostic approach",
                    "technical_explanations": "network-centric with topology details",
                    "escalation_tendency": "medium - escalates non-network issues"
                }
            }
        }
        
        # Initialize persona selection weights based on honeypot types
        self.persona_selection_weights = {
            "ssh": {
                "senior_admin": 0.4,
                "junior_admin": 0.3,
                "security_admin": 0.2,
                "network_admin": 0.1
            },
            "web_admin": {
                "junior_admin": 0.4,
                "senior_admin": 0.3,
                "security_admin": 0.3
            },
            "database": {
                "database_admin": 0.6,
                "senior_admin": 0.3,
                "security_admin": 0.1
            },
            "file_share": {
                "senior_admin": 0.4,
                "junior_admin": 0.3,
                "security_admin": 0.3
            },
            "email": {
                "security_admin": 0.5,
                "senior_admin": 0.3,
                "junior_admin": 0.2
            }
        }
    

    
    async def initialize(self):
        """Initialize the Interaction Agent"""
        self.logger.info("Initializing AI-powered interaction engine...")
        
        # Initialize AI models for different interaction types
        await self._initialize_ai_models()
        
        # Load conversation templates
        await self._load_conversation_templates()
        
        self.state["status"] = "ready"
        self.logger.info("Interaction Agent initialization complete")
    
    async def cleanup(self):
        """Cleanup agent resources"""
        self.logger.info("Cleaning up Interaction Agent...")
        
        # Terminate all active sessions
        for session_id in list(self.active_sessions.keys()):
            await self._terminate_session(session_id, "agent_shutdown")
        
        self.logger.info("Interaction Agent cleanup complete")
    
    async def _initialize_ai_models(self):
        """Initialize AI models for different interaction scenarios"""
        # Initialize specialized AI models for different honeypot types
        self.ai_models = {
            "ssh_interaction": {
                "model_type": "command_line_nlp",
                "context_window": 2048,
                "temperature": 0.7,
                "specialized_prompts": {
                    "system_admin": "You are a system administrator responding to SSH commands",
                    "security_focused": "You are security-conscious and ask verification questions",
                    "helpful_junior": "You are helpful but sometimes uncertain about advanced topics"
                }
            },
            "web_interaction": {
                "model_type": "web_response_nlp", 
                "context_window": 1024,
                "temperature": 0.6,
                "specialized_prompts": {
                    "admin_portal": "You manage a corporate admin web portal",
                    "error_handling": "You provide realistic error messages and troubleshooting",
                    "authentication": "You handle login attempts and user management"
                }
            },
            "database_interaction": {
                "model_type": "sql_response_nlp",
                "context_window": 1536,
                "temperature": 0.5,
                "specialized_prompts": {
                    "dba_expert": "You are a database administrator with deep SQL knowledge",
                    "query_helper": "You help with SQL queries and database operations",
                    "security_aware": "You are cautious about database security and permissions"
                }
            },
            "email_interaction": {
                "model_type": "email_conversation_nlp",
                "context_window": 2048,
                "temperature": 0.8,
                "specialized_prompts": {
                    "corporate_email": "You handle corporate email communications professionally",
                    "it_support": "You provide IT support through email interactions",
                    "executive_assistant": "You manage executive communications and scheduling"
                }
            }
        }
        
        # Initialize conversation context tracking
        self.context_tracking = {
            "max_context_length": 10,  # Keep last 10 interactions
            "context_decay_factor": 0.9,  # Reduce importance of older context
            "persona_consistency_weight": 0.8,  # How much to weight persona consistency
            "topic_coherence_weight": 0.7  # How much to weight topic coherence
        }
    
    async def _load_conversation_templates(self):
        """Load conversation templates for different scenarios"""
        self.conversation_templates = {
            "login_attempt": {
                "success": "Login successful. Welcome {username}!",
                "failure": "Login failed. Invalid credentials.",
                "locked": "Account locked due to multiple failed attempts."
            },
            "command_execution": {
                "success": "Command executed successfully.",
                "permission_denied": "Permission denied. Insufficient privileges.",
                "not_found": "Command not found or file does not exist."
            },
            "file_access": {
                "success": "File accessed successfully.",
                "not_found": "File not found.",
                "permission_denied": "Access denied. Check file permissions."
            }
        }
    
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process interaction messages from attackers"""
        try:
            message_type = message.get("type")
            session_id = message.get("session_id")
            
            if message_type == "start_interaction":
                return await self._start_interaction(message)
            elif message_type == "attacker_input":
                return await self._process_attacker_input(session_id, message)
            elif message_type == "terminate_session":
                return await self._terminate_session(session_id, message.get("reason", "manual"))
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            self.error_count += 1
            return {"error": str(e)}
    
    async def _start_interaction(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Start a new attacker interaction session"""
        session_id = str(uuid4())
        honeypot_type = message.get("honeypot_type", "ssh")
        attacker_ip = message.get("attacker_ip", "unknown")
        
        # Select appropriate persona based on honeypot type
        persona_key = self._select_persona(honeypot_type)
        persona = self.personas[persona_key]
        
        # Initialize session
        session = {
            "session_id": session_id,
            "honeypot_type": honeypot_type,
            "attacker_ip": attacker_ip,
            "persona": persona,
            "start_time": datetime.utcnow().isoformat(),
            "interaction_count": 0,
            "context": {
                "current_directory": "/home/admin" if honeypot_type == "ssh" else "/",
                "logged_in_user": persona["name"].lower().replace(" ", ""),
                "system_state": "normal"
            },
            "flags": {
                "suspicious_activity": False,
                "escalation_required": False,
                "real_data_detected": False
            }
        }
        
        self.active_sessions[session_id] = session
        self.conversation_contexts[session_id] = []
        
        # Update metrics
        self.update_active_sessions(len(self.active_sessions))
        self.increment_message_count("start_interaction")
        
        # Generate initial greeting
        greeting = await self._generate_initial_greeting(session)
        
        self.logger.info(f"Started interaction session {session_id} for {honeypot_type} honeypot")
        
        return {
            "session_id": session_id,
            "persona": persona,
            "initial_response": greeting,
            "status": "active"
        }
    
    def _select_persona(self, honeypot_type: str) -> str:
        """Select appropriate persona based on honeypot type with weighted randomization"""
        import random
        
        # Get weights for this honeypot type
        weights = self.persona_selection_weights.get(honeypot_type, {
            "senior_admin": 0.4,
            "junior_admin": 0.4,
            "security_admin": 0.2
        })
        
        # Create weighted selection
        personas = list(weights.keys())
        probabilities = list(weights.values())
        
        # Normalize probabilities
        total_weight = sum(probabilities)
        if total_weight > 0:
            probabilities = [p / total_weight for p in probabilities]
        else:
            # Fallback to equal weights
            probabilities = [1.0 / len(personas) for _ in personas]
        
        # Select persona using weighted random choice
        selected_persona = random.choices(personas, weights=probabilities)[0]
        
        # Ensure selected persona exists
        if selected_persona not in self.personas:
            selected_persona = "senior_admin"  # Safe fallback
        
        return selected_persona
    
    async def _generate_initial_greeting(self, session: Dict[str, Any]) -> str:
        """Generate initial greeting based on honeypot type and persona"""
        honeypot_type = session["honeypot_type"]
        persona = session["persona"]
        
        greeting_prompts = {
            "ssh": f"You are {persona['name']}, a {persona['role']}. Generate a realistic SSH login banner and prompt.",
            "web_admin": f"You are {persona['name']}, a {persona['role']}. Generate a welcome message for an admin portal.",
            "database": f"You are {persona['name']}, a {persona['role']}. Generate a database connection welcome message.",
            "file_share": f"You are {persona['name']}, a {persona['role']}. Generate a file server welcome message.",
            "email": f"You are {persona['name']}, a {persona['role']}. Generate an email server login prompt."
        }
        
        prompt = greeting_prompts.get(honeypot_type, "Generate a generic system welcome message.")
        
        # Use AI to generate contextual greeting
        greeting = await self.process_with_ai(
            f"{prompt}\n\nPersonality: {persona['personality']}\nStyle: {persona['response_style']}\n\nGenerate a brief, realistic greeting (1-2 lines)."
        )
        
        return greeting.strip()
    
    async def _process_attacker_input(self, session_id: str, message: Dict[str, Any]) -> Dict[str, Any]:
        """Process input from attacker and generate AI-powered response"""
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        attacker_input = message.get("input", "")
        
        # Security checks
        security_result = await self._perform_security_checks(session_id, attacker_input)
        if security_result["escalate"]:
            return await self._handle_escalation(session_id, security_result)
        
        # Update conversation context
        self.conversation_contexts[session_id].append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": "attacker_input",
            "content": attacker_input
        })
        
        # Generate AI response with synthetic data
        response = await self._generate_ai_response(session, attacker_input)
        
        # Apply isolation controls if needed
        if self._requires_command_execution(attacker_input):
            isolation_result = await self.security_controls.enforce_isolation(attacker_input, session)
            if not isolation_result["allowed"]:
                response = f"Error: {isolation_result['blocked_reason']}"
        
        # Update conversation context with response
        self.conversation_contexts[session_id].append({
            "timestamp": datetime.utcnow().isoformat(), 
            "type": "agent_response",
            "content": response
        })
        
        # Track conversation context for better continuity
        await self._track_conversation_context(session_id, attacker_input, response)
        
        # Update session metrics
        session["interaction_count"] += 1
        session["last_activity"] = datetime.utcnow().isoformat()
        
        self.increment_message_count("attacker_input")
        
        return {
            "session_id": session_id,
            "response": response,
            "context_updated": True,
            "conversation_state": session.get("conversation_state", {})
        }
    
    async def _perform_security_checks(self, session_id: str, input_text: str) -> Dict[str, Any]:
        """Perform comprehensive security checks on attacker input"""
        session = self.active_sessions[session_id]
        
        # Perform comprehensive security scan
        comprehensive_scan = await self.security_controls.comprehensive_security_scan(session, input_text)
        
        # Extract individual results for backward compatibility
        real_data_result = {"real_data_detected": False, "risk_level": "low"}
        suspicious_activity = {"suspicious_activity_detected": False, "threat_level": "low"}
        escalation_check = {"escalation_required": False}
        
        # Process scan results
        for violation in comprehensive_scan.get("security_violations", []):
            if violation["type"] == "real_data_detected":
                real_data_result = violation["details"]
            elif violation["type"] == "suspicious_activity":
                suspicious_activity = violation["details"]
            elif violation["type"] == "escalation_triggered":
                escalation_check = violation["details"]
        
        # Update session flags based on comprehensive scan
        if comprehensive_scan["overall_risk_level"] in ["high", "critical"]:
            session["flags"]["suspicious_activity"] = True
        
        if real_data_result["real_data_detected"]:
            session["flags"]["real_data_detected"] = True
        
        if escalation_check["escalation_required"] or comprehensive_scan["immediate_escalation_required"]:
            session["flags"]["escalation_required"] = True
        
        # Implement session isolation if high risk detected
        if comprehensive_scan["overall_risk_level"] == "high":
            await self.security_controls.implement_session_isolation(session_id, "enhanced")
        elif comprehensive_scan["overall_risk_level"] == "critical":
            await self.security_controls.implement_session_isolation(session_id, "maximum")
        
        return {
            "escalate": comprehensive_scan["immediate_escalation_required"],
            "real_data_detected": real_data_result["real_data_detected"],
            "escalation_triggered": escalation_check["escalation_required"],
            "risk_level": comprehensive_scan["overall_risk_level"],
            "suspicious_activity": suspicious_activity,
            "escalation_details": escalation_check,
            "comprehensive_scan": comprehensive_scan,
            "security_violations": comprehensive_scan.get("security_violations", []),
            "recommended_actions": comprehensive_scan.get("recommended_actions", [])
        }
    
    async def _handle_escalation(self, session_id: str, security_result: Dict[str, Any]) -> Dict[str, Any]:
        """Handle security escalation with enhanced response procedures"""
        session = self.active_sessions[session_id]
        
        escalation_data = {
            "session_id": session_id,
            "escalation_type": "security_violation",
            "details": security_result,
            "timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": session.get("attacker_ip"),
            "honeypot_type": session.get("honeypot_type"),
            "risk_level": security_result.get("risk_level", "unknown"),
            "security_violations": security_result.get("security_violations", []),
            "recommended_actions": security_result.get("recommended_actions", [])
        }
        
        # Log comprehensive escalation details
        self.logger.warning(f"Security escalation for session {session_id}: {security_result}")
        self.logger.error(f"SECURITY_ESCALATION: Security violation detected in session {session_id}")
        self.logger.error(f"Security details: {security_result}")
        
        # Determine escalation response based on risk level and violations
        response_actions = []
        
        # Handle critical security violations
        if security_result["real_data_detected"]:
            # Immediate emergency shutdown for real data detection
            shutdown_result = await self.security_controls.emergency_shutdown("real_data_detected", session_id)
            response_actions.append("emergency_shutdown_executed")
            escalation_data["shutdown_details"] = shutdown_result
            
            # Terminate session with forensic preservation
            termination_result = await self.security_controls.implement_emergency_termination(
                session_id, "real_data_detected", immediate=True
            )
            response_actions.append("session_terminated_with_forensics")
            escalation_data["termination_details"] = termination_result
            
            # Remove from active sessions
            await self._terminate_session(session_id, "real_data_detected")
        
        # Handle immediate threat escalations
        elif security_result.get("risk_level") == "critical" or \
             security_result.get("escalation_details", {}).get("escalation_level") == "immediate":
            
            # Implement maximum containment
            containment_result = await self.security_controls.implement_advanced_containment(
                session_id, "maximum"
            )
            response_actions.append("maximum_containment_applied")
            escalation_data["containment_details"] = containment_result
            
            # Check if emergency shutdown is recommended
            if "emergency_shutdown" in security_result.get("recommended_actions", []):
                shutdown_result = await self.security_controls.emergency_shutdown("immediate_threat", session_id)
                response_actions.append("emergency_shutdown_executed")
                escalation_data["shutdown_details"] = shutdown_result
                
                await self._terminate_session(session_id, "immediate_threat")
            else:
                # Enhanced monitoring and potential termination
                response_actions.append("enhanced_monitoring_activated")
        
        # Handle high-risk situations
        elif security_result.get("risk_level") == "high":
            # Implement enhanced containment
            containment_result = await self.security_controls.implement_advanced_containment(
                session_id, "enhanced"
            )
            response_actions.append("enhanced_containment_applied")
            escalation_data["containment_details"] = containment_result
            
            # Check for pivot attempts
            if any(v["type"] == "pivot_attempt" for v in security_result.get("security_violations", [])):
                # Implement forensic containment for pivot attempts
                forensic_result = await self.security_controls.implement_advanced_containment(
                    session_id, "forensic"
                )
                response_actions.append("forensic_containment_applied")
                escalation_data["forensic_details"] = forensic_result
        
        # Handle medium-risk situations
        elif security_result.get("risk_level") == "medium":
            # Standard enhanced monitoring
            response_actions.append("enhanced_monitoring_enabled")
        
        escalation_data["response_actions"] = response_actions
        
        return {
            "session_id": session_id,
            "escalation": escalation_data,
            "action": "comprehensive_security_response_executed",
            "response_actions": response_actions
        }
    
    async def _generate_ai_response(self, session: Dict[str, Any], attacker_input: str) -> str:
        """Generate AI-powered response to attacker input"""
        persona = session["persona"]
        honeypot_type = session["honeypot_type"]
        context = session["context"]
        conversation_history = self.conversation_contexts[session["session_id"]]
        
        # Get AI model configuration for this honeypot type
        ai_config = self.ai_models.get(f"{honeypot_type}_interaction", self.ai_models["ssh_interaction"])
        
        # Analyze input intent and context
        input_analysis = await self._analyze_input_intent(attacker_input, conversation_history)
        
        # Select appropriate specialized prompt based on input analysis
        specialized_prompt = self._select_specialized_prompt(ai_config, input_analysis, persona)
        
        # Build enhanced context for AI with conversation tracking
        context_prompt = await self._build_enhanced_context_prompt(
            persona, honeypot_type, context, conversation_history, 
            attacker_input, input_analysis, specialized_prompt
        )
        
        # Generate response with AI model
        response = await self.process_with_ai(context_prompt)
        
        # Apply persona consistency checks
        response = await self._ensure_persona_consistency(response, persona, conversation_history)
        
        # Clean and validate response
        response = self._clean_response(response)
        
        # Generate synthetic data if needed
        if self._requires_synthetic_data(attacker_input, response):
            response = await self._enhance_with_synthetic_data(response, session, attacker_input)
        
        # Update conversation context with response metadata
        await self._update_conversation_metadata(session["session_id"], attacker_input, response, input_analysis)
        
        return response
    
    def _format_conversation_history(self, history: List[Dict[str, Any]]) -> str:
        """Format conversation history for AI context"""
        formatted = []
        for entry in history:
            if entry["type"] == "attacker_input":
                formatted.append(f"Attacker: {entry['content']}")
            elif entry["type"] == "agent_response":
                formatted.append(f"You: {entry['content']}")
        return "\n".join(formatted)
    
    def _clean_response(self, response: str) -> str:
        """Clean and validate AI response"""
        # Remove any potential real data or inappropriate content
        response = response.strip()
        
        # Ensure response is not too long
        if len(response) > 500:
            response = response[:500] + "..."
        
        # Add synthetic data markers if needed
        if "password" in response.lower():
            response = response.replace("password", "synthetic_password")
        
        return response
    
    async def _terminate_session(self, session_id: str, reason: str) -> Dict[str, Any]:
        """Terminate an interaction session"""
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        session["end_time"] = datetime.utcnow().isoformat()
        session["termination_reason"] = reason
        
        # Archive session data
        archived_session = {
            **session,
            "conversation_history": self.conversation_contexts.get(session_id, [])
        }
        
        # Clean up active session
        del self.active_sessions[session_id]
        if session_id in self.conversation_contexts:
            del self.conversation_contexts[session_id]
        
        # Update metrics
        self.update_active_sessions(len(self.active_sessions))
        
        self.logger.info(f"Terminated session {session_id}, reason: {reason}")
        
        return {
            "session_id": session_id,
            "status": "terminated",
            "reason": reason,
            "archived_session": archived_session
        }
    
    # Strands tools for interaction management
    @tool
    def get_active_sessions_tool(self) -> Dict[str, Any]:
        """Get information about active interaction sessions"""
        sessions_info = {}
        for session_id, session in self.active_sessions.items():
            sessions_info[session_id] = {
                "honeypot_type": session["honeypot_type"],
                "persona": session["persona"]["name"],
                "start_time": session["start_time"],
                "interaction_count": session["interaction_count"],
                "flags": session["flags"]
            }
        
        return {
            "active_sessions_count": len(self.active_sessions),
            "sessions": sessions_info
        }
    
    @tool
    def update_persona_tool(self, persona_key: str, persona_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update or add a persona"""
        self.personas[persona_key] = persona_data
        self.logger.info(f"Updated persona: {persona_key}")
        
        return {
            "persona_key": persona_key,
            "persona_data": persona_data,
            "updated_at": datetime.utcnow().isoformat()
        }
    
    @tool
    def get_session_context_tool(self, session_id: str) -> Dict[str, Any]:
        """Get context for a specific session"""
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        conversation = self.conversation_contexts.get(session_id, [])
        
        return {
            "session": session,
            "conversation_history": conversation,
            "context_length": len(conversation)
        }
    
    @tool
    def emergency_shutdown_tool(self, reason: str) -> Dict[str, Any]:
        """Emergency shutdown of all active sessions"""
        terminated_sessions = []
        
        for session_id in list(self.active_sessions.keys()):
            result = asyncio.create_task(self._terminate_session(session_id, f"emergency_shutdown: {reason}"))
            terminated_sessions.append(session_id)
        
        self.logger.warning(f"Emergency shutdown executed: {reason}")
        
        return {
            "action": "emergency_shutdown",
            "reason": reason,
            "terminated_sessions": terminated_sessions,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @tool
    def get_security_status_tool(self) -> Dict[str, Any]:
        """Get current security status and controls"""
        return self.security_controls.get_security_status()
    
    @tool
    def generate_synthetic_credentials_tool(self, count: int = 1) -> List[Dict[str, Any]]:
        """Generate synthetic credentials for testing"""
        return self.synthetic_generator.generate_synthetic_credentials(count)
    
    @tool
    def validate_synthetic_data_tool(self, data: Any) -> bool:
        """Validate that data is properly marked as synthetic"""
        return self.synthetic_generator.validate_synthetic_data(data)
    
    @tool
    def get_quarantine_summary_tool(self) -> Dict[str, Any]:
        """Get summary of quarantined data"""
        return self.security_controls.get_quarantined_data_summary()
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get interaction agent specific metrics"""
        base_metrics = await super().get_metrics()
        
        interaction_metrics = {
            "active_sessions": len(self.active_sessions),
            "total_personas": len(self.personas),
            "conversation_contexts": len(self.conversation_contexts),
            "sessions_by_type": self._get_sessions_by_type(),
            "escalations_count": sum(1 for s in self.active_sessions.values() 
                                   if s["flags"]["escalation_required"]),
            "real_data_detections": sum(1 for s in self.active_sessions.values() 
                                      if s["flags"]["real_data_detected"])
        }
        
        return {**base_metrics, **interaction_metrics}
    
    def _get_sessions_by_type(self) -> Dict[str, int]:
        """Get count of sessions by honeypot type"""
        type_counts = {}
        for session in self.active_sessions.values():
            honeypot_type = session["honeypot_type"]
            type_counts[honeypot_type] = type_counts.get(honeypot_type, 0) + 1
        return type_counts
    
    async def _analyze_input_intent(self, input_text: str, conversation_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attacker input to understand intent and context"""
        intent_analysis = {
            "primary_intent": "unknown",
            "confidence": 0.0,
            "intent_categories": [],
            "requires_technical_response": False,
            "requires_authentication": False,
            "requires_escalation": False,
            "topic_continuity": False
        }
        
        # Define intent patterns
        intent_patterns = {
            "authentication": [
                r"(?i)(login|password|auth|credential|user)",
                r"(?i)(sign.?in|log.?in|access)"
            ],
            "information_gathering": [
                r"(?i)(list|show|display|get|find|search)",
                r"(?i)(who|what|where|when|how|why)",
                r"(?i)(status|info|information|details)"
            ],
            "system_exploration": [
                r"(?i)(ls|dir|cat|grep|find|ps|netstat)",
                r"(?i)(file|directory|folder|path|system)"
            ],
            "privilege_escalation": [
                r"(?i)(sudo|su|admin|root|privilege)",
                r"(?i)(permission|access|rights|elevate)"
            ],
            "data_access": [
                r"(?i)(download|copy|backup|export|save)",
                r"(?i)(database|db|sql|query|table)"
            ],
            "network_operations": [
                r"(?i)(ping|connect|ssh|ftp|telnet)",
                r"(?i)(network|connection|remote|tunnel)"
            ]
        }
        
        # Analyze input against patterns
        matched_intents = []
        total_confidence = 0.0
        
        for intent, patterns in intent_patterns.items():
            intent_confidence = 0.0
            
            for pattern in patterns:
                matches = re.findall(pattern, input_text)
                if matches:
                    intent_confidence += len(matches) * 0.2
            
            if intent_confidence > 0:
                matched_intents.append({
                    "intent": intent,
                    "confidence": min(intent_confidence, 1.0)
                })
                total_confidence += intent_confidence
        
        # Determine primary intent
        if matched_intents:
            primary_intent = max(matched_intents, key=lambda x: x["confidence"])
            intent_analysis["primary_intent"] = primary_intent["intent"]
            intent_analysis["confidence"] = primary_intent["confidence"]
            intent_analysis["intent_categories"] = [m["intent"] for m in matched_intents]
        
        # Set response requirements
        technical_intents = ["system_exploration", "network_operations", "data_access"]
        auth_intents = ["authentication", "privilege_escalation"]
        
        intent_analysis["requires_technical_response"] = any(
            intent in technical_intents for intent in intent_analysis["intent_categories"]
        )
        intent_analysis["requires_authentication"] = any(
            intent in auth_intents for intent in intent_analysis["intent_categories"]
        )
        
        # Check topic continuity with conversation history
        if conversation_history:
            last_interaction = conversation_history[-1] if conversation_history else None
            if last_interaction and "intent_analysis" in last_interaction:
                previous_intent = last_interaction["intent_analysis"]["primary_intent"]
                intent_analysis["topic_continuity"] = (
                    intent_analysis["primary_intent"] == previous_intent or
                    intent_analysis["primary_intent"] in intent_analysis["intent_categories"]
                )
        
        return intent_analysis
    
    def _select_specialized_prompt(self, ai_config: Dict[str, Any], intent_analysis: Dict[str, Any], persona: Dict[str, Any]) -> str:
        """Select appropriate specialized prompt based on intent and persona"""
        specialized_prompts = ai_config.get("specialized_prompts", {})
        
        # Map persona knowledge level to prompt type
        persona_mapping = {
            "basic": "helpful_junior",
            "advanced": "system_admin", 
            "expert": "security_focused"
        }
        
        # Map intent to prompt type
        intent_mapping = {
            "authentication": "authentication",
            "privilege_escalation": "security_focused",
            "system_exploration": "system_admin",
            "information_gathering": "helpful_junior"
        }
        
        # Select prompt based on intent first, then persona
        primary_intent = intent_analysis.get("primary_intent", "unknown")
        knowledge_level = persona.get("knowledge_level", "basic")
        
        prompt_key = intent_mapping.get(primary_intent) or persona_mapping.get(knowledge_level, "system_admin")
        
        return specialized_prompts.get(prompt_key, specialized_prompts.get("system_admin", "You are a system administrator."))
    
    async def _build_enhanced_context_prompt(self, persona: Dict[str, Any], honeypot_type: str, 
                                           context: Dict[str, Any], conversation_history: List[Dict[str, Any]],
                                           attacker_input: str, intent_analysis: Dict[str, Any], 
                                           specialized_prompt: str) -> str:
        """Build enhanced context prompt for AI with conversation tracking"""
        
        # Format recent conversation with context weighting
        formatted_history = self._format_weighted_conversation_history(conversation_history)
        
        # Build persona context
        persona_context = f"""
PERSONA PROFILE:
Name: {persona['name']}
Role: {persona['role']}
Personality: {persona['personality']}
Response Style: {persona['response_style']}
Knowledge Level: {persona['knowledge_level']}
Typical Responses: {', '.join(persona.get('typical_responses', [])[:2])}
"""
        
        # Build system context
        system_context = f"""
SYSTEM CONTEXT:
Honeypot Type: {honeypot_type}
Current Directory: {context.get('current_directory', '/')}
Logged in as: {context.get('logged_in_user', 'admin')}
System State: {context.get('system_state', 'normal')}
"""
        
        # Build interaction context
        interaction_context = f"""
INTERACTION ANALYSIS:
Primary Intent: {intent_analysis['primary_intent']}
Confidence: {intent_analysis['confidence']:.2f}
Intent Categories: {', '.join(intent_analysis['intent_categories'])}
Requires Technical Response: {intent_analysis['requires_technical_response']}
Requires Authentication: {intent_analysis['requires_authentication']}
Topic Continuity: {intent_analysis['topic_continuity']}
"""
        
        # Build conversation context
        conversation_context = f"""
RECENT CONVERSATION:
{formatted_history}

CURRENT INPUT: "{attacker_input}"
"""
        
        # Build response guidelines
        response_guidelines = """
RESPONSE GUIDELINES:
1. Stay completely in character with the persona profile
2. Respond appropriately for the honeypot type and system context
3. Maintain conversation continuity and topic coherence
4. Provide plausible but synthetic information only
5. Never expose real data or break the deception
6. Keep responses realistic and concise (1-3 sentences)
7. Match the persona's knowledge level and response style
8. Use appropriate technical language for the intent
"""
        
        # Combine all context
        full_prompt = f"""
{specialized_prompt}

{persona_context}
{system_context}
{interaction_context}
{conversation_context}
{response_guidelines}

Generate your response as {persona['name']}:"""
        
        return full_prompt
    
    def _format_weighted_conversation_history(self, history: List[Dict[str, Any]]) -> str:
        """Format conversation history with context weighting"""
        if not history:
            return "No previous conversation."
        
        # Get recent interactions with decay weighting
        max_context = self.context_tracking["max_context_length"]
        decay_factor = self.context_tracking["context_decay_factor"]
        
        recent_history = history[-max_context:]
        formatted_lines = []
        
        for i, entry in enumerate(recent_history):
            # Calculate weight based on recency
            weight = decay_factor ** (len(recent_history) - i - 1)
            weight_indicator = ">>>" if weight > 0.7 else ">>" if weight > 0.4 else ">"
            
            if entry["type"] == "attacker_input":
                formatted_lines.append(f"{weight_indicator} Attacker: {entry['content']}")
            elif entry["type"] == "agent_response":
                formatted_lines.append(f"{weight_indicator} You: {entry['content']}")
        
        return "\n".join(formatted_lines)
    
    async def _ensure_persona_consistency(self, response: str, persona: Dict[str, Any], 
                                        conversation_history: List[Dict[str, Any]]) -> str:
        """Ensure response is consistent with persona and conversation history"""
        consistency_weight = self.context_tracking["persona_consistency_weight"]
        
        # Check if response matches persona style
        persona_keywords = {
            "helpful but inexperienced": ["help", "not sure", "let me check", "maybe", "think"],
            "experienced, cautious": ["verify", "check", "policy", "procedure", "authorization"],
            "suspicious, thorough": ["documentation", "logged", "security", "verify", "review"]
        }
        
        personality = persona.get("personality", "")
        expected_keywords = []
        
        for personality_type, keywords in persona_keywords.items():
            if personality_type in personality:
                expected_keywords.extend(keywords)
        
        # If response doesn't match persona, add persona-appropriate elements
        if expected_keywords and not any(keyword in response.lower() for keyword in expected_keywords):
            persona_phrases = persona.get("typical_responses", [])
            if persona_phrases:
                # Add a persona-appropriate phrase
                selected_phrase = persona_phrases[0]
                response = f"{response} {selected_phrase}"
        
        return response
    
    async def _update_conversation_metadata(self, session_id: str, input_text: str, 
                                          response: str, intent_analysis: Dict[str, Any]):
        """Update conversation context with metadata for better tracking"""
        if session_id in self.conversation_contexts:
            conversation = self.conversation_contexts[session_id]
            
            # Add metadata to the last attacker input entry
            if len(conversation) >= 2:
                last_entry = conversation[-2]  # -2 because response was just added
                if last_entry["type"] == "attacker_input":
                    last_entry["intent_analysis"] = intent_analysis
                    last_entry["response_generated"] = True
            
            # Add metadata to the response entry
            if len(conversation) >= 1:
                response_entry = conversation[-1]
                if response_entry["type"] == "agent_response":
                    response_entry["intent_addressed"] = intent_analysis["primary_intent"]
                    response_entry["technical_response"] = intent_analysis["requires_technical_response"]
    
    def _requires_command_execution(self, input_text: str) -> bool:
        """Check if input requires command execution simulation"""
        command_indicators = ["ls", "cat", "grep", "find", "ps", "netstat", "whoami", "pwd"]
        return any(cmd in input_text.lower() for cmd in command_indicators)
    
    def _requires_synthetic_data(self, attacker_input: str, response: str) -> bool:
        """Check if response needs synthetic data enhancement"""
        data_requests = [
            "password", "credential", "user", "login", "file", "directory",
            "config", "database", "server", "network", "ip", "address"
        ]
        return any(keyword in attacker_input.lower() or keyword in response.lower() 
                  for keyword in data_requests)
    
    async def _enhance_with_synthetic_data(self, response: str, session: Dict[str, Any], attacker_input: str) -> str:
        """Enhance response with appropriate synthetic data"""
        honeypot_type = session["honeypot_type"]
        
        # Generate command output if it's a command
        if self._requires_command_execution(attacker_input):
            command_output = self.synthetic_generator.generate_command_output(
                attacker_input, session["context"]
            )
            return f"{response}\n\n{command_output}"
        
        # Generate credentials if requested
        if any(word in attacker_input.lower() for word in ["password", "credential", "login"]):
            credentials = self.synthetic_generator.generate_synthetic_credentials(1)
            cred = credentials[0]
            return f"{response}\n\nUsername: {cred['username']}\nPassword: {cred['password']}"
        
        # Generate file listing if requested
        if any(word in attacker_input.lower() for word in ["file", "directory", "ls"]):
            files = self.synthetic_generator.generate_synthetic_files(3)
            file_list = "\n".join([f"{f['filename']} ({f['size']} bytes)" for f in files])
            return f"{response}\n\n{file_list}"
        
        # Generate network info if requested
        if any(word in attacker_input.lower() for word in ["network", "ip", "connection"]):
            network_sim = self.synthetic_generator.generate_network_simulation()
            return f"{response}\n\nNetwork Status: {network_sim['status']}"
        
        return response    

    async def _track_conversation_context(self, session_id: str, input_text: str, response: str):
        """Advanced conversation context tracking for better continuity"""
        if session_id not in self.conversation_contexts:
            return
        
        session = self.active_sessions.get(session_id)
        if not session:
            return
        
        # Extract conversation topics and themes
        topics = await self._extract_conversation_topics(input_text, response)
        
        # Update session context with conversation state
        if "conversation_state" not in session:
            session["conversation_state"] = {
                "topics": [],
                "interaction_patterns": {},
                "persona_consistency_score": 1.0,
                "technical_depth_progression": [],
                "trust_level": 0.5  # Start neutral
            }
        
        conv_state = session["conversation_state"]
        
        # Update topics
        conv_state["topics"].extend(topics)
        # Keep only recent topics (last 10)
        conv_state["topics"] = conv_state["topics"][-10:]
        
        # Track interaction patterns
        input_type = self._classify_interaction_type(input_text)
        if input_type not in conv_state["interaction_patterns"]:
            conv_state["interaction_patterns"][input_type] = 0
        conv_state["interaction_patterns"][input_type] += 1
        
        # Update technical depth progression
        technical_level = self._assess_technical_level(input_text)
        conv_state["technical_depth_progression"].append(technical_level)
        # Keep only recent progression (last 5 interactions)
        conv_state["technical_depth_progression"] = conv_state["technical_depth_progression"][-5:]
        
        # Update trust level based on interaction patterns
        conv_state["trust_level"] = self._calculate_trust_level(conv_state, session["persona"])
    
    async def _extract_conversation_topics(self, input_text: str, response: str) -> List[str]:
        """Extract topics from conversation for context tracking"""
        topics = []
        
        # Define topic keywords
        topic_keywords = {
            "authentication": ["login", "password", "auth", "credential", "user", "account"],
            "file_operations": ["file", "directory", "folder", "ls", "cat", "find", "grep"],
            "system_info": ["system", "process", "ps", "status", "info", "whoami", "uname"],
            "network": ["network", "ping", "connection", "ssh", "ftp", "port", "ip"],
            "database": ["database", "db", "sql", "query", "table", "select", "insert"],
            "security": ["security", "permission", "access", "privilege", "sudo", "root"],
            "troubleshooting": ["error", "problem", "issue", "fix", "help", "debug"],
            "configuration": ["config", "setting", "configure", "setup", "install"]
        }
        
        combined_text = f"{input_text} {response}".lower()
        
        for topic, keywords in topic_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                topics.append(topic)
        
        return topics
    
    def _classify_interaction_type(self, input_text: str) -> str:
        """Classify the type of interaction for pattern tracking"""
        input_lower = input_text.lower()
        
        if any(cmd in input_lower for cmd in ["ls", "dir", "cat", "grep", "find"]):
            return "file_exploration"
        elif any(cmd in input_lower for cmd in ["ps", "top", "netstat", "whoami"]):
            return "system_inquiry"
        elif any(word in input_lower for word in ["login", "password", "auth"]):
            return "authentication_attempt"
        elif any(word in input_lower for word in ["help", "how", "what", "?"]):
            return "help_seeking"
        elif any(word in input_lower for word in ["sudo", "su", "admin", "root"]):
            return "privilege_escalation"
        else:
            return "general_interaction"
    
    def _assess_technical_level(self, input_text: str) -> float:
        """Assess the technical sophistication level of the input"""
        technical_indicators = {
            "basic": ["help", "how", "what", "ls", "cat", "pwd"],
            "intermediate": ["grep", "find", "ps", "netstat", "chmod", "chown"],
            "advanced": ["awk", "sed", "crontab", "systemctl", "iptables", "tcpdump"],
            "expert": ["strace", "ltrace", "gdb", "objdump", "hexdump", "nc -l"]
        }
        
        input_lower = input_text.lower()
        level_scores = {"basic": 0.2, "intermediate": 0.4, "advanced": 0.7, "expert": 1.0}
        
        for level, indicators in technical_indicators.items():
            if any(indicator in input_lower for indicator in indicators):
                return level_scores[level]
        
        return 0.1  # Very basic if no indicators found
    
    def _calculate_trust_level(self, conv_state: Dict[str, Any], persona: Dict[str, Any]) -> float:
        """Calculate trust level based on interaction patterns and persona"""
        current_trust = conv_state.get("trust_level", 0.5)
        
        # Factors that increase trust
        trust_factors = {
            "help_seeking": 0.1,  # Asking for help increases trust
            "general_interaction": 0.05,  # Normal interactions
            "file_exploration": 0.02  # Basic exploration
        }
        
        # Factors that decrease trust
        suspicion_factors = {
            "privilege_escalation": -0.2,  # Trying to escalate privileges
            "authentication_attempt": -0.1,  # Multiple auth attempts
            "system_inquiry": -0.05  # Probing system info
        }
        
        # Calculate trust adjustment based on interaction patterns
        trust_adjustment = 0.0
        interaction_patterns = conv_state.get("interaction_patterns", {})
        
        for pattern, count in interaction_patterns.items():
            if pattern in trust_factors:
                trust_adjustment += trust_factors[pattern] * min(count, 3)  # Cap influence
            elif pattern in suspicion_factors:
                trust_adjustment += suspicion_factors[pattern] * min(count, 5)  # Cap influence
        
        # Persona-specific trust adjustments
        persona_personality = persona.get("personality", "")
        if "suspicious" in persona_personality:
            trust_adjustment *= 0.5  # Security-focused personas are more suspicious
        elif "helpful" in persona_personality:
            trust_adjustment *= 1.2  # Helpful personas are more trusting
        
        # Apply adjustment with bounds
        new_trust = max(0.0, min(1.0, current_trust + trust_adjustment * 0.1))
        
        return new_trust
    
    def _get_persona_response_modifiers(self, persona: Dict[str, Any], conv_state: Dict[str, Any]) -> Dict[str, Any]:
        """Get response modifiers based on persona and conversation state"""
        behavioral_traits = persona.get("behavioral_traits", {})
        trust_level = conv_state.get("trust_level", 0.5)
        
        modifiers = {
            "uncertainty_probability": behavioral_traits.get("uncertainty_frequency", 0.1),
            "help_seeking_probability": behavioral_traits.get("help_seeking", 0.1),
            "technical_depth": behavioral_traits.get("technical_depth", 0.5),
            "response_delay_type": behavioral_traits.get("response_delay", "normal"),
            "trust_influenced_responses": trust_level < 0.3  # Low trust affects responses
        }
        
        # Adjust probabilities based on trust level
        if trust_level < 0.3:
            modifiers["uncertainty_probability"] *= 1.5  # More uncertain when suspicious
            modifiers["help_seeking_probability"] *= 0.5  # Less likely to help when suspicious
        elif trust_level > 0.7:
            modifiers["uncertainty_probability"] *= 0.7  # More confident when trusting
            modifiers["help_seeking_probability"] *= 1.3  # More helpful when trusting
        
        return modifiers
    
    async def process_with_ai(self, prompt: str) -> str:
        """Process prompt with AI model to generate realistic responses"""
        try:
            # Simulate AI processing with realistic response generation
            # In a real implementation, this would call an actual AI model
            
            # Extract key elements from prompt for response generation
            response_context = self._extract_response_context(prompt)
            
            # Generate response based on context
            if "error" in prompt.lower() or "failed" in prompt.lower():
                return self._generate_error_response(response_context)
            elif "login" in prompt.lower() or "auth" in prompt.lower():
                return self._generate_auth_response(response_context)
            elif "command" in prompt.lower() or "execute" in prompt.lower():
                return self._generate_command_response(response_context)
            elif "file" in prompt.lower() or "directory" in prompt.lower():
                return self._generate_file_response(response_context)
            elif "help" in prompt.lower() or "how" in prompt.lower():
                return self._generate_help_response(response_context)
            else:
                return self._generate_general_response(response_context)
                
        except Exception as e:
            self.logger.error(f"Error in AI processing: {e}")
            return "I'm having trouble processing that request right now."
    
    def _extract_response_context(self, prompt: str) -> Dict[str, Any]:
        """Extract context from AI prompt for response generation"""
        context = {
            "persona_name": "Admin",
            "persona_role": "System Administrator",
            "personality": "helpful",
            "knowledge_level": "advanced",
            "response_style": "professional"
        }
        
        # Extract persona information from prompt
        if "Name:" in prompt:
            name_match = re.search(r"Name:\s*([^\n]+)", prompt)
            if name_match:
                context["persona_name"] = name_match.group(1).strip()
        
        if "Role:" in prompt:
            role_match = re.search(r"Role:\s*([^\n]+)", prompt)
            if role_match:
                context["persona_role"] = role_match.group(1).strip()
        
        if "Personality:" in prompt:
            personality_match = re.search(r"Personality:\s*([^\n]+)", prompt)
            if personality_match:
                context["personality"] = personality_match.group(1).strip()
        
        if "Knowledge Level:" in prompt:
            knowledge_match = re.search(r"Knowledge Level:\s*([^\n]+)", prompt)
            if knowledge_match:
                context["knowledge_level"] = knowledge_match.group(1).strip()
        
        # Extract current input
        if "CURRENT INPUT:" in prompt:
            input_match = re.search(r'CURRENT INPUT:\s*"([^"]+)"', prompt)
            if input_match:
                context["current_input"] = input_match.group(1).strip()
        
        return context
    
    def _generate_error_response(self, context: Dict[str, Any]) -> str:
        """Generate error response based on persona"""
        personality = context.get("personality", "helpful")
        knowledge_level = context.get("knowledge_level", "advanced")
        
        if "inexperienced" in personality or knowledge_level == "basic":
            responses = [
                "Hmm, that's strange. Let me check what went wrong...",
                "I'm not sure why that happened. Maybe I should ask someone?",
                "That error is new to me. Let me look it up.",
                "Sorry, I'm still learning about these kinds of issues."
            ]
        elif "cautious" in personality or "security" in context.get("persona_role", "").lower():
            responses = [
                "I need to investigate this error according to our procedures.",
                "This requires proper documentation before I can proceed.",
                "Let me check the security logs for this error.",
                "I'll need to escalate this to ensure proper handling."
            ]
        else:
            responses = [
                "Let me troubleshoot this step by step.",
                "I'll check the system logs to identify the issue.",
                "This looks like a configuration problem. Let me verify the settings.",
                "I can help resolve this. Let me run some diagnostics."
            ]
        
        import random
        return random.choice(responses)
    
    def _generate_auth_response(self, context: Dict[str, Any]) -> str:
        """Generate authentication response based on persona"""
        personality = context.get("personality", "helpful")
        
        if "suspicious" in personality or "security" in context.get("persona_role", "").lower():
            responses = [
                "I need to verify your authorization first.",
                "Please provide proper documentation for this access request.",
                "Security policy requires additional verification steps.",
                "I'll need to check with the security team before proceeding."
            ]
        elif "inexperienced" in personality:
            responses = [
                "Let me check how to handle login requests...",
                "I think I need supervisor approval for this.",
                "I'm not sure about the login procedure. One moment...",
                "Let me find the right process for this."
            ]
        else:
            responses = [
                "I can help you with the login process.",
                "Let me verify your credentials in the system.",
                "I'll check your account status and permissions.",
                "Please provide your username and I'll assist you."
            ]
        
        import random
        return random.choice(responses)
    
    def _generate_command_response(self, context: Dict[str, Any]) -> str:
        """Generate command execution response based on persona"""
        knowledge_level = context.get("knowledge_level", "advanced")
        personality = context.get("personality", "helpful")
        
        if knowledge_level == "basic" or "inexperienced" in personality:
            responses = [
                "Let me try to run that command for you...",
                "I'm not completely familiar with that command. Let me check...",
                "I think that should work, but let me verify first.",
                "Let me see if I have the right permissions for that."
            ]
        elif "security" in context.get("persona_role", "").lower():
            responses = [
                "I need to verify this command is authorized.",
                "Let me check if this command complies with security policy.",
                "This operation will be logged for security review.",
                "I'll need to validate the command parameters first."
            ]
        else:
            responses = [
                "I'll execute that command for you.",
                "Running the requested command now...",
                "Let me process that command and show you the results.",
                "Executing command with appropriate parameters."
            ]
        
        import random
        return random.choice(responses)
    
    def _generate_file_response(self, context: Dict[str, Any]) -> str:
        """Generate file operation response based on persona"""
        personality = context.get("personality", "helpful")
        
        if "cautious" in personality:
            responses = [
                "Let me check the file permissions first.",
                "I need to verify you have access to these files.",
                "I'll check the file integrity before proceeding.",
                "Let me ensure this file operation is safe."
            ]
        elif "inexperienced" in personality:
            responses = [
                "Let me find that file for you...",
                "I think it should be in the usual location...",
                "Let me check where that file might be stored.",
                "I'm looking for the file now..."
            ]
        else:
            responses = [
                "I'll locate that file for you.",
                "Checking the file system for your request.",
                "Let me access the file and show you the contents.",
                "Retrieving the requested file information."
            ]
        
        import random
        return random.choice(responses)
    
    def _generate_help_response(self, context: Dict[str, Any]) -> str:
        """Generate help response based on persona"""
        personality = context.get("personality", "helpful")
        knowledge_level = context.get("knowledge_level", "advanced")
        
        if "inexperienced" in personality or knowledge_level == "basic":
            responses = [
                "I'm still learning, but I'll try to help you.",
                "Let me see what I can figure out for you.",
                "I might need to ask someone else, but let me try first.",
                "I'll do my best to help, though I'm still new at this."
            ]
        elif knowledge_level == "expert":
            responses = [
                "I can definitely help you with that.",
                "Let me walk you through the proper procedure.",
                "I have experience with this type of request.",
                "I'll provide you with the detailed information you need."
            ]
        else:
            responses = [
                "I'd be happy to help you with that.",
                "Let me assist you with your request.",
                "I can guide you through the process.",
                "I'll help you resolve this issue."
            ]
        
        import random
        return random.choice(responses)
    
    def _generate_general_response(self, context: Dict[str, Any]) -> str:
        """Generate general response based on persona"""
        personality = context.get("personality", "helpful")
        current_input = context.get("current_input", "")
        
        if "suspicious" in personality:
            responses = [
                "I need more information before I can assist with that.",
                "Let me verify what you're trying to accomplish.",
                "I'll need to check our procedures for this type of request.",
                "Can you provide more details about what you need?"
            ]
        elif "inexperienced" in personality:
            responses = [
                "I'm not sure I understand. Can you explain more?",
                "Let me think about how to handle this...",
                "I might need to get help with this request.",
                "That's not something I've dealt with before."
            ]
        else:
            responses = [
                "I understand what you're asking for.",
                "Let me see how I can help you with that.",
                "I'll work on addressing your request.",
                "I can assist you with that task."
            ]
        
        import random
        return random.choice(responses)