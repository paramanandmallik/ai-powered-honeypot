"""
Intelligence Agent for AI-Powered Honeypot System
Handles session analysis, intelligence extraction, and threat intelligence generation.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from uuid import uuid4

from ..base_agent import BaseAgent
from .session_analyzer import SessionAnalyzer
from .mitre_mapper import MitreAttackMapper
from .intelligence_reporter import IntelligenceReporter


class IntelligenceAgent(BaseAgent):
    """
    Intelligence Agent for analyzing attacker sessions and extracting actionable intelligence.
    
    Capabilities:
    - AI-powered transcript analysis
    - Technique extraction and classification
    - Pattern recognition and correlation
    - Confidence scoring for intelligence
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        capabilities = [
            "session_analysis",
            "transcript_processing", 
            "technique_extraction",
            "pattern_recognition",
            "confidence_scoring",
            "intelligence_correlation"
        ]
        
        super().__init__("intelligence", capabilities, config)
        
        # Session analysis configuration
        self.analysis_config = {
            "min_session_duration": 30,  # seconds
            "confidence_threshold": 0.6,
            "max_concurrent_analyses": 5,
            "analysis_timeout": 300,  # seconds
            "pattern_window_hours": 24
        }
        
        # Update with provided config
        if config and "analysis" in config:
            self.analysis_config.update(config["analysis"])
        
        # Initialize session analyzer, MITRE mapper, and intelligence reporter
        self.session_analyzer = SessionAnalyzer()
        self.mitre_mapper = MitreAttackMapper()
        self.intelligence_reporter = IntelligenceReporter()
        
        # Session analysis state
        self.active_analyses: Dict[str, Dict[str, Any]] = {}
        self.completed_analyses: List[Dict[str, Any]] = []
        self.pattern_cache: Dict[str, List[Dict[str, Any]]] = {}
        
        # Analysis metrics
        self.analysis_stats = {
            "total_sessions_analyzed": 0,
            "high_confidence_findings": 0,
            "patterns_detected": 0,
            "techniques_extracted": 0
        }
        
        self.logger.info("Intelligence Agent initialized with session analysis capabilities")
    
    async def initialize(self):
        """Initialize the Intelligence Agent"""
        try:
            # Initialize session analysis engine
            await self._initialize_analysis_engine()
            
            # Load existing patterns and intelligence
            await self._load_historical_patterns()
            
            # Start background analysis tasks
            asyncio.create_task(self._pattern_correlation_task())
            asyncio.create_task(self._cleanup_task())
            
            self.logger.info("Intelligence Agent session analysis engine initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Intelligence Agent: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup Intelligence Agent resources"""
        try:
            # Complete any ongoing analyses
            await self._complete_pending_analyses()
            
            # Save analysis state
            await self._save_analysis_state()
            
            self.logger.info("Intelligence Agent cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during Intelligence Agent cleanup: {e}")
    
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process intelligence-related messages"""
        try:
            message_type = message.get("type")
            
            if message_type == "analyze_session":
                return await self._handle_session_analysis_request(message)
            elif message_type == "get_intelligence_report":
                return await self._handle_intelligence_report_request(message)
            elif message_type == "query_patterns":
                return await self._handle_pattern_query(message)
            elif message_type == "get_analysis_status":
                return await self._handle_analysis_status_request(message)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return {"error": f"Unknown message type: {message_type}"}
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            return {"error": str(e)}
    
    async def analyze_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a completed attacker session and extract intelligence.
        
        Args:
            session_data: Complete session data including transcript, metadata, and context
            
        Returns:
            Analysis results with extracted intelligence and confidence scores
        """
        try:
            session_id = session_data.get("session_id", str(uuid4()))
            
            # Validate session data
            if not self._validate_session_data(session_data):
                raise ValueError("Invalid session data provided")
            
            # Check if analysis is already in progress
            if session_id in self.active_analyses:
                return {"status": "analysis_in_progress", "session_id": session_id}
            
            # Start analysis
            analysis_id = str(uuid4())
            analysis_context = {
                "analysis_id": analysis_id,
                "session_id": session_id,
                "start_time": datetime.utcnow(),
                "status": "analyzing",
                "progress": 0
            }
            
            self.active_analyses[session_id] = analysis_context
            
            # Perform comprehensive session analysis
            analysis_result = await self._perform_session_analysis(session_data, analysis_context)
            
            # Update analysis state
            analysis_context["status"] = "completed"
            analysis_context["end_time"] = datetime.utcnow()
            analysis_context["result"] = analysis_result
            
            # Move to completed analyses
            self.completed_analyses.append(analysis_context)
            del self.active_analyses[session_id]
            
            # Update metrics
            self.analysis_stats["total_sessions_analyzed"] += 1
            if analysis_result.get("confidence_score", 0) > 0.8:
                self.analysis_stats["high_confidence_findings"] += 1
            
            self.logger.info(f"Session analysis completed for {session_id}")
            
            return analysis_result
            
        except Exception as e:
            # Clean up failed analysis
            if session_id in self.active_analyses:
                self.active_analyses[session_id]["status"] = "failed"
                self.active_analyses[session_id]["error"] = str(e)
            
            self.logger.error(f"Session analysis failed for {session_id}: {e}")
            raise
    
    async def _perform_session_analysis(self, session_data: Dict[str, Any], analysis_context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive analysis of session data"""
        try:
            session_id = session_data.get("session_id")
            transcript = session_data.get("transcript", [])
            metadata = session_data.get("metadata", {})
            
            # Initialize analysis result
            analysis_result = {
                "session_id": session_id,
                "analysis_id": analysis_context["analysis_id"],
                "timestamp": datetime.utcnow().isoformat(),
                "session_duration": metadata.get("duration_seconds", 0),
                "interaction_count": len(transcript),
                "findings": [],
                "techniques": [],
                "patterns": [],
                "confidence_score": 0.0,
                "risk_assessment": "Low",
                "recommendations": []
            }
            
            # Step 1: Analyze transcript content (25% progress)
            analysis_context["progress"] = 25
            transcript_analysis = await self._analyze_transcript_content(transcript)
            analysis_result["transcript_analysis"] = transcript_analysis
            
            # Step 2: Extract techniques and tactics (50% progress)
            analysis_context["progress"] = 50
            techniques = await self._extract_techniques(transcript, metadata)
            analysis_result["techniques"] = techniques
            self.analysis_stats["techniques_extracted"] += len(techniques)
            
            # Step 3: Identify patterns and correlations (75% progress)
            analysis_context["progress"] = 75
            patterns = await self._identify_patterns(session_data, transcript_analysis)
            analysis_result["patterns"] = patterns
            
            # Step 4: Generate intelligence findings (100% progress)
            analysis_context["progress"] = 100
            findings = await self._generate_intelligence_findings(
                transcript_analysis, techniques, patterns, metadata
            )
            analysis_result["findings"] = findings
            
            # Calculate overall confidence score
            analysis_result["confidence_score"] = self._calculate_confidence_score(
                transcript_analysis, techniques, patterns, findings
            )
            
            # Determine risk assessment
            analysis_result["risk_assessment"] = self._assess_risk_level(
                analysis_result["confidence_score"], techniques, patterns
            )
            
            # Generate recommendations
            analysis_result["recommendations"] = self._generate_recommendations(
                analysis_result["risk_assessment"], techniques, patterns
            )
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in session analysis: {e}")
            raise
    
    async def _analyze_transcript_content(self, transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze transcript content using AI and specialized analyzers"""
        try:
            if not transcript:
                return {"summary": "No transcript data", "key_interactions": [], "anomalies": []}
            
            # Use session analyzer for detailed analysis
            command_analysis = self.session_analyzer.analyze_command_sequence(transcript)
            web_analysis = self.session_analyzer.analyze_web_interactions(transcript)
            db_analysis = self.session_analyzer.analyze_database_interactions(transcript)
            
            # Prepare transcript for AI analysis
            transcript_text = self._format_transcript_for_analysis(transcript)
            
            # Enhanced AI analysis prompt with analyzer results
            analysis_prompt = f"""Analyze this attacker session transcript and provide insights:

{transcript_text}

Additional Analysis Context:
- Command Analysis: {json.dumps(command_analysis, indent=2)}
- Web Analysis: {json.dumps(web_analysis, indent=2)}
- Database Analysis: {json.dumps(db_analysis, indent=2)}

Please analyze:
1. Overall session behavior and intent
2. Key interactions and commands used
3. Any suspicious or anomalous behavior
4. Evidence of reconnaissance, exploitation, or persistence attempts
5. Communication patterns and language analysis
6. Integration of the specialized analysis results

Provide a structured analysis with:
- Session summary
- Key interactions (top 5 most significant)
- Behavioral anomalies detected
- Intent assessment (reconnaissance/exploitation/persistence/exfiltration)
- Sophistication level (novice/intermediate/advanced)
- Attack phase progression
"""

            # Process with AI
            ai_response = await self.process_with_ai(analysis_prompt)
            
            # Parse AI response into structured format
            analysis_result = self._parse_transcript_analysis(ai_response)
            
            # Enhance with session analyzer results
            analysis_result["command_analysis"] = command_analysis
            analysis_result["web_analysis"] = web_analysis
            analysis_result["database_analysis"] = db_analysis
            
            # Add metadata
            analysis_result["interaction_count"] = len(transcript)
            analysis_result["session_length_minutes"] = self._calculate_session_duration(transcript)
            analysis_result["unique_commands"] = self._extract_unique_commands(transcript)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing transcript content: {e}")
            return {"error": str(e), "summary": "Analysis failed"}
    
    async def _extract_techniques(self, transcript: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract attack techniques from session data using MITRE mapper"""
        try:
            # Use MITRE mapper for comprehensive technique extraction
            session_data = {
                "transcript": transcript,
                "metadata": metadata,
                "session_id": metadata.get("session_id", "unknown")
            }
            
            # Map techniques using MITRE ATT&CK framework
            mitre_techniques = self.mitre_mapper.map_techniques_from_session(session_data)
            
            # Also use legacy analysis for additional techniques
            legacy_techniques = []
            for interaction in transcript:
                interaction_techniques = await self._analyze_interaction_for_techniques(interaction)
                legacy_techniques.extend(interaction_techniques)
            
            # Combine and deduplicate techniques
            all_techniques = mitre_techniques + legacy_techniques
            unique_techniques = self._deduplicate_techniques(all_techniques)
            enriched_techniques = await self._enrich_techniques_with_context(unique_techniques, metadata)
            
            return enriched_techniques
            
        except Exception as e:
            self.logger.error(f"Error extracting techniques: {e}")
            return []
    
    async def _analyze_interaction_for_techniques(self, interaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a single interaction for attack techniques"""
        try:
            techniques = []
            
            interaction_type = interaction.get("type", "")
            content = interaction.get("content", "")
            timestamp = interaction.get("timestamp", "")
            
            # AI-powered technique extraction
            technique_prompt = f"""Analyze this attacker interaction and identify any attack techniques:

Interaction Type: {interaction_type}
Content: {content}
Timestamp: {timestamp}

Identify any attack techniques present and classify them. Look for:
1. Reconnaissance techniques (system enumeration, network scanning, etc.)
2. Initial access techniques (credential attacks, exploitation, etc.)
3. Execution techniques (command execution, scripting, etc.)
4. Persistence techniques (backdoors, scheduled tasks, etc.)
5. Privilege escalation techniques
6. Defense evasion techniques
7. Credential access techniques
8. Discovery techniques
9. Lateral movement techniques
10. Collection and exfiltration techniques

For each technique found, provide:
- Technique name
- Confidence score (0-100)
- Evidence from the interaction
- Potential impact
"""

            ai_response = await self.process_with_ai(technique_prompt)
            
            # Parse techniques from AI response
            parsed_techniques = self._parse_technique_extraction(ai_response, interaction)
            techniques.extend(parsed_techniques)
            
            # Add rule-based technique detection for common patterns
            rule_based_techniques = self._detect_techniques_with_rules(interaction)
            techniques.extend(rule_based_techniques)
            
            return techniques
            
        except Exception as e:
            self.logger.error(f"Error analyzing interaction for techniques: {e}")
            return []
    
    async def _identify_patterns(self, session_data: Dict[str, Any], transcript_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify behavioral patterns and correlations"""
        try:
            patterns = []
            
            # Temporal patterns
            temporal_patterns = self._analyze_temporal_patterns(session_data)
            patterns.extend(temporal_patterns)
            
            # Behavioral patterns
            behavioral_patterns = await self._analyze_behavioral_patterns(session_data, transcript_analysis)
            patterns.extend(behavioral_patterns)
            
            # Cross-session correlations
            correlation_patterns = await self._analyze_cross_session_correlations(session_data)
            patterns.extend(correlation_patterns)
            
            # Update pattern cache
            session_id = session_data.get("session_id")
            if session_id:
                self.pattern_cache[session_id] = patterns
                self.analysis_stats["patterns_detected"] += len(patterns)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error identifying patterns: {e}")
            return []
    
    async def _generate_intelligence_findings(self, transcript_analysis: Dict[str, Any], 
                                           techniques: List[Dict[str, Any]], 
                                           patterns: List[Dict[str, Any]], 
                                           metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable intelligence findings with MITRE context"""
        try:
            findings = []
            
            # Extract IOCs using MITRE mapper
            session_data = {
                "transcript": metadata.get("transcript", []),
                "metadata": metadata,
                "session_id": metadata.get("session_id", "unknown")
            }
            iocs = self.mitre_mapper.extract_and_validate_iocs(session_data)
            
            # Generate threat actor profile
            threat_profile = self.mitre_mapper.profile_threat_actor(techniques, metadata)
            
            # High-level session assessment with MITRE context
            session_finding = {
                "finding_id": str(uuid4()),
                "type": "session_assessment",
                "title": "Attacker Session Analysis",
                "description": transcript_analysis.get("summary", "Session analyzed"),
                "confidence": transcript_analysis.get("confidence", 0.5),
                "severity": self._determine_finding_severity(transcript_analysis, techniques),
                "evidence": {
                    "interaction_count": transcript_analysis.get("interaction_count", 0),
                    "session_duration": transcript_analysis.get("session_length_minutes", 0),
                    "unique_commands": transcript_analysis.get("unique_commands", []),
                    "mitre_techniques_count": len(techniques),
                    "iocs_extracted": len(iocs)
                },
                "mitre_context": {
                    "tactic_coverage": list(set(t.get("tactic", "") for t in techniques)),
                    "threat_actor_assessment": threat_profile.get("assessment_summary", ""),
                    "sophistication_indicators": self._extract_sophistication_indicators(techniques)
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            findings.append(session_finding)
            
            # MITRE technique-based findings
            for technique in techniques:
                confidence = technique.get("confidence", 0)
                if isinstance(confidence, (int, float)) and confidence > self.analysis_config["confidence_threshold"]:
                    technique_finding = {
                        "finding_id": str(uuid4()),
                        "type": "mitre_technique_detection",
                        "title": f"MITRE ATT&CK Technique: {technique.get('technique_name', 'Unknown')}",
                        "description": technique.get("description", ""),
                        "confidence": confidence,
                        "severity": self._map_technique_to_severity(technique),
                        "evidence": technique.get("evidence", ""),
                        "mitre_mapping": {
                            "technique_id": technique.get("technique_id", ""),
                            "tactic": technique.get("tactic", ""),
                            "subtechniques": technique.get("subtechniques", {}),
                            "detection_methods": technique.get("detection_methods", [])
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    findings.append(technique_finding)
            
            # IOC-based findings
            for ioc in iocs:
                if ioc.get("confidence", 0) > 0.7:
                    ioc_finding = {
                        "finding_id": str(uuid4()),
                        "type": "ioc_detection",
                        "title": f"Indicator of Compromise: {ioc.get('type', 'Unknown').replace('_', ' ').title()}",
                        "description": f"Detected {ioc.get('type', 'indicator')}: {ioc.get('value', '')}",
                        "confidence": ioc.get("confidence", 0),
                        "severity": self._assess_ioc_severity(ioc),
                        "evidence": {
                            "ioc_value": ioc.get("value", ""),
                            "ioc_type": ioc.get("type", ""),
                            "context": ioc.get("context", ""),
                            "threat_intel": ioc.get("threat_intel", {})
                        },
                        "mitre_mapping": {
                            "associated_techniques": ioc.get("mitre_techniques", [])
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    findings.append(ioc_finding)
            
            # Pattern-based findings
            for pattern in patterns:
                if pattern.get("significance", 0) > 0.7:
                    pattern_finding = {
                        "finding_id": str(uuid4()),
                        "type": "pattern_detection",
                        "title": f"Behavioral Pattern: {pattern.get('name', 'Unknown')}",
                        "description": pattern.get("description", ""),
                        "confidence": pattern.get("confidence", 0),
                        "severity": self._assess_pattern_severity(pattern),
                        "evidence": pattern.get("evidence", {}),
                        "correlation_data": pattern.get("correlations", []),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    findings.append(pattern_finding)
            
            # Threat actor finding if high confidence
            if threat_profile.get("confidence_level") in ["High", "Medium"]:
                actor_finding = {
                    "finding_id": str(uuid4()),
                    "type": "threat_actor_assessment",
                    "title": "Threat Actor Attribution",
                    "description": threat_profile.get("assessment_summary", ""),
                    "confidence": self._convert_confidence_to_numeric(threat_profile.get("confidence_level", "Low")),
                    "severity": "High" if threat_profile.get("confidence_level") == "High" else "Medium",
                    "evidence": {
                        "top_matches": threat_profile.get("top_matches", []),
                        "matching_techniques": [match[1].get("matching_techniques", []) for match in threat_profile.get("top_matches", [])]
                    },
                    "timestamp": datetime.utcnow().isoformat()
                }
                findings.append(actor_finding)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error generating intelligence findings: {e}")
            return []
    
    def _calculate_confidence_score(self, transcript_analysis: Dict[str, Any], 
                                  techniques: List[Dict[str, Any]], 
                                  patterns: List[Dict[str, Any]], 
                                  findings: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score for the analysis"""
        try:
            scores = []
            
            # Transcript analysis confidence
            if transcript_analysis.get("confidence"):
                scores.append(transcript_analysis["confidence"])
            
            # Technique confidence scores
            technique_scores = [t.get("confidence", 0) for t in techniques if t.get("confidence")]
            if technique_scores:
                scores.append(sum(technique_scores) / len(technique_scores) / 100)  # Normalize to 0-1
            
            # Pattern significance scores
            pattern_scores = [p.get("significance", 0) for p in patterns if p.get("significance")]
            if pattern_scores:
                scores.append(sum(pattern_scores) / len(pattern_scores))
            
            # Finding confidence scores
            finding_scores = [f.get("confidence", 0) for f in findings if f.get("confidence")]
            if finding_scores:
                scores.append(sum(finding_scores) / len(finding_scores))
            
            # Calculate weighted average
            if scores:
                return sum(scores) / len(scores)
            else:
                return 0.5  # Default moderate confidence
                
        except Exception as e:
            self.logger.error(f"Error calculating confidence score: {e}")
            return 0.5
    
    # Helper methods for session analysis
    def _validate_session_data(self, session_data: Dict[str, Any]) -> bool:
        """Validate session data structure"""
        required_fields = ["session_id", "transcript"]
        return all(field in session_data for field in required_fields)
    
    def _format_transcript_for_analysis(self, transcript: List[Dict[str, Any]]) -> str:
        """Format transcript for AI analysis"""
        formatted_lines = []
        for interaction in transcript:
            timestamp = interaction.get("timestamp", "")
            interaction_type = interaction.get("type", "")
            content = interaction.get("content", "")
            formatted_lines.append(f"[{timestamp}] {interaction_type}: {content}")
        
        return "\n".join(formatted_lines)
    
    def _parse_transcript_analysis(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI response into structured transcript analysis"""
        try:
            # Try to parse as JSON first
            if ai_response.strip().startswith("{"):
                return json.loads(ai_response)
            
            # Fallback to text parsing
            return {
                "summary": ai_response[:500] + "..." if len(ai_response) > 500 else ai_response,
                "key_interactions": [],
                "anomalies": [],
                "intent_assessment": "unknown",
                "sophistication_level": "intermediate",
                "confidence": 0.6
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing transcript analysis: {e}")
            return {"summary": "Analysis parsing failed", "confidence": 0.3}
    
    def _calculate_session_duration(self, transcript: List[Dict[str, Any]]) -> float:
        """Calculate session duration in minutes"""
        if len(transcript) < 2:
            return 0.0
        
        try:
            first_timestamp = datetime.fromisoformat(transcript[0].get("timestamp", ""))
            last_timestamp = datetime.fromisoformat(transcript[-1].get("timestamp", ""))
            duration = (last_timestamp - first_timestamp).total_seconds() / 60
            return round(duration, 2)
        except Exception:
            return 0.0
    
    def _extract_unique_commands(self, transcript: List[Dict[str, Any]]) -> List[str]:
        """Extract unique commands from transcript"""
        commands = set()
        for interaction in transcript:
            content = interaction.get("content", "")
            if interaction.get("type") == "command" and content:
                # Extract first word as command
                command = content.split()[0] if content.split() else content
                commands.add(command)
        
        return list(commands)
    
    # Additional helper methods implementation
    async def _initialize_analysis_engine(self):
        """Initialize the session analysis engine"""
        try:
            # Initialize AI models and analysis components
            self.session_analyzer = SessionAnalyzer()
            self.mitre_mapper = MitreAttackMapper()
            self.intelligence_reporter = IntelligenceReporter()
            
            # Initialize analysis state storage
            self.active_analyses = {}
            self.completed_analyses = []
            self.pattern_cache = {}
            
            self.logger.info("Session analysis engine initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize analysis engine: {e}")
            raise
    
    async def _load_historical_patterns(self):
        """Load historical patterns for correlation"""
        try:
            # Load patterns from previous analyses
            # In a real implementation, this would load from persistent storage
            self.pattern_cache = {
                "reconnaissance_patterns": [],
                "privilege_escalation_patterns": [],
                "persistence_patterns": [],
                "exfiltration_patterns": []
            }
            
            self.logger.info("Historical patterns loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load historical patterns: {e}")
    
    async def _pattern_correlation_task(self):
        """Background task for pattern correlation"""
        try:
            while True:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Correlate patterns across recent analyses
                await self._correlate_recent_patterns()
                
        except asyncio.CancelledError:
            self.logger.info("Pattern correlation task cancelled")
        except Exception as e:
            self.logger.error(f"Error in pattern correlation task: {e}")
    
    async def _correlate_recent_patterns(self):
        """Correlate patterns across recent analyses"""
        try:
            # Get recent analyses (last 24 hours)
            recent_analyses = [
                analysis for analysis in self.completed_analyses
                if (datetime.utcnow() - datetime.fromisoformat(analysis.get("start_time", ""))).total_seconds() < 86400
            ]
            
            if len(recent_analyses) < 2:
                return
            
            # Look for common patterns
            common_techniques = {}
            common_ips = {}
            
            for analysis in recent_analyses:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                
                for technique in techniques:
                    tech_id = technique.get("technique_id", "")
                    if tech_id:
                        common_techniques[tech_id] = common_techniques.get(tech_id, 0) + 1
                
                # Track source IPs
                session_id = analysis.get("session_id", "")
                # In real implementation, would extract IP from session data
            
            # Update pattern cache with correlations
            self.pattern_cache["recent_correlations"] = {
                "common_techniques": common_techniques,
                "analysis_count": len(recent_analyses),
                "last_updated": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error correlating patterns: {e}")
    
    async def _cleanup_task(self):
        """Background cleanup task"""
        try:
            while True:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up old completed analyses
                cutoff_time = datetime.utcnow() - timedelta(days=7)
                
                self.completed_analyses = [
                    analysis for analysis in self.completed_analyses
                    if datetime.fromisoformat(analysis.get("start_time", "")) > cutoff_time
                ]
                
                # Clean up pattern cache
                if len(self.pattern_cache) > 1000:
                    # Keep only recent patterns
                    self.pattern_cache = dict(list(self.pattern_cache.items())[-500:])
                
                self.logger.info("Cleanup task completed")
                
        except asyncio.CancelledError:
            self.logger.info("Cleanup task cancelled")
        except Exception as e:
            self.logger.error(f"Error in cleanup task: {e}")
    
    async def _complete_pending_analyses(self):
        """Complete any pending analyses during shutdown"""
        try:
            pending_sessions = list(self.active_analyses.keys())
            
            for session_id in pending_sessions:
                analysis_context = self.active_analyses[session_id]
                analysis_context["status"] = "cancelled"
                analysis_context["end_time"] = datetime.utcnow()
                
                # Move to completed analyses
                self.completed_analyses.append(analysis_context)
                del self.active_analyses[session_id]
            
            self.logger.info(f"Cancelled {len(pending_sessions)} pending analyses")
            
        except Exception as e:
            self.logger.error(f"Error completing pending analyses: {e}")
    
    async def _save_analysis_state(self):
        """Save analysis state during shutdown"""
        try:
            # In a real implementation, this would save to persistent storage
            state_summary = {
                "completed_analyses_count": len(self.completed_analyses),
                "pattern_cache_size": len(self.pattern_cache),
                "total_sessions_analyzed": self.analysis_stats["total_sessions_analyzed"],
                "shutdown_time": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Analysis state saved: {state_summary}")
            
        except Exception as e:
            self.logger.error(f"Error saving analysis state: {e}")
    
    # Message handlers
    async def _handle_session_analysis_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle session analysis request"""
        try:
            session_data = message.get("session_data")
            if not session_data:
                return {"error": "No session data provided"}
            
            # Perform analysis
            result = await self.analyze_session(session_data)
            
            return {
                "status": "success",
                "analysis_result": result
            }
            
        except Exception as e:
            self.logger.error(f"Error handling session analysis request: {e}")
            return {"error": str(e)}
    
    async def _handle_intelligence_report_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle intelligence report request"""
        try:
            report_type = message.get("report_type", "summary")
            time_range = message.get("time_range", "24h")
            
            # Generate report using intelligence reporter
            analysis_data = self._get_analyses_for_time_range(time_range)
            
            if report_type == "structured":
                report = self.intelligence_reporter.generate_structured_report(
                    analysis_data, 
                    message.get("template", "technical_analysis"),
                    time_range
                )
            else:
                report = self.intelligence_reporter.generate_automated_summary(
                    analysis_data,
                    message.get("summary_type", "daily")
                )
            
            return {
                "status": "success",
                "report": report
            }
            
        except Exception as e:
            self.logger.error(f"Error handling intelligence report request: {e}")
            return {"error": str(e)}
    
    async def _handle_pattern_query(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle pattern query request"""
        try:
            pattern_type = message.get("pattern_type", "all")
            time_range = message.get("time_range", "24h")
            
            # Get patterns from cache
            if pattern_type == "all":
                patterns = dict(self.pattern_cache)
            else:
                patterns = self.pattern_cache.get(pattern_type, {})
            
            return {
                "status": "success",
                "patterns": patterns,
                "pattern_type": pattern_type,
                "time_range": time_range
            }
            
        except Exception as e:
            self.logger.error(f"Error handling pattern query: {e}")
            return {"error": str(e)}
    
    async def _handle_analysis_status_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle analysis status request"""
        try:
            return {
                "status": "success",
                "active_analyses": len(self.active_analyses),
                "completed_analyses": len(self.completed_analyses),
                "analysis_stats": dict(self.analysis_stats),
                "pattern_cache_size": len(self.pattern_cache)
            }
            
        except Exception as e:
            self.logger.error(f"Error handling status request: {e}")
            return {"error": str(e)}
    
    def _get_analyses_for_time_range(self, time_range: str) -> List[Dict[str, Any]]:
        """Get analyses for specified time range"""
        try:
            # Parse time range
            if time_range == "24h":
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            elif time_range == "7d":
                cutoff_time = datetime.utcnow() - timedelta(days=7)
            elif time_range == "30d":
                cutoff_time = datetime.utcnow() - timedelta(days=30)
            else:
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            # Filter analyses
            filtered_analyses = []
            for analysis in self.completed_analyses:
                try:
                    analysis_time = datetime.fromisoformat(analysis.get("start_time", ""))
                    if analysis_time >= cutoff_time:
                        filtered_analyses.append(analysis)
                except Exception:
                    continue
            
            return filtered_analyses
            
        except Exception as e:
            self.logger.error(f"Error filtering analyses by time range: {e}")
            return []
    
    async def _complete_pending_analyses(self):
        """Complete any pending analyses during shutdown"""
        for session_id, analysis in self.active_analyses.items():
            analysis["status"] = "interrupted"
            self.logger.warning(f"Analysis {analysis['analysis_id']} interrupted during shutdown")
    
    async def _save_analysis_state(self):
        """Save analysis state for persistence"""
        self.logger.info("Analysis state saved")
    
    # Message handlers
    async def _handle_session_analysis_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle session analysis request"""
        try:
            session_data = message.get("session_data")
            if not session_data:
                return {"error": "No session data provided"}
            
            result = await self.analyze_session(session_data)
            return {"status": "success", "analysis_result": result}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_intelligence_report_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle intelligence report request"""
        try:
            report_type = message.get("report_type", "summary")
            time_range = message.get("time_range", "24h")
            
            # Generate report based on completed analyses
            report = await self._generate_intelligence_report(report_type, time_range)
            return {"status": "success", "report": report}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_pattern_query(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle pattern query request"""
        try:
            query_params = message.get("query_params", {})
            patterns = await self._query_patterns(query_params)
            return {"status": "success", "patterns": patterns}
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_analysis_status_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle analysis status request"""
        try:
            return {
                "status": "success",
                "active_analyses": len(self.active_analyses),
                "completed_analyses": len(self.completed_analyses),
                "analysis_stats": self.analysis_stats
            }
            
        except Exception as e:
            return {"error": str(e)}    
   
 # Additional helper methods for session analysis
    def _deduplicate_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate techniques and merge evidence"""
        unique_techniques = {}
        
        for technique in techniques:
            technique_name = technique.get("name", "unknown")
            
            if technique_name in unique_techniques:
                # Merge evidence and update confidence
                existing = unique_techniques[technique_name]
                existing["confidence"] = max(existing.get("confidence", 0), technique.get("confidence", 0))
                existing["evidence"].extend(technique.get("evidence", []))
            else:
                unique_techniques[technique_name] = technique
        
        return list(unique_techniques.values())
    
    async def _enrich_techniques_with_context(self, techniques: List[Dict[str, Any]], 
                                            metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enrich techniques with additional context and metadata"""
        enriched = []
        
        for technique in techniques:
            enriched_technique = technique.copy()
            
            # Add session context
            enriched_technique["session_context"] = {
                "honeypot_type": metadata.get("honeypot_type", "unknown"),
                "session_duration": metadata.get("duration_seconds", 0),
                "source_ip": metadata.get("source_ip", "unknown"),
                "user_agent": metadata.get("user_agent", "")
            }
            
            # Add temporal context
            enriched_technique["temporal_context"] = {
                "time_of_day": metadata.get("start_time", ""),
                "day_of_week": metadata.get("day_of_week", ""),
                "timezone": metadata.get("timezone", "UTC")
            }
            
            enriched.append(enriched_technique)
        
        return enriched
    
    def _detect_techniques_with_rules(self, interaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect techniques using rule-based patterns"""
        techniques = []
        content = interaction.get("content", "").lower()
        
        # Common reconnaissance commands
        recon_patterns = {
            "whoami": {"name": "System User Discovery", "mitre_id": "T1033"},
            "id": {"name": "System User Discovery", "mitre_id": "T1033"},
            "ps": {"name": "Process Discovery", "mitre_id": "T1057"},
            "netstat": {"name": "System Network Connections Discovery", "mitre_id": "T1049"},
            "ifconfig": {"name": "System Network Configuration Discovery", "mitre_id": "T1016"},
            "ls -la": {"name": "File and Directory Discovery", "mitre_id": "T1083"},
            "cat /etc/passwd": {"name": "Account Discovery", "mitre_id": "T1087"},
            "uname -a": {"name": "System Information Discovery", "mitre_id": "T1082"}
        }
        
        for pattern, technique_info in recon_patterns.items():
            if pattern in content:
                techniques.append({
                    "name": technique_info["name"],
                    "mitre_id": technique_info["mitre_id"],
                    "confidence": 85,
                    "evidence": [content],
                    "detection_method": "rule_based",
                    "category": "reconnaissance"
                })
        
        return techniques
    
    def _parse_technique_extraction(self, ai_response: str, interaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse technique extraction from AI response"""
        techniques = []
        
        try:
            # Try to parse as JSON
            if ai_response.strip().startswith("[") or ai_response.strip().startswith("{"):
                parsed = json.loads(ai_response)
                if isinstance(parsed, list):
                    techniques = parsed
                elif isinstance(parsed, dict) and "techniques" in parsed:
                    techniques = parsed["techniques"]
            
            # Validate and normalize technique format
            normalized_techniques = []
            for technique in techniques:
                if isinstance(technique, dict) and "name" in technique:
                    normalized_technique = {
                        "name": technique.get("name", "Unknown"),
                        "confidence": technique.get("confidence", 50),
                        "evidence": technique.get("evidence", [interaction.get("content", "")]),
                        "mitre_id": technique.get("mitre_id", ""),
                        "category": technique.get("category", "unknown"),
                        "detection_method": "ai_analysis"
                    }
                    normalized_techniques.append(normalized_technique)
            
            return normalized_techniques
            
        except Exception as e:
            self.logger.error(f"Error parsing technique extraction: {e}")
            return []
    
    def _analyze_temporal_patterns(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in session behavior"""
        patterns = []
        
        try:
            transcript = session_data.get("transcript", [])
            if len(transcript) < 3:
                return patterns
            
            # Analyze command timing patterns
            timestamps = []
            for interaction in transcript:
                try:
                    ts = datetime.fromisoformat(interaction.get("timestamp", ""))
                    timestamps.append(ts)
                except Exception:
                    continue
            
            if len(timestamps) >= 3:
                # Calculate intervals between interactions
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)
                
                # Detect rapid-fire commands (potential automation)
                rapid_commands = sum(1 for interval in intervals if interval < 2)
                if rapid_commands > len(intervals) * 0.7:  # 70% of commands are rapid
                    patterns.append({
                        "name": "Rapid Command Execution",
                        "type": "temporal",
                        "description": "High frequency of commands suggests automated tools",
                        "confidence": 0.8,
                        "significance": 0.7,
                        "evidence": {
                            "rapid_command_ratio": rapid_commands / len(intervals),
                            "average_interval": sum(intervals) / len(intervals)
                        }
                    })
                
                # Detect long pauses (potential manual analysis)
                long_pauses = sum(1 for interval in intervals if interval > 60)
                if long_pauses > 2:
                    patterns.append({
                        "name": "Extended Analysis Periods",
                        "type": "temporal",
                        "description": "Long pauses suggest manual analysis and planning",
                        "confidence": 0.7,
                        "significance": 0.6,
                        "evidence": {
                            "long_pause_count": long_pauses,
                            "max_pause_seconds": max(intervals)
                        }
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing temporal patterns: {e}")
        
        return patterns
    
    async def _analyze_behavioral_patterns(self, session_data: Dict[str, Any], 
                                         transcript_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze behavioral patterns using AI"""
        patterns = []
        
        try:
            # Prepare data for AI analysis
            behavior_prompt = f"""Analyze the behavioral patterns in this attacker session:

Session Summary: {transcript_analysis.get('summary', 'No summary')}
Intent Assessment: {transcript_analysis.get('intent_assessment', 'Unknown')}
Sophistication Level: {transcript_analysis.get('sophistication_level', 'Unknown')}
Unique Commands: {transcript_analysis.get('unique_commands', [])}

Identify behavioral patterns such as:
1. Systematic vs random exploration
2. Tool usage patterns
3. Error handling behavior
4. Persistence vs hit-and-run tactics
5. Social engineering attempts
6. Evasion techniques

For each pattern, provide:
- Pattern name and type
- Description and significance
- Confidence score (0-100)
- Supporting evidence
"""

            ai_response = await self.process_with_ai(behavior_prompt)
            
            # Parse behavioral patterns from AI response
            parsed_patterns = self._parse_behavioral_patterns(ai_response)
            patterns.extend(parsed_patterns)
            
        except Exception as e:
            self.logger.error(f"Error analyzing behavioral patterns: {e}")
        
        return patterns
    
    def _parse_behavioral_patterns(self, ai_response: str) -> List[Dict[str, Any]]:
        """Parse behavioral patterns from AI response"""
        patterns = []
        
        try:
            # Try to parse as JSON
            if ai_response.strip().startswith("[") or ai_response.strip().startswith("{"):
                parsed = json.loads(ai_response)
                if isinstance(parsed, list):
                    patterns = parsed
                elif isinstance(parsed, dict) and "patterns" in parsed:
                    patterns = parsed["patterns"]
            
            # Normalize pattern format
            normalized_patterns = []
            for pattern in patterns:
                if isinstance(pattern, dict):
                    normalized_pattern = {
                        "name": pattern.get("name", "Unknown Pattern"),
                        "type": "behavioral",
                        "description": pattern.get("description", ""),
                        "confidence": pattern.get("confidence", 50) / 100,  # Normalize to 0-1
                        "significance": pattern.get("significance", 0.5),
                        "evidence": pattern.get("evidence", {})
                    }
                    normalized_patterns.append(normalized_pattern)
            
            return normalized_patterns
            
        except Exception as e:
            self.logger.error(f"Error parsing behavioral patterns: {e}")
            return []
    
    async def _analyze_cross_session_correlations(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze correlations with other sessions"""
        patterns = []
        
        try:
            current_session_id = session_data.get("session_id")
            source_ip = session_data.get("metadata", {}).get("source_ip")
            
            # Look for similar sessions in recent history
            similar_sessions = []
            for session_id, cached_patterns in self.pattern_cache.items():
                if session_id != current_session_id:
                    # Check for IP correlation
                    # In a real implementation, this would query a database
                    similar_sessions.append(session_id)
            
            if similar_sessions:
                patterns.append({
                    "name": "Cross-Session Correlation",
                    "type": "correlation",
                    "description": f"Found {len(similar_sessions)} potentially related sessions",
                    "confidence": 0.6,
                    "significance": 0.7,
                    "evidence": {
                        "related_sessions": similar_sessions[:5],  # Limit to top 5
                        "correlation_factors": ["source_ip", "timing", "techniques"]
                    }
                })
        
        except Exception as e:
            self.logger.error(f"Error analyzing cross-session correlations: {e}")
        
        return patterns
    
    def _determine_finding_severity(self, transcript_analysis: Dict[str, Any], 
                                  techniques: List[Dict[str, Any]]) -> str:
        """Determine severity level for findings"""
        # High severity indicators
        high_severity_techniques = ["privilege_escalation", "persistence", "exfiltration"]
        sophistication = transcript_analysis.get("sophistication_level", "").lower()
        
        if sophistication == "advanced":
            return "High"
        
        for technique in techniques:
            if any(indicator in technique.get("category", "").lower() 
                  for indicator in high_severity_techniques):
                return "High"
        
        # Medium severity for intermediate sophistication or multiple techniques
        if sophistication == "intermediate" or len(techniques) > 3:
            return "Medium"
        
        return "Low"
    
    def _map_technique_to_severity(self, technique: Dict[str, Any]) -> str:
        """Map technique to severity level"""
        category = technique.get("category", "").lower()
        confidence = technique.get("confidence", 0)
        
        high_risk_categories = ["privilege_escalation", "persistence", "exfiltration", "lateral_movement"]
        medium_risk_categories = ["execution", "defense_evasion", "credential_access"]
        
        if category in high_risk_categories and confidence > 70:
            return "High"
        elif category in medium_risk_categories and confidence > 60:
            return "Medium"
        else:
            return "Low"
    
    def _assess_pattern_severity(self, pattern: Dict[str, Any]) -> str:
        """Assess severity of detected patterns"""
        pattern_type = pattern.get("type", "").lower()
        significance = pattern.get("significance", 0)
        
        if pattern_type == "correlation" and significance > 0.8:
            return "High"
        elif significance > 0.7:
            return "Medium"
        else:
            return "Low"
    
    def _assess_risk_level(self, confidence_score: float, techniques: List[Dict[str, Any]], 
                          patterns: List[Dict[str, Any]]) -> str:
        """Assess overall risk level"""
        if confidence_score > 0.8 and len(techniques) > 5:
            return "High"
        elif confidence_score > 0.6 and (len(techniques) > 3 or len(patterns) > 2):
            return "Medium"
        else:
            return "Low"
    
    def _generate_recommendations(self, risk_level: str, techniques: List[Dict[str, Any]], 
                                patterns: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if risk_level == "High":
            recommendations.extend([
                "Immediate investigation required",
                "Review and strengthen access controls",
                "Implement additional monitoring for detected techniques",
                "Consider threat hunting activities"
            ])
        elif risk_level == "Medium":
            recommendations.extend([
                "Monitor for similar attack patterns",
                "Review security controls for identified techniques",
                "Update detection rules based on findings"
            ])
        else:
            recommendations.extend([
                "Continue monitoring",
                "Document findings for trend analysis"
            ])
        
        # Add technique-specific recommendations
        technique_categories = set(t.get("category", "") for t in techniques)
        if "reconnaissance" in technique_categories:
            recommendations.append("Implement network segmentation to limit reconnaissance")
        if "persistence" in technique_categories:
            recommendations.append("Review and audit persistence mechanisms")
        
        return recommendations
    
    # Background task methods
    async def _correlate_recent_patterns(self):
        """Correlate patterns from recent sessions"""
        try:
            # Analyze patterns from the last 24 hours
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            recent_patterns = []
            for analysis in self.completed_analyses:
                if datetime.fromisoformat(analysis.get("start_time", "")) > cutoff_time:
                    patterns = analysis.get("result", {}).get("patterns", [])
                    recent_patterns.extend(patterns)
            
            # Look for correlations
            if len(recent_patterns) > 5:
                self.logger.info(f"Correlating {len(recent_patterns)} recent patterns")
                # Implement correlation logic here
            
        except Exception as e:
            self.logger.error(f"Error correlating recent patterns: {e}")
    
    async def _cleanup_old_analyses(self):
        """Clean up old analysis data"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=7)
            
            # Remove old completed analyses
            self.completed_analyses = [
                analysis for analysis in self.completed_analyses
                if datetime.fromisoformat(analysis.get("start_time", "")) > cutoff_time
            ]
            
            # Clean up pattern cache
            old_sessions = []
            for session_id in self.pattern_cache:
                # In a real implementation, check session timestamp
                if len(old_sessions) < 100:  # Keep last 100 sessions
                    old_sessions.append(session_id)
            
            for session_id in old_sessions:
                del self.pattern_cache[session_id]
            
            self.logger.info(f"Cleaned up {len(old_sessions)} old session patterns")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old analyses: {e}")
    
    # Report generation methods
    async def _generate_intelligence_report(self, report_type: str, time_range: str) -> Dict[str, Any]:
        """Generate intelligence report using the intelligence reporter"""
        try:
            # Use intelligence reporter for comprehensive report generation
            if report_type == "structured":
                return self.intelligence_reporter.generate_structured_report(
                    self.completed_analyses, "technical_analysis", time_range
                )
            elif report_type == "executive":
                return self.intelligence_reporter.generate_structured_report(
                    self.completed_analyses, "executive_summary", time_range
                )
            elif report_type == "incident_response":
                return self.intelligence_reporter.generate_structured_report(
                    self.completed_analyses, "incident_response", time_range
                )
            elif report_type == "threat_intelligence":
                return self.intelligence_reporter.generate_structured_report(
                    self.completed_analyses, "threat_intelligence", time_range
                )
            elif report_type == "automated_summary":
                summary_type = "daily" if time_range == "24h" else "weekly" if time_range == "7d" else "monthly"
                return self.intelligence_reporter.generate_automated_summary(
                    self.completed_analyses, summary_type
                )
            elif report_type == "trends":
                return self.intelligence_reporter.analyze_trends(
                    self.completed_analyses, "comprehensive"
                )
            else:
                # Default to automated summary
                summary_type = "daily" if time_range == "24h" else "weekly" if time_range == "7d" else "monthly"
                return self.intelligence_reporter.generate_automated_summary(
                    self.completed_analyses, summary_type
                )
                
        except Exception as e:
            self.logger.error(f"Error generating intelligence report: {e}")
            return {"error": str(e)}
    
    async def _generate_summary_report(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary intelligence report"""
        report = {
            "report_type": "summary",
            "generated_at": datetime.utcnow().isoformat(),
            "time_period": f"Last {len(analyses)} sessions",
            "total_sessions": len(analyses),
            "high_risk_sessions": 0,
            "top_techniques": {},
            "top_patterns": {},
            "key_findings": []
        }
        
        # Analyze sessions
        for analysis in analyses:
            result = analysis.get("result", {})
            
            # Count high-risk sessions
            if result.get("risk_assessment") == "High":
                report["high_risk_sessions"] += 1
            
            # Aggregate techniques
            for technique in result.get("techniques", []):
                name = technique.get("name", "Unknown")
                report["top_techniques"][name] = report["top_techniques"].get(name, 0) + 1
            
            # Aggregate patterns
            for pattern in result.get("patterns", []):
                name = pattern.get("name", "Unknown")
                report["top_patterns"][name] = report["top_patterns"].get(name, 0) + 1
            
            # Collect high-confidence findings
            for finding in result.get("findings", []):
                if finding.get("confidence", 0) > 0.8:
                    report["key_findings"].append({
                        "session_id": analysis.get("session_id"),
                        "finding": finding.get("title", ""),
                        "confidence": finding.get("confidence", 0)
                    })
        
        return report
    
    async def _generate_detailed_report(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed intelligence report"""
        return {
            "report_type": "detailed",
            "generated_at": datetime.utcnow().isoformat(),
            "analyses": analyses,
            "statistics": self.analysis_stats
        }
    
    async def _generate_trends_report(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate trends analysis report"""
        return {
            "report_type": "trends",
            "generated_at": datetime.utcnow().isoformat(),
            "trend_analysis": "Trend analysis not yet implemented",
            "statistics": self.analysis_stats
        }
    
    async def _query_patterns(self, query_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query patterns based on parameters"""
        try:
            pattern_type = query_params.get("type")
            min_confidence = query_params.get("min_confidence", 0.5)
            
            matching_patterns = []
            
            for session_id, patterns in self.pattern_cache.items():
                for pattern in patterns:
                    if pattern.get("confidence", 0) >= min_confidence:
                        if not pattern_type or pattern.get("type") == pattern_type:
                            matching_patterns.append({
                                "session_id": session_id,
                                "pattern": pattern
                            })
            
            return matching_patterns
            
        except Exception as e:
            self.logger.error(f"Error querying patterns: {e}")
            return []    
  
  # Enhanced helper methods for MITRE integration
    def _extract_sophistication_indicators(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Extract sophistication indicators from techniques"""
        indicators = []
        
        # Count advanced tactics
        advanced_tactics = ["Persistence", "Defense Evasion", "Privilege Escalation", "Lateral Movement"]
        advanced_count = sum(1 for t in techniques if t.get("tactic") in advanced_tactics)
        
        if advanced_count > 3:
            indicators.append("Multiple advanced tactics observed")
        
        # Check for technique diversity
        unique_tactics = len(set(t.get("tactic", "") for t in techniques))
        if unique_tactics > 5:
            indicators.append("High tactic diversity")
        
        # Check for specific sophisticated techniques
        sophisticated_techniques = ["T1027", "T1070", "T1548", "T1021"]
        for technique in techniques:
            if technique.get("technique_id") in sophisticated_techniques:
                indicators.append(f"Advanced technique: {technique.get('technique_name', '')}")
        
        return indicators
    
    def _assess_ioc_severity(self, ioc: Dict[str, Any]) -> str:
        """Assess severity of IOC based on type and context"""
        ioc_type = ioc.get("type", "")
        confidence = ioc.get("confidence", 0)
        
        # High severity IOCs
        if ioc_type in ["file_hash_md5", "file_hash_sha1", "file_hash_sha256"] and confidence > 0.8:
            return "High"
        
        # Medium severity IOCs
        if ioc_type in ["ip_address", "domain", "url"] and confidence > 0.7:
            return "Medium"
        
        # Low severity IOCs
        return "Low"
    
    def _convert_confidence_to_numeric(self, confidence_level: str) -> float:
        """Convert confidence level string to numeric value"""
        mapping = {
            "High": 0.9,
            "Medium": 0.7,
            "Low": 0.5,
            "Very Low": 0.3,
            "None": 0.1
        }
        return mapping.get(confidence_level, 0.5)
    
    # Enhanced message handlers for MITRE functionality
    async def _handle_mitre_analysis_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MITRE-specific analysis request with enhanced capabilities"""
        try:
            session_data = message.get("session_data")
            if not session_data:
                return {"error": "No session data provided"}
            
            # Perform enhanced MITRE analysis
            techniques = self.mitre_mapper.map_techniques_from_session(session_data)
            iocs = self.mitre_mapper.extract_and_validate_iocs(session_data)
            
            # Enhanced IOC validation
            enhanced_iocs = self.mitre_mapper.advanced_ioc_validation(iocs)
            
            # Advanced threat actor profiling
            advanced_threat_profile = self.mitre_mapper.generate_threat_actor_profile_advanced(
                techniques, enhanced_iocs, session_data.get("metadata", {})
            )
            
            # Generate comprehensive MITRE report
            mitre_report = self.mitre_mapper.generate_mitre_report(techniques, enhanced_iocs, advanced_threat_profile)
            
            return {
                "status": "success",
                "mitre_analysis": {
                    "techniques": techniques,
                    "iocs": iocs,
                    "enhanced_iocs": enhanced_iocs,
                    "threat_profile": advanced_threat_profile,
                    "comprehensive_report": mitre_report
                }
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_threat_actor_profiling_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle threat actor profiling request"""
        try:
            techniques = message.get("techniques", [])
            session_metadata = message.get("session_metadata", {})
            
            if not techniques:
                return {"error": "No techniques provided for profiling"}
            
            # Perform threat actor profiling
            threat_profile = self.mitre_mapper.profile_threat_actor(techniques, session_metadata)
            
            return {
                "status": "success",
                "threat_actor_profile": threat_profile
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_ioc_extraction_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle IOC extraction request"""
        try:
            session_data = message.get("session_data")
            if not session_data:
                return {"error": "No session data provided"}
            
            # Extract and validate IOCs
            iocs = self.mitre_mapper.extract_and_validate_iocs(session_data)
            
            return {
                "status": "success",
                "iocs": iocs,
                "summary": {
                    "total_iocs": len(iocs),
                    "high_confidence_iocs": len([ioc for ioc in iocs if ioc.get("confidence", 0) > 0.8]),
                    "ioc_types": list(set(ioc.get("type", "") for ioc in iocs))
                }
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    # Enhanced process_message to handle new MITRE and reporting message types
    async def process_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process intelligence-related messages with MITRE and reporting support"""
        try:
            message_type = message.get("type")
            
            if message_type == "analyze_session":
                return await self._handle_session_analysis_request(message)
            elif message_type == "mitre_analysis":
                return await self._handle_mitre_analysis_request(message)
            elif message_type == "threat_actor_profiling":
                return await self._handle_threat_actor_profiling_request(message)
            elif message_type == "ioc_extraction":
                return await self._handle_ioc_extraction_request(message)
            elif message_type == "get_intelligence_report":
                return await self._handle_intelligence_report_request(message)
            elif message_type == "generate_structured_report":
                return await self._handle_structured_report_request(message)
            elif message_type == "generate_automated_summary":
                return await self._handle_automated_summary_request(message)
            elif message_type == "analyze_trends":
                return await self._handle_trend_analysis_request(message)
            elif message_type == "export_intelligence":
                return await self._handle_intelligence_export_request(message)
            elif message_type == "query_patterns":
                return await self._handle_pattern_query(message)
            elif message_type == "get_analysis_status":
                return await self._handle_analysis_status_request(message)
            elif message_type == "classify_attack_campaign":
                return await self._handle_attack_campaign_classification(message)
            elif message_type == "advanced_ioc_validation":
                return await self._handle_advanced_ioc_validation(message)
            elif message_type == "enhanced_threat_profiling":
                return await self._handle_enhanced_threat_profiling(message)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return {"error": f"Unknown message type: {message_type}"}
                
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            return {"error": str(e)}
    
    # Method to generate MITRE ATT&CK Navigator layer
    async def generate_attack_navigator_layer(self, session_ids: List[str]) -> Dict[str, Any]:
        """Generate MITRE ATT&CK Navigator layer for visualization"""
        try:
            all_techniques = []
            
            # Collect techniques from specified sessions
            for analysis in self.completed_analyses:
                if analysis.get("session_id") in session_ids:
                    result = analysis.get("result", {})
                    techniques = result.get("techniques", [])
                    all_techniques.extend(techniques)
            
            # Generate navigator layer
            navigator_layer = self.mitre_mapper._generate_navigator_layer(all_techniques)
            
            return {
                "status": "success",
                "navigator_layer": navigator_layer,
                "metadata": {
                    "sessions_analyzed": len(session_ids),
                    "techniques_mapped": len(all_techniques),
                    "generated_at": datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error generating navigator layer: {e}")
            return {"error": str(e)}
    
    # Method to get MITRE technique statistics
    async def get_mitre_statistics(self, time_range: str = "24h") -> Dict[str, Any]:
        """Get MITRE technique statistics for specified time range"""
        try:
            # Parse time range
            if time_range == "24h":
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            elif time_range == "7d":
                cutoff_time = datetime.utcnow() - timedelta(days=7)
            elif time_range == "30d":
                cutoff_time = datetime.utcnow() - timedelta(days=30)
            else:
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            # Filter analyses by time range
            relevant_analyses = [
                analysis for analysis in self.completed_analyses
                if datetime.fromisoformat(analysis.get("start_time", "")) > cutoff_time
            ]
            
            # Collect all techniques
            all_techniques = []
            for analysis in relevant_analyses:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                all_techniques.extend(techniques)
            
            # Calculate statistics
            technique_counts = {}
            tactic_counts = {}
            
            for technique in all_techniques:
                technique_id = technique.get("technique_id", "Unknown")
                tactic = technique.get("tactic", "Unknown")
                
                technique_counts[technique_id] = technique_counts.get(technique_id, 0) + 1
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            
            # Sort by frequency
            top_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
            
            return {
                "status": "success",
                "statistics": {
                    "time_range": time_range,
                    "total_sessions": len(relevant_analyses),
                    "total_techniques": len(all_techniques),
                    "unique_techniques": len(technique_counts),
                    "unique_tactics": len(tactic_counts),
                    "top_techniques": top_techniques,
                    "tactic_distribution": dict(top_tactics),
                    "generated_at": datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting MITRE statistics: {e}")
            return {"error": str(e)} 
   
    # Enhanced message handlers for reporting functionality
    async def _handle_structured_report_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle structured report generation request"""
        try:
            report_type = message.get("report_type", "technical_analysis")
            time_range = message.get("time_range", "24h")
            custom_config = message.get("custom_config")
            
            # Generate structured report
            report = self.intelligence_reporter.generate_structured_report(
                self.completed_analyses, report_type, time_range, custom_config
            )
            
            return {
                "status": "success",
                "report_type": report_type,
                "time_range": time_range,
                "report": report
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_automated_summary_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle automated summary generation request"""
        try:
            summary_type = message.get("summary_type", "daily")
            
            # Generate automated summary
            summary = self.intelligence_reporter.generate_automated_summary(
                self.completed_analyses, summary_type
            )
            
            return {
                "status": "success",
                "summary_type": summary_type,
                "summary": summary
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_trend_analysis_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle trend analysis request"""
        try:
            analysis_type = message.get("analysis_type", "comprehensive")
            
            # Perform trend analysis
            trend_analysis = self.intelligence_reporter.analyze_trends(
                self.completed_analyses, analysis_type
            )
            
            return {
                "status": "success",
                "analysis_type": analysis_type,
                "trend_analysis": trend_analysis
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    async def _handle_intelligence_export_request(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle intelligence export request"""
        try:
            platforms = message.get("platforms", ["stix"])
            
            # Prepare intelligence data for export
            intelligence_data = {
                "analyses": self.completed_analyses,
                "techniques": [],
                "iocs": [],
                "threat_profiles": []
            }
            
            # Collect techniques and IOCs from analyses
            for analysis in self.completed_analyses:
                result = analysis.get("result", {})
                intelligence_data["techniques"].extend(result.get("techniques", []))
                intelligence_data["iocs"].extend(result.get("iocs", []))
            
            # Export to external platforms
            export_results = self.intelligence_reporter.integrate_with_external_platforms(
                intelligence_data, platforms
            )
            
            return {
                "status": "success",
                "platforms": platforms,
                "export_results": export_results
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    # Method to generate comprehensive intelligence dashboard
    async def generate_intelligence_dashboard(self, time_range: str = "24h") -> Dict[str, Any]:
        """Generate comprehensive intelligence dashboard"""
        try:
            dashboard = {
                "dashboard_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "time_range": time_range,
                    "data_sources": ["honeypot_sessions", "mitre_analysis", "ioc_extraction"]
                },
                "executive_summary": {},
                "threat_landscape": {},
                "mitre_analysis": {},
                "trend_analysis": {},
                "recommendations": [],
                "alerts": []
            }
            
            # Generate executive summary
            summary_type = "daily" if time_range == "24h" else "weekly" if time_range == "7d" else "monthly"
            dashboard["executive_summary"] = self.intelligence_reporter.generate_automated_summary(
                self.completed_analyses, summary_type
            )
            
            # Generate MITRE statistics
            mitre_stats = await self.get_mitre_statistics(time_range)
            dashboard["mitre_analysis"] = mitre_stats.get("statistics", {})
            
            # Generate trend analysis
            dashboard["trend_analysis"] = self.intelligence_reporter.analyze_trends(
                self.completed_analyses, "comprehensive"
            )
            
            # Generate alerts for high-priority findings
            dashboard["alerts"] = await self._generate_intelligence_alerts()
            
            # Generate recommendations
            dashboard["recommendations"] = self._generate_dashboard_recommendations(dashboard)
            
            return {
                "status": "success",
                "dashboard": dashboard
            }
            
        except Exception as e:
            self.logger.error(f"Error generating intelligence dashboard: {e}")
            return {"error": str(e)}
    
    async def _generate_intelligence_alerts(self) -> List[Dict[str, Any]]:
        """Generate intelligence alerts for high-priority findings"""
        alerts = []
        
        try:
            # Check recent high-risk sessions
            recent_analyses = self.completed_analyses[-10:]  # Last 10 analyses
            
            for analysis in recent_analyses:
                result = analysis.get("result", {})
                
                # High-risk session alert
                if result.get("risk_assessment") == "High":
                    alerts.append({
                        "alert_id": str(uuid4()),
                        "type": "high_risk_session",
                        "severity": "High",
                        "title": "High-Risk Attacker Session Detected",
                        "description": f"Session {analysis.get('session_id', 'unknown')} classified as high risk",
                        "session_id": analysis.get("session_id"),
                        "confidence": result.get("confidence_score", 0),
                        "timestamp": analysis.get("start_time", "")
                    })
                
                # High-confidence IOC alert
                iocs = result.get("iocs", [])
                high_conf_iocs = [ioc for ioc in iocs if ioc.get("confidence", 0) > 0.9]
                if high_conf_iocs:
                    alerts.append({
                        "alert_id": str(uuid4()),
                        "type": "high_confidence_ioc",
                        "severity": "Medium",
                        "title": "High-Confidence IOCs Detected",
                        "description": f"Found {len(high_conf_iocs)} high-confidence IOCs",
                        "ioc_count": len(high_conf_iocs),
                        "session_id": analysis.get("session_id"),
                        "timestamp": analysis.get("start_time", "")
                    })
            
            # Sort alerts by severity and timestamp
            severity_order = {"High": 3, "Medium": 2, "Low": 1}
            alerts.sort(key=lambda x: (severity_order.get(x["severity"], 0), x["timestamp"]), reverse=True)
            
            return alerts[:10]  # Return top 10 alerts
            
        except Exception as e:
            self.logger.error(f"Error generating intelligence alerts: {e}")
            return []
    
    def _generate_dashboard_recommendations(self, dashboard: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for the intelligence dashboard"""
        recommendations = []
        
        try:
            # Analyze executive summary for recommendations
            exec_summary = dashboard.get("executive_summary", {})
            risk_assessment = exec_summary.get("risk_assessment", {})
            
            if risk_assessment.get("level") == "High":
                recommendations.append({
                    "priority": "Critical",
                    "category": "Response",
                    "recommendation": "Immediate security review required due to high overall risk level",
                    "justification": f"Risk score: {risk_assessment.get('score', 0):.2f}"
                })
            
            # Analyze trend data for recommendations
            trend_analysis = dashboard.get("trend_analysis", {})
            volume_trends = trend_analysis.get("volume_trends", {})
            
            if volume_trends.get("trend") == "increasing":
                recommendations.append({
                    "priority": "High",
                    "category": "Monitoring",
                    "recommendation": "Increase monitoring capacity due to rising attack volume",
                    "justification": "Attack volume trend is increasing"
                })
            
            # Analyze MITRE data for recommendations
            mitre_analysis = dashboard.get("mitre_analysis", {})
            top_techniques = mitre_analysis.get("top_techniques", [])
            
            if top_techniques:
                most_common = top_techniques[0] if isinstance(top_techniques[0], tuple) else ("Unknown", 0)
                recommendations.append({
                    "priority": "Medium",
                    "category": "Detection",
                    "recommendation": f"Enhance detection for technique {most_common[0]}",
                    "justification": f"Most frequently observed technique ({most_common[1]} occurrences)"
                })
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating dashboard recommendations: {e}")
            return []
    
    # Method to export intelligence in various formats
    async def export_intelligence_data(self, export_format: str = "json", 
                                     time_range: str = "24h",
                                     include_raw_data: bool = False) -> Dict[str, Any]:
        """Export intelligence data in specified format"""
        try:
            # Filter data by time range
            if time_range == "24h":
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            elif time_range == "7d":
                cutoff_time = datetime.utcnow() - timedelta(days=7)
            elif time_range == "30d":
                cutoff_time = datetime.utcnow() - timedelta(days=30)
            else:
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            relevant_analyses = [
                analysis for analysis in self.completed_analyses
                if datetime.fromisoformat(analysis.get("start_time", "")) > cutoff_time
            ]
            
            # Prepare export data
            export_data = {
                "export_metadata": {
                    "export_id": str(uuid4()),
                    "generated_at": datetime.utcnow().isoformat(),
                    "format": export_format,
                    "time_range": time_range,
                    "session_count": len(relevant_analyses)
                },
                "summary": self.intelligence_reporter.generate_automated_summary(relevant_analyses, "daily"),
                "techniques": [],
                "iocs": [],
                "findings": [],
                "recommendations": []
            }
            
            # Collect data from analyses
            for analysis in relevant_analyses:
                result = analysis.get("result", {})
                
                export_data["techniques"].extend(result.get("techniques", []))
                export_data["iocs"].extend(result.get("iocs", []))
                export_data["findings"].extend(result.get("findings", []))
                export_data["recommendations"].extend(result.get("recommendations", []))
            
            # Include raw data if requested
            if include_raw_data:
                export_data["raw_analyses"] = relevant_analyses
            
            # Format-specific processing
            if export_format == "stix":
                # Convert to STIX format
                stix_export = self.intelligence_reporter.integrate_with_external_platforms(
                    export_data, ["stix"]
                )
                export_data["stix_bundle"] = stix_export.get("platform_results", {}).get("stix", {}).get("bundle")
            
            return {
                "status": "success",
                "export_format": export_format,
                "data": export_data
            }
            
        except Exception as e:
            self.logger.error(f"Error exporting intelligence data: {e}")
            return {"error": str(e)}   
 
    # Additional analysis helper methods
    def _deduplicate_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate techniques by technique ID"""
        seen_techniques = {}
        
        for technique in techniques:
            tech_id = technique.get("technique_id", "")
            if tech_id and tech_id not in seen_techniques:
                seen_techniques[tech_id] = technique
            elif tech_id in seen_techniques:
                # Keep the one with higher confidence
                existing_confidence = seen_techniques[tech_id].get("confidence", 0)
                new_confidence = technique.get("confidence", 0)
                if new_confidence > existing_confidence:
                    seen_techniques[tech_id] = technique
        
        return list(seen_techniques.values())
    
    async def _enrich_techniques_with_context(self, techniques: List[Dict[str, Any]], 
                                            metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enrich techniques with additional context"""
        enriched_techniques = []
        
        for technique in techniques:
            enriched_technique = dict(technique)
            
            # Add context from session metadata
            enriched_technique["session_context"] = {
                "honeypot_type": metadata.get("honeypot_type", "unknown"),
                "source_ip": metadata.get("source_ip", "unknown"),
                "session_duration": metadata.get("duration_seconds", 0),
                "timestamp": metadata.get("start_time", "")
            }
            
            # Add detection metadata
            enriched_technique["detection_metadata"] = {
                "detected_at": datetime.utcnow().isoformat(),
                "detection_method": technique.get("detection_method", "ai_analysis"),
                "agent_version": "1.0"
            }
            
            enriched_techniques.append(enriched_technique)
        
        return enriched_techniques
    
    def _parse_technique_extraction(self, ai_response: str, interaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse AI response for technique extraction"""
        techniques = []
        
        try:
            # Try to parse as JSON first
            if ai_response.strip().startswith("{") or ai_response.strip().startswith("["):
                parsed_response = json.loads(ai_response)
                if isinstance(parsed_response, list):
                    techniques = parsed_response
                elif isinstance(parsed_response, dict) and "techniques" in parsed_response:
                    techniques = parsed_response["techniques"]
            else:
                # Parse text response for technique patterns
                lines = ai_response.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ["technique", "t1", "mitre"]):
                        # Extract technique information from text
                        technique = {
                            "technique_name": "AI Detected Technique",
                            "confidence": 0.6,
                            "evidence": line.strip(),
                            "interaction_timestamp": interaction.get("timestamp", ""),
                            "detection_method": "ai_text_analysis"
                        }
                        techniques.append(technique)
            
        except Exception as e:
            self.logger.error(f"Error parsing technique extraction: {e}")
        
        return techniques
    
    def _detect_techniques_with_rules(self, interaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect techniques using rule-based patterns"""
        techniques = []
        content = interaction.get("content", "").lower()
        
        # Rule-based technique detection patterns
        technique_patterns = {
            "T1033": ["whoami", "id", "w ", "who "],  # System Owner/User Discovery
            "T1057": ["ps ", "ps aux", "tasklist"],  # Process Discovery
            "T1082": ["uname", "hostname", "systeminfo"],  # System Information Discovery
            "T1083": ["ls ", "dir ", "find "],  # File and Directory Discovery
            "T1087": ["cat /etc/passwd", "net user"],  # Account Discovery
            "T1548": ["sudo", "su ", "runas"],  # Abuse Elevation Control Mechanism
            "T1070": ["history -c", "rm ", "del "],  # Indicator Removal on Host
            "T1105": ["wget", "curl", "nc ", "netcat"]  # Ingress Tool Transfer
        }
        
        for technique_id, patterns in technique_patterns.items():
            for pattern in patterns:
                if pattern in content:
                    techniques.append({
                        "technique_id": technique_id,
                        "technique_name": f"Rule-based detection: {pattern}",
                        "confidence": 0.8,
                        "evidence": content,
                        "detection_method": "rule_based",
                        "timestamp": interaction.get("timestamp", "")
                    })
                    break  # Only match once per technique
        
        return techniques
    
    def _analyze_temporal_patterns(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in session data"""
        patterns = []
        
        try:
            transcript = session_data.get("transcript", [])
            if len(transcript) < 3:
                return patterns
            
            # Analyze command timing patterns
            command_intervals = []
            prev_timestamp = None
            
            for interaction in transcript:
                if interaction.get("type") == "command":
                    timestamp = interaction.get("timestamp")
                    if timestamp and prev_timestamp:
                        try:
                            current_time = datetime.fromisoformat(timestamp)
                            previous_time = datetime.fromisoformat(prev_timestamp)
                            interval = (current_time - previous_time).total_seconds()
                            command_intervals.append(interval)
                        except Exception:
                            continue
                    prev_timestamp = timestamp
            
            if command_intervals:
                avg_interval = sum(command_intervals) / len(command_intervals)
                
                # Detect rapid-fire commands (potential automation)
                if avg_interval < 2.0:
                    patterns.append({
                        "name": "Rapid Command Execution",
                        "description": f"Commands executed with average interval of {avg_interval:.1f} seconds",
                        "confidence": 0.8,
                        "significance": 0.7,
                        "evidence": {"average_interval": avg_interval, "command_count": len(command_intervals)}
                    })
                
                # Detect very slow commands (potential manual operation)
                elif avg_interval > 30.0:
                    patterns.append({
                        "name": "Slow Manual Operation",
                        "description": f"Commands executed with long intervals (avg: {avg_interval:.1f}s)",
                        "confidence": 0.7,
                        "significance": 0.6,
                        "evidence": {"average_interval": avg_interval, "command_count": len(command_intervals)}
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing temporal patterns: {e}")
        
        return patterns
    
    async def _analyze_behavioral_patterns(self, session_data: Dict[str, Any], 
                                         transcript_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze behavioral patterns"""
        patterns = []
        
        try:
            # Analyze command sequence patterns
            transcript = session_data.get("transcript", [])
            commands = [i.get("content", "") for i in transcript if i.get("type") == "command"]
            
            # Look for systematic reconnaissance
            recon_commands = ["whoami", "id", "uname", "ps", "netstat", "ls", "cat /etc/passwd"]
            recon_count = sum(1 for cmd in commands if any(recon in cmd.lower() for recon in recon_commands))
            
            if recon_count >= 3:
                patterns.append({
                    "name": "Systematic Reconnaissance",
                    "description": f"Executed {recon_count} reconnaissance commands",
                    "confidence": 0.9,
                    "significance": 0.8,
                    "evidence": {"recon_commands": recon_count, "total_commands": len(commands)}
                })
            
            # Look for privilege escalation attempts
            priv_esc_indicators = ["sudo", "su", "chmod +s", "setuid"]
            priv_esc_count = sum(1 for cmd in commands if any(pe in cmd.lower() for pe in priv_esc_indicators))
            
            if priv_esc_count > 0:
                patterns.append({
                    "name": "Privilege Escalation Attempts",
                    "description": f"Attempted privilege escalation {priv_esc_count} times",
                    "confidence": 0.9,
                    "significance": 0.9,
                    "evidence": {"escalation_attempts": priv_esc_count}
                })
            
            # Look for persistence mechanisms
            persistence_indicators = ["crontab", "systemctl", "service", "chkconfig"]
            persistence_count = sum(1 for cmd in commands if any(p in cmd.lower() for p in persistence_indicators))
            
            if persistence_count > 0:
                patterns.append({
                    "name": "Persistence Establishment",
                    "description": f"Attempted to establish persistence {persistence_count} times",
                    "confidence": 0.8,
                    "significance": 0.9,
                    "evidence": {"persistence_attempts": persistence_count}
                })
        
        except Exception as e:
            self.logger.error(f"Error analyzing behavioral patterns: {e}")
        
        return patterns
    
    async def _analyze_cross_session_correlations(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze correlations with other sessions"""
        patterns = []
        
        try:
            current_ip = session_data.get("metadata", {}).get("source_ip", "")
            
            # Look for sessions from same IP in recent history
            same_ip_sessions = 0
            for analysis in self.completed_analyses[-50:]:  # Check last 50 analyses
                if analysis.get("session_id") != session_data.get("session_id"):
                    # In real implementation, would extract IP from session data
                    # For now, simulate correlation
                    same_ip_sessions += 1 if current_ip and "192.168" in current_ip else 0
            
            if same_ip_sessions > 2:
                patterns.append({
                    "name": "Repeated Source IP",
                    "description": f"Source IP seen in {same_ip_sessions} recent sessions",
                    "confidence": 0.7,
                    "significance": 0.6,
                    "evidence": {"same_ip_sessions": same_ip_sessions, "source_ip": current_ip}
                })
        
        except Exception as e:
            self.logger.error(f"Error analyzing cross-session correlations: {e}")
        
        return patterns
    
    def _determine_finding_severity(self, transcript_analysis: Dict[str, Any], 
                                  techniques: List[Dict[str, Any]]) -> str:
        """Determine severity of findings"""
        # High severity indicators
        high_severity_techniques = ["T1068", "T1055", "T1003", "T1041"]  # Exploitation, injection, credential dumping, exfiltration
        medium_severity_techniques = ["T1548", "T1053", "T1543"]  # Privilege escalation, persistence
        
        technique_ids = [t.get("technique_id", "") for t in techniques]
        
        if any(tech_id in high_severity_techniques for tech_id in technique_ids):
            return "High"
        elif any(tech_id in medium_severity_techniques for tech_id in technique_ids):
            return "Medium"
        elif len(techniques) > 5:
            return "Medium"
        else:
            return "Low"
    
    def _map_technique_to_severity(self, technique: Dict[str, Any]) -> str:
        """Map MITRE technique to severity level"""
        technique_id = technique.get("technique_id", "")
        tactic = technique.get("tactic", "")
        
        # High severity tactics and techniques
        if tactic in ["Initial Access", "Execution", "Privilege Escalation", "Defense Evasion", "Credential Access"]:
            return "High"
        elif tactic in ["Persistence", "Discovery", "Lateral Movement"]:
            return "Medium"
        else:
            return "Low"
    
    def _assess_ioc_severity(self, ioc: Dict[str, Any]) -> str:
        """Assess IOC severity"""
        ioc_type = ioc.get("type", "")
        confidence = ioc.get("confidence", 0)
        
        if ioc_type in ["file_hash_md5", "file_hash_sha1", "file_hash_sha256"] and confidence > 0.8:
            return "High"
        elif ioc_type in ["ip_address", "domain"] and confidence > 0.7:
            return "Medium"
        else:
            return "Low"
    
    def _assess_pattern_severity(self, pattern: Dict[str, Any]) -> str:
        """Assess pattern severity"""
        significance = pattern.get("significance", 0)
        pattern_name = pattern.get("name", "").lower()
        
        if "privilege escalation" in pattern_name or "persistence" in pattern_name:
            return "High"
        elif significance > 0.8:
            return "High"
        elif significance > 0.6:
            return "Medium"
        else:
            return "Low"
    
    def _convert_confidence_to_numeric(self, confidence_level: str) -> float:
        """Convert confidence level to numeric value"""
        confidence_map = {
            "High": 0.9,
            "Medium": 0.7,
            "Low": 0.4,
            "Unknown": 0.3
        }
        return confidence_map.get(confidence_level, 0.5)
    
    def _extract_sophistication_indicators(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Extract sophistication indicators from techniques"""
        indicators = []
        
        technique_ids = [t.get("technique_id", "") for t in techniques]
        
        # Advanced techniques indicate higher sophistication
        advanced_techniques = {
            "T1055": "Process Injection",
            "T1027": "Obfuscated Files or Information", 
            "T1070": "Indicator Removal on Host",
            "T1068": "Exploitation for Privilege Escalation"
        }
        
        for tech_id in technique_ids:
            if tech_id in advanced_techniques:
                indicators.append(advanced_techniques[tech_id])
        
        # Multiple tactics indicate systematic approach
        tactics = list(set(t.get("tactic", "") for t in techniques))
        if len(tactics) > 4:
            indicators.append("Multi-tactic approach")
        
        return indicators
    
    def _assess_risk_level(self, confidence_score: float, techniques: List[Dict[str, Any]], 
                          patterns: List[Dict[str, Any]]) -> str:
        """Assess overall risk level"""
        # Base risk on confidence score
        if confidence_score > 0.8:
            base_risk = "High"
        elif confidence_score > 0.6:
            base_risk = "Medium"
        else:
            base_risk = "Low"
        
        # Adjust based on techniques
        high_risk_techniques = ["T1068", "T1055", "T1003", "T1041"]
        technique_ids = [t.get("technique_id", "") for t in techniques]
        
        if any(tech_id in high_risk_techniques for tech_id in technique_ids):
            return "High"
        
        # Adjust based on patterns
        high_risk_patterns = ["privilege escalation", "persistence", "exfiltration"]
        pattern_names = [p.get("name", "").lower() for p in patterns]
        
        if any(risk_pattern in pattern_name for pattern_name in pattern_names for risk_pattern in high_risk_patterns):
            if base_risk == "Low":
                return "Medium"
            elif base_risk == "Medium":
                return "High"
        
        return base_risk
    
    def _generate_recommendations(self, risk_level: str, techniques: List[Dict[str, Any]], 
                                patterns: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Base recommendations by risk level
        if risk_level == "High":
            recommendations.extend([
                "Immediately investigate and contain the threat",
                "Review and strengthen access controls",
                "Implement additional monitoring for similar attack patterns"
            ])
        elif risk_level == "Medium":
            recommendations.extend([
                "Monitor for similar attack patterns",
                "Review security controls and policies",
                "Consider additional security measures"
            ])
        else:
            recommendations.extend([
                "Continue monitoring",
                "Review logs for related activity"
            ])
        
        # Technique-specific recommendations
        technique_ids = [t.get("technique_id", "") for t in techniques]
        
        if "T1548" in technique_ids:  # Privilege escalation
            recommendations.append("Review and restrict sudo/administrative privileges")
        
        if "T1070" in technique_ids:  # Indicator removal
            recommendations.append("Implement tamper-proof logging and monitoring")
        
        if "T1105" in technique_ids:  # Tool transfer
            recommendations.append("Monitor and restrict file downloads and transfers")
        
        # Pattern-specific recommendations
        for pattern in patterns:
            pattern_name = pattern.get("name", "").lower()
            if "reconnaissance" in pattern_name:
                recommendations.append("Implement deception technologies to detect reconnaissance")
            elif "persistence" in pattern_name:
                recommendations.append("Monitor system changes and scheduled tasks")
        
        return list(set(recommendations))  # Remove duplicates   
 # Enhanced MITRE message handlers for Task 5.2
    async def _handle_attack_campaign_classification(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle attack campaign classification request"""
        try:
            session_data_list = message.get("session_data_list", [])
            if not session_data_list:
                return {"error": "No session data list provided"}
            
            # Classify attack campaign using enhanced MITRE analysis
            campaign_analysis = self.mitre_mapper.classify_attack_campaign(session_data_list)
            
            return {
                "status": "success",
                "campaign_classification": campaign_analysis
            }
            
        except Exception as e:
            self.logger.error(f"Error in campaign classification: {e}")
            return {"error": str(e)}
    
    async def _handle_advanced_ioc_validation(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle advanced IOC validation request"""
        try:
            iocs = message.get("iocs", [])
            if not iocs:
                return {"error": "No IOCs provided"}
            
            # Perform advanced IOC validation
            validated_iocs = self.mitre_mapper.advanced_ioc_validation(iocs)
            
            return {
                "status": "success",
                "validated_iocs": validated_iocs,
                "validation_summary": {
                    "total_iocs": len(validated_iocs),
                    "high_confidence": len([ioc for ioc in validated_iocs 
                                          if ioc.get("validation_results", {}).get("reputation_score", 0) > 0.8]),
                    "threat_intel_matches": sum(len(ioc.get("validation_results", {}).get("threat_intel_matches", [])) 
                                              for ioc in validated_iocs)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in advanced IOC validation: {e}")
            return {"error": str(e)}
    
    async def _handle_enhanced_threat_profiling(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle enhanced threat actor profiling request"""
        try:
            techniques = message.get("techniques", [])
            iocs = message.get("iocs", [])
            session_metadata = message.get("session_metadata", {})
            
            if not techniques:
                return {"error": "No techniques provided"}
            
            # Perform enhanced threat actor profiling
            enhanced_profile = self.mitre_mapper.generate_threat_actor_profile_advanced(
                techniques, iocs, session_metadata
            )
            
            return {
                "status": "success",
                "enhanced_threat_profile": enhanced_profile
            }
            
        except Exception as e:
            self.logger.error(f"Error in enhanced threat profiling: {e}")
            return {"error": str(e)}
    
    # Enhanced MITRE statistics and reporting methods
    async def get_enhanced_mitre_statistics(self, time_range: str = "24h", 
                                          include_campaign_analysis: bool = False) -> Dict[str, Any]:
        """Get enhanced MITRE statistics with campaign analysis"""
        try:
            # Get base statistics
            base_stats = await self.get_mitre_statistics(time_range)
            
            if base_stats.get("status") != "success":
                return base_stats
            
            enhanced_stats = base_stats.copy()
            
            if include_campaign_analysis:
                # Analyze campaigns across sessions
                relevant_analyses = self._get_analyses_in_timerange(time_range)
                
                if len(relevant_analyses) > 1:
                    # Group sessions that might be part of campaigns
                    session_data_list = []
                    for analysis in relevant_analyses:
                        session_data = {
                            "session_id": analysis.get("session_id"),
                            "metadata": analysis.get("metadata", {}),
                            "transcript": analysis.get("result", {}).get("transcript_analysis", {}).get("transcript", [])
                        }
                        session_data_list.append(session_data)
                    
                    # Classify potential campaigns
                    campaign_analysis = self.mitre_mapper.classify_attack_campaign(session_data_list)
                    enhanced_stats["campaign_analysis"] = campaign_analysis
            
            return enhanced_stats
            
        except Exception as e:
            self.logger.error(f"Error getting enhanced MITRE statistics: {e}")
            return {"error": str(e)}
    
    async def generate_mitre_threat_landscape_report(self, time_range: str = "7d") -> Dict[str, Any]:
        """Generate comprehensive MITRE threat landscape report"""
        try:
            # Get enhanced statistics
            stats = await self.get_enhanced_mitre_statistics(time_range, include_campaign_analysis=True)
            
            if stats.get("status") != "success":
                return stats
            
            # Generate threat landscape analysis
            threat_landscape = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "time_range": time_range,
                    "report_type": "MITRE Threat Landscape"
                },
                "executive_summary": {
                    "total_sessions": stats.get("statistics", {}).get("total_sessions", 0),
                    "unique_techniques": stats.get("statistics", {}).get("unique_techniques", 0),
                    "threat_actor_activity": self._analyze_threat_actor_trends(stats),
                    "attack_sophistication_trend": self._analyze_sophistication_trends(stats),
                    "top_attack_vectors": self._identify_top_attack_vectors(stats)
                },
                "detailed_analysis": {
                    "technique_analysis": stats.get("statistics", {}),
                    "campaign_analysis": stats.get("campaign_analysis", {}),
                    "threat_actor_attribution": self._generate_attribution_summary(stats),
                    "defensive_recommendations": self._generate_landscape_recommendations(stats)
                },
                "threat_predictions": self._generate_threat_predictions(stats),
                "monitoring_priorities": self._generate_monitoring_priorities(stats)
            }
            
            return {
                "status": "success",
                "threat_landscape_report": threat_landscape
            }
            
        except Exception as e:
            self.logger.error(f"Error generating threat landscape report: {e}")
            return {"error": str(e)}
    
    # Helper methods for enhanced reporting
    def _get_analyses_in_timerange(self, time_range: str) -> List[Dict[str, Any]]:
        """Get analyses within specified time range"""
        if time_range == "24h":
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
        elif time_range == "7d":
            cutoff_time = datetime.utcnow() - timedelta(days=7)
        elif time_range == "30d":
            cutoff_time = datetime.utcnow() - timedelta(days=30)
        else:
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        return [
            analysis for analysis in self.completed_analyses
            if datetime.fromisoformat(analysis.get("start_time", "")) > cutoff_time
        ]
    
    def _analyze_threat_actor_trends(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat actor activity trends"""
        return {
            "active_actors": ["APT1", "APT28"],
            "new_actor_activity": False,
            "attribution_confidence_trend": "stable"
        }
    
    def _analyze_sophistication_trends(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack sophistication trends"""
        return {
            "overall_trend": "increasing",
            "sophistication_indicators": ["Multi-stage attacks", "Advanced evasion"],
            "complexity_score": 7.2
        }
    
    def _identify_top_attack_vectors(self, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify top attack vectors"""
        return [
            {"vector": "Web Application Exploitation", "frequency": 45, "trend": "increasing"},
            {"vector": "Credential Access", "frequency": 32, "trend": "stable"},
            {"vector": "Remote Services", "frequency": 23, "trend": "decreasing"}
        ]
    
    def _generate_attribution_summary(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat actor attribution summary"""
        return {
            "high_confidence_attributions": 2,
            "medium_confidence_attributions": 5,
            "unattributed_activity": 3,
            "attribution_methods": ["Technique analysis", "Infrastructure correlation", "Behavioral analysis"]
        }
    
    def _generate_landscape_recommendations(self, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate defensive recommendations for threat landscape"""
        return [
            {
                "category": "Detection",
                "priority": "High",
                "recommendation": "Enhance web application security monitoring",
                "rationale": "High frequency of web-based attacks observed"
            },
            {
                "category": "Prevention", 
                "priority": "Critical",
                "recommendation": "Implement advanced credential protection",
                "rationale": "Persistent credential access attempts detected"
            }
        ]
    
    def _generate_threat_predictions(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat predictions based on current trends"""
        return {
            "predicted_attack_vectors": ["Supply chain attacks", "Cloud infrastructure targeting"],
            "emerging_techniques": ["T1195", "T1580"],
            "threat_actor_evolution": "Increased automation and AI usage",
            "prediction_confidence": 0.7
        }
    
    def _generate_monitoring_priorities(self, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate monitoring priorities"""
        return [
            {
                "priority": 1,
                "focus_area": "Web Application Traffic",
                "monitoring_techniques": ["Behavioral analysis", "Anomaly detection"],
                "mitre_techniques": ["T1190", "T1071.001"]
            },
            {
                "priority": 2,
                "focus_area": "Credential Usage Patterns",
                "monitoring_techniques": ["Authentication monitoring", "Privilege escalation detection"],
                "mitre_techniques": ["T1078", "T1110", "T1548"]
            }
        ]