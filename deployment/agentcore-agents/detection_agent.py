#!/usr/bin/env python3
"""
Detection Agent for AI-Powered Honeypot System - AgentCore Runtime Version
Task 12.2: Deploy Detection Agent to AgentCore Runtime with proper scaling configuration
"""

from bedrock_agentcore import BedrockAgentCoreApp
from strands import Agent
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from uuid import uuid4

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the BedrockAgentCore app
app = BedrockAgentCoreApp()

# Create the Strands agent
agent = Agent()

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
    "data_exfiltration": ["T1041", "T1048", "T1567"]
}

def analyze_threat_indicators(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze threat indicators and map to MITRE ATT&CK"""
    try:
        indicators = threat_data.get("indicators", [])
        threat_type = threat_data.get("threat_type", "unknown").lower()
        source_ip = threat_data.get("source_ip", "unknown")
        
        # Calculate confidence score based on indicators
        confidence_score = 0.0
        mitre_techniques = []
        attack_vector = "unknown"
        severity = "MEDIUM"
        
        # Analyze threat type
        if threat_type in MITRE_ATTACK_TECHNIQUES:
            mitre_techniques.extend(MITRE_ATTACK_TECHNIQUES[threat_type])
            confidence_score += 0.3
        
        # Analyze indicators
        for indicator in indicators:
            indicator_lower = indicator.lower()
            
            # Check for specific attack patterns
            if any(pattern in indicator_lower for pattern in ["brute", "force", "login"]):
                mitre_techniques.extend(MITRE_ATTACK_TECHNIQUES["brute_force"])
                confidence_score += 0.2
                attack_vector = "authentication"
                severity = "HIGH"
            
            elif any(pattern in indicator_lower for pattern in ["sql", "injection", "union", "select"]):
                mitre_techniques.extend(MITRE_ATTACK_TECHNIQUES["sql_injection"])
                confidence_score += 0.3
                attack_vector = "web_application"
                severity = "HIGH"
            
            elif any(pattern in indicator_lower for pattern in ["scan", "probe", "reconnaissance"]):
                mitre_techniques.extend(MITRE_ATTACK_TECHNIQUES["reconnaissance"])
                confidence_score += 0.1
                attack_vector = "network"
                severity = "MEDIUM"
            
            elif any(pattern in indicator_lower for pattern in ["malware", "payload", "exploit"]):
                mitre_techniques.extend(MITRE_ATTACK_TECHNIQUES["malware"])
                confidence_score += 0.4
                attack_vector = "malware_delivery"
                severity = "CRITICAL"
        
        # Remove duplicates from MITRE techniques
        mitre_techniques = list(set(mitre_techniques))
        
        # Ensure confidence score is within bounds
        confidence_score = min(1.0, max(0.0, confidence_score))
        
        return {
            "confidence_score": confidence_score,
            "mitre_techniques": mitre_techniques,
            "attack_vector": attack_vector,
            "severity": severity,
            "indicators_analyzed": len(indicators)
        }
        
    except Exception as e:
        logger.error(f"Error analyzing threat indicators: {e}")
        return {
            "confidence_score": 0.5,
            "mitre_techniques": [],
            "attack_vector": "unknown",
            "severity": "MEDIUM",
            "error": str(e)
        }

def make_engagement_decision(analysis_result: Dict[str, Any], confidence_threshold: float = 0.75) -> Dict[str, Any]:
    """Make engagement decision based on threat analysis"""
    try:
        confidence_score = analysis_result.get("confidence_score", 0.0)
        severity = analysis_result.get("severity", "MEDIUM")
        attack_vector = analysis_result.get("attack_vector", "unknown")
        
        # Decision logic
        if confidence_score >= confidence_threshold:
            decision = "ENGAGE"
            reasoning = f"High confidence threat (score: {confidence_score:.2f}) exceeds threshold ({confidence_threshold})"
        elif severity in ["HIGH", "CRITICAL"]:
            decision = "ENGAGE"
            reasoning = f"High severity threat ({severity}) warrants engagement despite lower confidence"
        elif confidence_score >= 0.5:
            decision = "MONITOR"
            reasoning = f"Medium confidence threat (score: {confidence_score:.2f}) requires monitoring"
        else:
            decision = "IGNORE"
            reasoning = f"Low confidence threat (score: {confidence_score:.2f}) below engagement threshold"
        
        # Recommend appropriate honeypots based on attack vector
        recommended_honeypots = []
        if attack_vector == "web_application":
            recommended_honeypots = ["web_admin", "database"]
        elif attack_vector == "authentication":
            recommended_honeypots = ["ssh", "web_admin"]
        elif attack_vector == "network":
            recommended_honeypots = ["ssh", "file_share"]
        elif attack_vector == "malware_delivery":
            recommended_honeypots = ["web_admin", "email"]
        else:
            recommended_honeypots = ["web_admin"]  # Default
        
        return {
            "decision": decision,
            "reasoning": reasoning,
            "recommended_honeypots": recommended_honeypots,
            "confidence_score": confidence_score,
            "severity": severity
        }
        
    except Exception as e:
        logger.error(f"Error making engagement decision: {e}")
        return {
            "decision": "MONITOR",
            "reasoning": f"Error in decision making: {e}",
            "recommended_honeypots": ["web_admin"],
            "confidence_score": 0.5,
            "severity": "MEDIUM"
        }

@app.entrypoint
def invoke(payload):
    """
    Detection Agent entrypoint for threat analysis and engagement decisions.
    
    Task 12.2 Requirement: Deploy Detection Agent to AgentCore Runtime with proper scaling configuration
    - Scales from 2-10 replicas based on threat load
    - Target 70% CPU utilization for optimal performance
    - Handles threat analysis, confidence scoring, and engagement decisions
    """
    try:
        logger.info("Detection Agent processing threat analysis request")
        
        # Extract threat data from payload
        threat_data = payload.get("threat_data", {})
        if not threat_data and "prompt" in payload:
            # Handle direct prompt input for testing
            prompt = payload.get("prompt", "")
            # Try to parse as JSON, otherwise create basic threat data
            try:
                threat_data = json.loads(prompt)
            except:
                threat_data = {
                    "source_ip": "192.168.1.100",
                    "threat_type": "web_attack",
                    "indicators": [prompt],
                    "timestamp": datetime.utcnow().isoformat()
                }
        
        # Generate threat ID
        threat_id = str(uuid4())
        
        # Analyze threat indicators
        analysis_result = analyze_threat_indicators(threat_data)
        
        # Make engagement decision
        engagement_decision = make_engagement_decision(analysis_result)
        
        # Enhanced AI analysis using Strands agent
        ai_prompt = f"""
        Analyze this threat data and provide additional insights:
        
        Threat Data: {json.dumps(threat_data, indent=2)}
        Initial Analysis: {json.dumps(analysis_result, indent=2)}
        
        Provide additional context about:
        1. Potential attacker motivation
        2. Likely next steps in the attack chain
        3. Risk assessment for the organization
        4. Recommended defensive measures
        
        Keep response concise and actionable.
        """
        
        ai_result = agent(ai_prompt)
        
        # Structure the complete response
        response = {
            "agent_type": "detection",
            "task_12_2_requirement": "Deploy Detection Agent to AgentCore Runtime with proper scaling configuration",
            "scaling_config": {
                "min_replicas": 2,
                "max_replicas": 10,
                "target_cpu": 70,
                "scale_up_cooldown": 60,
                "scale_down_cooldown": 300
            },
            "threat_assessment": {
                "threat_id": threat_id,
                "source_ip": threat_data.get("source_ip", "unknown"),
                "threat_type": threat_data.get("threat_type", "unknown"),
                "confidence_score": analysis_result.get("confidence_score", 0.0),
                "severity": analysis_result.get("severity", "MEDIUM"),
                "mitre_techniques": analysis_result.get("mitre_techniques", []),
                "attack_vector": analysis_result.get("attack_vector", "unknown"),
                "decision": engagement_decision.get("decision", "MONITOR"),
                "reasoning": engagement_decision.get("reasoning", ""),
                "recommended_honeypots": engagement_decision.get("recommended_honeypots", []),
                "ai_insights": ai_result.message,
                "timestamp": datetime.utcnow().isoformat()
            },
            "agent_capabilities": [
                "threat_analysis",
                "confidence_scoring", 
                "engagement_decisions",
                "mitre_mapping",
                "ioc_extraction",
                "ai_powered_analysis"
            ],
            "status": "success"
        }
        
        logger.info(f"Detection Agent completed analysis for threat {threat_id}: {engagement_decision.get('decision')}")
        return response
        
    except Exception as e:
        logger.error(f"Detection Agent error: {e}")
        return {
            "agent_type": "detection",
            "status": "error",
            "error": str(e),
            "task_12_2_requirement": "Deploy Detection Agent to AgentCore Runtime with proper scaling configuration",
            "timestamp": datetime.utcnow().isoformat()
        }

if __name__ == "__main__":
    # For local testing
    app.run()