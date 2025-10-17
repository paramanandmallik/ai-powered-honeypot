"""
Main AgentCore Runtime Entry Point for AI-Powered Honeypot System

This module provides the main entry points for deploying agents to Amazon Bedrock AgentCore Runtime.
Each agent type has its own entry point that can be deployed independently.
"""

import os
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def create_detection_agent_app():
    """Create Detection Agent application for AgentCore Runtime deployment"""
    try:
        from agents.detection.detection_agent import DetectionAgent
        
        # Initialize agent with configuration
        config = {
            "confidence_threshold": float(os.getenv("DETECTION_CONFIDENCE_THRESHOLD", "0.75")),
            "enable_mitre_mapping": os.getenv("MITRE_ATTACK_MAPPING", "true").lower() == "true",
            "max_concurrent_assessments": int(os.getenv("MAX_CONCURRENT_ASSESSMENTS", "10"))
        }
        
        agent = DetectionAgent(config)
        
        # Create AgentCore Runtime application
        app = agent.create_agentcore_app()
        
        logger.info("Detection Agent application created for AgentCore Runtime")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Detection Agent application: {e}")
        raise

def create_coordinator_agent_app():
    """Create Coordinator Agent application for AgentCore Runtime deployment"""
    try:
        from agents.coordinator.coordinator_agent import CoordinatorAgent
        
        # Initialize agent with configuration
        config = {
            "max_concurrent_honeypots": int(os.getenv("MAX_CONCURRENT_HONEYPOTS", "50")),
            "honeypot_timeout_minutes": int(os.getenv("HONEYPOT_TIMEOUT_MINUTES", "60")),
            "auto_scaling_enabled": os.getenv("AUTO_SCALING_ENABLED", "true").lower() == "true",
            "emergency_shutdown_enabled": os.getenv("EMERGENCY_SHUTDOWN_ENABLED", "true").lower() == "true"
        }
        
        agent = CoordinatorAgent(config)
        
        # Create AgentCore Runtime application
        app = agent.create_agentcore_app()
        
        logger.info("Coordinator Agent application created for AgentCore Runtime")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Coordinator Agent application: {e}")
        raise

def create_interaction_agent_app():
    """Create Interaction Agent application for AgentCore Runtime deployment"""
    try:
        from agents.interaction.interaction_agent import InteractionAgent
        
        # Initialize agent with configuration
        config = {
            "max_concurrent_sessions": int(os.getenv("MAX_CONCURRENT_SESSIONS", "10")),
            "session_timeout_minutes": int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")),
            "synthetic_data_enabled": os.getenv("SYNTHETIC_DATA_ENABLED", "true").lower() == "true",
            "real_data_detection_enabled": os.getenv("REAL_DATA_DETECTION_ENABLED", "true").lower() == "true",
            "persona_consistency_enabled": os.getenv("PERSONA_CONSISTENCY_ENABLED", "true").lower() == "true"
        }
        
        agent = InteractionAgent(config)
        
        # Create AgentCore Runtime application
        app = agent.create_agentcore_app()
        
        logger.info("Interaction Agent application created for AgentCore Runtime")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Interaction Agent application: {e}")
        raise

def create_intelligence_agent_app():
    """Create Intelligence Agent application for AgentCore Runtime deployment"""
    try:
        from agents.intelligence.intelligence_agent import IntelligenceAgent
        
        # Initialize agent with configuration
        config = {
            "analysis_batch_size": int(os.getenv("ANALYSIS_BATCH_SIZE", "10")),
            "confidence_threshold": float(os.getenv("INTELLIGENCE_CONFIDENCE_THRESHOLD", "0.7")),
            "enable_mitre_mapping": os.getenv("MITRE_ATTACK_MAPPING", "true").lower() == "true",
            "enable_ioc_extraction": os.getenv("IOC_EXTRACTION_ENABLED", "true").lower() == "true"
        }
        
        agent = IntelligenceAgent(config)
        
        # Create AgentCore Runtime application
        app = agent.create_agentcore_app()
        
        logger.info("Intelligence Agent application created for AgentCore Runtime")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Intelligence Agent application: {e}")
        raise

# Default application for AgentCore Runtime deployment
# The specific agent type is determined by environment variable
def create_app():
    """Create the appropriate agent application based on environment configuration"""
    agent_type = os.getenv("AGENT_TYPE", "detection").lower()
    
    if agent_type == "detection":
        return create_detection_agent_app()
    elif agent_type == "coordinator":
        return create_coordinator_agent_app()
    elif agent_type == "interaction":
        return create_interaction_agent_app()
    elif agent_type == "intelligence":
        return create_intelligence_agent_app()
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")

# AgentCore Runtime entry point
app = create_app()

if __name__ == "__main__":
    # For local testing
    import uvicorn
    
    port = int(os.getenv("PORT", "8000"))
    agent_type = os.getenv("AGENT_TYPE", "detection")
    
    logger.info(f"Starting {agent_type} agent locally on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)