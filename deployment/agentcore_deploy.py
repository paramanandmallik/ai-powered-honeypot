"""
AgentCore Runtime Deployment Script
Deploy AI honeypot agents to Amazon Bedrock AgentCore Runtime
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agents.detection_agent import create_detection_agent_app

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_agentcore_app():
    """
    Create the main AgentCore Runtime application using AWS official approach
    This follows the AWS documentation pattern for AgentCore Runtime deployment
    """
    logger.info("Creating AgentCore Runtime application using AWS official approach...")
    
    # The app is now created in agent.py following AWS documentation
    # This function is kept for compatibility but the main app is in agent.py
    from agent import app
    return app

# For local testing
async def test_agent_locally():
    """Test the agent locally before deployment"""
    from agents.detection_agent import DetectionAgent
    import json
    
    logger.info("Testing Detection Agent locally...")
    
    agent = DetectionAgent()
    await agent.start()
    
    try:
        # Test 1: Basic agent functionality (without AI calls)
        logger.info("Test 1: Basic agent functionality")
        health = agent.health_check_tool()
        logger.info(f"Health Check: {json.dumps(health, indent=2)}")
        
        # Test 2: Agent status
        logger.info("Test 2: Agent status")
        status = agent.get_status_tool()
        logger.info(f"Agent Status: {json.dumps(status, indent=2)}")
        
        # Test 3: Tool usage (non-AI tools)
        logger.info("Test 3: Tool usage")
        reputation = agent.check_reputation_tool("192.168.1.100")
        logger.info(f"Reputation Check: {json.dumps(reputation, indent=2)}")
        
        # Test 4: IOC extraction
        logger.info("Test 4: IOC extraction")
        sample_text = "Suspicious activity from 10.0.0.1 connecting to malicious.example.com with hash abc123def456"
        iocs = agent.extract_iocs_tool(sample_text)
        logger.info(f"Extracted IOCs: {json.dumps(iocs, indent=2)}")
        
        # Test 5: Network traffic analysis
        logger.info("Test 5: Network traffic analysis")
        traffic_data = {
            "packet_count": 15000,
            "unique_destinations": 150,
            "protocol": "TCP",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        traffic_analysis = agent.analyze_network_traffic_tool(traffic_data)
        logger.info(f"Traffic Analysis: {json.dumps(traffic_analysis, indent=2)}")
        
        # Test 6: Configuration update
        logger.info("Test 6: Configuration update")
        new_config = {"threat_threshold": 0.8, "test_mode": True}
        config_result = agent.update_config_tool(new_config)
        logger.info(f"Config Update: {json.dumps(config_result, indent=2)}")
        
        # Test 7: Activity logging
        logger.info("Test 7: Activity logging")
        log_result = agent.log_activity_tool("test_activity", {"test": True})
        logger.info(f"Activity Log: {log_result}")
        
        # Test 8: Alert generation
        logger.info("Test 8: Alert generation")
        alert = agent.send_alert_tool("test_alert", "This is a test alert", "low")
        logger.info(f"Alert Generated: {json.dumps(alert, indent=2)}")
        
        logger.info("✅ All basic functionality tests completed successfully!")
        logger.info("Note: AI-powered features require valid AWS Bedrock credentials and model access")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise
    finally:
        await agent.stop()

def main():
    """Main function for deployment and testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AgentCore Runtime Deployment")
    parser.add_argument("--test", action="store_true", help="Run local tests")
    parser.add_argument("--deploy", action="store_true", help="Deploy to AgentCore Runtime")
    
    args = parser.parse_args()
    
    if args.test:
        asyncio.run(test_agent_locally())
    elif args.deploy:
        logger.info("Creating AgentCore Runtime application...")
        app = create_agentcore_app()
        logger.info("AgentCore Runtime application created successfully!")
        logger.info("Use 'agentcore launch' to deploy to AWS")
    else:
        logger.info("Use --test for local testing or --deploy for deployment preparation")

if __name__ == "__main__":
    main()