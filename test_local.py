"""
Simple local test without AWS dependencies
"""

import asyncio
import json
import logging
from agents.detection_agent import DetectionAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_basic_functionality():
    """Test basic agent functionality without AWS calls"""
    logger.info("Testing Detection Agent basic functionality...")
    
    # Create agent with mock configuration
    config = {
        "threat_threshold": 0.7,
        "confidence_threshold": 0.6,
        "test_mode": True
    }
    
    agent = DetectionAgent(config=config)
    
    try:
        # Test basic tools (no AWS calls)
        logger.info("✅ Agent created successfully")
        
        # Test 1: Health check
        health = agent.health_check_tool()
        logger.info(f"✅ Health Check: {health['status']}")
        
        # Test 2: Status check
        status = agent.get_status_tool()
        logger.info(f"✅ Agent Status: {status['status']}")
        
        # Test 3: Reputation check
        reputation = agent.check_reputation_tool("192.168.1.100")
        logger.info(f"✅ Reputation Check: IP is {'malicious' if reputation['is_malicious'] else 'clean'}")
        
        # Test 4: IOC extraction
        sample_text = "Suspicious activity from 10.0.0.1 connecting to malicious.example.com with hash abc123def456789"
        iocs = agent.extract_iocs_tool(sample_text)
        logger.info(f"✅ IOC Extraction: Found {len(iocs['ip_addresses'])} IPs, {len(iocs['domains'])} domains, {len(iocs['hashes'])} hashes")
        
        # Test 5: Network traffic analysis
        traffic_data = {
            "packet_count": 15000,
            "unique_destinations": 150,
            "protocol": "TCP"
        }
        traffic_analysis = agent.analyze_network_traffic_tool(traffic_data)
        logger.info(f"✅ Traffic Analysis: Risk score {traffic_analysis['risk_score']}")
        
        # Test 6: Configuration update
        new_config = {"threat_threshold": 0.8}
        config_result = agent.update_config_tool(new_config)
        logger.info(f"✅ Config Update: Updated at {config_result['updated_at']}")
        
        # Test 7: Alert generation
        alert = agent.send_alert_tool("test_alert", "Test alert message", "medium")
        logger.info(f"✅ Alert Generated: {alert['alert_id']}")
        
        logger.info("🎉 All basic functionality tests passed!")
        logger.info("Agent is ready for AgentCore Runtime deployment")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_basic_functionality())
    exit(0 if success else 1)