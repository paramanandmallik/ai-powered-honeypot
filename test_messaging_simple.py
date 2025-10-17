#!/usr/bin/env python3
"""
Simple Test for AgentCore Messaging Integration
Tests the messaging functionality in test mode.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from agents.detection_agent import DetectionAgent
from config.agentcore_sdk import Message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_messaging_simple():
    """Test messaging integration in test mode"""
    logger.info("Starting simple AgentCore messaging integration test...")
    
    # Create agent with test mode enabled
    config = {
        "test_mode": True,
        "threat_threshold": 0.75,
        "engagement_threshold": 0.75
    }
    
    agent = DetectionAgent(config=config)
    
    try:
        # Test 1: Agent initialization in test mode
        logger.info("Test 1: Agent initialization in test mode")
        await agent.start()
        
        # Verify agent started successfully
        assert agent.state["status"] == "running", "Agent should be running"
        logger.info("✅ Agent initialized successfully in test mode")
        
        # Test 2: Messaging status
        logger.info("Test 2: Messaging status")
        status = agent.get_messaging_status_tool()
        logger.info(f"Messaging Status: {json.dumps(status, indent=2)}")
        
        # In test mode, SDK should not be initialized
        assert not status["agentcore_sdk_initialized"], "SDK should not be initialized in test mode"
        logger.info("✅ Messaging status correct for test mode")
        
        # Test 3: Message handling without SDK
        logger.info("Test 3: Message handling without SDK")
        
        # Create a mock threat feed message
        threat_feed_message = Message(
            message_id="test-msg-001",
            from_agent="test_agent",
            to_agent=agent.agent_id,
            message_type="threat_feed_update",
            payload={
                "feed_type": "malicious_ips",
                "feed_data": {
                    "indicators": ["192.168.100.1", "10.0.100.1"],
                    "source": "test_feed"
                }
            }
        )
        
        # Test the handler directly (should work even without SDK)
        await agent._handle_threat_feed_message(threat_feed_message)
        logger.info("✅ Threat feed message handling works without SDK")
        
        # Test 4: Threat analysis
        logger.info("Test 4: Threat analysis")
        
        threat_data = {
            "source_ip": "192.168.1.100",
            "commands": ["whoami", "ls -la", "ps aux"],
            "failed_login_attempts": 5,
            "session_duration": 300
        }
        
        analysis_result = await agent._analyze_threat(threat_data)
        
        # Verify analysis completed
        assert "overall_confidence" in analysis_result, "Analysis should return confidence"
        assert "threat_level" in analysis_result, "Analysis should return threat level"
        
        logger.info(f"Analysis completed: confidence={analysis_result['overall_confidence']:.2f}, "
                   f"threat_level={analysis_result['threat_level']}")
        logger.info("✅ Threat analysis works without SDK")
        
        # Test 5: Engagement decision (simulated)
        logger.info("Test 5: Engagement decision (simulated)")
        
        if analysis_result.get("threshold_met", False):
            # This should work even without SDK (simulated)
            await agent._publish_engagement_decision(analysis_result)
            
            # Verify engagement decision was stored
            assert len(agent.engagement_decisions) > 0, "Engagement decision should be stored"
            logger.info("✅ Engagement decision works in simulation mode")
        else:
            logger.info("ℹ️ Engagement threshold not met - no decision to publish")
        
        # Test 6: Tools work in test mode
        logger.info("Test 6: Tools work in test mode")
        
        # Test engagement decision tool
        mock_analysis_result = {
            "overall_confidence": 0.85,
            "threat_level": "High",
            "engagement_decision": {"decision": "engage"},
            "mitre_techniques": [{"technique_id": "T1110", "confidence": 0.8}],
            "threshold_met": True
        }
        
        engagement_result = agent.send_engagement_decision_tool(mock_analysis_result)
        logger.info(f"Engagement Decision Tool: {json.dumps(engagement_result, indent=2)}")
        
        # Test threat feed update tool
        feed_update_result = agent.send_threat_feed_update_tool(
            target_agent="test_agent",
            feed_type="test_feed",
            feed_data={"test": "data"}
        )
        logger.info(f"Threat Feed Update Tool: {json.dumps(feed_update_result, indent=2)}")
        
        logger.info("✅ Tools work correctly in test mode")
        
        # Test 7: State management
        logger.info("Test 7: State management")
        
        # Update state (should work without SDK)
        await agent._update_agentcore_state()
        logger.info("✅ State management works without SDK")
        
        # Test 8: Basic agent functionality
        logger.info("Test 8: Basic agent functionality")
        
        # Test health check
        health = agent.health_check_tool()
        assert health["status"] == "running", "Agent should be healthy"
        
        # Test reputation check
        reputation = agent.check_reputation_tool("192.168.1.100")
        assert "ip_address" in reputation, "Should return reputation data"
        assert "is_malicious" in reputation, "Should return malicious status"
        
        # Test IOC extraction
        iocs = agent.extract_iocs_tool("Suspicious activity from 10.0.0.1")
        assert "ip_addresses" in iocs, "Should extract IOCs"
        assert len(iocs["ip_addresses"]) > 0, "Should find IP addresses"
        
        logger.info("✅ Basic agent functionality works correctly")
        
        logger.info("🎉 All simple messaging integration tests passed!")
        
        # Print summary
        logger.info("\n" + "="*50)
        logger.info("TEST SUMMARY")
        logger.info("="*50)
        logger.info(f"✅ Agent Status: {agent.state['status']}")
        logger.info(f"✅ Test Mode: {agent.config.get('test_mode', False)}")
        logger.info(f"✅ AgentCore SDK: {'Not initialized (test mode)' if not agent.agentcore_sdk else 'Initialized'}")
        logger.info(f"✅ Message Handlers: {'Not registered (test mode)' if not agent.message_handlers_registered else 'Registered'}")
        logger.info(f"✅ Threat Analyses: {len(agent.threat_analysis_state)}")
        logger.info(f"✅ Engagement Decisions: {len(agent.engagement_decisions)}")
        logger.info("="*50)
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise
    finally:
        await agent.stop()

def main():
    """Main test function"""
    asyncio.run(test_messaging_simple())

if __name__ == "__main__":
    main()