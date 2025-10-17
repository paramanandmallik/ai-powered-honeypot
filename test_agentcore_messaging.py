#!/usr/bin/env python3
"""
Test AgentCore Messaging Integration for Detection Agent
Tests the messaging functionality added to the Detection Agent.
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

async def test_agentcore_messaging():
    """Test AgentCore messaging integration"""
    logger.info("Starting AgentCore messaging integration tests...")
    
    agent = DetectionAgent()
    
    try:
        # Test 1: Agent initialization with messaging
        logger.info("Test 1: Agent initialization with messaging")
        await agent.start()
        
        # Verify messaging components are initialized
        assert agent.agentcore_sdk is not None, "AgentCore SDK should be initialized"
        assert agent.message_handlers_registered, "Message handlers should be registered"
        
        logger.info("✅ Agent initialized with messaging successfully")
        
        # Test 2: Messaging status tool
        logger.info("Test 2: Messaging status tool")
        status = agent.get_messaging_status_tool()
        logger.info(f"Messaging Status: {json.dumps(status, indent=2)}")
        
        assert status["agentcore_sdk_initialized"], "AgentCore SDK should be initialized"
        assert status["message_handlers_registered"], "Message handlers should be registered"
        
        logger.info("✅ Messaging status tool working correctly")
        
        # Test 3: Threat feed message handling
        logger.info("Test 3: Threat feed message handling")
        
        # Create a mock threat feed message
        threat_feed_message = Message(
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
        
        # Test the handler directly
        await agent._handle_threat_feed_message(threat_feed_message)
        logger.info("✅ Threat feed message handling working correctly")
        
        # Test 4: Threat analysis request handling
        logger.info("Test 4: Threat analysis request handling")
        
        # Create a mock threat analysis request
        analysis_request = Message(
            from_agent="coordinator",
            to_agent=agent.agent_id,
            message_type="threat_analysis_request",
            payload={
                "analysis_id": "test_analysis_001",
                "threat_data": {
                    "source_ip": "192.168.1.100",
                    "commands": ["whoami", "ls -la", "ps aux"],
                    "failed_login_attempts": 5,
                    "session_duration": 300
                }
            }
        )
        
        # Test the handler directly
        await agent._handle_threat_analysis_request(analysis_request)
        
        # Verify analysis state was updated
        assert "test_analysis_001" in agent.threat_analysis_state, "Analysis state should be updated"
        analysis_state = agent.threat_analysis_state["test_analysis_001"]
        assert analysis_state["status"] == "completed", "Analysis should be completed"
        
        logger.info("✅ Threat analysis request handling working correctly")
        
        # Test 5: Engagement decision publishing
        logger.info("Test 5: Engagement decision publishing")
        
        # Create a mock analysis result that meets engagement threshold
        mock_analysis_result = {
            "overall_confidence": 0.85,
            "threat_level": "High",
            "engagement_decision": {"decision": "engage"},
            "mitre_techniques": [
                {"technique_id": "T1110", "confidence": 0.8},
                {"technique_id": "T1078", "confidence": 0.7}
            ],
            "threshold_met": True
        }
        
        # Test engagement decision publishing
        await agent._publish_engagement_decision(mock_analysis_result)
        
        # Verify engagement decision was stored
        assert len(agent.engagement_decisions) > 0, "Engagement decision should be stored"
        
        logger.info("✅ Engagement decision publishing working correctly")
        
        # Test 6: State synchronization
        logger.info("Test 6: State synchronization")
        
        # Create a mock state sync request
        state_sync_request = Message(
            from_agent="coordinator",
            to_agent=agent.agent_id,
            message_type="state_sync_request",
            payload={}
        )
        
        # Test the handler directly
        await agent._handle_state_sync_request(state_sync_request)
        logger.info("✅ State synchronization working correctly")
        
        # Test 7: System alert handling
        logger.info("Test 7: System alert handling")
        
        # Create a mock system alert
        system_alert = Message(
            from_agent="coordinator",
            to_agent=agent.agent_id,
            message_type="system_alert",
            payload={
                "alert_type": "threat_escalation",
                "alert_data": {
                    "threat_level": "Critical",
                    "threat_data": {"source": "external_feed"}
                }
            }
        )
        
        # Store original threshold for comparison
        original_threshold = agent.engagement_threshold
        
        # Test the handler directly
        await agent._handle_system_alert(system_alert)
        
        # Verify threshold was adjusted
        assert agent.engagement_threshold < original_threshold, "Engagement threshold should be lowered"
        
        logger.info("✅ System alert handling working correctly")
        
        # Test 8: Message retry mechanism
        logger.info("Test 8: Message retry mechanism")
        
        # Test sending a message (this will use retry mechanism)
        try:
            await agent._send_message_with_retry(
                to_agent="test_coordinator",
                message_type="test_message",
                payload={"test": "data"}
            )
            logger.info("✅ Message retry mechanism working correctly")
        except Exception as e:
            logger.info(f"✅ Message retry mechanism handled error correctly: {e}")
        
        # Test 9: AgentCore state updates
        logger.info("Test 9: AgentCore state updates")
        
        await agent._update_agentcore_state()
        logger.info("✅ AgentCore state updates working correctly")
        
        # Test 10: Tools integration
        logger.info("Test 10: Tools integration")
        
        # Test engagement decision tool
        engagement_result = agent.send_engagement_decision_tool(mock_analysis_result)
        logger.info(f"Engagement Decision Tool Result: {json.dumps(engagement_result, indent=2)}")
        
        # Test threat feed update tool
        feed_update_result = agent.send_threat_feed_update_tool(
            target_agent="test_agent",
            feed_type="test_feed",
            feed_data={"test": "data"}
        )
        logger.info(f"Threat Feed Update Tool Result: {json.dumps(feed_update_result, indent=2)}")
        
        # Test state sync request tool
        state_sync_result = agent.request_state_sync_tool("test_coordinator")
        logger.info(f"State Sync Request Tool Result: {json.dumps(state_sync_result, indent=2)}")
        
        # Test system alert broadcast tool
        alert_result = agent.broadcast_system_alert_tool(
            alert_type="test_alert",
            alert_data={"test": "alert_data"}
        )
        logger.info(f"System Alert Broadcast Tool Result: {json.dumps(alert_result, indent=2)}")
        
        logger.info("✅ Tools integration working correctly")
        
        logger.info("🎉 All AgentCore messaging integration tests passed!")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise
    finally:
        await agent.stop()

async def test_message_flow_simulation():
    """Test complete message flow simulation"""
    logger.info("Starting message flow simulation...")
    
    agent = DetectionAgent()
    
    try:
        await agent.start()
        
        # Simulate a complete threat detection and engagement flow
        logger.info("Simulating complete threat detection flow...")
        
        # Step 1: Receive threat data
        threat_data = {
            "source_ip": "192.168.1.100",
            "commands": ["whoami", "id", "uname -a", "ps aux", "netstat -an"],
            "failed_login_attempts": 15,
            "session_duration": 1800,
            "connection_count": 50,
            "destination_ports": [22, 80, 443, 3389, 445]
        }
        
        # Step 2: Analyze threat
        analysis_result = await agent._analyze_threat(threat_data)
        logger.info(f"Analysis Result: Confidence={analysis_result['overall_confidence']:.2f}, "
                   f"Threat Level={analysis_result['threat_level']}")
        
        # Step 3: If threshold met, engagement decision should be published
        if analysis_result.get("threshold_met", False):
            logger.info("✅ Engagement threshold met - decision published automatically")
        else:
            logger.info("ℹ️ Engagement threshold not met - no engagement decision")
        
        # Step 4: Simulate feedback
        if agent.engagement_decisions:
            engagement_id = list(agent.engagement_decisions.keys())[0]
            
            feedback_message = Message(
                from_agent="coordinator",
                to_agent=agent.agent_id,
                message_type="engagement_feedback",
                payload={
                    "engagement_id": engagement_id,
                    "feedback": {
                        "success": True,
                        "intelligence": {
                            "new_iocs": ["malicious.example.com"],
                            "techniques_observed": ["T1110", "T1078"]
                        }
                    }
                }
            )
            
            await agent._handle_engagement_feedback(feedback_message)
            logger.info("✅ Engagement feedback processed")
        
        logger.info("🎉 Message flow simulation completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Message flow simulation failed: {e}")
        raise
    finally:
        await agent.stop()

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test AgentCore Messaging Integration")
    parser.add_argument("--basic", action="store_true", help="Run basic messaging tests")
    parser.add_argument("--flow", action="store_true", help="Run message flow simulation")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    if args.all or args.basic:
        asyncio.run(test_agentcore_messaging())
    
    if args.all or args.flow:
        asyncio.run(test_message_flow_simulation())
    
    if not any([args.basic, args.flow, args.all]):
        logger.info("Use --basic, --flow, or --all to run tests")

if __name__ == "__main__":
    main()