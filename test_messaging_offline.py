#!/usr/bin/env python3
"""
Offline Test for AgentCore Messaging Integration
Tests the messaging functionality without requiring AgentCore Runtime server.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from agents.detection_agent import DetectionAgent
from config.agentcore_sdk import Message

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MockAgentCoreSDK:
    """Mock AgentCore SDK for offline testing"""
    
    def __init__(self, config):
        self.config = config
        self.message_handlers = {}
        self.is_running = False
        self.sent_messages = []
        self.broadcast_messages = []
        self.state_updates = []
    
    async def start(self):
        self.is_running = True
        logger.info(f"Mock AgentCore SDK started for {self.config.agent_name}")
    
    async def stop(self):
        self.is_running = False
        logger.info(f"Mock AgentCore SDK stopped for {self.config.agent_name}")
    
    async def send_message(self, to_agent: str, message_type: str, payload: dict):
        message_id = f"msg-{len(self.sent_messages)}"
        self.sent_messages.append({
            "message_id": message_id,
            "to_agent": to_agent,
            "message_type": message_type,
            "payload": payload
        })
        logger.info(f"Mock message sent: {message_type} to {to_agent}")
        return message_id
    
    async def broadcast_message(self, message_type: str, payload: dict):
        message_id = f"broadcast-{len(self.broadcast_messages)}"
        self.broadcast_messages.append({
            "message_id": message_id,
            "message_type": message_type,
            "payload": payload
        })
        logger.info(f"Mock broadcast message: {message_type}")
        return [message_id]
    
    def register_message_handler(self, message_type: str, handler):
        self.message_handlers[message_type] = handler
        logger.info(f"Mock handler registered for: {message_type}")
    
    async def update_state(self, state: dict):
        self.state_updates.append(state)
        logger.info("Mock state updated")

async def test_messaging_integration_offline():
    """Test messaging integration without server connection"""
    logger.info("Starting offline AgentCore messaging integration tests...")
    
    # Create agent with mocked SDK
    agent = DetectionAgent()
    
    # Mock the AgentCore SDK creation
    original_create_sdk = None
    
    try:
        # Replace the SDK initialization with mock
        async def mock_create_sdk(agent_id, agent_name, agent_type, capabilities):
            from config.agentcore_sdk import AgentConfig
            config = AgentConfig(
                agent_id=agent_id,
                agent_name=agent_name,
                agent_type=agent_type,
                capabilities=capabilities
            )
            return MockAgentCoreSDK(config)
        
        # Patch the create_agent_sdk function
        import config.agentcore_sdk
        original_create_sdk = config.agentcore_sdk.create_agent_sdk
        config.agentcore_sdk.create_agent_sdk = mock_create_sdk
        
        # Test 1: Agent initialization with mocked messaging
        logger.info("Test 1: Agent initialization with mocked messaging")
        await agent.start()
        
        # Verify messaging components are initialized
        assert agent.agentcore_sdk is not None, "AgentCore SDK should be initialized"
        assert isinstance(agent.agentcore_sdk, MockAgentCoreSDK), "Should use mock SDK"
        assert agent.message_handlers_registered, "Message handlers should be registered"
        
        logger.info("✅ Agent initialized with mocked messaging successfully")
        
        # Test 2: Message handler registration
        logger.info("Test 2: Message handler registration")
        
        expected_handlers = [
            "threat_feed_update",
            "threat_analysis_request", 
            "engagement_feedback",
            "system_alert",
            "state_sync_request"
        ]
        
        for handler_type in expected_handlers:
            assert handler_type in agent.agentcore_sdk.message_handlers, f"Handler {handler_type} should be registered"
        
        logger.info("✅ All message handlers registered correctly")
        
        # Test 3: Threat feed message handling
        logger.info("Test 3: Threat feed message handling")
        
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
        
        await agent._handle_threat_feed_message(threat_feed_message)
        
        # Verify acknowledgment was sent
        assert len(agent.agentcore_sdk.sent_messages) > 0, "Acknowledgment should be sent"
        ack_message = agent.agentcore_sdk.sent_messages[-1]
        assert ack_message["message_type"] == "threat_feed_ack", "Should send acknowledgment"
        
        logger.info("✅ Threat feed message handling working correctly")
        
        # Test 4: Threat analysis request handling
        logger.info("Test 4: Threat analysis request handling")
        
        analysis_request = Message(
            message_id="test-msg-002",
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
        
        await agent._handle_threat_analysis_request(analysis_request)
        
        # Verify analysis state was updated
        assert "test_analysis_001" in agent.threat_analysis_state, "Analysis state should be updated"
        analysis_state = agent.threat_analysis_state["test_analysis_001"]
        assert analysis_state["status"] == "completed", "Analysis should be completed"
        
        # Verify analysis result was sent
        result_messages = [msg for msg in agent.agentcore_sdk.sent_messages 
                          if msg["message_type"] == "threat_analysis_result"]
        assert len(result_messages) > 0, "Analysis result should be sent"
        
        logger.info("✅ Threat analysis request handling working correctly")
        
        # Test 5: Engagement decision publishing
        logger.info("Test 5: Engagement decision publishing")
        
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
        
        initial_message_count = len(agent.agentcore_sdk.sent_messages)
        await agent._publish_engagement_decision(mock_analysis_result)
        
        # Verify engagement decision was stored
        assert len(agent.engagement_decisions) > 0, "Engagement decision should be stored"
        
        # Verify engagement decision message was sent
        engagement_messages = [msg for msg in agent.agentcore_sdk.sent_messages[initial_message_count:] 
                              if msg["message_type"] == "engagement_decision"]
        assert len(engagement_messages) > 0, "Engagement decision should be sent"
        
        logger.info("✅ Engagement decision publishing working correctly")
        
        # Test 6: State synchronization
        logger.info("Test 6: State synchronization")
        
        state_sync_request = Message(
            message_id="test-msg-003",
            from_agent="coordinator",
            to_agent=agent.agent_id,
            message_type="state_sync_request",
            payload={}
        )
        
        initial_message_count = len(agent.agentcore_sdk.sent_messages)
        await agent._handle_state_sync_request(state_sync_request)
        
        # Verify state sync response was sent
        sync_messages = [msg for msg in agent.agentcore_sdk.sent_messages[initial_message_count:] 
                        if msg["message_type"] == "state_sync_response"]
        assert len(sync_messages) > 0, "State sync response should be sent"
        
        logger.info("✅ State synchronization working correctly")
        
        # Test 7: System alert handling
        logger.info("Test 7: System alert handling")
        
        system_alert = Message(
            message_id="test-msg-004",
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
        
        original_threshold = agent.engagement_threshold
        await agent._handle_system_alert(system_alert)
        
        # Verify threshold was adjusted
        assert agent.engagement_threshold < original_threshold, "Engagement threshold should be lowered"
        
        logger.info("✅ System alert handling working correctly")
        
        # Test 8: Message retry mechanism
        logger.info("Test 8: Message retry mechanism")
        
        initial_message_count = len(agent.agentcore_sdk.sent_messages)
        await agent._send_message_with_retry(
            to_agent="test_coordinator",
            message_type="test_message",
            payload={"test": "data"}
        )
        
        # Verify message was sent
        assert len(agent.agentcore_sdk.sent_messages) > initial_message_count, "Message should be sent"
        
        logger.info("✅ Message retry mechanism working correctly")
        
        # Test 9: AgentCore state updates
        logger.info("Test 9: AgentCore state updates")
        
        initial_state_count = len(agent.agentcore_sdk.state_updates)
        await agent._update_agentcore_state()
        
        # Verify state was updated
        assert len(agent.agentcore_sdk.state_updates) > initial_state_count, "State should be updated"
        
        logger.info("✅ AgentCore state updates working correctly")
        
        # Test 10: Tools integration
        logger.info("Test 10: Tools integration")
        
        # Test messaging status tool
        status = agent.get_messaging_status_tool()
        assert status["agentcore_sdk_initialized"], "SDK should be initialized"
        assert status["message_handlers_registered"], "Handlers should be registered"
        
        # Test engagement decision tool
        engagement_result = agent.send_engagement_decision_tool(mock_analysis_result)
        assert engagement_result["status"] == "engagement_decision_sent", "Should indicate success"
        
        # Test threat feed update tool
        feed_update_result = agent.send_threat_feed_update_tool(
            target_agent="test_agent",
            feed_type="test_feed",
            feed_data={"test": "data"}
        )
        assert feed_update_result["status"] == "threat_feed_update_sent", "Should indicate success"
        
        # Test state sync request tool
        state_sync_result = agent.request_state_sync_tool("test_coordinator")
        assert state_sync_result["status"] == "state_sync_requested", "Should indicate success"
        
        # Test system alert broadcast tool
        alert_result = agent.broadcast_system_alert_tool(
            alert_type="test_alert",
            alert_data={"test": "alert_data"}
        )
        assert alert_result["status"] == "system_alert_broadcasted", "Should indicate success"
        
        logger.info("✅ Tools integration working correctly")
        
        # Test 11: Message statistics
        logger.info("Test 11: Message statistics")
        
        logger.info(f"Total messages sent: {len(agent.agentcore_sdk.sent_messages)}")
        logger.info(f"Total broadcast messages: {len(agent.agentcore_sdk.broadcast_messages)}")
        logger.info(f"Total state updates: {len(agent.agentcore_sdk.state_updates)}")
        logger.info(f"Active analyses: {len(agent.threat_analysis_state)}")
        logger.info(f"Engagement decisions: {len(agent.engagement_decisions)}")
        
        # Verify we have reasonable activity
        assert len(agent.agentcore_sdk.sent_messages) >= 5, "Should have sent multiple messages"
        assert len(agent.threat_analysis_state) >= 1, "Should have processed analysis"
        assert len(agent.engagement_decisions) >= 1, "Should have made engagement decisions"
        
        logger.info("✅ Message statistics look good")
        
        logger.info("🎉 All offline AgentCore messaging integration tests passed!")
        
        # Print summary
        logger.info("\n" + "="*60)
        logger.info("TEST SUMMARY")
        logger.info("="*60)
        logger.info(f"✅ AgentCore SDK initialized: {agent.agentcore_sdk is not None}")
        logger.info(f"✅ Message handlers registered: {len(agent.agentcore_sdk.message_handlers)}")
        logger.info(f"✅ Messages sent: {len(agent.agentcore_sdk.sent_messages)}")
        logger.info(f"✅ Broadcast messages: {len(agent.agentcore_sdk.broadcast_messages)}")
        logger.info(f"✅ State updates: {len(agent.agentcore_sdk.state_updates)}")
        logger.info(f"✅ Threat analyses: {len(agent.threat_analysis_state)}")
        logger.info(f"✅ Engagement decisions: {len(agent.engagement_decisions)}")
        logger.info("="*60)
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise
    finally:
        # Restore original function
        if original_create_sdk:
            config.agentcore_sdk.create_agent_sdk = original_create_sdk
        
        await agent.stop()

def main():
    """Main test function"""
    asyncio.run(test_messaging_integration_offline())

if __name__ == "__main__":
    main()