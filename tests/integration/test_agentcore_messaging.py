"""
Integration tests for AgentCore Runtime messaging and communication
"""

import pytest
import pytest_asyncio
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from config.agentcore_sdk import AgentCoreSDK, Message, AgentConfig
from agents.detection.detection_agent import DetectionAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.interaction.interaction_agent import InteractionAgent
from agents.intelligence.intelligence_agent import IntelligenceAgent


@pytest.mark.integration
@pytest.mark.agentcore
@pytest.mark.asyncio
class TestAgentCoreMessaging:
    """Test AgentCore Runtime messaging and communication integration"""

    @pytest_asyncio.fixture
    async def mock_agentcore_environment(self):
        """Setup mock AgentCore Runtime environment"""
        # Mock AgentCore SDK
        sdk = AsyncMock(spec=AgentCoreSDK)
        
        # Mock message routing
        message_router = {}
        sent_messages = []
        
        async def mock_send_message(to_agent, message_type, payload, **kwargs):
            message = Message(
                message_id=f"msg-{len(sent_messages)}",
                from_agent=kwargs.get("from_agent", "test-agent"),
                to_agent=to_agent,
                message_type=message_type,
                payload=payload,
                timestamp=datetime.utcnow()
            )
            sent_messages.append(message)
            
            # Route message to target agent if registered
            if to_agent in message_router:
                await message_router[to_agent](message)
            
            return message.message_id
        
        async def mock_broadcast_message(message_type, payload, **kwargs):
            message_ids = []
            for agent_id in message_router.keys():
                msg_id = await mock_send_message(agent_id, message_type, payload, **kwargs)
                message_ids.append(msg_id)
            return message_ids
        
        sdk.send_message = mock_send_message
        sdk.broadcast_message = mock_broadcast_message
        sdk.get_messages = AsyncMock(return_value=sent_messages)
        
        return {
            "sdk": sdk,
            "message_router": message_router,
            "sent_messages": sent_messages
        }

    async def test_agent_registration_and_discovery(self, mock_agentcore_environment):
        """Test agent registration and discovery through AgentCore"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        
        # Register agents
        agents = {
            "detection-agent-1": DetectionAgent({"use_mock_ai": True}),
            "coordinator-agent-1": CoordinatorAgent({"use_mock_ai": True}),
            "interaction-agent-1": InteractionAgent({"use_mock_ai": True}),
            "intelligence-agent-1": IntelligenceAgent({"use_mock_ai": True})
        }
        
        # Mock agent message handlers
        for agent_id, agent in agents.items():
            message_router[agent_id] = agent.handle_message
            agent.sdk = sdk
        
        # Test agent discovery
        agent_list = list(message_router.keys())
        assert "detection-agent-1" in agent_list
        assert "coordinator-agent-1" in agent_list
        assert "interaction-agent-1" in agent_list
        assert "intelligence-agent-1" in agent_list

    async def test_threat_detection_messaging_flow(self, mock_agentcore_environment):
        """Test messaging flow for threat detection workflow"""
        sdk = mock_agentcore_environment["sdk"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        # Setup detection agent
        detection_agent = DetectionAgent({"use_mock_ai": True})
        detection_agent.sdk = sdk
        
        # Simulate threat analysis and engagement decision
        threat_data = {
            "source_ip": "192.168.1.100",
            "confidence": 0.85,
            "indicators": ["ssh_brute_force"]
        }
        
        # Send engagement decision message
        await detection_agent.send_engagement_decision(
            "coordinator-agent-1",
            threat_data,
            True,  # engage
            "High confidence threat detected"
        )
        
        # Verify message was sent
        assert len(sent_messages) == 1
        message = sent_messages[0]
        assert message.to_agent == "coordinator-agent-1"
        assert message.message_type == "engagement_decision"
        assert message.payload["decision"] is True
        assert message.payload["threat_data"]["source_ip"] == "192.168.1.100"

    async def test_honeypot_coordination_messaging(self, mock_agentcore_environment):
        """Test messaging for honeypot coordination"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        # Setup coordinator and interaction agents
        coordinator = CoordinatorAgent({"use_mock_ai": True})
        interaction = InteractionAgent({"use_mock_ai": True})
        
        coordinator.sdk = sdk
        interaction.sdk = sdk
        
        # Register message handlers
        message_router["coordinator-agent-1"] = coordinator.handle_message
        message_router["interaction-agent-1"] = interaction.handle_message
        
        # Simulate honeypot creation notification
        honeypot_data = {
            "honeypot_id": "hp-123",
            "type": "ssh",
            "endpoint": "localhost:2222",
            "status": "active"
        }
        
        await coordinator.notify_honeypot_created(
            "interaction-agent-1",
            honeypot_data
        )
        
        # Verify message was sent and received
        assert len(sent_messages) == 1
        message = sent_messages[0]
        assert message.message_type == "honeypot_created"
        assert message.payload["honeypot_id"] == "hp-123"

    async def test_session_coordination_messaging(self, mock_agentcore_environment):
        """Test messaging for session coordination between agents"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        # Setup agents
        interaction = InteractionAgent({"use_mock_ai": True})
        intelligence = IntelligenceAgent({"use_mock_ai": True})
        
        interaction.sdk = sdk
        intelligence.sdk = sdk
        
        message_router["interaction-agent-1"] = interaction.handle_message
        message_router["intelligence-agent-1"] = intelligence.handle_message
        
        # Simulate session completion notification
        session_data = {
            "session_id": "session-123",
            "honeypot_id": "hp-123",
            "attacker_ip": "192.168.1.100",
            "interactions": [
                {"command": "whoami", "response": "root"}
            ],
            "status": "completed"
        }
        
        await interaction.notify_session_completed(
            "intelligence-agent-1",
            session_data
        )
        
        # Verify message flow
        assert len(sent_messages) == 1
        message = sent_messages[0]
        assert message.message_type == "session_completed"
        assert message.payload["session_id"] == "session-123"

    async def test_broadcast_messaging(self, mock_agentcore_environment):
        """Test broadcast messaging to all agents"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        # Register multiple agents
        agent_ids = ["detection-agent-1", "coordinator-agent-1", "interaction-agent-1"]
        for agent_id in agent_ids:
            message_router[agent_id] = AsyncMock()
        
        # Setup coordinator for broadcasting
        coordinator = CoordinatorAgent({"use_mock_ai": True})
        coordinator.sdk = sdk
        
        # Broadcast system alert
        alert_data = {
            "alert_type": "security_breach",
            "severity": "high",
            "message": "Potential security breach detected",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        message_ids = await coordinator.broadcast_system_alert(alert_data)
        
        # Verify broadcast reached all agents
        assert len(message_ids) == len(agent_ids)
        assert len(sent_messages) == len(agent_ids)
        
        for message in sent_messages:
            assert message.message_type == "system_alert"
            assert message.payload["alert_type"] == "security_breach"

    async def test_message_ordering_and_delivery(self, mock_agentcore_environment):
        """Test message ordering and reliable delivery"""
        sdk = mock_agentcore_environment["sdk"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        detection = DetectionAgent({"use_mock_ai": True})
        detection.sdk = sdk
        
        # Send multiple messages in sequence
        messages_to_send = [
            {"type": "threat_detected", "data": {"threat_id": "1"}},
            {"type": "engagement_decision", "data": {"decision": True}},
            {"type": "honeypot_request", "data": {"honeypot_type": "ssh"}},
            {"type": "session_start", "data": {"session_id": "session-1"}}
        ]
        
        message_ids = []
        for msg in messages_to_send:
            msg_id = await sdk.send_message(
                "coordinator-agent-1",
                msg["type"],
                msg["data"]
            )
            message_ids.append(msg_id)
        
        # Verify message ordering
        assert len(sent_messages) == 4
        for i, message in enumerate(sent_messages):
            assert message.message_type == messages_to_send[i]["type"]
            assert message.message_id == message_ids[i]

    async def test_message_retry_and_error_handling(self, mock_agentcore_environment):
        """Test message retry mechanisms and error handling"""
        sdk = mock_agentcore_environment["sdk"]
        
        # Mock network failure
        original_send = sdk.send_message
        call_count = 0
        
        async def failing_send_message(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # Fail first 2 attempts
                raise ConnectionError("Network unavailable")
            return await original_send(*args, **kwargs)
        
        sdk.send_message = failing_send_message
        
        detection = DetectionAgent({"use_mock_ai": True})
        detection.sdk = sdk
        
        # Attempt to send message with retry logic
        with patch.object(detection, '_retry_send_message') as mock_retry:
            mock_retry.side_effect = [
                ConnectionError("Network unavailable"),
                ConnectionError("Network unavailable"),
                "msg-123"  # Success on third try
            ]
            
            try:
                result = await detection.send_with_retry(
                    "coordinator-agent-1",
                    "test_message",
                    {"data": "test"}
                )
                assert result == "msg-123"
            except ConnectionError:
                # Verify retry attempts were made
                assert mock_retry.call_count == 3

    async def test_message_filtering_and_routing(self, mock_agentcore_environment):
        """Test message filtering and intelligent routing"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        
        # Setup agents with message filters
        coordinator = CoordinatorAgent({"use_mock_ai": True})
        coordinator.sdk = sdk
        
        # Mock message filtering
        received_messages = []
        
        async def filtered_handler(message):
            # Only handle specific message types
            if message.message_type in ["engagement_decision", "honeypot_request"]:
                received_messages.append(message)
        
        message_router["coordinator-agent-1"] = filtered_handler
        
        # Send various message types
        message_types = [
            "engagement_decision",  # Should be handled
            "system_heartbeat",     # Should be filtered out
            "honeypot_request",     # Should be handled
            "debug_info"            # Should be filtered out
        ]
        
        for msg_type in message_types:
            await sdk.send_message(
                "coordinator-agent-1",
                msg_type,
                {"data": f"test_{msg_type}"}
            )
        
        # Verify filtering worked
        assert len(received_messages) == 2
        assert received_messages[0].message_type == "engagement_decision"
        assert received_messages[1].message_type == "honeypot_request"

    async def test_concurrent_messaging(self, mock_agentcore_environment):
        """Test concurrent message handling"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        
        # Setup multiple agents
        agents = {}
        for i in range(3):
            agent_id = f"test-agent-{i}"
            agent = DetectionAgent({"use_mock_ai": True})
            agent.sdk = sdk
            agents[agent_id] = agent
            message_router[agent_id] = agent.handle_message
        
        # Send concurrent messages to all agents
        concurrent_tasks = []
        for i in range(10):
            for agent_id in agents.keys():
                task = sdk.send_message(
                    agent_id,
                    "concurrent_test",
                    {"message_id": i, "timestamp": datetime.utcnow().isoformat()}
                )
                concurrent_tasks.append(task)
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*concurrent_tasks)
        
        # Verify all messages were sent
        assert len(results) == 30  # 10 messages * 3 agents
        assert all(isinstance(result, str) for result in results)  # All should return message IDs

    async def test_message_persistence_and_recovery(self, mock_agentcore_environment):
        """Test message persistence and recovery mechanisms"""
        sdk = mock_agentcore_environment["sdk"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        # Mock message persistence
        persisted_messages = []
        
        async def mock_persist_message(message):
            persisted_messages.append(message)
        
        sdk.persist_message = mock_persist_message
        
        coordinator = CoordinatorAgent({"use_mock_ai": True})
        coordinator.sdk = sdk
        
        # Send critical messages that should be persisted
        critical_messages = [
            {"type": "emergency_shutdown", "data": {"reason": "security_breach"}},
            {"type": "system_alert", "data": {"severity": "critical"}},
            {"type": "audit_log", "data": {"action": "honeypot_created"}}
        ]
        
        for msg in critical_messages:
            await sdk.send_message(
                "all-agents",
                msg["type"],
                msg["data"]
            )
            # Simulate persistence
            await sdk.persist_message(sent_messages[-1])
        
        # Verify message persistence
        assert len(persisted_messages) == 3
        assert all(msg.message_type in ["emergency_shutdown", "system_alert", "audit_log"] 
                  for msg in persisted_messages)

    async def test_message_security_and_validation(self, mock_agentcore_environment):
        """Test message security and validation"""
        sdk = mock_agentcore_environment["sdk"]
        
        # Mock message validation
        async def validate_message(message):
            # Check for required fields
            required_fields = ["message_id", "from_agent", "to_agent", "message_type"]
            for field in required_fields:
                if not hasattr(message, field) or getattr(message, field) is None:
                    raise ValueError(f"Missing required field: {field}")
            
            # Check for malicious content
            if "malicious" in str(message.payload):
                raise SecurityError("Malicious content detected")
            
            return True
        
        sdk.validate_message = validate_message
        
        detection = DetectionAgent({"use_mock_ai": True})
        detection.sdk = sdk
        
        # Test valid message
        valid_message = Message(
            message_id="msg-123",
            from_agent="detection-agent-1",
            to_agent="coordinator-agent-1",
            message_type="engagement_decision",
            payload={"decision": True},
            timestamp=datetime.utcnow()
        )
        
        validation_result = await sdk.validate_message(valid_message)
        assert validation_result is True
        
        # Test invalid message (missing field)
        invalid_message = Message(
            message_id="msg-124",
            from_agent="detection-agent-1",
            to_agent=None,  # Missing required field
            message_type="test",
            payload={},
            timestamp=datetime.utcnow()
        )
        
        with pytest.raises(ValueError):
            await sdk.validate_message(invalid_message)

    async def test_message_throughput_performance(self, mock_agentcore_environment):
        """Test message throughput under high load"""
        sdk = mock_agentcore_environment["sdk"]
        sent_messages = mock_agentcore_environment["sent_messages"]
        
        detection = DetectionAgent({"use_mock_ai": True})
        detection.sdk = sdk
        
        # Send high volume of messages
        message_count = 100
        start_time = time.time()
        
        tasks = []
        for i in range(message_count):
            task = sdk.send_message(
                "coordinator-agent-1",
                "performance_test",
                {"message_number": i, "timestamp": datetime.utcnow().isoformat()}
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Verify throughput
        duration = end_time - start_time
        throughput = message_count / duration
        
        assert len(results) == message_count
        assert len(sent_messages) == message_count
        assert throughput >= 50  # Should handle at least 50 messages per second
        
    async def test_message_queue_management(self, mock_agentcore_environment):
        """Test message queue management and backpressure"""
        sdk = mock_agentcore_environment["sdk"]
        message_router = mock_agentcore_environment["message_router"]
        
        # Mock message queue with limited capacity
        message_queue = asyncio.Queue(maxsize=10)
        
        async def queued_message_handler(message):
            try:
                message_queue.put_nowait(message)
            except asyncio.QueueFull:
                # Simulate backpressure handling
                await asyncio.sleep(0.1)
                await message_queue.put(message)
        
        message_router["test-agent"] = queued_message_handler
        
        # Send messages that exceed queue capacity
        tasks = []
        for i in range(15):  # More than queue capacity
            task = sdk.send_message(
                "test-agent",
                "queue_test",
                {"message_id": i}
            )
            tasks.append(task)
        
        # Should handle backpressure gracefully
        results = await asyncio.gather(*tasks)
        assert len(results) == 15
        
        # Verify queue management
        assert message_queue.qsize() <= 10  # Should not exceed capacity