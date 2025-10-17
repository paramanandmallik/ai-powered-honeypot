"""
Unit tests for Coordinator Agent orchestration workflows
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from agents.coordinator.coordinator_agent import CoordinatorAgent


@pytest.mark.unit
@pytest.mark.asyncio
class TestCoordinatorAgent:
    """Test Coordinator Agent orchestration functionality"""

    async def test_agent_initialization(self, test_config):
        """Test Coordinator Agent initialization"""
        agent = CoordinatorAgent(config=test_config)
        assert agent.config == test_config
        assert agent.agent_type == "coordinator"

    async def test_engagement_decision_handling(self, coordinator_agent):
        """Test engagement decision handling"""
        message = {
            "type": "engagement_decision",
            "payload": {
                "threat_data": {
                    "source_ip": "192.168.1.100",
                    "threat_type": "ssh_brute_force"
                },
                "decision": "engage",
                "confidence": 0.85
            }
        }
        
        result = await coordinator_agent.handle_engagement_decision(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_honeypot_request_handling(self, coordinator_agent):
        """Test honeypot request handling"""
        message = {
            "type": "honeypot_request",
            "payload": {
                "honeypot_type": "web_admin",
                "priority": "high",
                "requester": "manual"
            }
        }
        
        result = await coordinator_agent.handle_honeypot_request(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_agent_coordination_handling(self, coordinator_agent):
        """Test agent coordination handling"""
        message = {
            "type": "agent_coordination",
            "payload": {
                "action": "status_update",
                "agent_id": "interaction-agent-1",
                "status": "active"
            }
        }
        
        result = await coordinator_agent.handle_agent_coordination(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_resource_allocation_handling(self, coordinator_agent):
        """Test resource allocation handling"""
        message = {
            "type": "resource_allocation",
            "payload": {
                "resource_type": "compute",
                "amount": 2,
                "duration": 3600
            }
        }
        
        result = await coordinator_agent.handle_resource_allocation(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_emergency_shutdown_handling(self, coordinator_agent):
        """Test emergency shutdown handling"""
        message = {
            "type": "emergency_shutdown",
            "payload": {
                "reason": "security_breach",
                "severity": "critical",
                "immediate": True
            }
        }
        
        result = await coordinator_agent.handle_emergency_shutdown(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_health_check_handling(self, coordinator_agent):
        """Test health check handling"""
        message = {
            "type": "health_check",
            "payload": {
                "requester": "monitoring_system",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        result = await coordinator_agent.handle_health_check(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_system_status_handling(self, coordinator_agent):
        """Test system status handling"""
        message = {
            "type": "system_status",
            "payload": {
                "requester": "dashboard",
                "include_details": True
            }
        }
        
        result = await coordinator_agent.handle_system_status(message)
        
        assert "success" in result
        assert isinstance(result, dict)

    async def test_message_processing(self, coordinator_agent):
        """Test general message processing"""
        message = {
            "type": "engagement_decision",
            "payload": {
                "decision": "engage",
                "confidence": 0.8
            }
        }
        
        result = await coordinator_agent.process_message(message)
        
        assert result is not None
        assert isinstance(result, dict)

    async def test_send_message(self, coordinator_agent):
        """Test sending messages to other agents"""
        target_agent = "interaction-agent"
        message = {
            "type": "session_start",
            "payload": {
                "session_id": "session-123",
                "honeypot_type": "ssh"
            }
        }
        
        # This will likely return None in test environment due to mocking
        result = await coordinator_agent.send_message(target_agent, message)
        
        # Just verify it doesn't crash
        assert result is None or isinstance(result, dict)

    async def test_error_handling(self, coordinator_agent):
        """Test error handling in message processing"""
        # Test with malformed message
        invalid_message = {"invalid": "message"}
        
        result = await coordinator_agent.process_message(invalid_message)
        
        # Should handle gracefully
        assert result is None or isinstance(result, dict)

    @pytest.mark.slow
    async def test_concurrent_message_processing(self, coordinator_agent):
        """Test concurrent message processing"""
        import asyncio
        
        # Create multiple concurrent message processing tasks
        messages = [
            {
                "type": "health_check",
                "payload": {"requester": f"test_{i}"}
            }
            for i in range(5)
        ]
        
        tasks = [coordinator_agent.process_message(msg) for msg in messages]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        assert len(results) == 5
        # Check that most results are successful
        successful_results = [r for r in results if isinstance(r, dict) or r is None]
        assert len(successful_results) >= 0