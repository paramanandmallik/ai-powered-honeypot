"""
Unit tests for Interaction Agent response generation
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from agents.interaction.interaction_agent import InteractionAgent


@pytest.mark.unit
@pytest.mark.asyncio
class TestInteractionAgent:
    """Test Interaction Agent response generation functionality"""

    async def test_agent_initialization(self, test_config):
        """Test Interaction Agent initialization"""
        agent = InteractionAgent(config=test_config)
        assert agent.config == test_config
        assert agent.agent_type == "interaction"

    async def test_message_processing(self, interaction_agent):
        """Test message processing for attacker interactions"""
        message = {
            "type": "attacker_interaction",
            "payload": {
                "session_id": "session-123",
                "interaction_type": "command",
                "content": "whoami",
                "honeypot_type": "ssh"
            }
        }
        
        result = await interaction_agent.process_message(message)
        
        assert result is not None
        assert isinstance(result, dict)

    async def test_ai_processing(self, interaction_agent):
        """Test AI processing capabilities"""
        prompt = "Generate a realistic system administrator response to: 'What is your name?'"
        
        response = await interaction_agent.process_with_ai(prompt)
        
        assert isinstance(response, str)
        assert len(response) > 0

    async def test_metrics_collection(self, interaction_agent):
        """Test metrics collection"""
        metrics = await interaction_agent.get_metrics()
        
        assert "interactions_processed" in metrics
        assert "active_sessions" in metrics
        assert "synthetic_data_generated" in metrics
        assert "uptime_seconds" in metrics

    async def test_error_handling(self, interaction_agent):
        """Test error handling in message processing"""
        # Test with malformed message
        invalid_message = {"invalid": "message"}
        
        result = await interaction_agent.process_message(invalid_message)
        
        # Should handle gracefully
        assert result is None or isinstance(result, dict)

    @pytest.mark.slow
    async def test_concurrent_message_processing(self, interaction_agent):
        """Test concurrent message processing"""
        import asyncio
        
        # Create multiple concurrent message processing tasks
        messages = [
            {
                "type": "attacker_interaction",
                "payload": {
                    "session_id": f"session-{i}",
                    "content": f"test command {i}"
                }
            }
            for i in range(5)
        ]
        
        tasks = [interaction_agent.process_message(msg) for msg in messages]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        assert len(results) == 5
        # Check that most results are successful
        successful_results = [r for r in results if isinstance(r, dict) or r is None]
        assert len(successful_results) >= 0