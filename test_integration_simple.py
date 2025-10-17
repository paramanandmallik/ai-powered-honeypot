"""
Simple integration test to verify the testing framework works
"""

import pytest
import pytest_asyncio
import asyncio
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.integration
@pytest.mark.asyncio
class TestSimpleIntegration:
    """Simple integration test class"""

    @pytest_asyncio.fixture
    async def simple_system(self):
        """Simple test system fixture"""
        system = {
            "test_agent": AsyncMock(),
            "test_data": {"message": "test"}
        }
        
        # Mock some basic functionality
        system["test_agent"].process_message = AsyncMock(return_value="processed")
        
        yield system
        
        # Cleanup
        await system["test_agent"].stop() if hasattr(system["test_agent"], 'stop') else None

    async def test_basic_integration(self, simple_system):
        """Test basic integration functionality"""
        agent = simple_system["test_agent"]
        test_data = simple_system["test_data"]
        
        # Test basic functionality
        result = await agent.process_message(test_data["message"])
        
        assert result == "processed"
        assert agent.process_message.called
        
    async def test_async_operations(self, simple_system):
        """Test async operations work correctly"""
        agent = simple_system["test_agent"]
        
        # Test concurrent operations
        tasks = [
            agent.process_message(f"message_{i}")
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 5
        assert all(result == "processed" for result in results)