#!/usr/bin/env python3
"""
Simple test for Coordinator Agent core functionality
"""

import asyncio
import logging
from agents.coordinator.coordinator_agent import CoordinatorAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_coordinator_basic():
    """Test basic coordinator functionality"""
    logger.info("Testing Coordinator Agent basic functionality...")
    
    # Create coordinator agent
    config = {
        "auto_scaling_enabled": True,
        "max_concurrent_engagements": 10,
        "honeypot_timeout_minutes": 60
    }
    
    coordinator = CoordinatorAgent(config)
    
    try:
        # Initialize
        await coordinator.initialize()
        logger.info("✓ Coordinator initialization successful")
        
        # Test engagement decision
        message = {
            "message_type": "engagement_decision",
            "payload": {
                "threat_data": {
                    "attack_vectors": ["web"],
                    "target_services": ["80"],
                    "confidence_score": 0.85
                },
                "engagement_approved": True
            }
        }
        
        response = await coordinator.handle_engagement_decision(message)
        assert response["success"] is True
        logger.info("✓ Engagement decision handling successful")
        
        # Test honeypot creation
        honeypot_id = await coordinator.orchestration_engine.create_honeypot(
            "ssh", {"port": 22}
        )
        assert honeypot_id is not None
        logger.info("✓ Honeypot creation successful")
        
        # Test system status
        status = await coordinator.orchestration_engine.get_system_status()
        assert "system_status" in status
        logger.info("✓ System status retrieval successful")
        
        # Test resource allocation
        allocation_id = await coordinator.orchestration_engine.allocate_resources(
            "honeypot", {"cpu_cores": 1, "memory_gb": 2}
        )
        assert allocation_id is not None
        logger.info("✓ Resource allocation successful")
        
        # Test workflow creation
        workflow_id = await coordinator.orchestration_engine.create_workflow(
            "Test Workflow", "test", [
                {
                    "step_name": "Test Step",
                    "agent_type": "coordinator",
                    "action": "test_action",
                    "parameters": {},
                    "dependencies": []
                }
            ]
        )
        assert workflow_id is not None
        logger.info("✓ Workflow creation successful")
        
        # Test agent coordination
        result = await coordinator.orchestration_engine.coordinate_agents(
            "test_coordination", ["detection", "interaction"], {"test": "param"}
        )
        assert result["success"] is True
        logger.info("✓ Agent coordination successful")
        
        logger.info("🎉 All basic coordinator tests passed!")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise
    finally:
        await coordinator.cleanup()

if __name__ == "__main__":
    asyncio.run(test_coordinator_basic())