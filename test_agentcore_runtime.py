#!/usr/bin/env python3
"""
Test script for AgentCore Runtime implementation
Tests the proper AgentCore Runtime integration without Bedrock dependencies.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set environment variables for AgentCore Runtime testing
os.environ["AGENTCORE_RUNTIME"] = "false"  # Use mock AI for local testing

async def test_agentcore_runtime_integration():
    """Test AgentCore Runtime integration"""
    try:
        from agents.interaction import InteractionAgent
        
        logger.info("Testing AgentCore Runtime integration...")
        
        # Test 1: Initialize Interaction Agent with AgentCore Runtime
        logger.info("1. Testing AgentCore Runtime agent initialization...")
        config = {
            "max_sessions": 10,
            "session_timeout": 1800,
            "security_level": "high"
        }
        
        agent = InteractionAgent(config)
        await agent.start()
        logger.info("✓ AgentCore Runtime agent initialized successfully")
        
        # Test 2: Test AgentCore app creation
        logger.info("2. Testing AgentCore app creation...")
        app = agent.create_agentcore_app()
        logger.info(f"✓ AgentCore app created: {type(app)}")
        
        # Test 3: Test AI processing without Bedrock
        logger.info("3. Testing AI processing...")
        test_prompts = [
            "Generate a greeting for SSH login",
            "Analyze this threat: suspicious login attempt",
            "Create synthetic credentials for testing",
            "Respond to attacker command: whoami"
        ]
        
        for prompt in test_prompts:
            try:
                result = await agent.process_with_ai(prompt)
                logger.info(f"✓ Prompt: '{prompt[:30]}...' -> Response: '{result[:50]}...'")
            except Exception as e:
                logger.error(f"✗ Failed to process prompt '{prompt[:30]}...': {e}")
        
        # Test 4: Test agent message processing
        logger.info("4. Testing agent message processing...")
        
        # Start interaction session
        start_message = {
            "type": "start_interaction",
            "honeypot_type": "ssh",
            "attacker_ip": "192.168.1.100"
        }
        
        session_result = await agent.process_message(start_message)
        if "session_id" in session_result:
            session_id = session_result["session_id"]
            logger.info(f"✓ Started session {session_id}")
            
            # Test attacker interaction
            input_message = {
                "type": "attacker_input",
                "session_id": session_id,
                "input": "whoami"
            }
            
            response = await agent.process_message(input_message)
            if "response" in response:
                logger.info(f"✓ Attacker interaction: 'whoami' -> '{response['response'][:50]}...'")
            else:
                logger.warning(f"Unexpected response format: {response}")
        else:
            logger.error(f"Failed to start session: {session_result}")
        
        # Test 5: Test agent tools
        logger.info("5. Testing agent tools...")
        
        # Test health check
        health = agent.health_check_tool()
        logger.info(f"✓ Health check: {health['status']}")
        
        # Test security status
        security_status = agent.get_security_status_tool()
        logger.info(f"✓ Security status: {security_status}")
        
        # Test synthetic data generation
        credentials = agent.generate_synthetic_credentials_tool(2)
        logger.info(f"✓ Generated {len(credentials)} synthetic credentials")
        
        # Test 6: Test metrics
        logger.info("6. Testing metrics...")
        metrics = await agent.get_metrics()
        logger.info(f"✓ Agent metrics: processed_messages={metrics.get('processed_messages', 0)}")
        
        # Cleanup
        await agent.stop()
        logger.info("✓ Agent stopped successfully")
        
        logger.info("All AgentCore Runtime tests completed successfully!")
        
    except Exception as e:
        logger.error(f"AgentCore Runtime test failed: {e}")
        import traceback
        traceback.print_exc()

async def test_agentcore_app_structure():
    """Test the AgentCore app structure independently"""
    logger.info("Testing AgentCore app structure...")
    
    try:
        from bedrock_agentcore import BedrockAgentCoreApp
        
        # Create a simple AgentCore app
        app = BedrockAgentCoreApp()
        
        @app.entrypoint
        async def invoke(payload):
            """Test entrypoint"""
            user_message = payload.get("prompt", "Hello!")
            return {
                "result": f"Processed: {user_message}",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        logger.info("✓ AgentCore app structure created successfully")
        logger.info(f"✓ App type: {type(app)}")
        
        # Test payload processing (simulate what AgentCore Runtime would do)
        test_payload = {"prompt": "Test message"}
        result = await invoke(test_payload)
        logger.info(f"✓ Test invocation result: {result}")
        
    except Exception as e:
        logger.error(f"AgentCore app structure test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("AgentCore Runtime Integration Test Suite")
    print("=" * 50)
    
    # Run tests
    asyncio.run(test_agentcore_app_structure())
    print()
    asyncio.run(test_agentcore_runtime_integration())