"""
Pytest configuration and fixtures for AI Honeypot System tests
"""

import pytest
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "agents: Agent-specific tests")
    config.addinivalue_line("markers", "honeypot: Honeypot-specific tests")
    config.addinivalue_line("markers", "agentcore: AgentCore Runtime tests")
    config.addinivalue_line("markers", "runner: Test runner tests")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config():
    """Basic test configuration"""
    return {
        "use_mock_ai": True,
        "test_mode": True,
        "log_level": "DEBUG",
        "max_concurrent_sessions": 10,
        "session_timeout": 300,
        "honeypot_timeout": 1800,
        "supported_honeypot_types": ["ssh", "web_admin", "database", "file_share", "email"],
        "security_mode": "test",
        "isolation_level": "test",
        "real_data_protection": True,
        "synthetic_data_only": True
    }


@pytest.fixture
def performance_config():
    """Performance testing configuration"""
    return {
        "max_concurrent_requests": 20,
        "expected_throughput_rps": 10,
        "expected_response_time_ms": 2000,
        "load_test_duration": 60,
        "stress_test_multiplier": 2,
        "memory_limit_mb": 1000,
        "cpu_limit_percent": 80
    }


@pytest.fixture
def mock_agentcore_sdk():
    """Mock AgentCore SDK for testing"""
    sdk = AsyncMock()
    
    # Mock basic SDK methods
    sdk.send_message = AsyncMock(return_value="msg-123")
    sdk.broadcast_message = AsyncMock(return_value=["msg-124", "msg-125"])
    sdk.get_messages = AsyncMock(return_value=[])
    sdk.get_agent_status = AsyncMock(return_value={"status": "active"})
    sdk.update_agent_state = AsyncMock(return_value=True)
    
    return sdk


@pytest.fixture
async def mock_detection_agent(test_config, mock_agentcore_sdk):
    """Mock Detection Agent for testing"""
    from agents.detection.detection_agent import DetectionAgent
    
    agent = DetectionAgent(config=test_config)
    agent.sdk = mock_agentcore_sdk
    
    # Mock AI analysis methods
    agent.analyze_threat = AsyncMock(return_value={
        "engagement_decision": True,
        "confidence_score": 0.85,
        "threat_classification": "ssh_brute_force",
        "decision_rationale": "High confidence threat detected"
    })
    
    await agent.start()
    yield agent
    await agent.stop()


@pytest.fixture
async def mock_coordinator_agent(test_config, mock_agentcore_sdk):
    """Mock Coordinator Agent for testing"""
    from agents.coordinator.coordinator_agent import CoordinatorAgent
    
    agent = CoordinatorAgent(config=test_config)
    agent.sdk = mock_agentcore_sdk
    
    # Mock honeypot management methods
    agent.create_honeypot = AsyncMock(return_value={
        "status": "created",
        "honeypot_id": "hp-123",
        "type": "ssh",
        "endpoint": "localhost:2222"
    })
    
    agent.destroy_honeypot = AsyncMock(return_value={
        "status": "destroyed",
        "honeypot_id": "hp-123"
    })
    
    agent.get_honeypot_status = AsyncMock(return_value={
        "status": "active",
        "honeypot_id": "hp-123",
        "uptime": 300
    })
    
    await agent.start()
    yield agent
    await agent.stop()


@pytest.fixture
async def mock_interaction_agent(test_config, mock_agentcore_sdk):
    """Mock Interaction Agent for testing"""
    from agents.interaction.interaction_agent import InteractionAgent
    
    agent = InteractionAgent(config=test_config)
    agent.sdk = mock_agentcore_sdk
    
    # Mock interaction methods
    agent.simulate_command = AsyncMock(return_value="root")
    agent.simulate_login_attempt = AsyncMock(return_value="Login successful")
    agent.simulate_database_query = AsyncMock(return_value="Query results")
    agent.simulate_web_request = AsyncMock(return_value="HTTP response")
    agent.simulate_file_access = AsyncMock(return_value="File content")
    
    await agent.start()
    yield agent
    await agent.stop()


@pytest.fixture
async def mock_intelligence_agent(test_config, mock_agentcore_sdk):
    """Mock Intelligence Agent for testing"""
    from agents.intelligence.intelligence_agent import IntelligenceAgent
    
    agent = IntelligenceAgent(config=test_config)
    agent.sdk = mock_agentcore_sdk
    
    # Mock analysis methods
    agent.analyze_session = AsyncMock(return_value={
        "techniques_identified": [
            {"technique_id": "T1078", "confidence": 0.9},
            {"technique_id": "T1082", "confidence": 0.8}
        ],
        "confidence_score": 0.85
    })
    
    agent.map_to_mitre_attack = AsyncMock(return_value={
        "tactics": [{"tactic": "Discovery", "confidence": 0.8}],
        "techniques": [
            {"technique_id": "T1078", "technique_name": "Valid Accounts"},
            {"technique_id": "T1082", "technique_name": "System Information Discovery"}
        ]
    })
    
    agent.generate_intelligence_report = AsyncMock(return_value={
        "report_id": "report-123",
        "session_id": "session-123",
        "threat_assessment": "Medium risk threat",
        "mitre_techniques": ["T1078", "T1082"],
        "iocs": ["192.168.1.100", "ssh_brute_force"],
        "recommendations": ["Monitor SSH access", "Implement rate limiting"],
        "confidence_assessment": {"overall_confidence": 0.85}
    })
    
    await agent.start()
    yield agent
    await agent.stop()


@pytest.fixture
def sample_threat_data():
    """Sample threat data for testing"""
    return {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.50",
        "threat_type": "ssh_brute_force",
        "indicators": ["multiple_failed_logins", "credential_stuffing"],
        "confidence": 0.87,
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": {
            "failed_attempts": 15,
            "time_window": "5_minutes",
            "user_agents": ["ssh-2.0-libssh"],
            "attack_pattern": "dictionary_attack"
        }
    }


@pytest.fixture
def sample_session_data():
    """Sample session data for testing"""
    return {
        "session_id": "test-session-123",
        "honeypot_id": "hp-123",
        "attacker_ip": "192.168.1.100",
        "honeypot_type": "ssh",
        "start_time": datetime.utcnow().isoformat(),
        "interactions": [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "command": "whoami",
                "response": "root",
                "synthetic": True
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "command": "id",
                "response": "uid=0(root) gid=0(root) groups=0(root)",
                "synthetic": True
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "command": "uname -a",
                "response": "Linux server 5.4.0-74-generic #83-Ubuntu",
                "synthetic": True
            }
        ]
    }


@pytest.fixture
def sample_honeypot_config():
    """Sample honeypot configuration for testing"""
    return {
        "honeypot_type": "ssh",
        "port": 2222,
        "max_sessions": 5,
        "session_timeout": 1800,
        "configuration": {
            "banner": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "synthetic_users": ["admin", "user", "service"],
            "fake_filesystem": True,
            "command_simulation": True
        },
        "security_config": {
            "isolation_level": "strict",
            "real_data_detection": True,
            "network_isolation": True
        }
    }


@pytest.fixture
def test_metrics():
    """Test metrics tracking"""
    return {
        "start_time": datetime.utcnow(),
        "test_count": 0,
        "passed_count": 0,
        "failed_count": 0,
        "error_count": 0,
        "performance_metrics": {
            "response_times": [],
            "throughput_measurements": [],
            "resource_usage": []
        }
    }


# Pytest hooks for test execution
def pytest_runtest_setup(item):
    """Setup for each test"""
    # Ensure test logs directory exists
    os.makedirs("test_logs", exist_ok=True)
    os.makedirs("test_logs/metrics", exist_ok=True)


def pytest_runtest_teardown(item, nextitem):
    """Teardown after each test"""
    # Clean up any test artifacts
    pass


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    # Add markers based on test file location
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
        elif "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)


# Custom exceptions for testing
class SecurityError(Exception):
    """Security-related test error"""
    pass


class PerformanceError(Exception):
    """Performance-related test error"""
    pass


class IntegrationError(Exception):
    """Integration test error"""
    pass