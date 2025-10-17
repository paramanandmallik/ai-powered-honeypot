#!/usr/bin/env python3
"""
Quick Integration Test Runner
Runs a subset of integration tests for rapid validation
"""

import asyncio
import sys
import pytest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


async def run_quick_integration_tests():
    """Run quick integration tests"""
    print("Running Quick Integration Tests...")
    
    # Test files to run
    test_files = [
        "tests/integration/test_agentcore_messaging.py::TestAgentCoreMessaging::test_agent_registration_and_discovery",
        "tests/integration/test_workflow_integration.py::TestWorkflowIntegration::test_complete_threat_response_workflow",
        "tests/integration/test_honeypot_lifecycle.py::TestHoneypotLifecycle::test_complete_honeypot_lifecycle",
        "tests/integration/test_performance_testing.py::TestPerformanceTesting::test_threat_detection_throughput",
        "tests/integration/test_security_isolation.py::TestSecurityIsolation::test_network_isolation_enforcement"
    ]
    
    # Run pytest with specific tests
    exit_code = pytest.main([
        "-v",
        "--tb=short",
        "--asyncio-mode=auto",
        "-m", "integration",
        *test_files
    ])
    
    return exit_code


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(run_quick_integration_tests())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nTest execution interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"Test execution failed: {e}")
        sys.exit(1)