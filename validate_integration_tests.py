#!/usr/bin/env python3
"""
Validation script for integration test framework
"""

import sys
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


async def validate_integration_framework():
    """Validate the integration test framework"""
    print("Validating Integration Test Framework...")
    
    validation_results = {}
    
    # Test 1: Import all integration test modules
    try:
        from tests.integration import test_agentcore_messaging
        from tests.integration import test_workflow_integration
        from tests.integration import test_honeypot_lifecycle
        from tests.integration import test_performance_testing
        from tests.integration import test_security_isolation
        from tests.integration import test_comprehensive_e2e
        from tests.integration import test_end_to_end_comprehensive
        from tests.integration import test_integration_runner
        from tests.integration import integration_test_config
        
        validation_results["imports"] = "✅ PASSED"
        print("✅ All integration test modules imported successfully")
        
    except Exception as e:
        validation_results["imports"] = f"❌ FAILED: {str(e)}"
        print(f"❌ Import failed: {str(e)}")
    
    # Test 2: Validate configuration
    try:
        from tests.integration.integration_test_config import get_test_config
        
        config = get_test_config("comprehensive")
        assert "use_mock_ai" in config
        assert "agentcore_simulation" in config
        assert "performance_monitoring" in config
        
        validation_results["configuration"] = "✅ PASSED"
        print("✅ Integration test configuration validated")
        
    except Exception as e:
        validation_results["configuration"] = f"❌ FAILED: {str(e)}"
        print(f"❌ Configuration validation failed: {str(e)}")
    
    # Test 3: Validate test class instantiation
    try:
        from tests.integration.test_agentcore_messaging import TestAgentCoreMessaging
        from tests.integration.test_workflow_integration import TestWorkflowIntegration
        from tests.integration.test_end_to_end_comprehensive import TestEndToEndComprehensive
        
        # Instantiate test classes
        messaging_tests = TestAgentCoreMessaging()
        workflow_tests = TestWorkflowIntegration()
        comprehensive_tests = TestEndToEndComprehensive()
        
        validation_results["instantiation"] = "✅ PASSED"
        print("✅ Test class instantiation successful")
        
    except Exception as e:
        validation_results["instantiation"] = f"❌ FAILED: {str(e)}"
        print(f"❌ Test class instantiation failed: {str(e)}")
    
    # Test 4: Validate agent imports
    try:
        from agents.detection.detection_agent import DetectionAgent
        from agents.coordinator.coordinator_agent import CoordinatorAgent
        from agents.interaction.interaction_agent import InteractionAgent
        from agents.intelligence.intelligence_agent import IntelligenceAgent
        
        validation_results["agent_imports"] = "✅ PASSED"
        print("✅ Agent imports successful")
        
    except Exception as e:
        validation_results["agent_imports"] = f"❌ FAILED: {str(e)}"
        print(f"❌ Agent imports failed: {str(e)}")
    
    # Test 5: Validate mock environment creation
    try:
        from unittest.mock import AsyncMock
        from config.agentcore_sdk import AgentCoreSDK, Message
        
        # Create mock SDK
        mock_sdk = AsyncMock(spec=AgentCoreSDK)
        
        # Create mock message
        message = Message(
            message_id="test-msg-1",
            from_agent="test-agent",
            to_agent="target-agent",
            message_type="test_message",
            payload={"test": "data"},
            timestamp=None
        )
        
        validation_results["mock_environment"] = "✅ PASSED"
        print("✅ Mock environment creation successful")
        
    except Exception as e:
        validation_results["mock_environment"] = f"❌ FAILED: {str(e)}"
        print(f"❌ Mock environment creation failed: {str(e)}")
    
    # Test 6: Validate test execution script
    try:
        from run_comprehensive_integration_tests import ComprehensiveTestExecutor
        
        config = get_test_config("default")
        executor = ComprehensiveTestExecutor(config)
        
        validation_results["test_executor"] = "✅ PASSED"
        print("✅ Test executor validation successful")
        
    except Exception as e:
        validation_results["test_executor"] = f"❌ FAILED: {str(e)}"
        print(f"❌ Test executor validation failed: {str(e)}")
    
    # Summary
    print("\n" + "="*60)
    print("INTEGRATION TEST FRAMEWORK VALIDATION SUMMARY")
    print("="*60)
    
    passed_count = sum(1 for result in validation_results.values() if result.startswith("✅"))
    total_count = len(validation_results)
    
    for test_name, result in validation_results.items():
        print(f"{test_name.replace('_', ' ').title()}: {result}")
    
    print(f"\nOverall: {passed_count}/{total_count} validations passed")
    
    if passed_count == total_count:
        print("🎉 Integration test framework is ready!")
        return True
    else:
        print("⚠️  Some validations failed - review and fix issues")
        return False


if __name__ == "__main__":
    try:
        success = asyncio.run(validate_integration_framework())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Validation failed: {e}")
        sys.exit(1)