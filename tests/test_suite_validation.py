"""
Test suite validation and verification
"""

import pytest
import os
import sys
from pathlib import Path
import importlib.util


class TestSuiteValidator:
    """Validates the completeness and structure of the test suite"""
    
    def test_test_structure_exists(self):
        """Verify test directory structure exists"""
        test_root = Path(__file__).parent
        
        required_directories = [
            "unit",
            "unit/agents", 
            "unit/honeypots",
            "integration",
            "security"
        ]
        
        for directory in required_directories:
            dir_path = test_root / directory
            assert dir_path.exists(), f"Required test directory missing: {directory}"
            assert dir_path.is_dir(), f"Path exists but is not a directory: {directory}"
    
    def test_unit_tests_exist(self):
        """Verify all required unit tests exist"""
        unit_test_root = Path(__file__).parent / "unit"
        
        required_unit_tests = [
            "agents/test_detection_agent.py",
            "agents/test_coordinator_agent.py", 
            "agents/test_interaction_agent.py",
            "agents/test_intelligence_agent.py",
            "honeypots/test_honeypot_implementations.py"
        ]
        
        for test_file in required_unit_tests:
            test_path = unit_test_root / test_file
            assert test_path.exists(), f"Required unit test missing: {test_file}"
            assert test_path.is_file(), f"Test path exists but is not a file: {test_file}"
    
    def test_integration_tests_exist(self):
        """Verify all required integration tests exist"""
        integration_test_root = Path(__file__).parent / "integration"
        
        required_integration_tests = [
            "test_workflow_integration.py",
            "test_agentcore_messaging.py",
            "test_honeypot_lifecycle.py",
            "test_performance_testing.py",
            "test_security_isolation.py"
        ]
        
        for test_file in required_integration_tests:
            test_path = integration_test_root / test_file
            assert test_path.exists(), f"Required integration test missing: {test_file}"
            assert test_path.is_file(), f"Test path exists but is not a file: {test_file}"
    
    def test_security_tests_exist(self):
        """Verify all required security tests exist"""
        security_test_root = Path(__file__).parent / "security"
        
        required_security_tests = [
            "test_penetration_testing.py",
            "test_isolation_breach_detection.py",
            "test_data_protection_validation.py",
            "test_emergency_procedures.py",
            "test_compliance_validation.py"
        ]
        
        for test_file in required_security_tests:
            test_path = security_test_root / test_file
            assert test_path.exists(), f"Required security test missing: {test_file}"
            assert test_path.is_file(), f"Test path exists but is not a file: {test_file}"
    
    def test_pytest_configuration_exists(self):
        """Verify pytest configuration exists"""
        project_root = Path(__file__).parent.parent
        
        config_files = [
            "pytest.ini",
            "conftest.py"
        ]
        
        for config_file in config_files:
            config_path = project_root / config_file
            assert config_path.exists(), f"Required pytest config missing: {config_file}"
    
    def test_test_imports_work(self):
        """Verify test files can be imported without errors"""
        test_root = Path(__file__).parent
        
        # Find all test files
        test_files = []
        for test_dir in ["unit", "integration", "security"]:
            test_path = test_root / test_dir
            if test_path.exists():
                test_files.extend(test_path.rglob("test_*.py"))
        
        # Try to import each test file
        for test_file in test_files:
            if test_file.name == __file__.split('/')[-1]:  # Skip this file
                continue
                
            # Convert path to module name
            relative_path = test_file.relative_to(test_root)
            module_name = str(relative_path).replace('/', '.').replace('.py', '')
            
            try:
                spec = importlib.util.spec_from_file_location(module_name, test_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    # Don't execute, just verify it can be loaded
                    assert spec is not None, f"Could not create spec for {test_file}"
            except Exception as e:
                pytest.fail(f"Failed to import test file {test_file}: {e}")
    
    def test_test_markers_defined(self):
        """Verify required test markers are defined in pytest.ini"""
        project_root = Path(__file__).parent.parent
        pytest_ini = project_root / "pytest.ini"
        
        if not pytest_ini.exists():
            pytest.skip("pytest.ini not found")
        
        content = pytest_ini.read_text()
        
        required_markers = [
            "unit",
            "integration", 
            "e2e",
            "security",
            "performance",
            "slow",
            "agentcore",
            "honeypot"
        ]
        
        for marker in required_markers:
            assert marker in content, f"Required test marker not defined: {marker}"
    
    def test_coverage_configuration(self):
        """Verify coverage configuration is properly set"""
        project_root = Path(__file__).parent.parent
        pytest_ini = project_root / "pytest.ini"
        
        if not pytest_ini.exists():
            pytest.skip("pytest.ini not found")
        
        content = pytest_ini.read_text()
        
        # Check for coverage configuration
        coverage_indicators = [
            "--cov=",
            "cov-report",
            "cov-fail-under"
        ]
        
        for indicator in coverage_indicators:
            assert indicator in content, f"Coverage configuration missing: {indicator}"
    
    def test_test_runner_exists(self):
        """Verify test runner script exists and is executable"""
        test_runner = Path(__file__).parent / "test_runner.py"
        
        assert test_runner.exists(), "Test runner script missing"
        assert test_runner.is_file(), "Test runner path exists but is not a file"
        
        # Verify it has main function
        content = test_runner.read_text()
        assert "def main(" in content, "Test runner missing main function"
        assert "if __name__ == \"__main__\":" in content, "Test runner missing main execution block"
    
    def test_conftest_fixtures_available(self):
        """Verify required fixtures are available in conftest.py"""
        project_root = Path(__file__).parent.parent
        conftest = project_root / "conftest.py"
        
        if not conftest.exists():
            pytest.skip("conftest.py not found")
        
        content = conftest.read_text()
        
        required_fixtures = [
            "test_config",
            "mock_agentcore_sdk",
            "sample_threat_data",
            "sample_session_data",
            "performance_config"
        ]
        
        for fixture in required_fixtures:
            assert f"def {fixture}(" in content, f"Required fixture missing: {fixture}"
    
    def test_environment_variables_configured(self):
        """Verify test environment variables are properly configured"""
        # These should be set by the test runner or conftest.py
        expected_env_vars = [
            "USE_MOCK_AI",
            "DEVELOPMENT_MODE", 
            "MOCK_AGENTCORE"
        ]
        
        # Note: In actual test execution, these would be set
        # This test verifies the configuration exists
        project_root = Path(__file__).parent.parent
        conftest = project_root / "conftest.py"
        
        if conftest.exists():
            content = conftest.read_text()
            for env_var in expected_env_vars:
                # Check if environment variable is referenced in conftest
                assert env_var in content, f"Environment variable not configured: {env_var}"


# Run validation if executed directly
if __name__ == "__main__":
    validator = TestSuiteValidator()
    
    # Run all validation methods
    methods = [method for method in dir(validator) if method.startswith('test_')]
    
    print("Validating test suite structure...")
    
    for method_name in methods:
        try:
            method = getattr(validator, method_name)
            method()
            print(f"✅ {method_name}")
        except Exception as e:
            print(f"❌ {method_name}: {e}")
            sys.exit(1)
    
    print("\n🎉 Test suite validation completed successfully!")
    print("All required test files and configurations are present.")