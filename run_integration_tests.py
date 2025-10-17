#!/usr/bin/env python3
"""
Integration Test Execution Script for AI Honeypot System
Runs comprehensive integration and end-to-end tests
"""

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def run_test_suite(test_path, description):
    """Run a specific test suite and return results"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Path: {test_path}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            test_path, 
            "-v", 
            "--tb=short",
            "--maxfail=3"
        ], capture_output=True, text=True, timeout=300)
        
        duration = time.time() - start_time
        
        print(f"Duration: {duration:.2f}s")
        print(f"Return code: {result.returncode}")
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return {
            "test_path": test_path,
            "description": description,
            "duration": duration,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
        
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        print(f"TEST TIMEOUT after {duration:.2f}s")
        return {
            "test_path": test_path,
            "description": description,
            "duration": duration,
            "return_code": -1,
            "error": "Timeout",
            "success": False
        }
    except Exception as e:
        duration = time.time() - start_time
        print(f"TEST ERROR: {e}")
        return {
            "test_path": test_path,
            "description": description,
            "duration": duration,
            "return_code": -1,
            "error": str(e),
            "success": False
        }


def main():
    """Main test execution function"""
    print("AI Honeypot System - Integration Test Suite")
    print(f"Started at: {datetime.now()}")
    
    # Define test suites to run
    test_suites = [
        {
            "path": "test_integration_simple.py",
            "description": "Simple Integration Test Verification"
        },
        {
            "path": "tests/integration/test_agentcore_messaging.py::TestAgentCoreMessaging::test_agent_registration_and_discovery",
            "description": "AgentCore Messaging - Agent Registration"
        },
        {
            "path": "tests/integration/test_agentcore_messaging.py::TestAgentCoreMessaging::test_threat_detection_messaging_flow",
            "description": "AgentCore Messaging - Threat Detection Flow"
        },
        {
            "path": "tests/integration/test_workflow_integration.py::TestWorkflowIntegration::test_complete_threat_response_workflow",
            "description": "Workflow Integration - Complete Threat Response"
        },
        {
            "path": "tests/integration/test_comprehensive_e2e.py::TestComprehensiveE2E::test_complete_threat_lifecycle_ssh",
            "description": "End-to-End - SSH Threat Lifecycle"
        }
    ]
    
    results = []
    total_start = time.time()
    
    for suite in test_suites:
        result = run_test_suite(suite["path"], suite["description"])
        results.append(result)
        
        # Short pause between test suites
        time.sleep(2)
    
    total_duration = time.time() - total_start
    
    # Generate summary report
    print(f"\n{'='*80}")
    print("INTEGRATION TEST SUMMARY")
    print(f"{'='*80}")
    
    successful_tests = [r for r in results if r["success"]]
    failed_tests = [r for r in results if not r["success"]]
    
    print(f"Total Duration: {total_duration:.2f}s")
    print(f"Total Test Suites: {len(results)}")
    print(f"Successful: {len(successful_tests)}")
    print(f"Failed: {len(failed_tests)}")
    print(f"Success Rate: {len(successful_tests)/len(results)*100:.1f}%")
    
    if successful_tests:
        print(f"\n✅ SUCCESSFUL TESTS ({len(successful_tests)}):")
        for result in successful_tests:
            print(f"  - {result['description']} ({result['duration']:.2f}s)")
    
    if failed_tests:
        print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
        for result in failed_tests:
            error_info = result.get('error', f"Return code: {result['return_code']}")
            print(f"  - {result['description']} - {error_info}")
    
    # Save detailed results
    log_dir = Path("test_logs")
    log_dir.mkdir(exist_ok=True)
    
    with open(log_dir / "integration_test_results.txt", "w") as f:
        f.write(f"Integration Test Results - {datetime.now()}\n")
        f.write(f"{'='*80}\n\n")
        
        for result in results:
            f.write(f"Test: {result['description']}\n")
            f.write(f"Path: {result['test_path']}\n")
            f.write(f"Duration: {result['duration']:.2f}s\n")
            f.write(f"Success: {result['success']}\n")
            
            if not result['success']:
                f.write(f"Error: {result.get('error', 'Unknown')}\n")
            
            if result.get('stdout'):
                f.write(f"STDOUT:\n{result['stdout']}\n")
            
            if result.get('stderr'):
                f.write(f"STDERR:\n{result['stderr']}\n")
            
            f.write(f"{'-'*40}\n\n")
    
    print(f"\nDetailed results saved to: {log_dir / 'integration_test_results.txt'}")
    
    # Return appropriate exit code
    return 0 if len(failed_tests) == 0 else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)