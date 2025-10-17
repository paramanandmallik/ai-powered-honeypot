#!/usr/bin/env python3
"""
Test AI Honeypot Detection Agent for AgentCore Runtime deployment
Validates all functionality before and after deployment
"""

import json
import logging
import requests
import time
import sys
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AgentCoreTester:
    """Test suite for AgentCore Runtime deployment"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.invocations_url = f"{base_url}/invocations"
        self.ping_url = f"{base_url}/ping"
        
    def test_ping_endpoint(self) -> bool:
        """Test the ping endpoint for health checks"""
        logger.info("🏓 Testing ping endpoint...")
        
        try:
            response = requests.get(self.ping_url, timeout=10)
            if response.status_code == 200:
                logger.info("✅ Ping endpoint working")
                return True
            else:
                logger.error(f"❌ Ping endpoint failed: {response.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"❌ Ping endpoint error: {e}")
            return False
    
    def test_invocation(self, payload: Dict[str, Any], test_name: str) -> bool:
        """Test an invocation with the given payload"""
        logger.info(f"🧪 Testing {test_name}...")
        
        try:
            response = requests.post(
                self.invocations_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✅ {test_name} successful")
                logger.info(f"📋 Response: {json.dumps(result, indent=2)}")
                return True
            else:
                logger.error(f"❌ {test_name} failed: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"❌ {test_name} error: {e}")
            return False
    
    def run_all_tests(self) -> bool:
        """Run all test cases"""
        logger.info("🎯 Starting comprehensive AgentCore Runtime tests")
        
        test_results = []
        
        # Test 1: Ping endpoint
        test_results.append(self.test_ping_endpoint())
        
        # Test 2: Basic invocation
        test_results.append(self.test_invocation(
            {"prompt": "Hello, AI Honeypot Detection Agent"},
            "Basic Invocation"
        ))
        
        # Test 3: Health check
        test_results.append(self.test_invocation(
            {"prompt": "health", "type": "health_check"},
            "Health Check"
        ))
        
        # Test 4: Reputation check
        test_results.append(self.test_invocation(
            {
                "prompt": "check reputation", 
                "type": "reputation_check",
                "ip_address": "192.168.1.100"
            },
            "Reputation Check"
        ))
        
        # Test 5: IOC extraction
        test_results.append(self.test_invocation(
            {
                "prompt": "extract IOCs",
                "type": "ioc_extraction", 
                "text_data": "Suspicious activity from 10.0.0.1 connecting to malicious.example.com with hash abc123def456789012345678901234567890"
            },
            "IOC Extraction"
        ))
        
        # Test 6: Traffic analysis
        test_results.append(self.test_invocation(
            {
                "prompt": "analyze traffic",
                "type": "traffic_analysis",
                "traffic_data": {
                    "packet_count": 15000,
                    "unique_destinations": 150,
                    "protocol": "TCP",
                    "timestamp": "2024-01-15T10:30:00Z"
                }
            },
            "Traffic Analysis"
        ))
        
        # Test 7: Error handling
        test_results.append(self.test_invocation(
            {
                "prompt": "test error handling",
                "type": "reputation_check"
                # Missing ip_address to test error handling
            },
            "Error Handling"
        ))
        
        # Summary
        passed = sum(test_results)
        total = len(test_results)
        
        logger.info(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            logger.info("🎉 All tests passed! Agent is ready for deployment.")
            return True
        else:
            logger.warning(f"⚠️ {total - passed} tests failed. Review issues before deployment.")
            return False

def wait_for_agent_startup(base_url: str = "http://localhost:8080", max_wait: int = 30) -> bool:
    """Wait for the agent to start up"""
    logger.info(f"⏳ Waiting for agent to start at {base_url}...")
    
    for i in range(max_wait):
        try:
            response = requests.get(f"{base_url}/ping", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Agent is ready!")
                return True
        except requests.RequestException:
            pass
        
        time.sleep(1)
        if i % 5 == 0:
            logger.info(f"Still waiting... ({i}/{max_wait}s)")
    
    logger.error("❌ Agent failed to start within timeout")
    return False

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test AgentCore Runtime deployment")
    parser.add_argument("--url", default="http://localhost:8080", 
                       help="Base URL of the agent (default: http://localhost:8080)")
    parser.add_argument("--wait", action="store_true",
                       help="Wait for agent to start up before testing")
    
    args = parser.parse_args()
    
    if args.wait:
        if not wait_for_agent_startup(args.url):
            sys.exit(1)
    
    tester = AgentCoreTester(args.url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()