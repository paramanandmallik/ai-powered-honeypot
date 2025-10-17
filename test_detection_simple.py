"""
Simple test for Detection Agent functionality
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.detection.detection_agent import DetectionAgent, ThreatAssessment
from datetime import datetime


async def test_detection_agent():
    """Simple test of Detection Agent functionality"""
    print("Testing Detection Agent...")
    
    # Create agent
    config = {
        "confidence_threshold": 0.75,
        "enable_mitre_mapping": True,
        "max_concurrent_assessments": 10
    }
    
    agent = DetectionAgent(config)
    print(f"✓ Agent created: {agent.agent_id}")
    
    # Initialize agent
    await agent.initialize()
    print("✓ Agent initialized")
    
    # Test threat assessment creation
    threat_data = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "threat_type": "brute_force",
        "indicators": ["multiple_failed_logins", "suspicious_timing"],
        "timestamp": datetime.utcnow().isoformat()
    }
    
    assessment = ThreatAssessment(threat_data)
    print(f"✓ Threat assessment created: {assessment.threat_id}")
    
    # Test threat evaluation
    result = await agent.evaluate_threat(threat_data)
    print(f"✓ Threat evaluated: {result['decision']} (confidence: {result['confidence']:.2f})")
    
    # Test reputation check
    reputation_result = await agent.check_reputation({"ip_address": "192.168.1.100"})
    print(f"✓ Reputation checked: {reputation_result['risk_level']}")
    
    # Test IOC extraction
    test_text = "Suspicious activity from 192.168.1.100 with hash d41d8cd98f00b204e9800998ecf8427e"
    ioc_result = await agent.extract_iocs({"text": test_text})
    print(f"✓ IOCs extracted: {ioc_result['total_iocs_found']} total")
    
    # Test metrics
    metrics = await agent.get_metrics()
    print(f"✓ Metrics collected: {metrics['total_assessments']} assessments")
    
    # Test health status
    health = await agent.get_health_status()
    print(f"✓ Health status: {health['detection_agent_status']}")
    
    # Cleanup
    await agent.cleanup()
    print("✓ Agent cleaned up")
    
    print("\n🎉 All tests passed!")


if __name__ == "__main__":
    asyncio.run(test_detection_agent())