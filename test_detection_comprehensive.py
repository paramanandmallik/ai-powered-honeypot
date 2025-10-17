"""
Comprehensive test for Detection Agent implementation
"""

import asyncio
import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.detection.detection_agent import DetectionAgent, MITRE_ATTACK_TECHNIQUES, THREAT_SEVERITY_MAPPING


async def test_comprehensive_detection_agent():
    """Comprehensive test of Detection Agent functionality"""
    print("🔍 Testing Detection Agent Comprehensive Functionality")
    print("=" * 60)
    
    # Create agent with specific configuration
    config = {
        "confidence_threshold": 0.75,
        "enable_mitre_mapping": True,
        "max_concurrent_assessments": 10,
        "engagement_cooldown_minutes": 2,
        "reputation_cache_ttl": 300
    }
    
    agent = DetectionAgent(config)
    print(f"✓ Agent created: {agent.agent_id}")
    print(f"  - Confidence threshold: {agent.confidence_threshold}")
    print(f"  - MITRE mapping enabled: {agent.enable_mitre_mapping}")
    
    # Initialize agent
    await agent.initialize()
    print("✓ Agent initialized successfully")
    
    # Test 1: High-confidence brute force attack
    print("\n📊 Test 1: High-confidence brute force attack")
    brute_force_data = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "threat_type": "brute_force",
        "indicators": ["multiple_failed_logins", "credential_stuffing_pattern", "automated_attack"],
        "timestamp": datetime.now().isoformat()
    }
    
    result1 = await agent.evaluate_threat(brute_force_data)
    print(f"  - Decision: {result1['decision']}")
    print(f"  - Confidence: {result1['confidence']:.3f}")
    print(f"  - MITRE Techniques: {result1['mitre_techniques']}")
    print(f"  - Recommended Honeypots: {result1['recommended_honeypots']}")
    print(f"  - Reasoning: {result1['reasoning']}")
    
    # Test 2: Medium-confidence SQL injection
    print("\n📊 Test 2: Medium-confidence SQL injection")
    sql_injection_data = {
        "source_ip": "203.0.113.50",
        "destination_ip": "10.0.0.2",
        "threat_type": "sql_injection",
        "indicators": ["union_select_pattern", "database_error_messages"],
        "timestamp": datetime.now().isoformat()
    }
    
    result2 = await agent.evaluate_threat(sql_injection_data)
    print(f"  - Decision: {result2['decision']}")
    print(f"  - Confidence: {result2['confidence']:.3f}")
    print(f"  - MITRE Techniques: {result2['mitre_techniques']}")
    print(f"  - Recommended Honeypots: {result2['recommended_honeypots']}")
    
    # Test 3: Low-confidence port scan
    print("\n📊 Test 3: Low-confidence port scan")
    port_scan_data = {
        "source_ip": "198.51.100.25",
        "destination_ip": "10.0.0.3",
        "threat_type": "port_scan",
        "indicators": ["sequential_port_access"],
        "timestamp": datetime.now().isoformat()
    }
    
    result3 = await agent.evaluate_threat(port_scan_data)
    print(f"  - Decision: {result3['decision']}")
    print(f"  - Confidence: {result3['confidence']:.3f}")
    print(f"  - MITRE Techniques: {result3['mitre_techniques']}")
    
    # Test 4: Reputation checking with caching
    print("\n📊 Test 4: Reputation checking and caching")
    
    # First reputation check
    rep_result1 = await agent.check_reputation({"ip_address": "192.168.1.100"})
    print(f"  - First check - Risk Level: {rep_result1['risk_level']}")
    print(f"  - Confidence Score: {rep_result1['confidence_score']}")
    print(f"  - Indicators: {rep_result1['indicators']}")
    
    # Second reputation check (should use cache)
    rep_result2 = await agent.check_reputation({"ip_address": "192.168.1.100"})
    print(f"  - Second check (cached) - Risk Level: {rep_result2['risk_level']}")
    
    # Test 5: IOC extraction with various types
    print("\n📊 Test 5: IOC extraction from complex text")
    complex_text = """
    Security Alert: Malicious activity detected
    
    Source IP: 192.168.1.100, 203.0.113.50
    Malware hashes:
    - MD5: d41d8cd98f00b204e9800998ecf8427e
    - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    
    Contacted domains: malicious-site.com, evil-domain.org
    Email addresses: attacker@evil.com, spam@malicious-site.com
    
    File paths:
    - C:\\Windows\\System32\\malware.exe
    - /tmp/backdoor.sh
    
    Registry keys: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware
    
    URLs: http://malicious-site.com/payload.php, https://evil-domain.org/exploit
    """
    
    ioc_result = await agent.extract_iocs({
        "text": complex_text,
        "source_type": "security_alert"
    })
    
    print(f"  - Total IOCs found: {ioc_result['total_iocs_found']}")
    print(f"  - IP addresses: {len(ioc_result['ip_addresses'])}")
    print(f"  - Domains: {len(ioc_result['domains'])}")
    print(f"  - File hashes: {len(ioc_result['file_hashes'])}")
    print(f"  - Email addresses: {len(ioc_result['email_addresses'])}")
    print(f"  - File paths: {len(ioc_result['file_paths'])}")
    print(f"  - URLs: {len(ioc_result['urls'])}")
    print(f"  - Registry keys: {len(ioc_result['registry_keys'])}")
    
    # Test 6: Engagement cooldown functionality
    print("\n📊 Test 6: Engagement cooldown testing")
    
    # First engagement attempt
    cooldown_data = {
        "source_ip": "192.168.1.200",
        "threat_type": "brute_force",
        "indicators": ["high_frequency_attempts"],
        "timestamp": datetime.now().isoformat()
    }
    
    cooldown_result1 = await agent.evaluate_threat(cooldown_data)
    print(f"  - First attempt: {cooldown_result1['decision']}")
    
    # Immediate second attempt (should trigger cooldown)
    cooldown_result2 = await agent.evaluate_threat(cooldown_data)
    print(f"  - Second attempt: {cooldown_result2['decision']}")
    print(f"  - Cooldown active: {cooldown_result2.get('cooldown_active', False)}")
    
    # Test 7: MITRE ATT&CK technique mapping
    print("\n📊 Test 7: MITRE ATT&CK technique mapping")
    print(f"  - Available threat types: {list(MITRE_ATTACK_TECHNIQUES.keys())}")
    print(f"  - Brute force techniques: {MITRE_ATTACK_TECHNIQUES.get('brute_force', [])}")
    print(f"  - Lateral movement techniques: {MITRE_ATTACK_TECHNIQUES.get('lateral_movement', [])}")
    
    # Test 8: Threat statistics and metrics
    print("\n📊 Test 8: Comprehensive metrics and statistics")
    
    metrics = await agent.get_metrics()
    print(f"  - Total assessments: {metrics['total_assessments']}")
    print(f"  - Average confidence: {metrics['average_confidence']:.3f}")
    print(f"  - Engagement decisions: {metrics['engagement_decisions']}")
    print(f"  - Threat type distribution: {metrics['threat_type_distribution']}")
    print(f"  - Severity distribution: {metrics['severity_distribution']}")
    print(f"  - Reputation cache size: {metrics['reputation_cache_size']}")
    
    stats = await agent.get_threat_statistics()
    print(f"  - Engagement rate: {stats['engagement_rate']:.3f}")
    print(f"  - MITRE techniques seen: {len(stats['mitre_techniques_seen'])}")
    print(f"  - Top source IPs: {dict(list(stats['top_source_ips'].items())[:3])}")
    
    # Test 9: Health status monitoring
    print("\n📊 Test 9: Health status monitoring")
    
    health = await agent.get_health_status()
    print(f"  - Overall status: {health['detection_agent_status']}")
    print(f"  - Health indicators: {health['health_indicators']}")
    print(f"  - Active assessments: {health['active_assessments']}")
    print(f"  - Cache status: {health['cache_status']}")
    
    # Test 10: Configuration updates
    print("\n📊 Test 10: Configuration updates")
    
    new_config = {
        "confidence_threshold": 0.8,
        "max_concurrent_assessments": 15,
        "engagement_cooldown_minutes": 3
    }
    
    config_result = await agent.update_configuration(new_config)
    print(f"  - Configuration update status: {config_result['status']}")
    print(f"  - New confidence threshold: {agent.confidence_threshold}")
    print(f"  - New max assessments: {agent.max_concurrent_assessments}")
    
    # Test 11: Honeypot recommendation logic
    print("\n📊 Test 11: Honeypot recommendation testing")
    
    test_scenarios = [
        ("brute_force", ["T1110", "T1110.001"]),
        ("sql_injection", ["T1190", "T1213"]),
        ("lateral_movement", ["T1021", "T1570"]),
        ("file_access", ["T1005", "T1083"]),
        ("phishing", ["T1566", "T1566.001"])
    ]
    
    for threat_type, techniques in test_scenarios:
        recommended = await agent._recommend_honeypots_by_techniques(threat_type, techniques)
        print(f"  - {threat_type}: {recommended}")
    
    # Final cleanup
    await agent.cleanup()
    print("\n✓ Agent cleaned up successfully")
    
    print("\n" + "=" * 60)
    print("🎉 All comprehensive tests completed successfully!")
    print(f"📈 Final metrics: {metrics['total_assessments']} threats analyzed")
    print(f"🎯 Engagement rate: {stats['engagement_rate']:.1%}")
    print(f"🔒 Security features: MITRE mapping, IOC extraction, reputation caching")
    print(f"⚡ Performance: {metrics['reputation_cache_size']} cached entries")


if __name__ == "__main__":
    asyncio.run(test_comprehensive_detection_agent())