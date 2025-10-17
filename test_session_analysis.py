#!/usr/bin/env python3
"""
Test script for Intelligence Agent session analysis capabilities
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from agents.intelligence.intelligence_agent import IntelligenceAgent
from agents.intelligence.session_analyzer import SessionAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_sample_session_data():
    """Create sample session data for testing"""
    base_time = datetime.utcnow()
    
    return {
        "session_id": "test-session-001",
        "metadata": {
            "honeypot_type": "ssh",
            "source_ip": "192.168.1.100",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=15)).isoformat(),
            "duration_seconds": 900,
            "user_agent": "OpenSSH_8.0"
        },
        "transcript": [
            {
                "timestamp": base_time.isoformat(),
                "type": "connection",
                "content": "SSH connection established"
            },
            {
                "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
                "type": "command",
                "content": "whoami"
            },
            {
                "timestamp": (base_time + timedelta(seconds=15)).isoformat(),
                "type": "response",
                "content": "admin"
            },
            {
                "timestamp": (base_time + timedelta(seconds=20)).isoformat(),
                "type": "command",
                "content": "id"
            },
            {
                "timestamp": (base_time + timedelta(seconds=25)).isoformat(),
                "type": "response",
                "content": "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo)"
            },
            {
                "timestamp": (base_time + timedelta(seconds=30)).isoformat(),
                "type": "command",
                "content": "uname -a"
            },
            {
                "timestamp": (base_time + timedelta(seconds=35)).isoformat(),
                "type": "response",
                "content": "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
            },
            {
                "timestamp": (base_time + timedelta(seconds=45)).isoformat(),
                "type": "command",
                "content": "ps aux"
            },
            {
                "timestamp": (base_time + timedelta(seconds=50)).isoformat(),
                "type": "response",
                "content": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  19312  1544 ?        Ss   10:00   0:01 /sbin/init"
            },
            {
                "timestamp": (base_time + timedelta(seconds=60)).isoformat(),
                "type": "command",
                "content": "netstat -an"
            },
            {
                "timestamp": (base_time + timedelta(seconds=65)).isoformat(),
                "type": "response",
                "content": "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State"
            },
            {
                "timestamp": (base_time + timedelta(seconds=75)).isoformat(),
                "type": "command",
                "content": "cat /etc/passwd"
            },
            {
                "timestamp": (base_time + timedelta(seconds=80)).isoformat(),
                "type": "response",
                "content": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash"
            },
            {
                "timestamp": (base_time + timedelta(seconds=90)).isoformat(),
                "type": "command",
                "content": "sudo -l"
            },
            {
                "timestamp": (base_time + timedelta(seconds=95)).isoformat(),
                "type": "response",
                "content": "User admin may run the following commands on honeypot:\n    (ALL : ALL) ALL"
            },
            {
                "timestamp": (base_time + timedelta(seconds=120)).isoformat(),
                "type": "command",
                "content": "find / -name '*.conf' 2>/dev/null"
            },
            {
                "timestamp": (base_time + timedelta(seconds=125)).isoformat(),
                "type": "response",
                "content": "/etc/ssh/sshd_config\n/etc/apache2/apache2.conf"
            },
            {
                "timestamp": (base_time + timedelta(seconds=140)).isoformat(),
                "type": "command",
                "content": "history -c"
            },
            {
                "timestamp": (base_time + timedelta(seconds=145)).isoformat(),
                "type": "response",
                "content": ""
            },
            {
                "timestamp": (base_time + timedelta(seconds=150)).isoformat(),
                "type": "disconnection",
                "content": "SSH connection closed"
            }
        ]
    }

def create_web_attack_session():
    """Create sample web attack session data"""
    base_time = datetime.utcnow()
    
    return {
        "session_id": "test-web-session-001",
        "metadata": {
            "honeypot_type": "web_admin",
            "source_ip": "10.0.0.50",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=10)).isoformat(),
            "duration_seconds": 600,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        "transcript": [
            {
                "timestamp": base_time.isoformat(),
                "type": "http_request",
                "content": "GET /admin/login.php HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=5)).isoformat(),
                "type": "http_request",
                "content": "POST /admin/login.php HTTP/1.1\nContent: username=admin&password=admin"
            },
            {
                "timestamp": (base_time + timedelta(seconds=15)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/users.php?id=1 UNION SELECT 1,2,3,4 HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=25)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/users.php?id=1' OR 1=1-- HTTP/1.1"
            },
            {
                "timestamp": (base_time + timedelta(seconds=35)).isoformat(),
                "type": "http_request",
                "content": "GET /admin/config.php?file=../../../etc/passwd HTTP/1.1"
            }
        ]
    }

async def test_session_analyzer():
    """Test the SessionAnalyzer class"""
    logger.info("Testing SessionAnalyzer...")
    
    analyzer = SessionAnalyzer()
    
    # Test command sequence analysis
    session_data = create_sample_session_data()
    transcript = session_data["transcript"]
    
    logger.info("Testing command sequence analysis...")
    command_analysis = analyzer.analyze_command_sequence(transcript)
    logger.info(f"Command Analysis Result: {json.dumps(command_analysis, indent=2)}")
    
    # Test web interactions analysis
    web_session = create_web_attack_session()
    web_transcript = web_session["transcript"]
    
    logger.info("Testing web interactions analysis...")
    web_analysis = analyzer.analyze_web_interactions(web_transcript)
    logger.info(f"Web Analysis Result: {json.dumps(web_analysis, indent=2)}")
    
    # Test sophistication scoring
    logger.info("Testing sophistication scoring...")
    score, level = analyzer.calculate_sophistication_score(session_data)
    logger.info(f"Sophistication Score: {score:.2f}, Level: {level}")
    
    # Test IOC extraction
    logger.info("Testing IOC extraction...")
    iocs = analyzer.extract_indicators_of_compromise(session_data)
    logger.info(f"Extracted IOCs: {json.dumps(iocs, indent=2)}")

async def test_intelligence_agent():
    """Test the IntelligenceAgent class"""
    logger.info("Testing IntelligenceAgent...")
    
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
        
        # Test session analysis
        session_data = create_sample_session_data()
        
        logger.info("Testing session analysis...")
        analysis_result = await agent.analyze_session(session_data)
        logger.info(f"Analysis Result: {json.dumps(analysis_result, indent=2, default=str)}")
        
        # Test message processing
        logger.info("Testing message processing...")
        
        # Test analysis request message
        analysis_message = {
            "type": "analyze_session",
            "session_data": session_data
        }
        
        message_result = await agent.process_message(analysis_message)
        logger.info(f"Message Processing Result: {json.dumps(message_result, indent=2, default=str)}")
        
        # Test status request
        status_message = {"type": "get_analysis_status"}
        status_result = await agent.process_message(status_message)
        logger.info(f"Status Result: {json.dumps(status_result, indent=2)}")
        
        # Test intelligence report request
        report_message = {
            "type": "get_intelligence_report",
            "report_type": "summary",
            "time_range": "24h"
        }
        
        report_result = await agent.process_message(report_message)
        logger.info(f"Report Result: {json.dumps(report_result, indent=2, default=str)}")
        
    finally:
        # Stop agent
        await agent.stop()

async def main():
    """Main test function"""
    logger.info("Starting Intelligence Agent Session Analysis Tests")
    
    try:
        # Test session analyzer
        await test_session_analyzer()
        
        print("\n" + "="*50 + "\n")
        
        # Test intelligence agent
        await test_intelligence_agent()
        
        logger.info("All tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())