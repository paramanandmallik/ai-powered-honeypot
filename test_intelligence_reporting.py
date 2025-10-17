#!/usr/bin/env python3
"""
Test script for Intelligence Reporting functionality
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from agents.intelligence.intelligence_agent import IntelligenceAgent
from agents.intelligence.intelligence_reporter import IntelligenceReporter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_sample_analysis_data():
    """Create sample analysis data for testing"""
    base_time = datetime.utcnow()
    
    analyses = []
    
    # Create multiple analysis results
    for i in range(10):
        analysis_time = base_time - timedelta(hours=i*2)
        
        analysis = {
            "session_id": f"test-session-{i:03d}",
            "analysis_id": f"analysis-{i:03d}",
            "start_time": analysis_time.isoformat(),
            "end_time": (analysis_time + timedelta(minutes=15)).isoformat(),
            "result": {
                "session_duration": 900 + (i * 100),
                "interaction_count": 15 + i,
                "confidence_score": 0.6 + (i * 0.05),
                "risk_assessment": ["Low", "Medium", "High"][i % 3],
                "techniques": [
                    {
                        "technique_id": f"T{1000 + (i % 5)}",
                        "technique_name": f"Test Technique {i % 5}",
                        "tactic": ["Discovery", "Execution", "Persistence", "Defense Evasion"][i % 4],
                        "confidence": 0.8 + (i * 0.02),
                        "evidence": f"Command evidence {i}"
                    }
                ],
                "iocs": [
                    {
                        "type": "ip_address",
                        "value": f"192.168.1.{100 + i}",
                        "confidence": 0.7 + (i * 0.03),
                        "context": f"Source IP from session {i}"
                    }
                ],
                "findings": [
                    {
                        "finding_id": f"finding-{i}",
                        "type": "technique_detection",
                        "title": f"Attack Technique Detected {i}",
                        "confidence": 0.75 + (i * 0.02),
                        "severity": ["Low", "Medium", "High"][i % 3]
                    }
                ],
                "recommendations": [
                    "Monitor for similar attack patterns",
                    "Review security controls",
                    "Update detection rules"
                ][i % 3:i % 3 + 1]
            }
        }
        
        analyses.append(analysis)
    
    return analyses

async def test_intelligence_reporter():
    """Test the IntelligenceReporter class"""
    logger.info("Testing Intelligence Reporter...")
    
    reporter = IntelligenceReporter()
    sample_data = create_sample_analysis_data()
    
    # Test structured report generation
    logger.info("Testing structured report generation...")
    
    report_types = ["executive_summary", "technical_analysis", "incident_response", "threat_intelligence"]
    
    for report_type in report_types:
        logger.info(f"Generating {report_type} report...")
        report = reporter.generate_structured_report(sample_data, report_type, "24h")
        
        if "error" not in report:
            logger.info(f"  ✓ {report_type} report generated successfully")
            logger.info(f"    Sections: {list(report.get('sections', {}).keys())}")
            logger.info(f"    Data points: {report.get('report_metadata', {}).get('data_points', 0)}")
        else:
            logger.error(f"  ✗ {report_type} report failed: {report['error']}")
    
    # Test automated summary generation
    logger.info("\nTesting automated summary generation...")
    
    summary_types = ["daily", "weekly", "monthly"]
    
    for summary_type in summary_types:
        logger.info(f"Generating {summary_type} summary...")
        summary = reporter.generate_automated_summary(sample_data, summary_type)
        
        if "error" not in summary:
            logger.info(f"  ✓ {summary_type} summary generated successfully")
            
            key_stats = summary.get("key_statistics", {})
            logger.info(f"    Session count: {key_stats.get('session_count', 0)}")
            logger.info(f"    Risk distribution: {key_stats.get('risk_distribution', {})}")
            
            narrative = summary.get("narrative", "")
            logger.info(f"    Narrative: {narrative[:100]}...")
        else:
            logger.error(f"  ✗ {summary_type} summary failed: {summary['error']}")
    
    # Test trend analysis
    logger.info("\nTesting trend analysis...")
    
    trend_analysis = reporter.analyze_trends(sample_data, "comprehensive")
    
    if "error" not in trend_analysis:
        logger.info("  ✓ Trend analysis completed successfully")
        
        volume_trends = trend_analysis.get("volume_trends", {})
        logger.info(f"    Volume trend: {volume_trends.get('trend', 'unknown')}")
        
        technique_trends = trend_analysis.get("technique_trends", {})
        top_techniques = technique_trends.get("top_techniques", {})
        logger.info(f"    Top techniques: {list(top_techniques.keys())[:3]}")
    else:
        logger.error(f"  ✗ Trend analysis failed: {trend_analysis['error']}")
    
    # Test external platform integration
    logger.info("\nTesting external platform integration...")
    
    intelligence_data = {
        "techniques": sample_data[0]["result"]["techniques"],
        "iocs": sample_data[0]["result"]["iocs"],
        "findings": sample_data[0]["result"]["findings"]
    }
    
    integration_result = reporter.integrate_with_external_platforms(intelligence_data, ["stix"])
    
    if "error" not in integration_result:
        logger.info("  ✓ External platform integration completed")
        
        platform_results = integration_result.get("platform_results", {})
        stix_result = platform_results.get("stix", {})
        
        if stix_result.get("status") == "success":
            logger.info(f"    STIX export: {stix_result.get('objects_count', 0)} objects")
        else:
            logger.info(f"    STIX export status: {stix_result.get('status', 'unknown')}")
    else:
        logger.error(f"  ✗ External platform integration failed: {integration_result['error']}")

async def test_intelligence_agent_reporting():
    """Test Intelligence Agent reporting integration"""
    logger.info("\nTesting Intelligence Agent Reporting Integration...")
    
    # Initialize agent with sample data
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
        
        # Add sample completed analyses
        sample_data = create_sample_analysis_data()
        agent.completed_analyses = sample_data
        
        # Test structured report request
        logger.info("Testing structured report request...")
        
        structured_report_msg = {
            "type": "generate_structured_report",
            "report_type": "technical_analysis",
            "time_range": "24h"
        }
        
        report_result = await agent.process_message(structured_report_msg)
        
        if report_result.get("status") == "success":
            logger.info("  ✓ Structured report generated successfully")
            report = report_result.get("report", {})
            logger.info(f"    Report sections: {len(report.get('sections', {}))}")
        else:
            logger.error(f"  ✗ Structured report failed: {report_result.get('error', 'Unknown error')}")
        
        # Test automated summary request
        logger.info("Testing automated summary request...")
        
        summary_msg = {
            "type": "generate_automated_summary",
            "summary_type": "daily"
        }
        
        summary_result = await agent.process_message(summary_msg)
        
        if summary_result.get("status") == "success":
            logger.info("  ✓ Automated summary generated successfully")
            summary = summary_result.get("summary", {})
            logger.info(f"    Summary type: {summary.get('summary_metadata', {}).get('summary_type', 'unknown')}")
        else:
            logger.error(f"  ✗ Automated summary failed: {summary_result.get('error', 'Unknown error')}")
        
        # Test trend analysis request
        logger.info("Testing trend analysis request...")
        
        trend_msg = {
            "type": "analyze_trends",
            "analysis_type": "comprehensive"
        }
        
        trend_result = await agent.process_message(trend_msg)
        
        if trend_result.get("status") == "success":
            logger.info("  ✓ Trend analysis completed successfully")
            trend_analysis = trend_result.get("trend_analysis", {})
            logger.info(f"    Analysis type: {trend_analysis.get('analysis_metadata', {}).get('analysis_type', 'unknown')}")
        else:
            logger.error(f"  ✗ Trend analysis failed: {trend_result.get('error', 'Unknown error')}")
        
        # Test intelligence export request
        logger.info("Testing intelligence export request...")
        
        export_msg = {
            "type": "export_intelligence",
            "platforms": ["stix"]
        }
        
        export_result = await agent.process_message(export_msg)
        
        if export_result.get("status") == "success":
            logger.info("  ✓ Intelligence export completed successfully")
            export_results = export_result.get("export_results", {})
            logger.info(f"    Platforms: {export_result.get('platforms', [])}")
        else:
            logger.error(f"  ✗ Intelligence export failed: {export_result.get('error', 'Unknown error')}")
        
        # Test intelligence dashboard generation
        logger.info("Testing intelligence dashboard generation...")
        
        dashboard_result = await agent.generate_intelligence_dashboard("24h")
        
        if dashboard_result.get("status") == "success":
            logger.info("  ✓ Intelligence dashboard generated successfully")
            dashboard = dashboard_result.get("dashboard", {})
            logger.info(f"    Dashboard sections: {list(dashboard.keys())}")
            logger.info(f"    Alerts: {len(dashboard.get('alerts', []))}")
            logger.info(f"    Recommendations: {len(dashboard.get('recommendations', []))}")
        else:
            logger.error(f"  ✗ Intelligence dashboard failed: {dashboard_result.get('error', 'Unknown error')}")
        
        # Test intelligence data export
        logger.info("Testing intelligence data export...")
        
        export_data_result = await agent.export_intelligence_data("json", "24h", False)
        
        if export_data_result.get("status") == "success":
            logger.info("  ✓ Intelligence data export completed successfully")
            data = export_data_result.get("data", {})
            export_metadata = data.get("export_metadata", {})
            logger.info(f"    Export format: {export_metadata.get('format', 'unknown')}")
            logger.info(f"    Session count: {export_metadata.get('session_count', 0)}")
            logger.info(f"    Techniques: {len(data.get('techniques', []))}")
            logger.info(f"    IOCs: {len(data.get('iocs', []))}")
        else:
            logger.error(f"  ✗ Intelligence data export failed: {export_data_result.get('error', 'Unknown error')}")
        
        # Test STIX export
        logger.info("Testing STIX format export...")
        
        stix_export_result = await agent.export_intelligence_data("stix", "24h", False)
        
        if stix_export_result.get("status") == "success":
            logger.info("  ✓ STIX export completed successfully")
            data = stix_export_result.get("data", {})
            stix_bundle = data.get("stix_bundle")
            if stix_bundle:
                logger.info(f"    STIX objects: {len(stix_bundle.get('objects', []))}")
            else:
                logger.info("    STIX bundle: Not generated")
        else:
            logger.error(f"  ✗ STIX export failed: {stix_export_result.get('error', 'Unknown error')}")
        
    finally:
        # Stop agent
        await agent.stop()

async def test_report_formats():
    """Test different report formats and outputs"""
    logger.info("\nTesting Report Formats and Outputs...")
    
    reporter = IntelligenceReporter()
    sample_data = create_sample_analysis_data()
    
    # Test executive summary format
    logger.info("Testing executive summary format...")
    exec_report = reporter.generate_structured_report(sample_data, "executive_summary", "24h")
    
    if "error" not in exec_report:
        logger.info("  ✓ Executive summary format validated")
        
        # Check required sections
        sections = exec_report.get("sections", {})
        required_sections = ["overview", "key_findings", "threat_assessment", "recommendations"]
        
        for section in required_sections:
            if section in sections:
                logger.info(f"    ✓ {section} section present")
            else:
                logger.warning(f"    ⚠ {section} section missing")
    
    # Test technical analysis format
    logger.info("Testing technical analysis format...")
    tech_report = reporter.generate_structured_report(sample_data, "technical_analysis", "24h")
    
    if "error" not in tech_report:
        logger.info("  ✓ Technical analysis format validated")
        
        # Check metrics
        metrics = tech_report.get("metrics", {})
        logger.info(f"    Total sessions: {metrics.get('total_sessions', 0)}")
        logger.info(f"    High risk sessions: {metrics.get('high_risk_sessions', 0)}")
        logger.info(f"    Unique techniques: {metrics.get('unique_techniques', 0)}")
    
    # Test automated summary narrative
    logger.info("Testing automated summary narrative...")
    daily_summary = reporter.generate_automated_summary(sample_data, "daily")
    
    if "error" not in daily_summary:
        narrative = daily_summary.get("narrative", "")
        logger.info(f"  ✓ Narrative generated: {len(narrative)} characters")
        logger.info(f"    Sample: {narrative[:150]}...")

async def main():
    """Main test function"""
    logger.info("Starting Intelligence Reporting Tests")
    
    try:
        # Test intelligence reporter
        await test_intelligence_reporter()
        
        print("\n" + "="*60 + "\n")
        
        # Test intelligence agent reporting integration
        await test_intelligence_agent_reporting()
        
        print("\n" + "="*60 + "\n")
        
        # Test report formats
        await test_report_formats()
        
        logger.info("All intelligence reporting tests completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())