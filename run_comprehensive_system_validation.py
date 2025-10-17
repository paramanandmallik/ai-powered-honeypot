#!/usr/bin/env python3
"""
Comprehensive System Validation Runner

Executes comprehensive system testing and validation including:
- Full end-to-end engagement scenarios with simulated attackers
- System performance and scalability testing under realistic concurrent load
- Security isolation controls and real data protection validation
- Intelligence extraction accuracy and MITRE ATT&CK mapping verification
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from testing.comprehensive_system_validator import run_comprehensive_validation


async def main():
    """Main validation runner"""
    print("AI Honeypot System - Comprehensive Validation")
    print("=" * 60)
    
    # Configure logging
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'comprehensive_validation.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Create reports directory
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        print(f"Starting comprehensive system validation at {datetime.utcnow().isoformat()}")
        print("This will test:")
        print("  • End-to-end engagement scenarios")
        print("  • Performance and scalability under load")
        print("  • Security isolation and data protection")
        print("  • Intelligence extraction and MITRE mapping")
        print()
        
        # Run comprehensive validation
        logger.info("Initiating comprehensive system validation...")
        
        report = await run_comprehensive_validation()
        
        # Print detailed results
        print("\n" + "=" * 80)
        print("COMPREHENSIVE VALIDATION RESULTS")
        print("=" * 80)
        
        # Validation Summary
        summary = report["validation_summary"]
        print("VALIDATION SUMMARY:")
        print(f"  Start Time: {summary['start_time']}")
        print(f"  End Time: {summary['end_time']}")
        print(f"  Total Duration: {summary['total_duration_seconds']:.1f} seconds")
        print(f"  Total Scenarios: {summary['total_scenarios']}")
        print(f"  Successful Scenarios: {summary['successful_scenarios']}")
        print(f"  Failed Scenarios: {summary['failed_scenarios']}")
        print(f"  Success Rate: {summary['success_rate_percent']:.1f}%")
        print(f"  Overall Result: {summary['overall_result']}")
        print()
        
        # Performance Metrics
        perf_metrics = report["performance_metrics"]
        print("PERFORMANCE METRICS:")
        print(f"  Average Response Time: {perf_metrics.get('average_response_time', 0):.2f}s")
        print(f"  Peak Concurrent Sessions: {perf_metrics.get('peak_concurrent_sessions', 0)}")
        print(f"  Intelligence Accuracy: {perf_metrics.get('intelligence_accuracy', 0):.2f}")
        print(f"  MITRE Mapping Accuracy: {perf_metrics.get('mitre_mapping_accuracy', 0):.2f}")
        print(f"  Security Violations: {perf_metrics.get('security_violations', 0)}")
        print()
        
        # Scenario Results
        print("SCENARIO RESULTS:")
        for result in report["scenario_results"]:
            status = "✓ PASS" if result["success"] else "✗ FAIL"
            scenario_name = next(
                (s["name"] for s in [
                    {"scenario_id": "web_admin_basic", "name": "Basic Web Admin Portal Attack"},
                    {"scenario_id": "ssh_lateral_movement", "name": "Advanced SSH Lateral Movement Attack"},
                    {"scenario_id": "database_exploitation", "name": "Database Exploitation Attack"},
                    {"scenario_id": "multi_service_chain", "name": "Multi-Service Attack Chain"},
                    {"scenario_id": "concurrent_attacks", "name": "High-Volume Concurrent Attacks"}
                ] if s["scenario_id"] == result["scenario_id"]),
                result["scenario_id"]
            )
            
            print(f"  {status} {scenario_name}")
            print(f"    Duration: {result['duration_seconds']:.1f}s")
            print(f"    Interactions: {result['metrics'].get('interactions_count', 0)}")
            print(f"    MITRE Techniques: {result['metrics'].get('mitre_techniques_count', 0)}")
            
            if not result["success"] and result.get("error_details"):
                print(f"    Error: {result['error_details']}")
            print()
        
        # Aggregate Metrics
        agg_metrics = report["aggregate_metrics"]
        print("AGGREGATE METRICS:")
        print(f"  Average Scenario Duration: {agg_metrics['average_scenario_duration']:.1f}s")
        print(f"  Average Interactions per Scenario: {agg_metrics['average_interactions_per_scenario']:.1f}")
        print(f"  Average Intelligence Confidence: {agg_metrics['average_intelligence_confidence']:.2f}")
        print(f"  Total MITRE Techniques Identified: {agg_metrics['total_mitre_techniques_identified']}")
        print(f"  Unique MITRE Techniques: {agg_metrics['unique_mitre_techniques']}")
        print()
        
        # Security Validation
        security = report["security_validation"]
        print("SECURITY VALIDATION:")
        print(f"  Network Isolation Tested: {'✓' if security['network_isolation_tested'] else '✗'}")
        print(f"  Real Data Protection Tested: {'✓' if security['real_data_protection_tested'] else '✗'}")
        print(f"  Synthetic Data Validation Tested: {'✓' if security['synthetic_data_validation_tested'] else '✗'}")
        print(f"  Security Violations: {security['security_violations']}")
        print()
        
        # Intelligence Validation
        intel = report["intelligence_validation"]
        print("INTELLIGENCE VALIDATION:")
        print(f"  MITRE Mapping Accuracy: {intel['mitre_mapping_accuracy']:.2f}")
        print(f"  Intelligence Extraction Accuracy: {intel['intelligence_extraction_accuracy']:.2f}")
        print()
        
        # Recommendations
        print("RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"  • {rec}")
        print()
        
        # Final Status
        overall_result = summary["overall_result"]
        if overall_result == "PASS":
            print("🟢 COMPREHENSIVE VALIDATION: PASSED")
            print("   System is ready for production deployment.")
            print("   All critical functionality validated successfully.")
        else:
            print("🔴 COMPREHENSIVE VALIDATION: FAILED")
            print("   System requires fixes before production deployment.")
            print("   Review failed scenarios and address issues.")
        
        print("=" * 80)
        
        # Save summary report
        summary_file = reports_dir / f"validation_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(summary_file, "w") as f:
            f.write("AI Honeypot System - Comprehensive Validation Summary\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Validation Date: {datetime.utcnow().isoformat()}\n")
            f.write(f"Overall Result: {overall_result}\n")
            f.write(f"Success Rate: {summary['success_rate_percent']:.1f}%\n")
            f.write(f"Total Scenarios: {summary['total_scenarios']}\n")
            f.write(f"Successful: {summary['successful_scenarios']}\n")
            f.write(f"Failed: {summary['failed_scenarios']}\n\n")
            
            f.write("Key Metrics:\n")
            f.write(f"- Average Response Time: {perf_metrics.get('average_response_time', 0):.2f}s\n")
            f.write(f"- Intelligence Accuracy: {perf_metrics.get('intelligence_accuracy', 0):.2f}\n")
            f.write(f"- Security Violations: {perf_metrics.get('security_violations', 0)}\n\n")
            
            f.write("Recommendations:\n")
            for rec in report["recommendations"]:
                f.write(f"- {rec}\n")
        
        print(f"Summary report saved to: {summary_file}")
        
        # Return appropriate exit code
        return 0 if overall_result == "PASS" else 1
        
    except Exception as e:
        logger.error(f"Comprehensive validation failed: {e}")
        print(f"\n🔴 VALIDATION ERROR: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)