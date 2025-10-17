#!/usr/bin/env python3
"""
System Integration Validation Script

Validates the complete system integration including:
- AgentCore Runtime agents connectivity
- AWS supporting services integration
- Honeypot infrastructure integration
- Management dashboard connectivity
- End-to-end data flow validation
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from integration.test_system_integration import SystemIntegrationTestSuite


async def main():
    """Main validation function"""
    print("AI Honeypot System Integration Validation")
    print("=" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/integration_validation.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Create reports directory if it doesn't exist
        Path("reports").mkdir(exist_ok=True)
        
        # Run comprehensive integration tests
        logger.info("Starting system integration validation...")
        
        test_suite = SystemIntegrationTestSuite()
        report = await test_suite.run_comprehensive_tests()
        
        # Save detailed report
        report_file = f"reports/integration_validation_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print validation results
        print("\n" + "=" * 80)
        print("SYSTEM INTEGRATION VALIDATION RESULTS")
        print("=" * 80)
        
        print(f"Validation Time: {datetime.utcnow().isoformat()}")
        print(f"Report File: {report_file}")
        print()
        
        # Test Summary
        summary = report["test_summary"]
        print("TEST SUMMARY:")
        print(f"  Total Tests: {summary['total_tests']}")
        print(f"  Passed: {summary['passed_tests']}")
        print(f"  Failed: {summary['failed_tests']}")
        print(f"  Success Rate: {summary['success_rate']:.1f}%")
        print(f"  Duration: {summary['duration_seconds']:.1f} seconds")
        print(f"  Overall Result: {summary.get('overall_result', 'UNKNOWN')}")
        print()
        
        # Detailed Results
        print("DETAILED TEST RESULTS:")
        for test_detail in report["test_details"]:
            status = "✓ PASS" if test_detail["success"] else "✗ FAIL"
            print(f"  {status} - {test_detail['test_name']}")
            if not test_detail["success"]:
                print(f"    Error: {test_detail['details']}")
        print()
        
        # Recommendations
        if report.get("recommendations"):
            print("RECOMMENDATIONS:")
            for rec in report["recommendations"]:
                print(f"  • {rec}")
            print()
        
        # Integration Status
        overall_result = report["test_summary"].get("overall_result", "UNKNOWN")
        if overall_result == "PASS":
            print("🟢 SYSTEM INTEGRATION: VALIDATED")
            print("   All components are properly integrated and functioning.")
            print("   The system is ready for deployment and operation.")
        else:
            print("🔴 SYSTEM INTEGRATION: VALIDATION FAILED")
            print("   One or more integration tests failed.")
            print("   Review the failed tests and address issues before deployment.")
        
        print("=" * 80)
        
        # Return appropriate exit code
        return 0 if overall_result == "PASS" else 1
        
    except Exception as e:
        logger.error(f"Integration validation failed: {e}")
        print(f"\n🔴 VALIDATION ERROR: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)