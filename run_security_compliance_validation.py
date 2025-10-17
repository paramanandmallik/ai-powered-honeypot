#!/usr/bin/env python3
"""
Security Compliance Validation Runner

Executes comprehensive security validation and compliance testing including:
- External penetration testing of all honeypot implementations
- Network isolation and containment mechanism validation
- Emergency shutdown procedures and incident response workflow testing
- Compliance verification with security requirements and audit trail integrity
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from security.security_compliance_validator import run_security_validation


async def main():
    """Main security validation runner"""
    print("AI Honeypot System - Security Compliance Validation")
    print("=" * 65)
    
    # Configure logging
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'security_compliance_validation.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Create reports directory
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        print(f"Starting security compliance validation at {datetime.utcnow().isoformat()}")
        print("This will test:")
        print("  • External penetration testing of honeypots")
        print("  • Network isolation and containment mechanisms")
        print("  • Emergency shutdown and incident response procedures")
        print("  • Security requirements and audit trail compliance")
        print()
        
        # Run security validation
        logger.info("Initiating security compliance validation...")
        
        report = await run_security_validation()
        
        # Print detailed results
        print("\n" + "=" * 80)
        print("SECURITY COMPLIANCE VALIDATION RESULTS")
        print("=" * 80)
        
        # Security Summary
        summary = report["security_validation_summary"]
        print("SECURITY VALIDATION SUMMARY:")
        print(f"  Start Time: {summary['start_time']}")
        print(f"  End Time: {summary['end_time']}")
        print(f"  Total Duration: {summary['total_duration_seconds']:.1f} seconds")
        print(f"  Total Security Tests: {summary['total_security_tests']}")
        print(f"  Passed Security Tests: {summary['passed_security_tests']}")
        print(f"  Failed Security Tests: {summary['failed_security_tests']}")
        print(f"  Success Rate: {summary['success_rate_percent']:.1f}%")
        print(f"  Overall Security Status: {summary['overall_security_status']}")
        print()
        
        # Security Metrics
        metrics = report["security_metrics"]
        print("SECURITY METRICS:")
        print(f"  Critical Findings: {metrics.get('critical_findings', 0)}")
        print(f"  High Findings: {metrics.get('high_findings', 0)}")
        print(f"  Medium Findings: {metrics.get('medium_findings', 0)}")
        print(f"  Low Findings: {metrics.get('low_findings', 0)}")
        print(f"  Compliance Score: {metrics.get('compliance_score', 0):.1f}%")
        print(f"  Audit Trail Integrity: {'✓' if metrics.get('audit_trail_integrity', False) else '✗'}")
        print()
        
        # Security Test Results
        print("SECURITY TEST RESULTS:")
        for result in report["security_test_results"]:
            status = "✓ PASS" if result["success"] else "✗ FAIL"
            print(f"  {status} {result['test_name']}")
            print(f"    Risk Level: {result['risk_level'].upper()}")
            print(f"    Compliance Status: {result['compliance_status'].upper()}")
            print(f"    Findings: {len(result['findings'])}")
            print(f"    Remediation Required: {'Yes' if result['remediation_required'] else 'No'}")
            
            if not result["success"] and result.get("error_details"):
                print(f"    Error: {result['error_details']}")
            print()
        
        # Findings Summary
        findings = report["findings_summary"]
        print("FINDINGS SUMMARY:")
        print(f"  Total Findings: {findings['total_findings']}")
        print("  Severity Breakdown:")
        severity_breakdown = findings["severity_breakdown"]
        for severity, count in severity_breakdown.items():
            if count > 0:
                print(f"    {severity.title()}: {count}")
        print(f"  Tests Requiring Remediation: {findings['remediation_required']}")
        print()
        
        # Compliance Summary
        compliance = report["compliance_summary"]
        print("COMPLIANCE SUMMARY:")
        print(f"  Frameworks Tested: {compliance['frameworks_tested']}")
        print(f"  Overall Compliance Score: {compliance['compliance_score']:.1f}%")
        print(f"  Compliant Requirements: {compliance['compliant_requirements']}")
        print(f"  Non-Compliant Requirements: {compliance['non_compliant_requirements']}")
        print()
        
        # Compliance Test Results
        if report["compliance_test_results"]:
            print("COMPLIANCE TEST RESULTS:")
            current_framework = None
            for result in report["compliance_test_results"]:
                if result["framework"] != current_framework:
                    current_framework = result["framework"]
                    print(f"  {current_framework.upper()} Framework:")
                
                status = "✓ COMPLIANT" if result["test_passed"] else "✗ NON-COMPLIANT"
                print(f"    {status} {result['requirement_id']}: {result['requirement_name']}")
                print(f"      Risk Rating: {result['risk_rating'].upper()}")
                
                if result["gaps_identified"]:
                    print(f"      Gaps: {', '.join(result['gaps_identified'])}")
                print()
        
        # Recommendations
        print("SECURITY RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"  • {rec}")
        print()
        
        # Final Status
        overall_status = summary["overall_security_status"]
        critical_findings = metrics.get("critical_findings", 0)
        failed_tests = summary["failed_security_tests"]
        
        if overall_status == "SECURE" and critical_findings == 0 and failed_tests == 0:
            print("🟢 SECURITY COMPLIANCE VALIDATION: PASSED")
            print("   System meets security requirements and compliance standards.")
            print("   All security controls validated successfully.")
        else:
            print("🔴 SECURITY COMPLIANCE VALIDATION: FAILED")
            print("   System has security issues that must be addressed.")
            print("   Review findings and implement recommended remediation.")
        
        print("=" * 80)
        
        # Save summary report
        summary_file = reports_dir / f"security_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(summary_file, "w") as f:
            f.write("AI Honeypot System - Security Compliance Validation Summary\n")
            f.write("=" * 65 + "\n\n")
            f.write(f"Validation Date: {datetime.utcnow().isoformat()}\n")
            f.write(f"Overall Security Status: {overall_status}\n")
            f.write(f"Security Success Rate: {summary['success_rate_percent']:.1f}%\n")
            f.write(f"Compliance Score: {compliance['compliance_score']:.1f}%\n")
            f.write(f"Critical Findings: {critical_findings}\n")
            f.write(f"Failed Tests: {failed_tests}\n\n")
            
            f.write("Security Test Summary:\n")
            f.write(f"- Total Tests: {summary['total_security_tests']}\n")
            f.write(f"- Passed: {summary['passed_security_tests']}\n")
            f.write(f"- Failed: {failed_tests}\n\n")
            
            f.write("Findings Summary:\n")
            for severity, count in severity_breakdown.items():
                if count > 0:
                    f.write(f"- {severity.title()}: {count}\n")
            f.write("\n")
            
            f.write("Compliance Summary:\n")
            f.write(f"- Frameworks Tested: {compliance['frameworks_tested']}\n")
            f.write(f"- Compliant Requirements: {compliance['compliant_requirements']}\n")
            f.write(f"- Non-Compliant Requirements: {compliance['non_compliant_requirements']}\n\n")
            
            f.write("Key Recommendations:\n")
            for rec in report["recommendations"][:5]:  # Top 5 recommendations
                f.write(f"- {rec}\n")
        
        print(f"Summary report saved to: {summary_file}")
        
        # Return appropriate exit code
        return 0 if overall_status == "SECURE" and critical_findings == 0 else 1
        
    except Exception as e:
        logger.error(f"Security compliance validation failed: {e}")
        print(f"\n🔴 VALIDATION ERROR: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)