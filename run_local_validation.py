#!/usr/bin/env python3
"""
Local Validation Runner
Simplified interface for running local validation and verification
Task 10.3 Implementation
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from local_validation_orchestrator import LocalValidationOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def run_validation():
    """Run local validation with default settings"""
    try:
        logger.info("Starting local validation and verification")
        
        # Initialize orchestrator
        orchestrator = LocalValidationOrchestrator()
        await orchestrator.initialize()
        
        # Run comprehensive validation
        report = await orchestrator.run_comprehensive_validation(
            include_optional=True,
            fail_fast=False
        )
        
        # Print results
        print(f"\n{'='*80}")
        print(f"LOCAL VALIDATION RESULTS")
        print(f"{'='*80}")
        print(f"Validation ID: {report.validation_id}")
        print(f"Overall Status: {'✅ PASSED' if report.overall_success else '❌ FAILED'}")
        print(f"Overall Score: {report.overall_score:.1f}%")
        print(f"Duration: {(report.end_time - report.start_time).total_seconds():.1f} seconds")
        
        print(f"\nPhase Results:")
        print(f"{'-'*80}")
        for phase in report.phases:
            status = "✅ PASS" if phase.success else "❌ FAIL"
            print(f"{phase.phase.replace('_', ' ').title():<35} {status:>8} ({phase.score:>5.1f}%)")
        
        if report.critical_issues:
            print(f"\nCritical Issues ({len(report.critical_issues)}):")
            print(f"{'-'*80}")
            for i, issue in enumerate(report.critical_issues, 1):
                print(f"{i:2d}. {issue}")
        
        if report.recommendations:
            print(f"\nRecommendations ({len(report.recommendations)}):")
            print(f"{'-'*80}")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"{i:2d}. {rec}")
        
        print(f"\nDetailed reports saved to: reports/validation/")
        print(f"{'='*80}")
        
        return report.overall_success
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_validation())
    sys.exit(0 if success else 1)