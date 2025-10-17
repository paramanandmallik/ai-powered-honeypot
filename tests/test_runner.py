"""
Comprehensive test runner for AI Honeypot AgentCore Runtime system
"""

import pytest
import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestRunner:
    """Comprehensive test runner with categorized test execution"""
    
    def __init__(self):
        self.test_categories = {
            "unit": {
                "description": "Unit tests for individual components",
                "path": "tests/unit/",
                "markers": ["unit"],
                "timeout": 300
            },
            "integration": {
                "description": "Integration tests for component interactions",
                "path": "tests/integration/",
                "markers": ["integration"],
                "timeout": 600
            },
            "security": {
                "description": "Security and penetration tests",
                "path": "tests/security/",
                "markers": ["security"],
                "timeout": 900
            },
            "performance": {
                "description": "Performance and load tests",
                "path": "tests/integration/",
                "markers": ["performance", "slow"],
                "timeout": 1800
            },
            "e2e": {
                "description": "End-to-end workflow tests",
                "path": "tests/integration/",
                "markers": ["e2e"],
                "timeout": 1200
            }
        }
    
    def run_category(self, category: str, verbose: bool = False, coverage: bool = True):
        """Run tests for a specific category"""
        if category not in self.test_categories:
            print(f"Unknown test category: {category}")
            return False
        
        config = self.test_categories[category]
        
        # Build pytest arguments
        args = [
            config["path"],
            f"--timeout={config['timeout']}",
            "--tb=short"
        ]
        
        # Add markers
        if config["markers"]:
            marker_expr = " or ".join(config["markers"])
            args.extend(["-m", marker_expr])
        
        # Add verbosity
        if verbose:
            args.append("-v")
        
        # Add coverage
        if coverage:
            args.extend([
                "--cov=agents",
                "--cov=honeypots", 
                "--cov=security",
                "--cov=management",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                f"--cov-report=xml:coverage_{category}.xml"
            ])
        
        print(f"\n{'='*60}")
        print(f"Running {category.upper()} tests")
        print(f"Description: {config['description']}")
        print(f"Path: {config['path']}")
        print(f"Timeout: {config['timeout']}s")
        print(f"{'='*60}\n")
        
        # Run tests
        exit_code = pytest.main(args)
        
        return exit_code == 0
    
    def run_all(self, verbose: bool = False, coverage: bool = True):
        """Run all test categories"""
        results = {}
        
        print(f"\n{'='*80}")
        print("AI HONEYPOT AGENTCORE RUNTIME - COMPREHENSIVE TEST SUITE")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")
        
        for category in self.test_categories.keys():
            start_time = datetime.now()
            success = self.run_category(category, verbose, coverage)
            end_time = datetime.now()
            
            results[category] = {
                "success": success,
                "duration": (end_time - start_time).total_seconds()
            }
        
        # Print summary
        self._print_summary(results)
        
        # Return overall success
        return all(result["success"] for result in results.values())
    
    def run_quick(self):
        """Run quick test suite (unit tests only)"""
        print("\n" + "="*60)
        print("QUICK TEST SUITE - UNIT TESTS ONLY")
        print("="*60)
        
        return self.run_category("unit", verbose=True, coverage=False)
    
    def run_security_suite(self):
        """Run comprehensive security test suite"""
        print("\n" + "="*60)
        print("SECURITY TEST SUITE")
        print("="*60)
        
        return self.run_category("security", verbose=True, coverage=True)
    
    def run_performance_suite(self):
        """Run performance test suite"""
        print("\n" + "="*60)
        print("PERFORMANCE TEST SUITE")
        print("="*60)
        
        return self.run_category("performance", verbose=True, coverage=False)
    
    def _print_summary(self, results):
        """Print test execution summary"""
        print(f"\n{'='*80}")
        print("TEST EXECUTION SUMMARY")
        print(f"{'='*80}")
        
        total_duration = sum(result["duration"] for result in results.values())
        successful_categories = sum(1 for result in results.values() if result["success"])
        
        for category, result in results.items():
            status = "✅ PASSED" if result["success"] else "❌ FAILED"
            duration = f"{result['duration']:.1f}s"
            print(f"{category.upper():15} {status:10} ({duration:>8})")
        
        print(f"{'-'*80}")
        print(f"{'TOTAL':15} {successful_categories}/{len(results)} categories passed")
        print(f"{'DURATION':15} {total_duration:.1f}s")
        
        if successful_categories == len(results):
            print(f"\n🎉 ALL TESTS PASSED! System is ready for deployment.")
        else:
            failed_categories = [cat for cat, result in results.items() if not result["success"]]
            print(f"\n⚠️  FAILED CATEGORIES: {', '.join(failed_categories)}")
            print("Please review test failures before deployment.")
        
        print(f"{'='*80}\n")


def main():
    """Main test runner entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI Honeypot AgentCore Runtime Test Runner")
    parser.add_argument(
        "category",
        nargs="?",
        choices=["unit", "integration", "security", "performance", "e2e", "all", "quick"],
        default="all",
        help="Test category to run"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-coverage", action="store_true", help="Disable coverage reporting")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    # Set environment variables for testing
    os.environ["USE_MOCK_AI"] = "true"
    os.environ["DEVELOPMENT_MODE"] = "true"
    os.environ["MOCK_AGENTCORE"] = "true"
    os.environ["LOG_LEVEL"] = "DEBUG"
    
    coverage = not args.no_coverage
    
    if args.category == "all":
        success = runner.run_all(args.verbose, coverage)
    elif args.category == "quick":
        success = runner.run_quick()
    else:
        success = runner.run_category(args.category, args.verbose, coverage)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()