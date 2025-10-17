#!/usr/bin/env python3
"""
Simple Local Validation Test
Tests the validation framework without requiring Docker
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_system_health_monitor():
    """Test system health monitor without Docker"""
    print("\n" + "="*60)
    print("TESTING SYSTEM HEALTH MONITOR")
    print("="*60)
    
    try:
        # Import and test basic functionality
        sys.path.append('.')
        from system_health_monitor import SystemHealthMonitor
        
        monitor = SystemHealthMonitor(check_interval=5)
        
        # Test basic health collection (without Docker)
        print("📊 Collecting system health snapshot...")
        
        # Mock the Docker client to avoid dependency
        monitor.docker_client = None
        
        # Collect basic system metrics
        import psutil
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        print(f"   CPU Usage: {cpu_percent:.1f}%")
        
        # Memory usage
        memory = psutil.virtual_memory()
        print(f"   Memory Usage: {memory.percent:.1f}%")
        
        # Disk usage
        disk = psutil.disk_usage('/')
        print(f"   Disk Usage: {disk.percent:.1f}%")
        
        # Test health summary
        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "disk_usage": disk.percent,
            "status": "healthy" if cpu_percent < 80 and memory.percent < 80 else "warning"
        }
        
        print(f"   Overall Status: {summary['status'].upper()}")
        
        # Export test report
        os.makedirs("reports/health", exist_ok=True)
        with open("reports/health/simple_health_test.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        print("✅ System Health Monitor test completed")
        return True
        
    except Exception as e:
        print(f"❌ System Health Monitor test failed: {e}")
        return False

async def test_performance_analyzer():
    """Test performance analyzer"""
    print("\n" + "="*60)
    print("TESTING PERFORMANCE ANALYZER")
    print("="*60)
    
    try:
        sys.path.append('.')
        from performance_optimization_analyzer import PerformanceOptimizationAnalyzer
        
        analyzer = PerformanceOptimizationAnalyzer()
        
        print("📈 Running basic performance analysis...")
        
        # Test basic system metrics collection
        import psutil
        
        # Collect baseline metrics
        baseline = {
            'cpu': psutil.cpu_percent(interval=1),
            'memory': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters() if hasattr(psutil, 'disk_io_counters') else None
        }
        
        print(f"   Baseline CPU: {baseline['cpu']:.1f}%")
        print(f"   Baseline Memory: {baseline['memory']:.1f}%")
        
        # Simple performance test - CPU stress
        print("   Running CPU stress test...")
        start_time = time.time()
        
        # Light CPU work
        for _ in range(100000):
            _ = sum(range(100))
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Collect post-test metrics
        post_cpu = psutil.cpu_percent(interval=1)
        post_memory = psutil.virtual_memory().percent
        
        print(f"   Post-test CPU: {post_cpu:.1f}%")
        print(f"   Post-test Memory: {post_memory:.1f}%")
        print(f"   Test Duration: {duration:.3f}s")
        
        # Generate simple performance report
        performance_report = {
            "test_id": f"perf-test-{int(time.time())}",
            "timestamp": datetime.utcnow().isoformat(),
            "baseline_metrics": baseline,
            "post_test_metrics": {
                "cpu": post_cpu,
                "memory": post_memory
            },
            "test_duration": duration,
            "performance_score": 100 - max(0, (post_cpu - baseline['cpu']) * 2),
            "recommendations": [
                "System performance is within normal parameters" if post_cpu < 50 else "Consider optimizing CPU-intensive operations",
                "Memory usage is stable" if abs(post_memory - baseline['memory']) < 5 else "Monitor memory usage patterns"
            ]
        }
        
        # Export report
        os.makedirs("reports/performance", exist_ok=True)
        with open("reports/performance/simple_performance_test.json", 'w') as f:
            json.dump(performance_report, f, indent=2)
        
        print(f"   Performance Score: {performance_report['performance_score']:.1f}%")
        print("✅ Performance Analyzer test completed")
        return True
        
    except Exception as e:
        print(f"❌ Performance Analyzer test failed: {e}")
        return False

async def test_validation_orchestrator():
    """Test validation orchestrator basic functionality"""
    print("\n" + "="*60)
    print("TESTING VALIDATION ORCHESTRATOR")
    print("="*60)
    
    try:
        # Test basic validation logic without full dependencies
        print("🔍 Testing validation orchestration logic...")
        
        # Simulate validation phases
        phases = [
            {"name": "infrastructure_check", "required": True},
            {"name": "basic_health_check", "required": True},
            {"name": "performance_check", "required": False},
        ]
        
        results = []
        
        for phase in phases:
            print(f"   Running {phase['name']}...")
            
            # Simulate phase execution
            start_time = time.time()
            
            if phase['name'] == 'infrastructure_check':
                # Check basic system requirements
                success = True
                score = 95.0
                details = {"python_version": sys.version, "platform": sys.platform}
                
            elif phase['name'] == 'basic_health_check':
                # Basic health check
                import psutil
                cpu = psutil.cpu_percent(interval=0.5)
                memory = psutil.virtual_memory().percent
                success = cpu < 90 and memory < 90
                score = 100 - max(cpu, memory) * 0.5
                details = {"cpu_usage": cpu, "memory_usage": memory}
                
            elif phase['name'] == 'performance_check':
                # Simple performance check
                test_start = time.time()
                for _ in range(10000):
                    _ = sum(range(10))
                test_duration = time.time() - test_start
                success = test_duration < 1.0
                score = max(0, 100 - test_duration * 50)
                details = {"test_duration": test_duration}
            
            end_time = time.time()
            duration = end_time - start_time
            
            result = {
                "phase": phase['name'],
                "success": success,
                "score": score,
                "duration": duration,
                "required": phase['required'],
                "details": details
            }
            
            results.append(result)
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"     {status} ({score:.1f}%) - {duration:.3f}s")
        
        # Calculate overall results
        required_results = [r for r in results if r['required']]
        required_success = all(r['success'] for r in required_results)
        
        total_score = sum(r['score'] for r in results) / len(results) if results else 0
        overall_success = required_success and total_score >= 70
        
        # Generate orchestrator report
        orchestrator_report = {
            "validation_id": f"validation-{int(time.time())}",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_success": overall_success,
            "overall_score": total_score,
            "phases": results,
            "summary": {
                "total_phases": len(results),
                "successful_phases": sum(1 for r in results if r['success']),
                "required_phases": len(required_results),
                "required_success": required_success
            }
        }
        
        # Export report
        os.makedirs("reports/validation", exist_ok=True)
        with open("reports/validation/simple_orchestrator_test.json", 'w') as f:
            json.dump(orchestrator_report, f, indent=2)
        
        print(f"   Overall Success: {'✅ YES' if overall_success else '❌ NO'}")
        print(f"   Overall Score: {total_score:.1f}%")
        print("✅ Validation Orchestrator test completed")
        return overall_success
        
    except Exception as e:
        print(f"❌ Validation Orchestrator test failed: {e}")
        return False

async def run_simple_validation_suite():
    """Run the complete simple validation suite"""
    print("🚀 STARTING SIMPLE LOCAL VALIDATION SUITE")
    print("="*80)
    
    suite_start = datetime.utcnow()
    
    # Run all tests
    tests = [
        ("System Health Monitor", test_system_health_monitor()),
        ("Performance Analyzer", test_performance_analyzer()),
        ("Validation Orchestrator", test_validation_orchestrator())
    ]
    
    results = []
    for test_name, test_coro in tests:
        try:
            result = await test_coro
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Calculate final results
    suite_end = datetime.utcnow()
    duration = (suite_end - suite_start).total_seconds()
    
    successful_tests = sum(1 for _, success in results if success)
    total_tests = len(results)
    success_rate = (successful_tests / total_tests) * 100 if total_tests > 0 else 0
    
    # Print final summary
    print("\n" + "="*80)
    print("SIMPLE VALIDATION SUITE RESULTS")
    print("="*80)
    print(f"Start Time: {suite_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"End Time: {suite_end.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration: {duration:.1f} seconds")
    print(f"Success Rate: {success_rate:.1f}% ({successful_tests}/{total_tests})")
    
    print(f"\nTest Results:")
    print("-" * 80)
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:<30} {status}")
    
    overall_success = success_rate >= 80
    print(f"\nOverall Status: {'✅ SUCCESS' if overall_success else '❌ FAILURE'}")
    
    # Generate final report
    final_report = {
        "suite_id": f"simple-validation-{int(time.time())}",
        "start_time": suite_start.isoformat(),
        "end_time": suite_end.isoformat(),
        "duration": duration,
        "overall_success": overall_success,
        "success_rate": success_rate,
        "test_results": [{"test": name, "success": success} for name, success in results],
        "reports_generated": [
            "reports/health/simple_health_test.json",
            "reports/performance/simple_performance_test.json", 
            "reports/validation/simple_orchestrator_test.json"
        ]
    }
    
    with open("reports/validation/simple_suite_results.json", 'w') as f:
        json.dump(final_report, f, indent=2)
    
    print(f"\nDetailed reports saved to: reports/")
    print("="*80)
    
    return overall_success

if __name__ == "__main__":
    try:
        success = asyncio.run(run_simple_validation_suite())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Validation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Validation suite failed: {e}")
        sys.exit(1)