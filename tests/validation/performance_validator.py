"""
Performance Benchmarking and Optimization Tools
Validates system performance and provides optimization recommendations
"""

import asyncio
import json
import logging
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import aiohttp
import psutil

logger = logging.getLogger(__name__)

@dataclass
class PerformanceBenchmark:
    metric_name: str
    current_value: float
    target_value: float
    unit: str
    passed: bool
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PerformanceReport:
    benchmark_id: str
    start_time: datetime
    end_time: Optional[datetime]
    benchmarks: List[PerformanceBenchmark] = field(default_factory=list)
    overall_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)

class PerformanceValidator:
    """Validates system performance against benchmarks"""
    
    def __init__(self):
        self.benchmarks = self._create_benchmarks()
        
    def _create_benchmarks(self) -> Dict[str, Dict[str, Any]]:
        """Create performance benchmarks"""
        return {
            "response_time": {
                "target": 1000,  # ms
                "unit": "ms",
                "description": "Average API response time"
            },
            "throughput": {
                "target": 10,  # requests per second
                "unit": "rps",
                "description": "System throughput"
            },
            "cpu_usage": {
                "target": 70,  # percentage
                "unit": "%",
                "description": "CPU utilization under load"
            },
            "memory_usage": {
                "target": 80,  # percentage
                "unit": "%",
                "description": "Memory utilization"
            },
            "concurrent_sessions": {
                "target": 50,  # number of sessions
                "unit": "sessions",
                "description": "Concurrent session handling"
            }
        }
    
    async def run_performance_validation(self) -> PerformanceReport:
        """Run comprehensive performance validation"""
        report = PerformanceReport(
            benchmark_id=f"perf-{int(time.time())}",
            start_time=datetime.utcnow()
        )
        
        try:
            # Test response time
            response_time_result = await self._test_response_time()
            report.benchmarks.append(response_time_result)
            
            # Test throughput
            throughput_result = await self._test_throughput()
            report.benchmarks.append(throughput_result)
            
            # Test resource usage
            cpu_result = await self._test_cpu_usage()
            report.benchmarks.append(cpu_result)
            
            memory_result = await self._test_memory_usage()
            report.benchmarks.append(memory_result)
            
            # Test concurrent sessions
            concurrent_result = await self._test_concurrent_sessions()
            report.benchmarks.append(concurrent_result)
            
            # Calculate overall score
            passed_benchmarks = sum(1 for b in report.benchmarks if b.passed)
            total_benchmarks = len(report.benchmarks)
            report.overall_score = (passed_benchmarks / total_benchmarks) * 100 if total_benchmarks > 0 else 0
            
            # Generate recommendations
            report.recommendations = self._generate_recommendations(report.benchmarks)
            
        except Exception as e:
            logger.error(f"Performance validation failed: {e}")
        
        report.end_time = datetime.utcnow()
        return report
    
    async def _test_response_time(self) -> PerformanceBenchmark:
        """Test API response times"""
        try:
            response_times = []
            
            async with aiohttp.ClientSession() as session:
                for _ in range(10):
                    start_time = time.time()
                    async with session.get("http://localhost:8000/health", timeout=5) as response:
                        end_time = time.time()
                        response_time = (end_time - start_time) * 1000
                        response_times.append(response_time)
            
            avg_response_time = statistics.mean(response_times)
            target = self.benchmarks["response_time"]["target"]
            
            return PerformanceBenchmark(
                metric_name="response_time",
                current_value=avg_response_time,
                target_value=target,
                unit="ms",
                passed=avg_response_time <= target,
                details={
                    "samples": len(response_times),
                    "min": min(response_times),
                    "max": max(response_times),
                    "std_dev": statistics.stdev(response_times) if len(response_times) > 1 else 0
                }
            )
            
        except Exception as e:
            return PerformanceBenchmark(
                metric_name="response_time",
                current_value=float('inf'),
                target_value=self.benchmarks["response_time"]["target"],
                unit="ms",
                passed=False,
                details={"error": str(e)}
            )
    
    async def _test_throughput(self) -> PerformanceBenchmark:
        """Test system throughput"""
        try:
            start_time = time.time()
            successful_requests = 0
            total_requests = 50
            
            async with aiohttp.ClientSession() as session:
                tasks = []
                for _ in range(total_requests):
                    task = session.get("http://localhost:8000/health", timeout=10)
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if not isinstance(response, Exception):
                        if response.status == 200:
                            successful_requests += 1
                        response.close()
            
            end_time = time.time()
            duration = end_time - start_time
            throughput = successful_requests / duration
            target = self.benchmarks["throughput"]["target"]
            
            return PerformanceBenchmark(
                metric_name="throughput",
                current_value=throughput,
                target_value=target,
                unit="rps",
                passed=throughput >= target,
                details={
                    "successful_requests": successful_requests,
                    "total_requests": total_requests,
                    "duration": duration,
                    "success_rate": successful_requests / total_requests
                }
            )
            
        except Exception as e:
            return PerformanceBenchmark(
                metric_name="throughput",
                current_value=0,
                target_value=self.benchmarks["throughput"]["target"],
                unit="rps",
                passed=False,
                details={"error": str(e)}
            )
    
    async def _test_cpu_usage(self) -> PerformanceBenchmark:
        """Test CPU usage under load"""
        try:
            # Monitor CPU during load test
            cpu_readings = []
            
            # Start load test
            async with aiohttp.ClientSession() as session:
                tasks = []
                for _ in range(20):
                    task = session.get("http://localhost:8000/health")
                    tasks.append(task)
                
                # Monitor CPU while requests are running
                for _ in range(5):
                    cpu_percent = psutil.cpu_percent(interval=0.5)
                    cpu_readings.append(cpu_percent)
                
                # Wait for requests to complete
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                for response in responses:
                    if not isinstance(response, Exception):
                        response.close()
            
            avg_cpu = statistics.mean(cpu_readings) if cpu_readings else 0
            target = self.benchmarks["cpu_usage"]["target"]
            
            return PerformanceBenchmark(
                metric_name="cpu_usage",
                current_value=avg_cpu,
                target_value=target,
                unit="%",
                passed=avg_cpu <= target,
                details={
                    "readings": cpu_readings,
                    "max_cpu": max(cpu_readings) if cpu_readings else 0,
                    "samples": len(cpu_readings)
                }
            )
            
        except Exception as e:
            return PerformanceBenchmark(
                metric_name="cpu_usage",
                current_value=100,
                target_value=self.benchmarks["cpu_usage"]["target"],
                unit="%",
                passed=False,
                details={"error": str(e)}
            )
    
    async def _test_memory_usage(self) -> PerformanceBenchmark:
        """Test memory usage"""
        try:
            memory = psutil.virtual_memory()
            current_usage = memory.percent
            target = self.benchmarks["memory_usage"]["target"]
            
            return PerformanceBenchmark(
                metric_name="memory_usage",
                current_value=current_usage,
                target_value=target,
                unit="%",
                passed=current_usage <= target,
                details={
                    "total_memory_gb": memory.total / (1024**3),
                    "available_memory_gb": memory.available / (1024**3),
                    "used_memory_gb": memory.used / (1024**3)
                }
            )
            
        except Exception as e:
            return PerformanceBenchmark(
                metric_name="memory_usage",
                current_value=100,
                target_value=self.benchmarks["memory_usage"]["target"],
                unit="%",
                passed=False,
                details={"error": str(e)}
            )
    
    async def _test_concurrent_sessions(self) -> PerformanceBenchmark:
        """Test concurrent session handling"""
        try:
            # Simulate concurrent sessions
            concurrent_sessions = 25
            successful_sessions = 0
            
            async with aiohttp.ClientSession() as session:
                # Create multiple sessions
                session_tasks = []
                
                for i in range(concurrent_sessions):
                    session_data = {
                        "session_id": f"perf-test-session-{i}",
                        "honeypot_id": "perf-test-honeypot",
                        "attacker_ip": f"192.168.1.{100 + i}",
                        "metadata": {"performance_test": True}
                    }
                    
                    task = session.post(
                        "http://localhost:8000/sessions/create",
                        json=session_data,
                        timeout=10
                    )
                    session_tasks.append(task)
                
                # Execute all session creations
                responses = await asyncio.gather(*session_tasks, return_exceptions=True)
                
                for response in responses:
                    if not isinstance(response, Exception):
                        if response.status == 200:
                            successful_sessions += 1
                        response.close()
            
            target = self.benchmarks["concurrent_sessions"]["target"]
            
            return PerformanceBenchmark(
                metric_name="concurrent_sessions",
                current_value=successful_sessions,
                target_value=target,
                unit="sessions",
                passed=successful_sessions >= target,
                details={
                    "attempted_sessions": concurrent_sessions,
                    "successful_sessions": successful_sessions,
                    "success_rate": successful_sessions / concurrent_sessions
                }
            )
            
        except Exception as e:
            return PerformanceBenchmark(
                metric_name="concurrent_sessions",
                current_value=0,
                target_value=self.benchmarks["concurrent_sessions"]["target"],
                unit="sessions",
                passed=False,
                details={"error": str(e)}
            )
    
    def _generate_recommendations(self, benchmarks: List[PerformanceBenchmark]) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        for benchmark in benchmarks:
            if not benchmark.passed:
                if benchmark.metric_name == "response_time":
                    recommendations.extend([
                        "Optimize database queries and add indexing",
                        "Implement response caching",
                        "Consider using a CDN for static content",
                        "Review and optimize slow API endpoints"
                    ])
                elif benchmark.metric_name == "throughput":
                    recommendations.extend([
                        "Increase the number of worker processes",
                        "Implement connection pooling",
                        "Consider horizontal scaling",
                        "Optimize resource-intensive operations"
                    ])
                elif benchmark.metric_name == "cpu_usage":
                    recommendations.extend([
                        "Optimize CPU-intensive algorithms",
                        "Implement asynchronous processing",
                        "Consider CPU scaling or more powerful instances",
                        "Profile code to identify bottlenecks"
                    ])
                elif benchmark.metric_name == "memory_usage":
                    recommendations.extend([
                        "Implement memory caching strategies",
                        "Optimize data structures and algorithms",
                        "Consider memory scaling",
                        "Review for memory leaks"
                    ])
                elif benchmark.metric_name == "concurrent_sessions":
                    recommendations.extend([
                        "Implement session pooling",
                        "Optimize session management",
                        "Consider load balancing",
                        "Review session timeout settings"
                    ])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def export_report(self, report: PerformanceReport, filename: str = None) -> str:
        """Export performance report to JSON"""
        if not filename:
            filename = f"performance_report_{report.benchmark_id}.json"
        
        # Convert to serializable format
        report_data = {
            "benchmark_id": report.benchmark_id,
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat() if report.end_time else None,
            "overall_score": report.overall_score,
            "benchmarks": [
                {
                    "metric_name": b.metric_name,
                    "current_value": b.current_value,
                    "target_value": b.target_value,
                    "unit": b.unit,
                    "passed": b.passed,
                    "details": b.details
                }
                for b in report.benchmarks
            ],
            "recommendations": report.recommendations
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Exported performance report to {filename}")
        return filename

# Convenience function
async def run_performance_validation():
    """Run performance validation"""
    validator = PerformanceValidator()
    report = await validator.run_performance_validation()
    validator.export_report(report, "performance_validation_report.json")
    return report

if __name__ == "__main__":
    # Example usage
    async def main():
        validator = PerformanceValidator()
        report = await validator.run_performance_validation()
        
        print(f"Performance Score: {report.overall_score:.1f}%")
        print(f"Benchmarks passed: {sum(1 for b in report.benchmarks if b.passed)}/{len(report.benchmarks)}")
        
        if report.recommendations:
            print("\nRecommendations:")
            for rec in report.recommendations[:5]:  # Show top 5
                print(f"  - {rec}")
        
        validator.export_report(report)
    
    asyncio.run(main())