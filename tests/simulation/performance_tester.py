"""
Performance Testing and Load Simulation for AI Honeypot System
Tests system performance under various load conditions
"""

import asyncio
import logging
import random
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import psutil
import json

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    test_name: str
    start_time: datetime
    end_time: datetime
    total_requests: int
    successful_requests: int
    failed_requests: int
    response_times: List[float] = field(default_factory=list)
    error_rates: Dict[str, int] = field(default_factory=dict)
    throughput_rps: float = 0.0
    avg_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    system_metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class LoadTestConfig:
    name: str
    target_url: str
    concurrent_users: int
    duration_seconds: int
    ramp_up_seconds: int = 0
    request_rate_per_second: Optional[int] = None
    test_data: Dict[str, Any] = field(default_factory=dict)

class SystemMonitor:
    """Monitors system resources during performance tests"""
    
    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self.monitoring = False
        self.metrics = []
        
    async def start_monitoring(self):
        """Start system monitoring"""
        self.monitoring = True
        self.metrics = []
        
        while self.monitoring:
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=None)
                cpu_count = psutil.cpu_count()
                
                # Memory metrics
                memory = psutil.virtual_memory()
                
                # Disk metrics
                disk = psutil.disk_usage('/')
                
                # Network metrics
                network = psutil.net_io_counters()
                
                metric = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "cpu": {
                        "percent": cpu_percent,
                        "count": cpu_count,
                        "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                    },
                    "memory": {
                        "total": memory.total,
                        "available": memory.available,
                        "percent": memory.percent,
                        "used": memory.used
                    },
                    "disk": {
                        "total": disk.total,
                        "used": disk.used,
                        "free": disk.free,
                        "percent": (disk.used / disk.total) * 100
                    },
                    "network": {
                        "bytes_sent": network.bytes_sent,
                        "bytes_recv": network.bytes_recv,
                        "packets_sent": network.packets_sent,
                        "packets_recv": network.packets_recv
                    }
                }
                
                self.metrics.append(metric)
                await asyncio.sleep(self.interval)
                
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
                await asyncio.sleep(self.interval)
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
    
    def get_summary_metrics(self) -> Dict[str, Any]:
        """Get summary of collected metrics"""
        if not self.metrics:
            return {}
        
        # Calculate averages and peaks
        cpu_values = [m["cpu"]["percent"] for m in self.metrics]
        memory_values = [m["memory"]["percent"] for m in self.metrics]
        
        return {
            "duration_seconds": len(self.metrics) * self.interval,
            "cpu": {
                "avg_percent": statistics.mean(cpu_values),
                "max_percent": max(cpu_values),
                "min_percent": min(cpu_values)
            },
            "memory": {
                "avg_percent": statistics.mean(memory_values),
                "max_percent": max(memory_values),
                "min_percent": min(memory_values)
            },
            "samples_collected": len(self.metrics)
        }

class PerformanceTester:
    """Main performance testing class"""
    
    def __init__(self, base_urls: Dict[str, str] = None):
        self.base_urls = base_urls or {
            "agentcore": "http://localhost:8000",
            "detection_agent": "http://localhost:8001",
            "coordinator_agent": "http://localhost:8002",
            "interaction_agent": "http://localhost:8003",
            "intelligence_agent": "http://localhost:8004",
            "dashboard": "http://localhost:8090"
        }
        
        self.test_configs = self._create_test_configs()
        self.system_monitor = SystemMonitor()
        
    def _create_test_configs(self) -> Dict[str, LoadTestConfig]:
        """Create predefined test configurations"""
        return {
            "agent_health_check": LoadTestConfig(
                name="Agent Health Check Load Test",
                target_url="{base_url}/health",
                concurrent_users=50,
                duration_seconds=60,
                ramp_up_seconds=10
            ),
            
            "message_publishing": LoadTestConfig(
                name="Message Publishing Load Test",
                target_url="{base_url}/messages/publish",
                concurrent_users=20,
                duration_seconds=120,
                ramp_up_seconds=15,
                test_data={
                    "method": "POST",
                    "json": {
                        "exchange": "agent.events",
                        "routing_key": "test.event",
                        "message_data": {"test": "data", "timestamp": "now"},
                        "message_type": "event"
                    }
                }
            ),
            
            "agent_registration": LoadTestConfig(
                name="Agent Registration Load Test",
                target_url="{base_url}/agents/register",
                concurrent_users=10,
                duration_seconds=60,
                test_data={
                    "method": "POST",
                    "json": {
                        "agent_id": "test-agent-{id}",
                        "agent_type": "test",
                        "endpoint": "http://test-agent-{id}:8000",
                        "metadata": {"test": True}
                    }
                }
            ),
            
            "honeypot_interaction": LoadTestConfig(
                name="Honeypot Interaction Simulation",
                target_url="{base_url}/sessions/create",
                concurrent_users=30,
                duration_seconds=180,
                test_data={
                    "method": "POST",
                    "json": {
                        "session_id": "session-{id}",
                        "honeypot_id": "honeypot-ssh-1",
                        "attacker_ip": "192.168.1.{random_ip}",
                        "metadata": {"test_session": True}
                    }
                }
            ),
            
            "dashboard_metrics": LoadTestConfig(
                name="Dashboard Metrics Load Test",
                target_url="{base_url}/system/metrics",
                concurrent_users=25,
                duration_seconds=90,
                ramp_up_seconds=5
            ),
            
            "intelligence_reporting": LoadTestConfig(
                name="Intelligence Reporting Load Test",
                target_url="{base_url}/messages/publish",
                concurrent_users=15,
                duration_seconds=150,
                test_data={
                    "method": "POST",
                    "json": {
                        "exchange": "intelligence.reports",
                        "routing_key": "report.generated",
                        "message_data": {
                            "report_id": "report-{id}",
                            "session_id": "session-{id}",
                            "mitre_techniques": ["T1110", "T1078"],
                            "confidence_score": 0.85
                        },
                        "message_type": "report"
                    }
                }
            )
        }
    
    async def run_single_request(self, session: aiohttp.ClientSession,
                               config: LoadTestConfig, request_id: int) -> Dict[str, Any]:
        """Execute a single request and measure performance"""
        start_time = time.time()
        
        try:
            # Prepare request data
            url = config.target_url
            method = config.test_data.get("method", "GET")
            
            # Replace placeholders in URL and data
            if "{base_url}" in url:
                # Use agentcore as default base URL
                base_url = self.base_urls["agentcore"]
                url = url.format(base_url=base_url)
            
            # Prepare request parameters
            kwargs = {}
            
            if method == "POST" and "json" in config.test_data:
                json_data = config.test_data["json"].copy()
                
                # Replace placeholders in JSON data
                json_str = json.dumps(json_data)
                json_str = json_str.replace("{id}", str(request_id))
                json_str = json_str.replace("{random_ip}", str(random.randint(1, 254)))
                kwargs["json"] = json.loads(json_str)
            
            # Execute request
            async with session.request(method, url, **kwargs) as response:
                response_text = await response.text()
                end_time = time.time()
                
                return {
                    "success": True,
                    "status_code": response.status,
                    "response_time": end_time - start_time,
                    "response_size": len(response_text),
                    "error": None
                }
                
        except Exception as e:
            end_time = time.time()
            return {
                "success": False,
                "status_code": 0,
                "response_time": end_time - start_time,
                "response_size": 0,
                "error": str(e)
            }
    
    async def run_user_simulation(self, config: LoadTestConfig, user_id: int,
                                duration: float) -> List[Dict[str, Any]]:
        """Simulate a single user's requests"""
        results = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            
            start_time = time.time()
            request_count = 0
            
            while (time.time() - start_time) < duration:
                request_count += 1
                request_id = user_id * 10000 + request_count
                
                result = await self.run_single_request(session, config, request_id)
                result["user_id"] = user_id
                result["request_id"] = request_id
                result["timestamp"] = time.time()
                
                results.append(result)
                
                # Add realistic delay between requests
                if config.request_rate_per_second:
                    delay = 1.0 / config.request_rate_per_second
                    await asyncio.sleep(delay + random.uniform(-0.1, 0.1))
                else:
                    await asyncio.sleep(random.uniform(0.1, 1.0))
        
        return results
    
    async def run_load_test(self, config: LoadTestConfig) -> PerformanceMetrics:
        """Run a complete load test"""
        logger.info(f"Starting load test: {config.name}")
        
        # Start system monitoring
        monitor_task = asyncio.create_task(self.system_monitor.start_monitoring())
        
        # Initialize metrics
        metrics = PerformanceMetrics(
            test_name=config.name,
            start_time=datetime.utcnow(),
            end_time=None,
            total_requests=0,
            successful_requests=0,
            failed_requests=0
        )
        
        try:
            # Create user simulation tasks
            tasks = []
            
            # Implement ramp-up
            if config.ramp_up_seconds > 0:
                ramp_delay = config.ramp_up_seconds / config.concurrent_users
            else:
                ramp_delay = 0
            
            for user_id in range(config.concurrent_users):
                # Calculate when this user should start
                start_delay = user_id * ramp_delay
                
                task = asyncio.create_task(
                    self._delayed_user_simulation(
                        config, user_id, config.duration_seconds, start_delay
                    )
                )
                tasks.append(task)
            
            # Wait for all user simulations to complete
            all_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for user_results in all_results:
                if isinstance(user_results, Exception):
                    logger.error(f"User simulation failed: {user_results}")
                    continue
                
                for result in user_results:
                    metrics.total_requests += 1
                    
                    if result["success"]:
                        metrics.successful_requests += 1
                        metrics.response_times.append(result["response_time"])
                    else:
                        metrics.failed_requests += 1
                        error_type = result.get("error", "unknown")
                        metrics.error_rates[error_type] = metrics.error_rates.get(error_type, 0) + 1
            
            # Calculate performance statistics
            if metrics.response_times:
                metrics.avg_response_time = statistics.mean(metrics.response_times)
                metrics.p95_response_time = statistics.quantiles(
                    metrics.response_times, n=20
                )[18]  # 95th percentile
                metrics.p99_response_time = statistics.quantiles(
                    metrics.response_times, n=100
                )[98]  # 99th percentile
            
            # Calculate throughput
            test_duration = (datetime.utcnow() - metrics.start_time).total_seconds()
            metrics.throughput_rps = metrics.successful_requests / test_duration if test_duration > 0 else 0
            
        finally:
            # Stop system monitoring
            self.system_monitor.stop_monitoring()
            await monitor_task
            
            metrics.end_time = datetime.utcnow()
            metrics.system_metrics = self.system_monitor.get_summary_metrics()
        
        logger.info(f"Load test completed: {config.name}")
        logger.info(f"Total requests: {metrics.total_requests}")
        logger.info(f"Success rate: {(metrics.successful_requests / metrics.total_requests * 100):.2f}%")
        logger.info(f"Average response time: {metrics.avg_response_time:.3f}s")
        logger.info(f"Throughput: {metrics.throughput_rps:.2f} RPS")
        
        return metrics
    
    async def _delayed_user_simulation(self, config: LoadTestConfig, user_id: int,
                                     duration: float, delay: float) -> List[Dict[str, Any]]:
        """Run user simulation with initial delay for ramp-up"""
        if delay > 0:
            await asyncio.sleep(delay)
        
        return await self.run_user_simulation(config, user_id, duration)
    
    async def run_stress_test(self, target_service: str = "agentcore",
                            max_concurrent_users: int = 200,
                            step_size: int = 25,
                            step_duration: int = 60) -> List[PerformanceMetrics]:
        """Run a stress test with increasing load"""
        logger.info(f"Starting stress test for {target_service}")
        
        results = []
        current_users = step_size
        
        while current_users <= max_concurrent_users:
            logger.info(f"Testing with {current_users} concurrent users")
            
            # Create stress test configuration
            stress_config = LoadTestConfig(
                name=f"Stress Test - {current_users} Users",
                target_url=f"{self.base_urls[target_service]}/health",
                concurrent_users=current_users,
                duration_seconds=step_duration,
                ramp_up_seconds=10
            )
            
            # Run the test
            metrics = await self.run_load_test(stress_config)
            results.append(metrics)
            
            # Check if system is failing
            success_rate = (metrics.successful_requests / metrics.total_requests) * 100
            if success_rate < 95:  # Less than 95% success rate
                logger.warning(f"Success rate dropped to {success_rate:.2f}% at {current_users} users")
                
            if success_rate < 50:  # Less than 50% success rate
                logger.error(f"System failing at {current_users} users, stopping stress test")
                break
            
            current_users += step_size
            
            # Brief pause between test steps
            await asyncio.sleep(5)
        
        return results
    
    async def run_endurance_test(self, target_service: str = "agentcore",
                               concurrent_users: int = 50,
                               duration_hours: int = 2) -> PerformanceMetrics:
        """Run an endurance test for extended duration"""
        logger.info(f"Starting {duration_hours}h endurance test for {target_service}")
        
        endurance_config = LoadTestConfig(
            name=f"Endurance Test - {duration_hours}h",
            target_url=f"{self.base_urls[target_service]}/health",
            concurrent_users=concurrent_users,
            duration_seconds=duration_hours * 3600,
            ramp_up_seconds=60
        )
        
        return await self.run_load_test(endurance_config)
    
    async def run_spike_test(self, target_service: str = "agentcore",
                           normal_users: int = 20,
                           spike_users: int = 200,
                           spike_duration: int = 30) -> List[PerformanceMetrics]:
        """Run a spike test with sudden load increase"""
        logger.info(f"Starting spike test for {target_service}")
        
        results = []
        
        # Normal load phase
        normal_config = LoadTestConfig(
            name="Spike Test - Normal Load",
            target_url=f"{self.base_urls[target_service]}/health",
            concurrent_users=normal_users,
            duration_seconds=60,
            ramp_up_seconds=10
        )
        
        normal_metrics = await self.run_load_test(normal_config)
        results.append(normal_metrics)
        
        # Spike phase
        spike_config = LoadTestConfig(
            name="Spike Test - Spike Load",
            target_url=f"{self.base_urls[target_service]}/health",
            concurrent_users=spike_users,
            duration_seconds=spike_duration,
            ramp_up_seconds=5  # Quick ramp-up for spike
        )
        
        spike_metrics = await self.run_load_test(spike_config)
        results.append(spike_metrics)
        
        # Recovery phase
        recovery_config = LoadTestConfig(
            name="Spike Test - Recovery",
            target_url=f"{self.base_urls[target_service]}/health",
            concurrent_users=normal_users,
            duration_seconds=60,
            ramp_up_seconds=10
        )
        
        recovery_metrics = await self.run_load_test(recovery_config)
        results.append(recovery_metrics)
        
        return results
    
    def export_metrics(self, metrics: List[PerformanceMetrics],
                      filename: str = "performance_results.json") -> str:
        """Export performance metrics to JSON"""
        results_data = []
        
        for metric in metrics:
            metric_dict = {
                "test_name": metric.test_name,
                "start_time": metric.start_time.isoformat(),
                "end_time": metric.end_time.isoformat() if metric.end_time else None,
                "duration_seconds": (
                    (metric.end_time - metric.start_time).total_seconds()
                    if metric.end_time else 0
                ),
                "total_requests": metric.total_requests,
                "successful_requests": metric.successful_requests,
                "failed_requests": metric.failed_requests,
                "success_rate_percent": (
                    (metric.successful_requests / metric.total_requests * 100)
                    if metric.total_requests > 0 else 0
                ),
                "throughput_rps": metric.throughput_rps,
                "avg_response_time": metric.avg_response_time,
                "p95_response_time": metric.p95_response_time,
                "p99_response_time": metric.p99_response_time,
                "error_rates": metric.error_rates,
                "system_metrics": metric.system_metrics
            }
            results_data.append(metric_dict)
        
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        logger.info(f"Exported {len(metrics)} performance metrics to {filename}")
        return filename
    
    def generate_performance_report(self, metrics: List[PerformanceMetrics]) -> str:
        """Generate a human-readable performance report"""
        report = []
        report.append("AI Honeypot System Performance Test Report")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.utcnow().isoformat()}")
        report.append("")
        
        for metric in metrics:
            report.append(f"Test: {metric.test_name}")
            report.append("-" * 30)
            
            duration = (metric.end_time - metric.start_time).total_seconds() if metric.end_time else 0
            success_rate = (metric.successful_requests / metric.total_requests * 100) if metric.total_requests > 0 else 0
            
            report.append(f"Duration: {duration:.1f} seconds")
            report.append(f"Total Requests: {metric.total_requests}")
            report.append(f"Successful: {metric.successful_requests}")
            report.append(f"Failed: {metric.failed_requests}")
            report.append(f"Success Rate: {success_rate:.2f}%")
            report.append(f"Throughput: {metric.throughput_rps:.2f} RPS")
            report.append(f"Avg Response Time: {metric.avg_response_time:.3f}s")
            report.append(f"95th Percentile: {metric.p95_response_time:.3f}s")
            report.append(f"99th Percentile: {metric.p99_response_time:.3f}s")
            
            if metric.system_metrics:
                report.append("System Metrics:")
                if "cpu" in metric.system_metrics:
                    cpu = metric.system_metrics["cpu"]
                    report.append(f"  CPU Avg: {cpu.get('avg_percent', 0):.1f}%")
                    report.append(f"  CPU Max: {cpu.get('max_percent', 0):.1f}%")
                
                if "memory" in metric.system_metrics:
                    memory = metric.system_metrics["memory"]
                    report.append(f"  Memory Avg: {memory.get('avg_percent', 0):.1f}%")
                    report.append(f"  Memory Max: {memory.get('max_percent', 0):.1f}%")
            
            if metric.error_rates:
                report.append("Error Types:")
                for error_type, count in metric.error_rates.items():
                    report.append(f"  {error_type}: {count}")
            
            report.append("")
        
        return "\n".join(report)

# Convenience functions for testing
async def run_quick_performance_test():
    """Run a quick performance test of all services"""
    tester = PerformanceTester()
    
    # Test all predefined configurations
    results = []
    
    for config_name, config in tester.test_configs.items():
        logger.info(f"Running {config_name}")
        
        # Reduce duration for quick test
        config.duration_seconds = 30
        config.concurrent_users = min(config.concurrent_users, 10)
        
        try:
            metrics = await tester.run_load_test(config)
            results.append(metrics)
        except Exception as e:
            logger.error(f"Test {config_name} failed: {e}")
    
    # Export results
    tester.export_metrics(results, "quick_performance_test.json")
    
    # Generate report
    report = tester.generate_performance_report(results)
    with open("quick_performance_report.txt", "w") as f:
        f.write(report)
    
    return results

if __name__ == "__main__":
    # Example usage
    async def main():
        tester = PerformanceTester()
        
        # Run a single load test
        config = tester.test_configs["agent_health_check"]
        metrics = await tester.run_load_test(config)
        
        print(f"Test completed: {metrics.test_name}")
        print(f"Success rate: {(metrics.successful_requests / metrics.total_requests * 100):.2f}%")
        print(f"Throughput: {metrics.throughput_rps:.2f} RPS")
        
        # Run stress test
        stress_results = await tester.run_stress_test("agentcore", max_concurrent_users=100)
        
        # Export all results
        all_results = [metrics] + stress_results
        tester.export_metrics(all_results, "performance_test_results.json")
        
        # Generate report
        report = tester.generate_performance_report(all_results)
        print("\nPerformance Report:")
        print(report)
    
    asyncio.run(main())