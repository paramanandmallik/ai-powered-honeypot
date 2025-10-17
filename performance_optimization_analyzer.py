#!/usr/bin/env python3
"""
Performance Optimization Analyzer
Analyzes system performance and provides optimization recommendations
Task 10.3 Implementation - Performance Benchmarking and Optimization Tools
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceProfile:
    component: str
    metric: str
    current_value: float
    baseline_value: Optional[float]
    target_value: float
    unit: str
    trend: str  # improving, degrading, stable
    bottleneck_score: float  # 0-100, higher = more critical bottleneck
    optimization_potential: float  # 0-100, higher = more optimization potential

@dataclass
class OptimizationRecommendation:
    priority: str  # high, medium, low
    category: str  # performance, resource, configuration
    title: str
    description: str
    expected_improvement: str
    implementation_effort: str  # low, medium, high
    steps: List[str] = field(default_factory=list)

@dataclass
class PerformanceAnalysisReport:
    analysis_id: str
    timestamp: datetime
    overall_performance_score: float
    profiles: List[PerformanceProfile] = field(default_factory=list)
    bottlenecks: List[str] = field(default_factory=list)
    recommendations: List[OptimizationRecommendation] = field(default_factory=list)
    system_metrics: Dict[str, Any] = field(default_factory=dict)

class PerformanceOptimizationAnalyzer:
    """Analyzes performance and provides optimization recommendations"""
    
    def __init__(self):
        self.baseline_metrics = {}
        self.performance_history = []
        
    async def analyze_performance(self, duration_seconds: int = 60) -> PerformanceAnalysisReport:
        """Run comprehensive performance analysis"""
        report = PerformanceAnalysisReport(
            analysis_id=f"perf-analysis-{int(time.time())}",
            timestamp=datetime.utcnow(),
            overall_performance_score=0.0
        )
        
        logger.info(f"Starting performance analysis (duration: {duration_seconds}s)")
        
        try:
            # Collect baseline metrics
            await self._collect_baseline_metrics()
            
            # Run performance profiling
            profiles = await self._run_performance_profiling(duration_seconds)
            report.profiles = profiles
            
            # Collect system metrics
            report.system_metrics = await self._collect_system_metrics()
            
            # Identify bottlenecks
            report.bottlenecks = self._identify_bottlenecks(profiles)
            
            # Generate optimization recommendations
            report.recommendations = self._generate_optimization_recommendations(profiles, report.system_metrics)
            
            # Calculate overall performance score
            report.overall_performance_score = self._calculate_performance_score(profiles)
            
            logger.info(f"Performance analysis completed (score: {report.overall_performance_score:.1f}%)")
            
        except Exception as e:
            logger.error(f"Performance analysis failed: {e}")
        
        return report
    
    async def _collect_baseline_metrics(self):
        """Collect baseline performance metrics"""
        try:
            # System baseline
            self.baseline_metrics['cpu'] = psutil.cpu_percent(interval=1)
            self.baseline_metrics['memory'] = psutil.virtual_memory().percent
            self.baseline_metrics['disk_io'] = psutil.disk_io_counters()
            self.baseline_metrics['network_io'] = psutil.net_io_counters()
            
            # Service baseline
            service_endpoints = [
                "http://localhost:8000/health",
                "http://localhost:8001/health",
                "http://localhost:8002/health"
            ]
            
            response_times = []
            async with aiohttp.ClientSession() as session:
                for endpoint in service_endpoints:
                    try:
                        start_time = time.time()
                        async with session.get(endpoint, timeout=5) as response:
                            end_time = time.time()
                            if response.status == 200:
                                response_times.append((end_time - start_time) * 1000)
                    except Exception:
                        pass
            
            if response_times:
                self.baseline_metrics['avg_response_time'] = statistics.mean(response_times)
            
            logger.debug("Baseline metrics collected")
            
        except Exception as e:
            logger.error(f"Failed to collect baseline metrics: {e}")
    
    async def _run_performance_profiling(self, duration_seconds: int) -> List[PerformanceProfile]:
        """Run detailed performance profiling"""
        profiles = []
        
        try:
            # Profile system resources
            profiles.extend(await self._profile_system_resources(duration_seconds))
            
            # Profile service performance
            profiles.extend(await self._profile_service_performance(duration_seconds))
            
            # Profile database performance
            profiles.extend(await self._profile_database_performance())
            
            # Profile network performance
            profiles.extend(await self._profile_network_performance())
            
        except Exception as e:
            logger.error(f"Performance profiling failed: {e}")
        
        return profiles
    
    async def _profile_system_resources(self, duration_seconds: int) -> List[PerformanceProfile]:
        """Profile system resource usage"""
        profiles = []
        
        try:
            # Collect metrics over time
            cpu_samples = []
            memory_samples = []
            disk_samples = []
            
            sample_interval = min(5, duration_seconds // 10)  # At least 10 samples
            samples = duration_seconds // sample_interval
            
            for _ in range(samples):
                cpu_samples.append(psutil.cpu_percent(interval=sample_interval))
                memory_samples.append(psutil.virtual_memory().percent)
                
                # Disk I/O rate
                disk_io = psutil.disk_io_counters()
                if hasattr(self, '_last_disk_io'):
                    disk_rate = (disk_io.read_bytes + disk_io.write_bytes - 
                               self._last_disk_io.read_bytes - self._last_disk_io.write_bytes) / sample_interval
                    disk_samples.append(disk_rate / (1024 * 1024))  # MB/s
                self._last_disk_io = disk_io
            
            # Create profiles
            if cpu_samples:
                avg_cpu = statistics.mean(cpu_samples)
                cpu_trend = self._calculate_trend(cpu_samples)
                profiles.append(PerformanceProfile(
                    component="system",
                    metric="cpu_usage",
                    current_value=avg_cpu,
                    baseline_value=self.baseline_metrics.get('cpu'),
                    target_value=70.0,  # Target < 70%
                    unit="%",
                    trend=cpu_trend,
                    bottleneck_score=min(100, max(0, (avg_cpu - 50) * 2)),  # Score increases above 50%
                    optimization_potential=max(0, avg_cpu - 30)  # Potential if > 30%
                ))
            
            if memory_samples:
                avg_memory = statistics.mean(memory_samples)
                memory_trend = self._calculate_trend(memory_samples)
                profiles.append(PerformanceProfile(
                    component="system",
                    metric="memory_usage",
                    current_value=avg_memory,
                    baseline_value=self.baseline_metrics.get('memory'),
                    target_value=80.0,  # Target < 80%
                    unit="%",
                    trend=memory_trend,
                    bottleneck_score=min(100, max(0, (avg_memory - 60) * 2.5)),
                    optimization_potential=max(0, avg_memory - 40)
                ))
            
            if disk_samples:
                avg_disk_io = statistics.mean(disk_samples)
                disk_trend = self._calculate_trend(disk_samples)
                profiles.append(PerformanceProfile(
                    component="system",
                    metric="disk_io_rate",
                    current_value=avg_disk_io,
                    baseline_value=None,
                    target_value=100.0,  # Target < 100 MB/s
                    unit="MB/s",
                    trend=disk_trend,
                    bottleneck_score=min(100, avg_disk_io / 2),  # Score based on I/O rate
                    optimization_potential=max(0, min(50, avg_disk_io / 4))
                ))
            
        except Exception as e:
            logger.error(f"System resource profiling failed: {e}")
        
        return profiles
    
    async def _profile_service_performance(self, duration_seconds: int) -> List[PerformanceProfile]:
        """Profile service performance"""
        profiles = []
        
        try:
            services = {
                "agentcore": "http://localhost:8000/health",
                "detection": "http://localhost:8001/health",
                "coordinator": "http://localhost:8002/health",
                "interaction": "http://localhost:8003/health",
                "intelligence": "http://localhost:8004/health"
            }
            
            for service_name, endpoint in services.items():
                response_times = []
                success_count = 0
                total_requests = 0
                
                # Test service performance
                test_duration = min(30, duration_seconds // 2)  # Max 30 seconds per service
                end_time = time.time() + test_duration
                
                async with aiohttp.ClientSession() as session:
                    while time.time() < end_time:
                        try:
                            start_time = time.time()
                            async with session.get(endpoint, timeout=5) as response:
                                end_time_req = time.time()
                                response_time = (end_time_req - start_time) * 1000
                                response_times.append(response_time)
                                
                                if response.status == 200:
                                    success_count += 1
                                total_requests += 1
                                
                        except Exception:
                            total_requests += 1
                        
                        await asyncio.sleep(1)  # 1 second between requests
                
                if response_times:
                    avg_response_time = statistics.mean(response_times)
                    success_rate = (success_count / total_requests * 100) if total_requests > 0 else 0
                    
                    # Response time profile
                    profiles.append(PerformanceProfile(
                        component=service_name,
                        metric="response_time",
                        current_value=avg_response_time,
                        baseline_value=self.baseline_metrics.get('avg_response_time'),
                        target_value=1000.0,  # Target < 1 second
                        unit="ms",
                        trend=self._calculate_trend(response_times),
                        bottleneck_score=min(100, max(0, (avg_response_time - 500) / 10)),
                        optimization_potential=max(0, min(80, (avg_response_time - 200) / 10))
                    ))
                    
                    # Success rate profile
                    profiles.append(PerformanceProfile(
                        component=service_name,
                        metric="success_rate",
                        current_value=success_rate,
                        baseline_value=None,
                        target_value=99.0,  # Target > 99%
                        unit="%",
                        trend="stable",
                        bottleneck_score=max(0, (100 - success_rate) * 2),
                        optimization_potential=max(0, 100 - success_rate)
                    ))
            
        except Exception as e:
            logger.error(f"Service performance profiling failed: {e}")
        
        return profiles
    
    async def _profile_database_performance(self) -> List[PerformanceProfile]:
        """Profile database performance"""
        profiles = []
        
        try:
            # Test Redis performance
            redis_response_times = []
            for _ in range(10):
                try:
                    import redis.asyncio as redis
                    start_time = time.time()
                    client = redis.from_url("redis://localhost:6379/0")
                    await client.ping()
                    await client.close()
                    end_time = time.time()
                    redis_response_times.append((end_time - start_time) * 1000)
                except Exception:
                    pass
                await asyncio.sleep(0.1)
            
            if redis_response_times:
                avg_redis_time = statistics.mean(redis_response_times)
                profiles.append(PerformanceProfile(
                    component="redis",
                    metric="response_time",
                    current_value=avg_redis_time,
                    baseline_value=None,
                    target_value=10.0,  # Target < 10ms
                    unit="ms",
                    trend=self._calculate_trend(redis_response_times),
                    bottleneck_score=min(100, max(0, (avg_redis_time - 5) * 5)),
                    optimization_potential=max(0, min(50, avg_redis_time - 2))
                ))
            
            # Test PostgreSQL performance
            postgres_response_times = []
            for _ in range(5):
                try:
                    import asyncpg
                    start_time = time.time()
                    conn = await asyncpg.connect(
                        "postgresql://honeypot:honeypot_dev_password@localhost:5432/honeypot_intelligence"
                    )
                    await conn.fetchval("SELECT 1")
                    await conn.close()
                    end_time = time.time()
                    postgres_response_times.append((end_time - start_time) * 1000)
                except Exception:
                    pass
                await asyncio.sleep(0.2)
            
            if postgres_response_times:
                avg_postgres_time = statistics.mean(postgres_response_times)
                profiles.append(PerformanceProfile(
                    component="postgres",
                    metric="response_time",
                    current_value=avg_postgres_time,
                    baseline_value=None,
                    target_value=50.0,  # Target < 50ms
                    unit="ms",
                    trend=self._calculate_trend(postgres_response_times),
                    bottleneck_score=min(100, max(0, (avg_postgres_time - 25) * 2)),
                    optimization_potential=max(0, min(60, avg_postgres_time - 10))
                ))
            
        except Exception as e:
            logger.error(f"Database performance profiling failed: {e}")
        
        return profiles
    
    async def _profile_network_performance(self) -> List[PerformanceProfile]:
        """Profile network performance"""
        profiles = []
        
        try:
            # Network I/O baseline
            net_io_start = psutil.net_io_counters()
            await asyncio.sleep(5)  # Sample for 5 seconds
            net_io_end = psutil.net_io_counters()
            
            # Calculate network throughput
            bytes_sent_rate = (net_io_end.bytes_sent - net_io_start.bytes_sent) / 5  # bytes/sec
            bytes_recv_rate = (net_io_end.bytes_recv - net_io_start.bytes_recv) / 5  # bytes/sec
            
            total_throughput = (bytes_sent_rate + bytes_recv_rate) / (1024 * 1024)  # MB/s
            
            profiles.append(PerformanceProfile(
                component="network",
                metric="throughput",
                current_value=total_throughput,
                baseline_value=None,
                target_value=100.0,  # Target < 100 MB/s for local dev
                unit="MB/s",
                trend="stable",
                bottleneck_score=min(100, total_throughput * 2),
                optimization_potential=max(0, min(30, total_throughput))
            ))
            
            # Network latency test (localhost)
            latency_times = []
            for _ in range(5):
                try:
                    start_time = time.time()
                    async with aiohttp.ClientSession() as session:
                        async with session.get("http://localhost:8000/health", timeout=2) as response:
                            end_time = time.time()
                            if response.status == 200:
                                latency_times.append((end_time - start_time) * 1000)
                except Exception:
                    pass
                await asyncio.sleep(0.5)
            
            if latency_times:
                avg_latency = statistics.mean(latency_times)
                profiles.append(PerformanceProfile(
                    component="network",
                    metric="latency",
                    current_value=avg_latency,
                    baseline_value=None,
                    target_value=50.0,  # Target < 50ms for localhost
                    unit="ms",
                    trend=self._calculate_trend(latency_times),
                    bottleneck_score=min(100, max(0, (avg_latency - 10) * 3)),
                    optimization_potential=max(0, min(40, avg_latency - 5))
                ))
            
        except Exception as e:
            logger.error(f"Network performance profiling failed: {e}")
        
        return profiles
    
    async def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        metrics = {}
        
        try:
            # CPU info
            metrics['cpu'] = {
                'count': psutil.cpu_count(),
                'usage_percent': psutil.cpu_percent(interval=1),
                'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
            
            # Memory info
            memory = psutil.virtual_memory()
            metrics['memory'] = {
                'total_gb': memory.total / (1024**3),
                'available_gb': memory.available / (1024**3),
                'usage_percent': memory.percent
            }
            
            # Disk info
            disk = psutil.disk_usage('/')
            metrics['disk'] = {
                'total_gb': disk.total / (1024**3),
                'free_gb': disk.free / (1024**3),
                'usage_percent': (disk.used / disk.total) * 100
            }
            
            # Process info
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if proc.info['cpu_percent'] > 1.0 or proc.info['memory_percent'] > 1.0:
                        processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            metrics['top_processes'] = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
        
        return metrics
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend from a series of values"""
        if len(values) < 3:
            return "stable"
        
        # Simple linear trend calculation
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = statistics.mean(values)
        
        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable"
        
        slope = numerator / denominator
        
        if slope > 0.1:
            return "degrading"
        elif slope < -0.1:
            return "improving"
        else:
            return "stable"
    
    def _identify_bottlenecks(self, profiles: List[PerformanceProfile]) -> List[str]:
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        # Sort by bottleneck score
        sorted_profiles = sorted(profiles, key=lambda p: p.bottleneck_score, reverse=True)
        
        for profile in sorted_profiles:
            if profile.bottleneck_score > 70:  # High bottleneck threshold
                bottlenecks.append(f"{profile.component}.{profile.metric}: {profile.current_value:.1f}{profile.unit} (score: {profile.bottleneck_score:.0f})")
        
        return bottlenecks[:5]  # Top 5 bottlenecks
    
    def _generate_optimization_recommendations(self, profiles: List[PerformanceProfile], system_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations"""
        recommendations = []
        
        # Analyze each profile for optimization opportunities
        for profile in profiles:
            if profile.optimization_potential > 20:  # Significant optimization potential
                recs = self._get_profile_recommendations(profile, system_metrics)
                recommendations.extend(recs)
        
        # System-wide recommendations
        recommendations.extend(self._get_system_recommendations(system_metrics))
        
        # Sort by priority and return top recommendations
        priority_order = {"high": 0, "medium": 1, "low": 2}
        recommendations.sort(key=lambda r: (priority_order.get(r.priority, 3), -len(r.steps)))
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _get_profile_recommendations(self, profile: PerformanceProfile, system_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Get recommendations for a specific performance profile"""
        recommendations = []
        
        if profile.component == "system" and profile.metric == "cpu_usage":
            if profile.current_value > 80:
                recommendations.append(OptimizationRecommendation(
                    priority="high",
                    category="resource",
                    title="Reduce CPU Usage",
                    description=f"CPU usage is at {profile.current_value:.1f}%, which may impact system performance",
                    expected_improvement="20-40% CPU reduction",
                    implementation_effort="medium",
                    steps=[
                        "Identify CPU-intensive processes using 'top' or 'htop'",
                        "Optimize or limit resource usage of high-CPU processes",
                        "Consider adding CPU cores or upgrading hardware",
                        "Implement process scheduling and priority management"
                    ]
                ))
        
        elif profile.component == "system" and profile.metric == "memory_usage":
            if profile.current_value > 85:
                recommendations.append(OptimizationRecommendation(
                    priority="high",
                    category="resource",
                    title="Optimize Memory Usage",
                    description=f"Memory usage is at {profile.current_value:.1f}%, approaching system limits",
                    expected_improvement="15-30% memory reduction",
                    implementation_effort="medium",
                    steps=[
                        "Identify memory-intensive processes",
                        "Implement memory caching strategies",
                        "Add swap space or increase RAM",
                        "Optimize data structures and algorithms"
                    ]
                ))
        
        elif profile.metric == "response_time" and profile.current_value > 1000:
            recommendations.append(OptimizationRecommendation(
                priority="medium",
                category="performance",
                title=f"Optimize {profile.component.title()} Response Time",
                description=f"Average response time is {profile.current_value:.0f}ms, exceeding target",
                expected_improvement="30-50% response time reduction",
                implementation_effort="medium",
                steps=[
                    "Profile application code for bottlenecks",
                    "Implement response caching",
                    "Optimize database queries",
                    "Consider load balancing or horizontal scaling"
                ]
            ))
        
        elif profile.component in ["redis", "postgres"] and profile.current_value > profile.target_value:
            recommendations.append(OptimizationRecommendation(
                priority="medium",
                category="configuration",
                title=f"Optimize {profile.component.title()} Performance",
                description=f"{profile.component.title()} response time is {profile.current_value:.1f}ms",
                expected_improvement="40-60% database performance improvement",
                implementation_effort="low",
                steps=[
                    f"Tune {profile.component} configuration parameters",
                    "Add database indexes for frequently queried data",
                    "Implement connection pooling",
                    "Consider database caching strategies"
                ]
            ))
        
        return recommendations
    
    def _get_system_recommendations(self, system_metrics: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Get system-wide optimization recommendations"""
        recommendations = []
        
        # Check for high-resource processes
        top_processes = system_metrics.get('top_processes', [])
        if top_processes:
            high_cpu_processes = [p for p in top_processes if p['cpu_percent'] > 10]
            if high_cpu_processes:
                recommendations.append(OptimizationRecommendation(
                    priority="medium",
                    category="resource",
                    title="Optimize High-CPU Processes",
                    description=f"Found {len(high_cpu_processes)} processes using significant CPU",
                    expected_improvement="10-25% overall CPU reduction",
                    implementation_effort="low",
                    steps=[
                        "Review high-CPU processes for optimization opportunities",
                        "Implement process monitoring and alerting",
                        "Consider process scheduling and resource limits",
                        "Optimize algorithms in resource-intensive applications"
                    ]
                ))
        
        # General system optimization
        recommendations.append(OptimizationRecommendation(
            priority="low",
            category="configuration",
            title="General System Optimization",
            description="Apply general system optimization techniques",
            expected_improvement="5-15% overall performance improvement",
            implementation_effort="low",
            steps=[
                "Enable system performance monitoring",
                "Configure log rotation and cleanup",
                "Optimize Docker container resource limits",
                "Implement automated performance alerting"
            ]
        ))
        
        return recommendations
    
    def _calculate_performance_score(self, profiles: List[PerformanceProfile]) -> float:
        """Calculate overall performance score"""
        if not profiles:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for profile in profiles:
            # Calculate individual score based on target achievement
            if profile.target_value > 0:
                if profile.metric in ["success_rate"]:
                    # Higher is better
                    score = min(100, (profile.current_value / profile.target_value) * 100)
                else:
                    # Lower is better
                    score = max(0, 100 - ((profile.current_value / profile.target_value) * 100))
            else:
                score = 50  # Neutral score if no target
            
            # Weight by component importance
            weight = 2.0 if profile.component == "system" else 1.0
            total_score += score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def export_analysis_report(self, report: PerformanceAnalysisReport, filename: str = None) -> str:
        """Export performance analysis report"""
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/performance/performance_analysis_{timestamp}.json"
        
        # Ensure directory exists
        import os
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        # Convert to serializable format
        report_data = {
            "analysis_id": report.analysis_id,
            "timestamp": report.timestamp.isoformat(),
            "overall_performance_score": report.overall_performance_score,
            "profiles": [
                {
                    "component": p.component,
                    "metric": p.metric,
                    "current_value": p.current_value,
                    "baseline_value": p.baseline_value,
                    "target_value": p.target_value,
                    "unit": p.unit,
                    "trend": p.trend,
                    "bottleneck_score": p.bottleneck_score,
                    "optimization_potential": p.optimization_potential
                }
                for p in report.profiles
            ],
            "bottlenecks": report.bottlenecks,
            "recommendations": [
                {
                    "priority": r.priority,
                    "category": r.category,
                    "title": r.title,
                    "description": r.description,
                    "expected_improvement": r.expected_improvement,
                    "implementation_effort": r.implementation_effort,
                    "steps": r.steps
                }
                for r in report.recommendations
            ],
            "system_metrics": report.system_metrics
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Performance analysis report exported to {filename}")
        return filename

async def run_performance_analysis():
    """Run performance analysis"""
    analyzer = PerformanceOptimizationAnalyzer()
    
    print("Starting performance optimization analysis...")
    report = await analyzer.analyze_performance(duration_seconds=60)
    
    print(f"\n{'='*80}")
    print(f"PERFORMANCE OPTIMIZATION ANALYSIS")
    print(f"{'='*80}")
    print(f"Analysis ID: {report.analysis_id}")
    print(f"Overall Performance Score: {report.overall_performance_score:.1f}%")
    print(f"Timestamp: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    if report.bottlenecks:
        print(f"\nBottlenecks Identified ({len(report.bottlenecks)}):")
        print(f"{'-'*80}")
        for i, bottleneck in enumerate(report.bottlenecks, 1):
            print(f"{i:2d}. {bottleneck}")
    
    if report.recommendations:
        print(f"\nOptimization Recommendations ({len(report.recommendations)}):")
        print(f"{'-'*80}")
        for i, rec in enumerate(report.recommendations, 1):
            priority_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(rec.priority, "⚪")
            print(f"{i:2d}. {priority_emoji} [{rec.priority.upper()}] {rec.title}")
            print(f"    {rec.description}")
            print(f"    Expected: {rec.expected_improvement} | Effort: {rec.implementation_effort}")
            if rec.steps:
                print(f"    Steps: {len(rec.steps)} implementation steps")
            print()
    
    # Export report
    report_file = analyzer.export_analysis_report(report)
    print(f"Detailed analysis report saved to: {report_file}")
    print(f"{'='*80}")
    
    return report.overall_performance_score >= 70

if __name__ == "__main__":
    success = asyncio.run(run_performance_analysis())
    sys.exit(0 if success else 1)