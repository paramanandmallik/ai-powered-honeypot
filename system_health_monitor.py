#!/usr/bin/env python3
"""
System Health Monitor
Continuous monitoring of system health and performance
Task 10.3 Implementation - System Health Checks
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import aiohttp
import psutil
import docker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class HealthMetric:
    name: str
    value: float
    unit: str
    status: str  # healthy, warning, critical
    threshold_warning: float
    threshold_critical: float
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SystemHealthSnapshot:
    timestamp: datetime
    overall_status: str
    metrics: List[HealthMetric] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    containers: Dict[str, str] = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)

class SystemHealthMonitor:
    """Monitors system health continuously"""
    
    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self.docker_client = None
        self.health_history = []
        self.max_history = 100
        self.running = False
        
    async def initialize(self):
        """Initialize health monitor"""
        try:
            self.docker_client = docker.from_env()
            logger.info("System health monitor initialized")
        except Exception as e:
            logger.error(f"Failed to initialize health monitor: {e}")
            raise
    
    async def start_monitoring(self):
        """Start continuous health monitoring"""
        self.running = True
        logger.info(f"Starting continuous health monitoring (interval: {self.check_interval}s)")
        
        try:
            while self.running:
                snapshot = await self.collect_health_snapshot()
                self.health_history.append(snapshot)
                
                # Limit history size
                if len(self.health_history) > self.max_history:
                    self.health_history.pop(0)
                
                # Log health status
                self._log_health_status(snapshot)
                
                # Check for alerts
                if snapshot.alerts:
                    for alert in snapshot.alerts:
                        logger.warning(f"HEALTH ALERT: {alert}")
                
                # Wait for next check
                await asyncio.sleep(self.check_interval)
                
        except Exception as e:
            logger.error(f"Health monitoring failed: {e}")
        finally:
            self.running = False
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.running = False
        logger.info("Health monitoring stopped")
    
    async def collect_health_snapshot(self) -> SystemHealthSnapshot:
        """Collect current system health snapshot"""
        snapshot = SystemHealthSnapshot(timestamp=datetime.utcnow())
        
        try:
            # Collect system metrics
            snapshot.metrics.extend(await self._collect_system_metrics())
            
            # Check service health
            snapshot.services = await self._check_service_health()
            
            # Check container health
            snapshot.containers = await self._check_container_health()
            
            # Determine overall status and alerts
            snapshot.overall_status, snapshot.alerts = self._analyze_health(snapshot)
            
        except Exception as e:
            logger.error(f"Failed to collect health snapshot: {e}")
            snapshot.overall_status = "unknown"
            snapshot.alerts.append(f"Health collection failed: {str(e)}")
        
        return snapshot
    
    async def _collect_system_metrics(self) -> List[HealthMetric]:
        """Collect system performance metrics"""
        metrics = []
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics.append(HealthMetric(
                name="cpu_usage",
                value=cpu_percent,
                unit="%",
                status=self._get_metric_status(cpu_percent, 70, 90),
                threshold_warning=70,
                threshold_critical=90
            ))
            
            # Memory usage
            memory = psutil.virtual_memory()
            metrics.append(HealthMetric(
                name="memory_usage",
                value=memory.percent,
                unit="%",
                status=self._get_metric_status(memory.percent, 80, 95),
                threshold_warning=80,
                threshold_critical=95
            ))
            
            # Disk usage
            disk = psutil.disk_usage('/')
            metrics.append(HealthMetric(
                name="disk_usage",
                value=disk.percent,
                unit="%",
                status=self._get_metric_status(disk.percent, 85, 95),
                threshold_warning=85,
                threshold_critical=95
            ))
            
            # Load average (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()[0]  # 1-minute load average
                cpu_count = psutil.cpu_count()
                load_percent = (load_avg / cpu_count) * 100
                metrics.append(HealthMetric(
                    name="load_average",
                    value=load_percent,
                    unit="%",
                    status=self._get_metric_status(load_percent, 80, 100),
                    threshold_warning=80,
                    threshold_critical=100
                ))
            except AttributeError:
                # getloadavg not available on Windows
                pass
            
            # Network connections
            connections = len(psutil.net_connections())
            metrics.append(HealthMetric(
                name="network_connections",
                value=connections,
                unit="count",
                status=self._get_metric_status(connections, 1000, 2000),
                threshold_warning=1000,
                threshold_critical=2000
            ))
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
        
        return metrics
    
    async def _check_service_health(self) -> Dict[str, str]:
        """Check health of key services"""
        services = {}
        
        service_endpoints = {
            "AgentCore Runtime": "http://localhost:8000/health",
            "Detection Agent": "http://localhost:8001/health",
            "Coordinator Agent": "http://localhost:8002/health",
            "Interaction Agent": "http://localhost:8003/health",
            "Intelligence Agent": "http://localhost:8004/health",
            "Dashboard": "http://localhost:8090/health"
        }
        
        async with aiohttp.ClientSession() as session:
            for service_name, endpoint in service_endpoints.items():
                try:
                    async with session.get(endpoint, timeout=5) as response:
                        if response.status == 200:
                            services[service_name] = "healthy"
                        else:
                            services[service_name] = f"unhealthy (HTTP {response.status})"
                except asyncio.TimeoutError:
                    services[service_name] = "timeout"
                except Exception as e:
                    services[service_name] = f"error ({str(e)[:50]})"
        
        return services
    
    async def _check_container_health(self) -> Dict[str, str]:
        """Check health of Docker containers"""
        containers = {}
        
        try:
            for container in self.docker_client.containers.list():
                if "honeypot" in container.name:
                    health = container.attrs.get("State", {}).get("Health", {})
                    health_status = health.get("Status", "unknown")
                    
                    if container.status == "running":
                        if health_status == "healthy":
                            containers[container.name] = "healthy"
                        elif health_status == "unhealthy":
                            containers[container.name] = "unhealthy"
                        else:
                            containers[container.name] = "running"
                    else:
                        containers[container.name] = container.status
        except Exception as e:
            logger.error(f"Failed to check container health: {e}")
        
        return containers
    
    def _get_metric_status(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Determine metric status based on thresholds"""
        if value >= critical_threshold:
            return "critical"
        elif value >= warning_threshold:
            return "warning"
        else:
            return "healthy"
    
    def _analyze_health(self, snapshot: SystemHealthSnapshot) -> tuple[str, List[str]]:
        """Analyze overall health and generate alerts"""
        alerts = []
        
        # Check metrics for issues
        critical_metrics = [m for m in snapshot.metrics if m.status == "critical"]
        warning_metrics = [m for m in snapshot.metrics if m.status == "warning"]
        
        # Check services for issues
        unhealthy_services = [name for name, status in snapshot.services.items() if status != "healthy"]
        
        # Check containers for issues
        unhealthy_containers = [name for name, status in snapshot.containers.items() if status not in ["healthy", "running"]]
        
        # Generate alerts
        for metric in critical_metrics:
            alerts.append(f"Critical {metric.name}: {metric.value:.1f}{metric.unit} (threshold: {metric.threshold_critical}{metric.unit})")
        
        for metric in warning_metrics:
            alerts.append(f"Warning {metric.name}: {metric.value:.1f}{metric.unit} (threshold: {metric.threshold_warning}{metric.unit})")
        
        for service in unhealthy_services:
            alerts.append(f"Service unhealthy: {service} ({snapshot.services[service]})")
        
        for container in unhealthy_containers:
            alerts.append(f"Container unhealthy: {container} ({snapshot.containers[container]})")
        
        # Determine overall status
        if critical_metrics or len(unhealthy_services) > 2 or len(unhealthy_containers) > 2:
            overall_status = "critical"
        elif warning_metrics or unhealthy_services or unhealthy_containers:
            overall_status = "warning"
        else:
            overall_status = "healthy"
        
        return overall_status, alerts
    
    def _log_health_status(self, snapshot: SystemHealthSnapshot):
        """Log current health status"""
        status_emoji = {
            "healthy": "✅",
            "warning": "⚠️",
            "critical": "🚨",
            "unknown": "❓"
        }
        
        emoji = status_emoji.get(snapshot.overall_status, "❓")
        logger.info(f"{emoji} System Health: {snapshot.overall_status.upper()}")
        
        # Log key metrics
        for metric in snapshot.metrics:
            if metric.status != "healthy":
                logger.warning(f"  {metric.name}: {metric.value:.1f}{metric.unit} ({metric.status})")
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get current health summary"""
        if not self.health_history:
            return {"status": "no_data", "message": "No health data available"}
        
        latest = self.health_history[-1]
        
        return {
            "timestamp": latest.timestamp.isoformat(),
            "overall_status": latest.overall_status,
            "metrics": {
                metric.name: {
                    "value": metric.value,
                    "unit": metric.unit,
                    "status": metric.status
                }
                for metric in latest.metrics
            },
            "services": latest.services,
            "containers": latest.containers,
            "alerts": latest.alerts,
            "history_count": len(self.health_history)
        }
    
    def export_health_report(self, filename: str = None) -> str:
        """Export health report to JSON"""
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/health/system_health_{timestamp}.json"
        
        # Ensure directory exists
        import os
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        # Prepare report data
        report_data = {
            "report_id": f"health-{int(time.time())}",
            "generation_time": datetime.utcnow().isoformat(),
            "monitoring_duration": len(self.health_history) * self.check_interval,
            "current_status": self.get_health_summary(),
            "history": [
                {
                    "timestamp": snapshot.timestamp.isoformat(),
                    "overall_status": snapshot.overall_status,
                    "metrics": {
                        metric.name: {
                            "value": metric.value,
                            "unit": metric.unit,
                            "status": metric.status
                        }
                        for metric in snapshot.metrics
                    },
                    "alert_count": len(snapshot.alerts)
                }
                for snapshot in self.health_history[-20:]  # Last 20 snapshots
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Health report exported to {filename}")
        return filename

async def run_health_check():
    """Run a single health check"""
    monitor = SystemHealthMonitor()
    await monitor.initialize()
    
    snapshot = await monitor.collect_health_snapshot()
    
    print(f"\n{'='*60}")
    print(f"SYSTEM HEALTH CHECK")
    print(f"{'='*60}")
    print(f"Timestamp: {snapshot.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Overall Status: {snapshot.overall_status.upper()}")
    
    print(f"\nSystem Metrics:")
    print(f"{'-'*60}")
    for metric in snapshot.metrics:
        status_emoji = {"healthy": "✅", "warning": "⚠️", "critical": "🚨"}.get(metric.status, "❓")
        print(f"{metric.name:<20} {metric.value:>8.1f}{metric.unit:<3} {status_emoji} {metric.status}")
    
    print(f"\nServices:")
    print(f"{'-'*60}")
    for service, status in snapshot.services.items():
        status_emoji = "✅" if status == "healthy" else "❌"
        print(f"{service:<25} {status_emoji} {status}")
    
    print(f"\nContainers:")
    print(f"{'-'*60}")
    for container, status in snapshot.containers.items():
        status_emoji = "✅" if status in ["healthy", "running"] else "❌"
        print(f"{container:<25} {status_emoji} {status}")
    
    if snapshot.alerts:
        print(f"\nAlerts ({len(snapshot.alerts)}):")
        print(f"{'-'*60}")
        for i, alert in enumerate(snapshot.alerts, 1):
            print(f"{i:2d}. {alert}")
    
    print(f"{'='*60}")
    
    return snapshot.overall_status == "healthy"

async def run_continuous_monitoring(duration_minutes: int = 60):
    """Run continuous health monitoring"""
    monitor = SystemHealthMonitor(check_interval=30)
    await monitor.initialize()
    
    print(f"Starting continuous health monitoring for {duration_minutes} minutes...")
    
    # Start monitoring in background
    monitoring_task = asyncio.create_task(monitor.start_monitoring())
    
    try:
        # Wait for specified duration
        await asyncio.sleep(duration_minutes * 60)
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user")
    finally:
        monitor.stop_monitoring()
        monitoring_task.cancel()
        
        # Export final report
        report_file = monitor.export_health_report()
        print(f"Health monitoring report saved to: {report_file}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        asyncio.run(run_continuous_monitoring(duration))
    else:
        success = asyncio.run(run_health_check())
        sys.exit(0 if success else 1)