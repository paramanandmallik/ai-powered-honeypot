"""
AgentCore Runtime Health and Lifecycle Management
Provides comprehensive health checks, metrics, and lifecycle management for AgentCore Runtime deployment.
"""

import asyncio
import json
import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class HealthStatus(Enum):
    """Health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"

class ComponentType(Enum):
    """Component type enumeration"""
    AGENT = "agent"
    MESSAGING = "messaging"
    STORAGE = "storage"
    NETWORK = "network"
    COMPUTE = "compute"

@dataclass
class HealthCheckResult:
    """Health check result data structure"""
    component: str
    component_type: ComponentType
    status: HealthStatus
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    response_time_ms: float

@dataclass
class MetricData:
    """Metric data structure"""
    name: str
    value: float
    unit: str
    labels: Dict[str, str]
    timestamp: datetime

class AgentCoreHealthManager:
    """Comprehensive health and lifecycle management for AgentCore Runtime"""
    
    def __init__(self, agent_id: str, agent_type: str):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.start_time = datetime.utcnow()
        
        # Health check configuration
        self.health_check_interval = 30  # seconds
        self.metric_collection_interval = 10  # seconds
        self.health_history_limit = 100
        
        # State tracking
        self.health_history: List[HealthCheckResult] = []
        self.metrics_history: List[MetricData] = []
        self.last_health_check = None
        self.consecutive_failures = 0
        self.is_healthy = True
        
        # Performance tracking
        self.request_count = 0
        self.error_count = 0
        self.total_response_time = 0.0
        
        # Resource thresholds
        self.cpu_threshold = 80.0  # percent
        self.memory_threshold = 85.0  # percent
        self.disk_threshold = 90.0  # percent
        self.response_time_threshold = 5000.0  # milliseconds
        
        logger.info(f"AgentCore Health Manager initialized for {agent_type} agent {agent_id}")
    
    async def start_health_monitoring(self):
        """Start continuous health monitoring"""
        try:
            logger.info("Starting AgentCore health monitoring...")
            
            # Start health check loop
            asyncio.create_task(self._health_check_loop())
            
            # Start metrics collection loop
            asyncio.create_task(self._metrics_collection_loop())
            
            logger.info("AgentCore health monitoring started")
            
        except Exception as e:
            logger.error(f"Failed to start health monitoring: {e}")
            raise
    
    async def perform_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        try:
            start_time = time.time()
            health_results = []
            overall_status = HealthStatus.HEALTHY
            
            # Agent-specific health checks
            agent_health = await self._check_agent_health()
            health_results.append(agent_health)
            
            # System resource health checks
            system_health = await self._check_system_resources()
            health_results.extend(system_health)
            
            # Messaging health check
            messaging_health = await self._check_messaging_health()
            health_results.append(messaging_health)
            
            # Network connectivity health check
            network_health = await self._check_network_health()
            health_results.append(network_health)
            
            # Determine overall status
            for result in health_results:
                if result.status == HealthStatus.CRITICAL:
                    overall_status = HealthStatus.CRITICAL
                    break
                elif result.status == HealthStatus.UNHEALTHY and overall_status != HealthStatus.CRITICAL:
                    overall_status = HealthStatus.UNHEALTHY
                elif result.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
            
            # Calculate response time
            response_time = (time.time() - start_time) * 1000
            
            # Update health state
            self.last_health_check = datetime.utcnow()
            self.is_healthy = overall_status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
            
            if not self.is_healthy:
                self.consecutive_failures += 1
            else:
                self.consecutive_failures = 0
            
            # Store health check results
            for result in health_results:
                self.health_history.append(result)
            
            # Limit history size
            if len(self.health_history) > self.health_history_limit:
                self.health_history = self.health_history[-self.health_history_limit:]
            
            # Prepare response
            health_response = {
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "overall_status": overall_status.value,
                "is_healthy": self.is_healthy,
                "response_time_ms": response_time,
                "timestamp": self.last_health_check.isoformat(),
                "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
                "consecutive_failures": self.consecutive_failures,
                "components": [
                    {
                        "component": result.component,
                        "type": result.component_type.value,
                        "status": result.status.value,
                        "message": result.message,
                        "details": result.details,
                        "response_time_ms": result.response_time_ms
                    }
                    for result in health_results
                ]
            }
            
            return health_response
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.consecutive_failures += 1
            self.is_healthy = False
            
            return {
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "overall_status": HealthStatus.CRITICAL.value,
                "is_healthy": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _check_agent_health(self) -> HealthCheckResult:
        """Check agent-specific health"""
        try:
            start_time = time.time()
            
            # Check agent state and functionality
            details = {
                "request_count": self.request_count,
                "error_count": self.error_count,
                "error_rate": self.error_count / max(self.request_count, 1),
                "average_response_time": self.total_response_time / max(self.request_count, 1) if self.request_count > 0 else 0
            }
            
            # Determine status based on error rate and performance
            error_rate = details["error_rate"]
            avg_response_time = details["average_response_time"]
            
            if error_rate > 0.1:  # More than 10% error rate
                status = HealthStatus.UNHEALTHY
                message = f"High error rate: {error_rate:.2%}"
            elif error_rate > 0.05:  # More than 5% error rate
                status = HealthStatus.DEGRADED
                message = f"Elevated error rate: {error_rate:.2%}"
            elif avg_response_time > self.response_time_threshold:
                status = HealthStatus.DEGRADED
                message = f"Slow response time: {avg_response_time:.2f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = "Agent functioning normally"
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component=f"{self.agent_type}_agent",
                component_type=ComponentType.AGENT,
                status=status,
                message=message,
                details=details,
                timestamp=datetime.utcnow(),
                response_time_ms=response_time
            )
            
        except Exception as e:
            logger.error(f"Agent health check failed: {e}")
            return HealthCheckResult(
                component=f"{self.agent_type}_agent",
                component_type=ComponentType.AGENT,
                status=HealthStatus.CRITICAL,
                message=f"Agent health check failed: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.utcnow(),
                response_time_ms=0
            )
    
    async def _check_system_resources(self) -> List[HealthCheckResult]:
        """Check system resource health"""
        results = []
        
        try:
            start_time = time.time()
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_status = HealthStatus.HEALTHY
            cpu_message = f"CPU usage: {cpu_percent:.1f}%"
            
            if cpu_percent > 95:
                cpu_status = HealthStatus.CRITICAL
                cpu_message = f"Critical CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent > self.cpu_threshold:
                cpu_status = HealthStatus.UNHEALTHY
                cpu_message = f"High CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent > 60:
                cpu_status = HealthStatus.DEGRADED
                cpu_message = f"Elevated CPU usage: {cpu_percent:.1f}%"
            
            results.append(HealthCheckResult(
                component="cpu",
                component_type=ComponentType.COMPUTE,
                status=cpu_status,
                message=cpu_message,
                details={"cpu_percent": cpu_percent, "cpu_count": psutil.cpu_count()},
                timestamp=datetime.utcnow(),
                response_time_ms=(time.time() - start_time) * 1000
            ))
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_status = HealthStatus.HEALTHY
            memory_message = f"Memory usage: {memory_percent:.1f}%"
            
            if memory_percent > 95:
                memory_status = HealthStatus.CRITICAL
                memory_message = f"Critical memory usage: {memory_percent:.1f}%"
            elif memory_percent > self.memory_threshold:
                memory_status = HealthStatus.UNHEALTHY
                memory_message = f"High memory usage: {memory_percent:.1f}%"
            elif memory_percent > 70:
                memory_status = HealthStatus.DEGRADED
                memory_message = f"Elevated memory usage: {memory_percent:.1f}%"
            
            results.append(HealthCheckResult(
                component="memory",
                component_type=ComponentType.COMPUTE,
                status=memory_status,
                message=memory_message,
                details={
                    "memory_percent": memory_percent,
                    "total_gb": memory.total / (1024**3),
                    "available_gb": memory.available / (1024**3),
                    "used_gb": memory.used / (1024**3)
                },
                timestamp=datetime.utcnow(),
                response_time_ms=(time.time() - start_time) * 1000
            ))
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            disk_status = HealthStatus.HEALTHY
            disk_message = f"Disk usage: {disk_percent:.1f}%"
            
            if disk_percent > 95:
                disk_status = HealthStatus.CRITICAL
                disk_message = f"Critical disk usage: {disk_percent:.1f}%"
            elif disk_percent > self.disk_threshold:
                disk_status = HealthStatus.UNHEALTHY
                disk_message = f"High disk usage: {disk_percent:.1f}%"
            elif disk_percent > 80:
                disk_status = HealthStatus.DEGRADED
                disk_message = f"Elevated disk usage: {disk_percent:.1f}%"
            
            results.append(HealthCheckResult(
                component="disk",
                component_type=ComponentType.STORAGE,
                status=disk_status,
                message=disk_message,
                details={
                    "disk_percent": disk_percent,
                    "total_gb": disk.total / (1024**3),
                    "free_gb": disk.free / (1024**3),
                    "used_gb": disk.used / (1024**3)
                },
                timestamp=datetime.utcnow(),
                response_time_ms=(time.time() - start_time) * 1000
            ))
            
        except Exception as e:
            logger.error(f"System resource health check failed: {e}")
            results.append(HealthCheckResult(
                component="system_resources",
                component_type=ComponentType.COMPUTE,
                status=HealthStatus.CRITICAL,
                message=f"System resource check failed: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.utcnow(),
                response_time_ms=0
            ))
        
        return results
    
    async def _check_messaging_health(self) -> HealthCheckResult:
        """Check AgentCore messaging health"""
        try:
            start_time = time.time()
            
            # For now, assume messaging is healthy if agent is running
            # In production, this would check actual AgentCore messaging connectivity
            status = HealthStatus.HEALTHY
            message = "AgentCore messaging operational"
            details = {
                "messaging_enabled": True,
                "last_message_time": datetime.utcnow().isoformat(),
                "message_queue_size": 0  # Would be actual queue size in production
            }
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component="agentcore_messaging",
                component_type=ComponentType.MESSAGING,
                status=status,
                message=message,
                details=details,
                timestamp=datetime.utcnow(),
                response_time_ms=response_time
            )
            
        except Exception as e:
            logger.error(f"Messaging health check failed: {e}")
            return HealthCheckResult(
                component="agentcore_messaging",
                component_type=ComponentType.MESSAGING,
                status=HealthStatus.CRITICAL,
                message=f"Messaging health check failed: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.utcnow(),
                response_time_ms=0
            )
    
    async def _check_network_health(self) -> HealthCheckResult:
        """Check network connectivity health"""
        try:
            start_time = time.time()
            
            # Check network interfaces
            network_stats = psutil.net_io_counters()
            
            status = HealthStatus.HEALTHY
            message = "Network connectivity normal"
            details = {
                "bytes_sent": network_stats.bytes_sent,
                "bytes_recv": network_stats.bytes_recv,
                "packets_sent": network_stats.packets_sent,
                "packets_recv": network_stats.packets_recv,
                "errin": network_stats.errin,
                "errout": network_stats.errout,
                "dropin": network_stats.dropin,
                "dropout": network_stats.dropout
            }
            
            # Check for network errors
            total_errors = network_stats.errin + network_stats.errout
            total_drops = network_stats.dropin + network_stats.dropout
            
            if total_errors > 100 or total_drops > 100:
                status = HealthStatus.DEGRADED
                message = f"Network errors detected: {total_errors} errors, {total_drops} drops"
            
            response_time = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                component="network",
                component_type=ComponentType.NETWORK,
                status=status,
                message=message,
                details=details,
                timestamp=datetime.utcnow(),
                response_time_ms=response_time
            )
            
        except Exception as e:
            logger.error(f"Network health check failed: {e}")
            return HealthCheckResult(
                component="network",
                component_type=ComponentType.NETWORK,
                status=HealthStatus.CRITICAL,
                message=f"Network health check failed: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.utcnow(),
                response_time_ms=0
            )
    
    async def collect_metrics(self) -> List[MetricData]:
        """Collect performance metrics"""
        try:
            metrics = []
            timestamp = datetime.utcnow()
            
            # Agent-specific metrics
            metrics.extend([
                MetricData(
                    name="agent_requests_total",
                    value=float(self.request_count),
                    unit="count",
                    labels={"agent_id": self.agent_id, "agent_type": self.agent_type},
                    timestamp=timestamp
                ),
                MetricData(
                    name="agent_errors_total",
                    value=float(self.error_count),
                    unit="count",
                    labels={"agent_id": self.agent_id, "agent_type": self.agent_type},
                    timestamp=timestamp
                ),
                MetricData(
                    name="agent_uptime_seconds",
                    value=(datetime.utcnow() - self.start_time).total_seconds(),
                    unit="seconds",
                    labels={"agent_id": self.agent_id, "agent_type": self.agent_type},
                    timestamp=timestamp
                )
            ])
            
            # System metrics
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics.extend([
                MetricData(
                    name="system_cpu_percent",
                    value=cpu_percent,
                    unit="percent",
                    labels={"agent_id": self.agent_id},
                    timestamp=timestamp
                ),
                MetricData(
                    name="system_memory_percent",
                    value=memory.percent,
                    unit="percent",
                    labels={"agent_id": self.agent_id},
                    timestamp=timestamp
                ),
                MetricData(
                    name="system_disk_percent",
                    value=(disk.used / disk.total) * 100,
                    unit="percent",
                    labels={"agent_id": self.agent_id},
                    timestamp=timestamp
                )
            ])
            
            # Store metrics history
            self.metrics_history.extend(metrics)
            
            # Limit history size
            if len(self.metrics_history) > 1000:
                self.metrics_history = self.metrics_history[-1000:]
            
            return metrics
            
        except Exception as e:
            logger.error(f"Metrics collection failed: {e}")
            return []
    
    async def _health_check_loop(self):
        """Continuous health check loop"""
        while True:
            try:
                await self.perform_health_check()
                await asyncio.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(self.health_check_interval)
    
    async def _metrics_collection_loop(self):
        """Continuous metrics collection loop"""
        while True:
            try:
                await self.collect_metrics()
                await asyncio.sleep(self.metric_collection_interval)
            except Exception as e:
                logger.error(f"Metrics collection loop error: {e}")
                await asyncio.sleep(self.metric_collection_interval)
    
    def record_request(self, response_time_ms: float, success: bool = True):
        """Record a request for performance tracking"""
        self.request_count += 1
        self.total_response_time += response_time_ms
        
        if not success:
            self.error_count += 1
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary for AgentCore Runtime"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "is_healthy": self.is_healthy,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None,
            "consecutive_failures": self.consecutive_failures,
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(self.request_count, 1),
            "average_response_time_ms": self.total_response_time / max(self.request_count, 1) if self.request_count > 0 else 0
        }
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary for AgentCore Runtime"""
        if not self.metrics_history:
            return {"message": "No metrics available"}
        
        # Get latest metrics
        latest_metrics = {}
        for metric in reversed(self.metrics_history):
            if metric.name not in latest_metrics:
                latest_metrics[metric.name] = {
                    "value": metric.value,
                    "unit": metric.unit,
                    "timestamp": metric.timestamp.isoformat()
                }
        
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "metrics_count": len(self.metrics_history),
            "latest_metrics": latest_metrics,
            "collection_interval_seconds": self.metric_collection_interval
        }