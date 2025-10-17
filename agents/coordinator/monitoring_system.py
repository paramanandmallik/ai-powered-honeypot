"""
System Monitoring and Alerting for Coordinator Agent
Provides comprehensive monitoring, alerting, performance metrics, and audit logging.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Callable
from uuid import uuid4
from dataclasses import dataclass, asdict
import hashlib
import hmac

from prometheus_client import Counter, Histogram, Gauge, Summary, CollectorRegistry, generate_latest
from strands import tool


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status states"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class MetricType(Enum):
    """Metric types for monitoring"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class Alert:
    """Alert definition and tracking"""
    alert_id: str
    alert_type: str
    severity: AlertSeverity
    title: str
    description: str
    source_component: str
    source_instance: str
    triggered_at: str
    status: AlertStatus = AlertStatus.ACTIVE
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class PerformanceMetric:
    """Performance metric data point"""
    metric_id: str
    metric_name: str
    metric_type: MetricType
    value: float
    labels: Dict[str, str]
    timestamp: str
    source_component: str
    source_instance: str


@dataclass
class AuditLogEntry:
    """Audit log entry for compliance tracking"""
    log_id: str
    timestamp: str
    event_type: str
    component: str
    user_id: Optional[str]
    action: str
    resource: str
    result: str
    details: Dict[str, Any]
    signature: str
    
    def __post_init__(self):
        if not self.signature:
            self.signature = self._generate_signature()
    
    def _generate_signature(self) -> str:
        """Generate digital signature for log integrity"""
        # In production, use proper cryptographic signing
        data = f"{self.timestamp}{self.event_type}{self.action}{self.resource}{self.result}"
        return hashlib.sha256(data.encode()).hexdigest()


class SystemMonitoringSystem:
    """
    Comprehensive system monitoring and alerting system that provides
    real-time monitoring, performance metrics, alerting, and audit logging.
    """
    
    def __init__(self, coordinator_agent):
        self.coordinator_agent = coordinator_agent
        self.logger = logging.getLogger("monitoring_system")
        
        # State management
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.performance_metrics: Dict[str, List[PerformanceMetric]] = {}
        self.audit_log: List[AuditLogEntry] = []
        
        # Prometheus metrics registry
        self.metrics_registry = CollectorRegistry()
        self._setup_prometheus_metrics()
        
        # Alert rules and thresholds
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.notification_channels: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.metrics_retention_hours = 24
        self.alert_history_retention_days = 30
        self.audit_log_retention_days = 90
        self.health_check_interval = 30
        self.metrics_collection_interval = 10
        
        # Load configuration
        self._load_alert_rules()
        self._setup_notification_channels()
        
        self.logger.info("System Monitoring System initialized")
    
    async def start(self):
        """Start the monitoring system"""
        try:
            # Start monitoring tasks
            asyncio.create_task(self._system_health_monitor())
            asyncio.create_task(self._performance_metrics_collector())
            asyncio.create_task(self._alert_processor())
            asyncio.create_task(self._audit_log_processor())
            asyncio.create_task(self._cleanup_monitor())
            
            # Start metrics server
            await self._start_metrics_server()
            
            self.logger.info("System Monitoring System started")
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring system: {e}")
            raise
    
    async def stop(self):
        """Stop the monitoring system"""
        try:
            # Archive current data
            await self._archive_monitoring_data()
            
            self.logger.info("System Monitoring System stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring system: {e}")
    
    # System Health Monitoring
    async def monitor_system_health(self) -> Dict[str, Any]:
        """Monitor overall system health"""
        try:
            health_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": "healthy",
                "components": {},
                "alerts": {
                    "active_count": len([a for a in self.active_alerts.values() if a.status == AlertStatus.ACTIVE]),
                    "critical_count": len([a for a in self.active_alerts.values() 
                                         if a.severity == AlertSeverity.CRITICAL and a.status == AlertStatus.ACTIVE])
                },
                "performance": await self._get_system_performance_summary(),
                "resources": await self._get_resource_utilization()
            }
            
            # Check component health
            components = ["orchestration_engine", "honeypot_manager", "detection_agent", 
                         "interaction_agent", "intelligence_agent"]
            
            for component in components:
                component_health = await self._check_component_health(component)
                health_data["components"][component] = component_health
                
                # Update overall status based on component health
                if component_health["status"] == "critical":
                    health_data["overall_status"] = "critical"
                elif component_health["status"] == "degraded" and health_data["overall_status"] == "healthy":
                    health_data["overall_status"] = "degraded"
            
            # Record health metrics
            await self._record_health_metrics(health_data)
            
            return health_data
            
        except Exception as e:
            self.logger.error(f"Failed to monitor system health: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
    
    async def monitor_agent_health(self, agent_type: str) -> Dict[str, Any]:
        """Monitor health of a specific agent"""
        try:
            # Get agent health data
            health_response = await self.coordinator_agent.orchestration_engine.send_agent_message(
                agent_type, "health_check", {}
            )
            
            if not health_response:
                return {
                    "agent_type": agent_type,
                    "status": "unreachable",
                    "error": "No response from agent",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Process health data
            health_data = {
                "agent_type": agent_type,
                "status": health_response.get("health", "unknown"),
                "response_time_ms": health_response.get("response_time_ms", 0),
                "uptime_seconds": health_response.get("uptime_seconds", 0),
                "processed_messages": health_response.get("processed_messages", 0),
                "error_count": health_response.get("error_count", 0),
                "active_sessions": health_response.get("active_sessions", 0),
                "resource_usage": health_response.get("resource_usage", {}),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Check for health issues and generate alerts
            await self._check_agent_health_alerts(agent_type, health_data)
            
            # Record metrics
            await self._record_agent_metrics(agent_type, health_data)
            
            return health_data
            
        except Exception as e:
            self.logger.error(f"Failed to monitor agent health for {agent_type}: {e}")
            return {"error": str(e), "agent_type": agent_type}
    
    # Performance Metrics Collection
    async def collect_performance_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics"""
        try:
            metrics_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "system_metrics": await self._collect_system_metrics(),
                "honeypot_metrics": await self._collect_honeypot_metrics(),
                "agent_metrics": await self._collect_agent_metrics(),
                "workflow_metrics": await self._collect_workflow_metrics()
            }
            
            # Store metrics
            await self._store_performance_metrics(metrics_data)
            
            return metrics_data
            
        except Exception as e:
            self.logger.error(f"Failed to collect performance metrics: {e}")
            return {"error": str(e)}
    
    async def get_performance_summary(self, time_range_hours: int = 1) -> Dict[str, Any]:
        """Get performance summary for specified time range"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=time_range_hours)
            
            # Filter metrics by time range
            relevant_metrics = []
            for metric_list in self.performance_metrics.values():
                for metric in metric_list:
                    metric_time = datetime.fromisoformat(metric.timestamp)
                    if start_time <= metric_time <= end_time:
                        relevant_metrics.append(metric)
            
            # Calculate summary statistics
            summary = {
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "hours": time_range_hours
                },
                "metrics_count": len(relevant_metrics),
                "system_performance": await self._calculate_performance_summary(relevant_metrics),
                "trends": await self._calculate_performance_trends(relevant_metrics),
                "anomalies": await self._detect_performance_anomalies(relevant_metrics)
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to get performance summary: {e}")
            return {"error": str(e)}
    
    # Alerting System
    async def create_alert(self, alert_type: str, severity: AlertSeverity, 
                         title: str, description: str, source_component: str,
                         source_instance: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Create a new alert"""
        try:
            alert_id = str(uuid4())
            
            alert = Alert(
                alert_id=alert_id,
                alert_type=alert_type,
                severity=severity,
                title=title,
                description=description,
                source_component=source_component,
                source_instance=source_instance,
                triggered_at=datetime.utcnow().isoformat(),
                metadata=metadata or {}
            )
            
            self.active_alerts[alert_id] = alert
            
            # Send notifications
            await self._send_alert_notifications(alert)
            
            # Log alert creation
            await self._log_audit_event(
                "alert_created",
                "monitoring_system",
                None,
                "create_alert",
                alert_id,
                "success",
                {"alert_type": alert_type, "severity": severity.value}
            )
            
            self.logger.info(f"Created {severity.value} alert: {title}")
            return alert_id
            
        except Exception as e:
            self.logger.error(f"Failed to create alert: {e}")
            raise
    
    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an active alert"""
        try:
            if alert_id not in self.active_alerts:
                return False
            
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow().isoformat()
            alert.acknowledged_by = acknowledged_by
            
            # Log acknowledgment
            await self._log_audit_event(
                "alert_acknowledged",
                "monitoring_system",
                acknowledged_by,
                "acknowledge_alert",
                alert_id,
                "success",
                {"acknowledged_by": acknowledged_by}
            )
            
            self.logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
    
    async def resolve_alert(self, alert_id: str, resolved_by: str, 
                          resolution_notes: Optional[str] = None) -> bool:
        """Resolve an alert"""
        try:
            if alert_id not in self.active_alerts:
                return False
            
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow().isoformat()
            alert.resolved_by = resolved_by
            
            if resolution_notes:
                alert.metadata["resolution_notes"] = resolution_notes
            
            # Move to history
            self.alert_history.append(alert)
            del self.active_alerts[alert_id]
            
            # Log resolution
            await self._log_audit_event(
                "alert_resolved",
                "monitoring_system",
                resolved_by,
                "resolve_alert",
                alert_id,
                "success",
                {"resolved_by": resolved_by, "resolution_notes": resolution_notes}
            )
            
            self.logger.info(f"Alert {alert_id} resolved by {resolved_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to resolve alert {alert_id}: {e}")
            return False
    
    async def get_active_alerts(self, severity_filter: Optional[AlertSeverity] = None) -> List[Dict[str, Any]]:
        """Get list of active alerts"""
        try:
            alerts = []
            
            for alert in self.active_alerts.values():
                if severity_filter is None or alert.severity == severity_filter:
                    alerts.append(asdict(alert))
            
            # Sort by severity and timestamp
            severity_order = {AlertSeverity.CRITICAL: 0, AlertSeverity.HIGH: 1, 
                            AlertSeverity.MEDIUM: 2, AlertSeverity.LOW: 3}
            
            alerts.sort(key=lambda x: (severity_order[AlertSeverity(x["severity"])], x["triggered_at"]))
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get active alerts: {e}")
            return []
    
    # Audit Logging
    async def log_audit_event(self, event_type: str, component: str, user_id: Optional[str],
                            action: str, resource: str, result: str, 
                            details: Optional[Dict[str, Any]] = None) -> str:
        """Log an audit event"""
        return await self._log_audit_event(event_type, component, user_id, action, resource, result, details)
    
    async def get_audit_log(self, start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          event_type_filter: Optional[str] = None,
                          component_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit log entries with optional filtering"""
        try:
            filtered_entries = []
            
            for entry in self.audit_log:
                entry_time = datetime.fromisoformat(entry.timestamp)
                
                # Apply time filters
                if start_time and entry_time < start_time:
                    continue
                if end_time and entry_time > end_time:
                    continue
                
                # Apply type and component filters
                if event_type_filter and entry.event_type != event_type_filter:
                    continue
                if component_filter and entry.component != component_filter:
                    continue
                
                filtered_entries.append(asdict(entry))
            
            # Sort by timestamp (newest first)
            filtered_entries.sort(key=lambda x: x["timestamp"], reverse=True)
            
            return filtered_entries
            
        except Exception as e:
            self.logger.error(f"Failed to get audit log: {e}")
            return []
    
    async def verify_audit_log_integrity(self) -> Dict[str, Any]:
        """Verify integrity of audit log entries"""
        try:
            verification_results = {
                "total_entries": len(self.audit_log),
                "verified_entries": 0,
                "corrupted_entries": 0,
                "corrupted_entry_ids": [],
                "verification_timestamp": datetime.utcnow().isoformat()
            }
            
            for entry in self.audit_log:
                # Recalculate signature
                expected_signature = entry._generate_signature()
                
                if entry.signature == expected_signature:
                    verification_results["verified_entries"] += 1
                else:
                    verification_results["corrupted_entries"] += 1
                    verification_results["corrupted_entry_ids"].append(entry.log_id)
            
            return verification_results
            
        except Exception as e:
            self.logger.error(f"Failed to verify audit log integrity: {e}")
            return {"error": str(e)}
    
    # Notification System
    async def send_notification(self, channel: str, message: str, 
                              severity: AlertSeverity, metadata: Optional[Dict[str, Any]] = None):
        """Send notification through specified channel"""
        try:
            if channel not in self.notification_channels:
                self.logger.warning(f"Unknown notification channel: {channel}")
                return
            
            channel_config = self.notification_channels[channel]
            
            # Format notification message
            notification = {
                "message": message,
                "severity": severity.value,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": metadata or {}
            }
            
            # Send based on channel type
            if channel_config["type"] == "log":
                self.logger.info(f"NOTIFICATION [{severity.value.upper()}]: {message}")
            elif channel_config["type"] == "webhook":
                await self._send_webhook_notification(channel_config, notification)
            elif channel_config["type"] == "email":
                await self._send_email_notification(channel_config, notification)
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
    
    # Strands Tools for Monitoring System
    @tool
    def get_system_health_tool(self) -> Dict[str, Any]:
        """Get current system health status"""
        try:
            # Run async method in event loop
            loop = asyncio.get_event_loop()
            health_data = loop.run_until_complete(self.monitor_system_health())
            return health_data
            
        except Exception as e:
            self.logger.error(f"Failed to get system health via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def create_alert_tool(self, alert_type: str, severity: str, title: str, 
                         description: str, source_component: str) -> Dict[str, Any]:
        """Create a new alert"""
        try:
            severity_enum = AlertSeverity(severity.lower())
            
            loop = asyncio.get_event_loop()
            alert_id = loop.run_until_complete(
                self.create_alert(alert_type, severity_enum, title, description, 
                                source_component, "monitoring_tool")
            )
            
            return {
                "alert_id": alert_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create alert via tool: {e}")
            return {"error": str(e)}
    
    @tool
    def get_active_alerts_tool(self, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of active alerts"""
        try:
            severity_enum = AlertSeverity(severity_filter.lower()) if severity_filter else None
            
            loop = asyncio.get_event_loop()
            alerts = loop.run_until_complete(self.get_active_alerts(severity_enum))
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get active alerts via tool: {e}")
            return []
    
    @tool
    def get_performance_metrics_tool(self, time_range_hours: int = 1) -> Dict[str, Any]:
        """Get performance metrics summary"""
        try:
            loop = asyncio.get_event_loop()
            metrics = loop.run_until_complete(self.get_performance_summary(time_range_hours))
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics via tool: {e}")
            return {"error": str(e)}
    
    # Private Helper Methods
    def _setup_prometheus_metrics(self):
        """Setup Prometheus metrics collectors"""
        try:
            # System metrics
            self.system_cpu_usage = Gauge('system_cpu_usage_percent', 'System CPU usage percentage', 
                                        registry=self.metrics_registry)
            self.system_memory_usage = Gauge('system_memory_usage_percent', 'System memory usage percentage',
                                           registry=self.metrics_registry)
            self.system_disk_usage = Gauge('system_disk_usage_percent', 'System disk usage percentage',
                                         registry=self.metrics_registry)
            
            # Agent metrics
            self.agent_response_time = Histogram('agent_response_time_seconds', 'Agent response time',
                                               ['agent_type'], registry=self.metrics_registry)
            self.agent_message_count = Counter('agent_messages_total', 'Total agent messages processed',
                                             ['agent_type', 'message_type'], registry=self.metrics_registry)
            self.agent_error_count = Counter('agent_errors_total', 'Total agent errors',
                                           ['agent_type'], registry=self.metrics_registry)
            
            # Honeypot metrics
            self.active_honeypots = Gauge('active_honeypots_total', 'Number of active honeypots',
                                        ['honeypot_type'], registry=self.metrics_registry)
            self.honeypot_sessions = Gauge('honeypot_active_sessions_total', 'Active honeypot sessions',
                                         ['honeypot_id'], registry=self.metrics_registry)
            
            # Alert metrics
            self.active_alerts_count = Gauge('active_alerts_total', 'Number of active alerts',
                                           ['severity'], registry=self.metrics_registry)
            
            self.logger.info("Prometheus metrics setup completed")
            
        except Exception as e:
            self.logger.error(f"Failed to setup Prometheus metrics: {e}")
    
    def _load_alert_rules(self):
        """Load alert rules configuration"""
        try:
            self.alert_rules = {
                "high_cpu_usage": {
                    "threshold": 80,
                    "duration_seconds": 300,
                    "severity": AlertSeverity.HIGH,
                    "description": "High CPU usage detected"
                },
                "high_memory_usage": {
                    "threshold": 85,
                    "duration_seconds": 300,
                    "severity": AlertSeverity.HIGH,
                    "description": "High memory usage detected"
                },
                "agent_unresponsive": {
                    "threshold": 60,  # seconds without response
                    "severity": AlertSeverity.CRITICAL,
                    "description": "Agent is unresponsive"
                },
                "honeypot_failure": {
                    "severity": AlertSeverity.HIGH,
                    "description": "Honeypot instance failure detected"
                },
                "high_error_rate": {
                    "threshold": 10,  # errors per minute
                    "duration_seconds": 300,
                    "severity": AlertSeverity.MEDIUM,
                    "description": "High error rate detected"
                }
            }
            
            self.logger.info("Alert rules loaded")
            
        except Exception as e:
            self.logger.error(f"Failed to load alert rules: {e}")
    
    def _setup_notification_channels(self):
        """Setup notification channels"""
        try:
            self.notification_channels = {
                "log": {
                    "type": "log",
                    "enabled": True
                },
                "webhook": {
                    "type": "webhook",
                    "enabled": False,
                    "url": os.getenv("ALERT_WEBHOOK_URL", ""),
                    "headers": {"Content-Type": "application/json"}
                },
                "email": {
                    "type": "email",
                    "enabled": False,
                    "smtp_server": os.getenv("SMTP_SERVER", ""),
                    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
                    "username": os.getenv("SMTP_USERNAME", ""),
                    "password": os.getenv("SMTP_PASSWORD", ""),
                    "recipients": os.getenv("ALERT_EMAIL_RECIPIENTS", "").split(",")
                }
            }
            
            self.logger.info("Notification channels configured")
            
        except Exception as e:
            self.logger.error(f"Failed to setup notification channels: {e}")
    
    async def _start_metrics_server(self):
        """Start Prometheus metrics server"""
        try:
            # In a real implementation, this would start an HTTP server
            # to serve Prometheus metrics
            self.logger.info("Metrics server started (simulated)")
            
        except Exception as e:
            self.logger.error(f"Failed to start metrics server: {e}")
    
    async def _check_component_health(self, component: str) -> Dict[str, Any]:
        """Check health of a system component"""
        try:
            if component in ["detection_agent", "interaction_agent", "intelligence_agent"]:
                return await self.monitor_agent_health(component)
            elif component == "orchestration_engine":
                # Check orchestration engine health
                return {
                    "component": component,
                    "status": "healthy",
                    "active_workflows": len(self.coordinator_agent.orchestration_engine.active_workflows),
                    "timestamp": datetime.utcnow().isoformat()
                }
            elif component == "honeypot_manager":
                # Check honeypot manager health
                return {
                    "component": component,
                    "status": "healthy",
                    "active_honeypots": len(self.coordinator_agent.orchestration_engine.honeypot_instances),
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "component": component,
                    "status": "unknown",
                    "error": "Unknown component",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            return {
                "component": component,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _get_system_performance_summary(self) -> Dict[str, Any]:
        """Get system performance summary"""
        try:
            return {
                "cpu_usage_percent": 25.5,
                "memory_usage_percent": 45.2,
                "disk_usage_percent": 30.1,
                "network_throughput_mbps": 150.0,
                "active_connections": 25
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system performance summary: {e}")
            return {}
    
    async def _get_resource_utilization(self) -> Dict[str, Any]:
        """Get resource utilization metrics"""
        try:
            return {
                "cpu_cores_used": 2.5,
                "cpu_cores_total": 8,
                "memory_gb_used": 6.2,
                "memory_gb_total": 16,
                "disk_gb_used": 45.8,
                "disk_gb_total": 100,
                "network_bandwidth_used_mbps": 150,
                "network_bandwidth_total_mbps": 1000
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get resource utilization: {e}")
            return {}
    
    async def _record_health_metrics(self, health_data: Dict[str, Any]):
        """Record health metrics to Prometheus"""
        try:
            # Update Prometheus metrics
            performance = health_data.get("performance", {})
            self.system_cpu_usage.set(performance.get("cpu_usage_percent", 0))
            self.system_memory_usage.set(performance.get("memory_usage_percent", 0))
            self.system_disk_usage.set(performance.get("disk_usage_percent", 0))
            
            # Update alert metrics
            alerts = health_data.get("alerts", {})
            for severity in AlertSeverity:
                count = len([a for a in self.active_alerts.values() 
                           if a.severity == severity and a.status == AlertStatus.ACTIVE])
                self.active_alerts_count.labels(severity=severity.value).set(count)
            
        except Exception as e:
            self.logger.error(f"Failed to record health metrics: {e}")
    
    async def _check_agent_health_alerts(self, agent_type: str, health_data: Dict[str, Any]):
        """Check agent health data for alert conditions"""
        try:
            # Check response time
            response_time = health_data.get("response_time_ms", 0)
            if response_time > 5000:  # 5 seconds
                await self.create_alert(
                    "high_response_time",
                    AlertSeverity.HIGH,
                    f"High response time for {agent_type}",
                    f"Agent {agent_type} response time is {response_time}ms",
                    agent_type,
                    "health_monitor"
                )
            
            # Check error rate
            error_count = health_data.get("error_count", 0)
            processed_messages = health_data.get("processed_messages", 0)
            error_rate = (error_count / max(processed_messages, 1)) * 100
            
            if error_rate > 10:  # 10% error rate
                await self.create_alert(
                    "high_error_rate",
                    AlertSeverity.MEDIUM,
                    f"High error rate for {agent_type}",
                    f"Agent {agent_type} error rate is {error_rate:.1f}%",
                    agent_type,
                    "health_monitor"
                )
            
            # Check if agent is unreachable
            if health_data.get("status") == "unreachable":
                await self.create_alert(
                    "agent_unreachable",
                    AlertSeverity.CRITICAL,
                    f"Agent {agent_type} unreachable",
                    f"Agent {agent_type} is not responding to health checks",
                    agent_type,
                    "health_monitor"
                )
            
        except Exception as e:
            self.logger.error(f"Failed to check agent health alerts: {e}")
    
    async def _record_agent_metrics(self, agent_type: str, health_data: Dict[str, Any]):
        """Record agent metrics to Prometheus"""
        try:
            # Record response time
            response_time_seconds = health_data.get("response_time_ms", 0) / 1000
            self.agent_response_time.labels(agent_type=agent_type).observe(response_time_seconds)
            
            # Record error count
            error_count = health_data.get("error_count", 0)
            self.agent_error_count.labels(agent_type=agent_type)._value._value = error_count
            
        except Exception as e:
            self.logger.error(f"Failed to record agent metrics: {e}")
    
    async def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level metrics"""
        try:
            return {
                "cpu_usage_percent": 25.5,
                "memory_usage_percent": 45.2,
                "disk_usage_percent": 30.1,
                "network_throughput_mbps": 150.0,
                "load_average": [1.2, 1.5, 1.8],
                "uptime_seconds": 86400
            }
            
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {e}")
            return {}
    
    async def _collect_honeypot_metrics(self) -> Dict[str, Any]:
        """Collect honeypot-related metrics"""
        try:
            honeypot_instances = self.coordinator_agent.orchestration_engine.honeypot_instances
            
            metrics = {
                "total_honeypots": len(honeypot_instances),
                "active_honeypots": len([hp for hp in honeypot_instances.values() 
                                       if hp.status.value == "active"]),
                "honeypots_by_type": {},
                "total_active_sessions": 0
            }
            
            for honeypot in honeypot_instances.values():
                hp_type = honeypot.honeypot_type
                metrics["honeypots_by_type"][hp_type] = metrics["honeypots_by_type"].get(hp_type, 0) + 1
                metrics["total_active_sessions"] += len(getattr(honeypot, 'active_sessions', []))
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to collect honeypot metrics: {e}")
            return {}
    
    async def _collect_agent_metrics(self) -> Dict[str, Any]:
        """Collect agent-related metrics"""
        try:
            agent_health = self.coordinator_agent.orchestration_engine.agent_health
            
            metrics = {
                "total_agents": len(agent_health),
                "healthy_agents": len([h for h in agent_health.values() if h.status.value == "healthy"]),
                "degraded_agents": len([h for h in agent_health.values() if h.status.value == "degraded"]),
                "failed_agents": len([h for h in agent_health.values() if h.status.value == "failed"]),
                "average_response_time_ms": 0
            }
            
            if agent_health:
                total_response_time = sum(h.response_time_ms for h in agent_health.values())
                metrics["average_response_time_ms"] = total_response_time / max(len(agent_health), 1)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to collect agent metrics: {e}")
            return {}
    
    async def _collect_workflow_metrics(self) -> Dict[str, Any]:
        """Collect workflow-related metrics"""
        try:
            workflows = self.coordinator_agent.orchestration_engine.active_workflows
            
            metrics = {
                "total_workflows": len(workflows),
                "running_workflows": len([w for w in workflows.values() if w.status.value == "running"]),
                "completed_workflows": len([w for w in workflows.values() if w.status.value == "completed"]),
                "failed_workflows": len([w for w in workflows.values() if w.status.value == "failed"])
            }
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to collect workflow metrics: {e}")
            return {}
    
    async def _store_performance_metrics(self, metrics_data: Dict[str, Any]):
        """Store performance metrics for historical analysis"""
        try:
            timestamp = metrics_data["timestamp"]
            
            # Store each metric type
            for metric_category, data in metrics_data.items():
                if metric_category == "timestamp":
                    continue
                
                metric_key = f"{metric_category}_{timestamp}"
                
                if metric_category not in self.performance_metrics:
                    self.performance_metrics[metric_category] = []
                
                # Create performance metric objects
                for key, value in data.items():
                    if isinstance(value, (int, float)):
                        metric = PerformanceMetric(
                            metric_id=str(uuid4()),
                            metric_name=key,
                            metric_type=MetricType.GAUGE,
                            value=float(value),
                            labels={"category": metric_category},
                            timestamp=timestamp,
                            source_component="monitoring_system",
                            source_instance="coordinator"
                        )
                        
                        self.performance_metrics[metric_category].append(metric)
            
            # Cleanup old metrics
            await self._cleanup_old_metrics()
            
        except Exception as e:
            self.logger.error(f"Failed to store performance metrics: {e}")
    
    async def _calculate_performance_summary(self, metrics: List[PerformanceMetric]) -> Dict[str, Any]:
        """Calculate performance summary statistics"""
        try:
            if not metrics:
                return {}
            
            # Group metrics by name
            metrics_by_name = {}
            for metric in metrics:
                if metric.metric_name not in metrics_by_name:
                    metrics_by_name[metric.metric_name] = []
                metrics_by_name[metric.metric_name].append(metric.value)
            
            # Calculate statistics
            summary = {}
            for name, values in metrics_by_name.items():
                summary[name] = {
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / max(len(values), 1),
                    "count": len(values)
                }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to calculate performance summary: {e}")
            return {}
    
    async def _calculate_performance_trends(self, metrics: List[PerformanceMetric]) -> Dict[str, Any]:
        """Calculate performance trends"""
        try:
            # Simplified trend calculation
            return {
                "cpu_trend": "stable",
                "memory_trend": "increasing",
                "response_time_trend": "stable",
                "error_rate_trend": "decreasing"
            }
            
        except Exception as e:
            self.logger.error(f"Failed to calculate performance trends: {e}")
            return {}
    
    async def _detect_performance_anomalies(self, metrics: List[PerformanceMetric]) -> List[Dict[str, Any]]:
        """Detect performance anomalies"""
        try:
            # Simplified anomaly detection
            anomalies = []
            
            # Check for high CPU usage
            cpu_metrics = [m for m in metrics if "cpu" in m.metric_name.lower()]
            if cpu_metrics:
                max_cpu = max(m.value for m in cpu_metrics)
                if max_cpu > 80:
                    anomalies.append({
                        "type": "high_cpu_usage",
                        "value": max_cpu,
                        "threshold": 80,
                        "severity": "high"
                    })
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Failed to detect performance anomalies: {e}")
            return []
    
    async def _send_alert_notifications(self, alert: Alert):
        """Send notifications for an alert"""
        try:
            message = f"[{alert.severity.value.upper()}] {alert.title}: {alert.description}"
            
            # Send to all enabled notification channels
            for channel_name, channel_config in self.notification_channels.items():
                if channel_config.get("enabled", False):
                    await self.send_notification(channel_name, message, alert.severity, asdict(alert))
            
        except Exception as e:
            self.logger.error(f"Failed to send alert notifications: {e}")
    
    async def _send_webhook_notification(self, channel_config: Dict[str, Any], 
                                       notification: Dict[str, Any]):
        """Send webhook notification"""
        try:
            # In a real implementation, this would make HTTP POST request
            self.logger.info(f"WEBHOOK NOTIFICATION: {notification['message']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
    
    async def _send_email_notification(self, channel_config: Dict[str, Any], 
                                     notification: Dict[str, Any]):
        """Send email notification"""
        try:
            # In a real implementation, this would send actual email
            self.logger.info(f"EMAIL NOTIFICATION: {notification['message']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
    
    async def _log_audit_event(self, event_type: str, component: str, user_id: Optional[str],
                             action: str, resource: str, result: str, 
                             details: Optional[Dict[str, Any]] = None) -> str:
        """Log an audit event with digital signature"""
        try:
            log_id = str(uuid4())
            
            entry = AuditLogEntry(
                log_id=log_id,
                timestamp=datetime.utcnow().isoformat(),
                event_type=event_type,
                component=component,
                user_id=user_id,
                action=action,
                resource=resource,
                result=result,
                details=details or {},
                signature=""  # Will be generated in __post_init__
            )
            
            self.audit_log.append(entry)
            
            # Cleanup old audit logs
            await self._cleanup_old_audit_logs()
            
            return log_id
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
            raise
    
    async def _archive_monitoring_data(self):
        """Archive monitoring data before shutdown"""
        try:
            # In a real implementation, this would save data to persistent storage
            self.logger.info("Archiving monitoring data")
            
            archive_data = {
                "active_alerts": [asdict(alert) for alert in self.active_alerts.values()],
                "alert_history": [asdict(alert) for alert in self.alert_history],
                "audit_log": [asdict(entry) for entry in self.audit_log],
                "performance_metrics_count": sum(len(metrics) for metrics in self.performance_metrics.values()),
                "archived_at": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Archived {len(archive_data)} monitoring data items")
            
        except Exception as e:
            self.logger.error(f"Failed to archive monitoring data: {e}")
    
    # Monitoring Tasks
    async def _system_health_monitor(self):
        """Continuous system health monitoring"""
        while True:
            try:
                await self.monitor_system_health()
                await asyncio.sleep(self.health_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in system health monitor: {e}")
                await asyncio.sleep(self.health_check_interval)
    
    async def _performance_metrics_collector(self):
        """Continuous performance metrics collection"""
        while True:
            try:
                await self.collect_performance_metrics()
                await asyncio.sleep(self.metrics_collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in performance metrics collector: {e}")
                await asyncio.sleep(self.metrics_collection_interval)
    
    async def _alert_processor(self):
        """Process and manage alerts"""
        while True:
            try:
                # Check for alert rule violations
                await self._check_alert_rules()
                
                # Auto-resolve alerts if conditions are met
                await self._auto_resolve_alerts()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in alert processor: {e}")
                await asyncio.sleep(60)
    
    async def _audit_log_processor(self):
        """Process and manage audit logs"""
        while True:
            try:
                # Verify log integrity periodically
                verification_results = await self.verify_audit_log_integrity()
                
                if verification_results.get("corrupted_entries", 0) > 0:
                    await self.create_alert(
                        "audit_log_corruption",
                        AlertSeverity.CRITICAL,
                        "Audit log corruption detected",
                        f"Found {verification_results['corrupted_entries']} corrupted audit log entries",
                        "monitoring_system",
                        "audit_processor"
                    )
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Error in audit log processor: {e}")
                await asyncio.sleep(3600)
    
    async def _cleanup_monitor(self):
        """Cleanup old data and manage retention"""
        while True:
            try:
                await self._cleanup_old_metrics()
                await self._cleanup_old_alerts()
                await self._cleanup_old_audit_logs()
                
                await asyncio.sleep(3600)  # Cleanup every hour
                
            except Exception as e:
                self.logger.error(f"Error in cleanup monitor: {e}")
                await asyncio.sleep(3600)
    
    async def _check_alert_rules(self):
        """Check for alert rule violations"""
        try:
            # Get current system metrics
            health_data = await self.monitor_system_health()
            performance = health_data.get("performance", {})
            
            # Check CPU usage rule
            cpu_usage = performance.get("cpu_usage_percent", 0)
            if cpu_usage > self.alert_rules["high_cpu_usage"]["threshold"]:
                await self.create_alert(
                    "high_cpu_usage",
                    self.alert_rules["high_cpu_usage"]["severity"],
                    "High CPU Usage",
                    f"CPU usage is {cpu_usage}%",
                    "monitoring_system",
                    "rule_processor"
                )
            
            # Check memory usage rule
            memory_usage = performance.get("memory_usage_percent", 0)
            if memory_usage > self.alert_rules["high_memory_usage"]["threshold"]:
                await self.create_alert(
                    "high_memory_usage",
                    self.alert_rules["high_memory_usage"]["severity"],
                    "High Memory Usage",
                    f"Memory usage is {memory_usage}%",
                    "monitoring_system",
                    "rule_processor"
                )
            
        except Exception as e:
            self.logger.error(f"Failed to check alert rules: {e}")
    
    async def _auto_resolve_alerts(self):
        """Auto-resolve alerts when conditions are no longer met"""
        try:
            current_time = datetime.utcnow()
            
            for alert_id, alert in list(self.active_alerts.items()):
                # Auto-resolve alerts older than 24 hours if they're not critical
                triggered_time = datetime.fromisoformat(alert.triggered_at)
                age_hours = (current_time - triggered_time).total_seconds() / 3600
                
                if (age_hours > 24 and alert.severity != AlertSeverity.CRITICAL and 
                    alert.status == AlertStatus.ACTIVE):
                    await self.resolve_alert(alert_id, "system", "Auto-resolved due to age")
            
        except Exception as e:
            self.logger.error(f"Failed to auto-resolve alerts: {e}")
    
    async def _cleanup_old_metrics(self):
        """Cleanup old performance metrics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=self.metrics_retention_hours)
            
            for metric_category in list(self.performance_metrics.keys()):
                metrics = self.performance_metrics[metric_category]
                
                # Filter out old metrics
                filtered_metrics = [
                    metric for metric in metrics
                    if datetime.fromisoformat(metric.timestamp) > cutoff_time
                ]
                
                removed_count = len(metrics) - len(filtered_metrics)
                if removed_count > 0:
                    self.performance_metrics[metric_category] = filtered_metrics
                    self.logger.debug(f"Cleaned up {removed_count} old {metric_category} metrics")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old metrics: {e}")
    
    async def _cleanup_old_alerts(self):
        """Cleanup old alert history"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=self.alert_history_retention_days)
            
            original_count = len(self.alert_history)
            self.alert_history = [
                alert for alert in self.alert_history
                if datetime.fromisoformat(alert.triggered_at) > cutoff_time
            ]
            
            removed_count = original_count - len(self.alert_history)
            if removed_count > 0:
                self.logger.debug(f"Cleaned up {removed_count} old alert history entries")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old alerts: {e}")
    
    async def _cleanup_old_audit_logs(self):
        """Cleanup old audit log entries"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=self.audit_log_retention_days)
            
            original_count = len(self.audit_log)
            self.audit_log = [
                entry for entry in self.audit_log
                if datetime.fromisoformat(entry.timestamp) > cutoff_time
            ]
            
            removed_count = original_count - len(self.audit_log)
            if removed_count > 0:
                self.logger.debug(f"Cleaned up {removed_count} old audit log entries")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old audit logs: {e}")