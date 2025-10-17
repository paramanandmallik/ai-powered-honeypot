"""
Alerting and Notification System for AI-Powered Honeypot System
Provides real-time alerting for high-priority events, escalation procedures,
integration with external notification systems, and customizable alert rules.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from uuid import uuid4
from dataclasses import dataclass, asdict
from enum import Enum
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiohttp
import boto3
from botocore.exceptions import ClientError


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class NotificationChannel(Enum):
    """Notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SNS = "sns"
    PAGERDUTY = "pagerduty"
    SMS = "sms"


class EscalationLevel(Enum):
    """Escalation levels"""
    LEVEL_1 = "level_1"  # First responders
    LEVEL_2 = "level_2"  # Team leads
    LEVEL_3 = "level_3"  # Management
    LEVEL_4 = "level_4"  # Executive


@dataclass
class AlertRule:
    """Alert rule configuration"""
    rule_id: str
    name: str
    description: str
    severity: AlertSeverity
    conditions: Dict[str, Any]
    enabled: bool
    notification_channels: List[NotificationChannel]
    escalation_enabled: bool
    escalation_timeout_minutes: int
    suppression_duration_minutes: int
    created_at: str
    updated_at: str


@dataclass
class Alert:
    """Alert instance"""
    alert_id: str
    rule_id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    source_data: Dict[str, Any]
    created_at: str
    updated_at: str
    acknowledged_at: Optional[str]
    acknowledged_by: Optional[str]
    resolved_at: Optional[str]
    resolved_by: Optional[str]
    escalation_level: EscalationLevel
    notification_history: List[Dict[str, Any]]
    tags: List[str]


@dataclass
class NotificationConfig:
    """Notification configuration"""
    channel: NotificationChannel
    config: Dict[str, Any]
    enabled: bool
    rate_limit_per_hour: int
    escalation_levels: List[EscalationLevel]


@dataclass
class EscalationPolicy:
    """Escalation policy configuration"""
    policy_id: str
    name: str
    description: str
    levels: List[Dict[str, Any]]  # Each level has timeout and notification configs
    enabled: bool


class AlertingNotificationSystem:
    """
    Alerting and Notification System
    Provides real-time alerting for high-priority events, escalation procedures,
    integration with external notification systems, and customizable alert rules.
    """
    
    def __init__(self, coordinator_agent=None, config: Optional[Dict[str, Any]] = None):
        self.coordinator_agent = coordinator_agent
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.alert_retention_days = self.config.get("alert_retention_days", 30)
        self.max_alerts_per_hour = self.config.get("max_alerts_per_hour", 100)
        self.default_escalation_timeout = self.config.get("default_escalation_timeout", 30)
        
        # Storage
        self.alert_rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.notification_configs: Dict[str, NotificationConfig] = {}
        self.escalation_policies: Dict[str, EscalationPolicy] = {}
        
        # Rate limiting
        self.notification_counts: Dict[str, List[datetime]] = {}
        
        # Background tasks
        self._background_tasks = []
        
        # Initialize default configurations
        self._initialize_default_configs()
        
        self.logger.info("Alerting and Notification System initialized")
    
    async def start(self):
        """Start the alerting and notification system"""
        try:
            # Start background monitoring tasks
            self._background_tasks.append(
                asyncio.create_task(self._monitor_system_events())
            )
            self._background_tasks.append(
                asyncio.create_task(self._process_escalations())
            )
            self._background_tasks.append(
                asyncio.create_task(self._cleanup_old_alerts())
            )
            self._background_tasks.append(
                asyncio.create_task(self._health_check_notifications())
            )
            
            self.logger.info("Alerting and Notification System started")
            
        except Exception as e:
            self.logger.error(f"Failed to start alerting system: {e}")
            raise
    
    async def stop(self):
        """Stop the alerting and notification system"""
        try:
            # Cancel background tasks
            for task in self._background_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            
            self.logger.info("Alerting and Notification System stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping alerting system: {e}")
    
    # Alert Rule Management
    async def create_alert_rule(self, name: str, description: str, severity: AlertSeverity,
                              conditions: Dict[str, Any], notification_channels: List[NotificationChannel],
                              escalation_enabled: bool = True, escalation_timeout_minutes: int = 30,
                              suppression_duration_minutes: int = 60) -> str:
        """Create a new alert rule"""
        try:
            rule_id = str(uuid4())
            
            rule = AlertRule(
                rule_id=rule_id,
                name=name,
                description=description,
                severity=severity,
                conditions=conditions,
                enabled=True,
                notification_channels=notification_channels,
                escalation_enabled=escalation_enabled,
                escalation_timeout_minutes=escalation_timeout_minutes,
                suppression_duration_minutes=suppression_duration_minutes,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat()
            )
            
            self.alert_rules[rule_id] = rule
            
            self.logger.info(f"Created alert rule: {name} ({rule_id})")
            return rule_id
            
        except Exception as e:
            self.logger.error(f"Failed to create alert rule: {e}")
            raise
    
    async def update_alert_rule(self, rule_id: str, **kwargs) -> bool:
        """Update an existing alert rule"""
        try:
            if rule_id not in self.alert_rules:
                return False
            
            rule = self.alert_rules[rule_id]
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            
            rule.updated_at = datetime.utcnow().isoformat()
            
            self.logger.info(f"Updated alert rule: {rule_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update alert rule: {e}")
            return False
    
    async def delete_alert_rule(self, rule_id: str) -> bool:
        """Delete an alert rule"""
        try:
            if rule_id in self.alert_rules:
                del self.alert_rules[rule_id]
                self.logger.info(f"Deleted alert rule: {rule_id}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to delete alert rule: {e}")
            return False
    
    async def get_alert_rules(self) -> List[AlertRule]:
        """Get all alert rules"""
        return list(self.alert_rules.values())
    
    # Alert Management
    async def create_alert(self, rule_id: str, title: str, description: str,
                         source: str, source_data: Dict[str, Any],
                         tags: Optional[List[str]] = None) -> str:
        """Create a new alert"""
        try:
            if rule_id not in self.alert_rules:
                raise ValueError(f"Alert rule {rule_id} not found")
            
            rule = self.alert_rules[rule_id]
            
            # Check if rule is enabled
            if not rule.enabled:
                self.logger.debug(f"Alert rule {rule_id} is disabled, skipping alert creation")
                return ""
            
            # Check for suppression
            if await self._is_alert_suppressed(rule_id, source_data):
                self.logger.debug(f"Alert suppressed for rule {rule_id}")
                return ""
            
            alert_id = str(uuid4())
            
            alert = Alert(
                alert_id=alert_id,
                rule_id=rule_id,
                title=title,
                description=description,
                severity=rule.severity,
                status=AlertStatus.ACTIVE,
                source=source,
                source_data=source_data,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat(),
                acknowledged_at=None,
                acknowledged_by=None,
                resolved_at=None,
                resolved_by=None,
                escalation_level=EscalationLevel.LEVEL_1,
                notification_history=[],
                tags=tags or []
            )
            
            self.active_alerts[alert_id] = alert
            
            # Send initial notifications
            await self._send_alert_notifications(alert)
            
            # Start escalation timer if enabled
            if rule.escalation_enabled:
                asyncio.create_task(self._schedule_escalation(alert_id, rule.escalation_timeout_minutes))
            
            self.logger.info(f"Created alert: {title} ({alert_id})")
            return alert_id
            
        except Exception as e:
            self.logger.error(f"Failed to create alert: {e}")
            raise
    
    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an alert"""
        try:
            if alert_id not in self.active_alerts:
                return False
            
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow().isoformat()
            alert.acknowledged_by = acknowledged_by
            alert.updated_at = datetime.utcnow().isoformat()
            
            # Send acknowledgment notifications
            await self._send_acknowledgment_notifications(alert)
            
            self.logger.info(f"Alert acknowledged: {alert_id} by {acknowledged_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to acknowledge alert: {e}")
            return False
    
    async def resolve_alert(self, alert_id: str, resolved_by: str, resolution_note: str = "") -> bool:
        """Resolve an alert"""
        try:
            if alert_id not in self.active_alerts:
                return False
            
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow().isoformat()
            alert.resolved_by = resolved_by
            alert.updated_at = datetime.utcnow().isoformat()
            
            if resolution_note:
                alert.source_data["resolution_note"] = resolution_note
            
            # Move to history
            self.alert_history.append(alert)
            del self.active_alerts[alert_id]
            
            # Send resolution notifications
            await self._send_resolution_notifications(alert)
            
            self.logger.info(f"Alert resolved: {alert_id} by {resolved_by}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to resolve alert: {e}")
            return False
    
    async def suppress_alert(self, alert_id: str, suppressed_by: str, duration_minutes: int = 60) -> bool:
        """Suppress an alert"""
        try:
            if alert_id not in self.active_alerts:
                return False
            
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.SUPPRESSED
            alert.updated_at = datetime.utcnow().isoformat()
            alert.source_data["suppressed_by"] = suppressed_by
            alert.source_data["suppressed_until"] = (
                datetime.utcnow() + timedelta(minutes=duration_minutes)
            ).isoformat()
            
            # Schedule unsuppression
            asyncio.create_task(self._schedule_unsuppression(alert_id, duration_minutes))
            
            self.logger.info(f"Alert suppressed: {alert_id} by {suppressed_by} for {duration_minutes} minutes")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to suppress alert: {e}")
            return False
    
    async def get_active_alerts(self, severity_filter: Optional[AlertSeverity] = None) -> List[Alert]:
        """Get active alerts with optional severity filter"""
        try:
            alerts = list(self.active_alerts.values())
            
            if severity_filter:
                alerts = [alert for alert in alerts if alert.severity == severity_filter]
            
            return sorted(alerts, key=lambda x: x.created_at, reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to get active alerts: {e}")
            return []
    
    async def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get alert history"""
        try:
            return sorted(self.alert_history[-limit:], key=lambda x: x.created_at, reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to get alert history: {e}")
            return []
    
    # Notification Configuration
    async def configure_notification_channel(self, channel: NotificationChannel,
                                           config: Dict[str, Any],
                                           rate_limit_per_hour: int = 50,
                                           escalation_levels: Optional[List[EscalationLevel]] = None) -> str:
        """Configure a notification channel"""
        try:
            config_id = f"{channel.value}_{str(uuid4())[:8]}"
            
            notification_config = NotificationConfig(
                channel=channel,
                config=config,
                enabled=True,
                rate_limit_per_hour=rate_limit_per_hour,
                escalation_levels=escalation_levels or [EscalationLevel.LEVEL_1]
            )
            
            self.notification_configs[config_id] = notification_config
            
            self.logger.info(f"Configured notification channel: {channel.value} ({config_id})")
            return config_id
            
        except Exception as e:
            self.logger.error(f"Failed to configure notification channel: {e}")
            raise
    
    async def test_notification_channel(self, config_id: str) -> bool:
        """Test a notification channel"""
        try:
            if config_id not in self.notification_configs:
                return False
            
            config = self.notification_configs[config_id]
            
            test_message = {
                "title": "Test Notification",
                "description": "This is a test notification from the AI Honeypot Alerting System",
                "severity": "info",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            success = await self._send_notification(config, test_message)
            
            self.logger.info(f"Test notification sent to {config.channel.value}: {'success' if success else 'failed'}")
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to test notification channel: {e}")
            return False
    
    # Escalation Management
    async def create_escalation_policy(self, name: str, description: str,
                                     levels: List[Dict[str, Any]]) -> str:
        """Create an escalation policy"""
        try:
            policy_id = str(uuid4())
            
            policy = EscalationPolicy(
                policy_id=policy_id,
                name=name,
                description=description,
                levels=levels,
                enabled=True
            )
            
            self.escalation_policies[policy_id] = policy
            
            self.logger.info(f"Created escalation policy: {name} ({policy_id})")
            return policy_id
            
        except Exception as e:
            self.logger.error(f"Failed to create escalation policy: {e}")
            raise
    
    # Notification Methods
    async def _send_alert_notifications(self, alert: Alert):
        """Send notifications for a new alert"""
        try:
            rule = self.alert_rules[alert.rule_id]
            
            message = {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "source": alert.source,
                "created_at": alert.created_at,
                "escalation_level": alert.escalation_level.value
            }
            
            # Send to configured channels
            for channel in rule.notification_channels:
                matching_configs = [
                    config for config in self.notification_configs.values()
                    if config.channel == channel and config.enabled
                    and alert.escalation_level in config.escalation_levels
                ]
                
                for config in matching_configs:
                    if await self._check_rate_limit(config):
                        success = await self._send_notification(config, message)
                        
                        # Record notification history
                        alert.notification_history.append({
                            "channel": channel.value,
                            "timestamp": datetime.utcnow().isoformat(),
                            "success": success,
                            "escalation_level": alert.escalation_level.value
                        })
            
        except Exception as e:
            self.logger.error(f"Failed to send alert notifications: {e}")
    
    async def _send_acknowledgment_notifications(self, alert: Alert):
        """Send acknowledgment notifications"""
        try:
            message = {
                "alert_id": alert.alert_id,
                "title": f"ACKNOWLEDGED: {alert.title}",
                "description": f"Alert acknowledged by {alert.acknowledged_by}",
                "severity": "info",
                "acknowledged_at": alert.acknowledged_at,
                "acknowledged_by": alert.acknowledged_by
            }
            
            # Send to configured channels (reduced set for acknowledgments)
            for config in self.notification_configs.values():
                if config.enabled and config.channel in [NotificationChannel.SLACK, NotificationChannel.TEAMS]:
                    await self._send_notification(config, message)
            
        except Exception as e:
            self.logger.error(f"Failed to send acknowledgment notifications: {e}")
    
    async def _send_resolution_notifications(self, alert: Alert):
        """Send resolution notifications"""
        try:
            message = {
                "alert_id": alert.alert_id,
                "title": f"RESOLVED: {alert.title}",
                "description": f"Alert resolved by {alert.resolved_by}",
                "severity": "info",
                "resolved_at": alert.resolved_at,
                "resolved_by": alert.resolved_by,
                "resolution_note": alert.source_data.get("resolution_note", "")
            }
            
            # Send to configured channels
            for config in self.notification_configs.values():
                if config.enabled:
                    await self._send_notification(config, message)
            
        except Exception as e:
            self.logger.error(f"Failed to send resolution notifications: {e}")
    
    async def _send_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send notification via specific channel"""
        try:
            if config.channel == NotificationChannel.EMAIL:
                return await self._send_email_notification(config, message)
            elif config.channel == NotificationChannel.SLACK:
                return await self._send_slack_notification(config, message)
            elif config.channel == NotificationChannel.TEAMS:
                return await self._send_teams_notification(config, message)
            elif config.channel == NotificationChannel.WEBHOOK:
                return await self._send_webhook_notification(config, message)
            elif config.channel == NotificationChannel.SNS:
                return await self._send_sns_notification(config, message)
            elif config.channel == NotificationChannel.PAGERDUTY:
                return await self._send_pagerduty_notification(config, message)
            elif config.channel == NotificationChannel.SMS:
                return await self._send_sms_notification(config, message)
            else:
                self.logger.warning(f"Unsupported notification channel: {config.channel}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send notification via {config.channel.value}: {e}")
            return False
    
    async def _send_email_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send email notification"""
        try:
            smtp_server = config.config.get("smtp_server")
            smtp_port = config.config.get("smtp_port", 587)
            username = config.config.get("username")
            password = config.config.get("password")
            from_email = config.config.get("from_email")
            to_emails = config.config.get("to_emails", [])
            
            if not all([smtp_server, username, password, from_email, to_emails]):
                self.logger.error("Missing email configuration parameters")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ", ".join(to_emails)
            msg['Subject'] = f"[{message['severity'].upper()}] {message['title']}"
            
            body = f"""
Alert Details:
- Title: {message['title']}
- Description: {message['description']}
- Severity: {message['severity'].upper()}
- Source: {message.get('source', 'Unknown')}
- Time: {message.get('created_at', datetime.utcnow().isoformat())}
- Alert ID: {message.get('alert_id', 'N/A')}

This is an automated alert from the AI Honeypot System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                server.login(username, password)
                server.sendmail(from_email, to_emails, msg.as_string())
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return False
    
    async def _send_slack_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send Slack notification"""
        try:
            webhook_url = config.config.get("webhook_url")
            channel = config.config.get("channel", "#alerts")
            
            if not webhook_url:
                self.logger.error("Missing Slack webhook URL")
                return False
            
            # Create Slack message
            severity_colors = {
                "critical": "#FF0000",
                "high": "#FF6600",
                "medium": "#FFCC00",
                "low": "#00FF00",
                "info": "#0099FF"
            }
            
            color = severity_colors.get(message['severity'], "#808080")
            
            slack_message = {
                "channel": channel,
                "username": "AI Honeypot Alerts",
                "icon_emoji": ":shield:",
                "attachments": [{
                    "color": color,
                    "title": message['title'],
                    "text": message['description'],
                    "fields": [
                        {
                            "title": "Severity",
                            "value": message['severity'].upper(),
                            "short": True
                        },
                        {
                            "title": "Source",
                            "value": message.get('source', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Alert ID",
                            "value": message.get('alert_id', 'N/A'),
                            "short": True
                        },
                        {
                            "title": "Time",
                            "value": message.get('created_at', datetime.utcnow().isoformat()),
                            "short": True
                        }
                    ],
                    "footer": "AI Honeypot System",
                    "ts": int(datetime.utcnow().timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=slack_message) as response:
                    return response.status == 200
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    async def _send_teams_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send Microsoft Teams notification"""
        try:
            webhook_url = config.config.get("webhook_url")
            
            if not webhook_url:
                self.logger.error("Missing Teams webhook URL")
                return False
            
            # Create Teams message
            severity_colors = {
                "critical": "FF0000",
                "high": "FF6600",
                "medium": "FFCC00",
                "low": "00FF00",
                "info": "0099FF"
            }
            
            color = severity_colors.get(message['severity'], "808080")
            
            teams_message = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color,
                "summary": message['title'],
                "sections": [{
                    "activityTitle": message['title'],
                    "activitySubtitle": f"Severity: {message['severity'].upper()}",
                    "activityImage": "https://example.com/shield-icon.png",
                    "facts": [
                        {
                            "name": "Description",
                            "value": message['description']
                        },
                        {
                            "name": "Source",
                            "value": message.get('source', 'Unknown')
                        },
                        {
                            "name": "Alert ID",
                            "value": message.get('alert_id', 'N/A')
                        },
                        {
                            "name": "Time",
                            "value": message.get('created_at', datetime.utcnow().isoformat())
                        }
                    ],
                    "markdown": True
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=teams_message) as response:
                    return response.status == 200
            
        except Exception as e:
            self.logger.error(f"Failed to send Teams notification: {e}")
            return False
    
    async def _send_webhook_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send webhook notification"""
        try:
            webhook_url = config.config.get("url")
            headers = config.config.get("headers", {})
            
            if not webhook_url:
                self.logger.error("Missing webhook URL")
                return False
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message, headers=headers) as response:
                    return response.status < 400
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
            return False
    
    async def _send_sns_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send SNS notification"""
        try:
            topic_arn = config.config.get("topic_arn")
            region = config.config.get("region", "us-east-1")
            
            if not topic_arn:
                self.logger.error("Missing SNS topic ARN")
                return False
            
            sns_client = boto3.client('sns', region_name=region)
            
            sns_message = {
                "default": json.dumps(message),
                "email": f"Alert: {message['title']}\n\n{message['description']}"
            }
            
            response = sns_client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(sns_message),
                MessageStructure='json',
                Subject=f"[{message['severity'].upper()}] {message['title']}"
            )
            
            return 'MessageId' in response
            
        except ClientError as e:
            self.logger.error(f"Failed to send SNS notification: {e}")
            return False
    
    async def _send_pagerduty_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send PagerDuty notification"""
        try:
            integration_key = config.config.get("integration_key")
            
            if not integration_key:
                self.logger.error("Missing PagerDuty integration key")
                return False
            
            pagerduty_message = {
                "routing_key": integration_key,
                "event_action": "trigger",
                "dedup_key": message.get('alert_id', str(uuid4())),
                "payload": {
                    "summary": message['title'],
                    "source": message.get('source', 'AI Honeypot System'),
                    "severity": message['severity'],
                    "component": "honeypot",
                    "group": "security",
                    "class": "alert",
                    "custom_details": {
                        "description": message['description'],
                        "alert_id": message.get('alert_id', 'N/A'),
                        "created_at": message.get('created_at', datetime.utcnow().isoformat())
                    }
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=pagerduty_message
                ) as response:
                    return response.status == 202
            
        except Exception as e:
            self.logger.error(f"Failed to send PagerDuty notification: {e}")
            return False
    
    async def _send_sms_notification(self, config: NotificationConfig, message: Dict[str, Any]) -> bool:
        """Send SMS notification"""
        try:
            # This would typically use AWS SNS SMS or Twilio
            # For now, we'll use SNS SMS
            phone_numbers = config.config.get("phone_numbers", [])
            region = config.config.get("region", "us-east-1")
            
            if not phone_numbers:
                self.logger.error("Missing SMS phone numbers")
                return False
            
            sns_client = boto3.client('sns', region_name=region)
            
            sms_message = f"[{message['severity'].upper()}] {message['title']}: {message['description'][:100]}..."
            
            success_count = 0
            for phone_number in phone_numbers:
                try:
                    response = sns_client.publish(
                        PhoneNumber=phone_number,
                        Message=sms_message
                    )
                    if 'MessageId' in response:
                        success_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to send SMS to {phone_number}: {e}")
            
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Failed to send SMS notification: {e}")
            return False
    
    # Background Tasks
    async def _monitor_system_events(self):
        """Monitor system events and trigger alerts"""
        while True:
            try:
                # Check for system events that should trigger alerts
                if self.coordinator_agent:
                    # Get system status
                    status = await self.coordinator_agent.get_system_status_tool()
                    
                    # Check for critical conditions
                    await self._check_system_health_alerts(status)
                    await self._check_honeypot_alerts(status)
                    await self._check_threat_alerts(status)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring system events: {e}")
                await asyncio.sleep(60)
    
    async def _process_escalations(self):
        """Process alert escalations"""
        while True:
            try:
                current_time = datetime.utcnow()
                
                for alert in self.active_alerts.values():
                    if alert.status == AlertStatus.ACTIVE:
                        rule = self.alert_rules.get(alert.rule_id)
                        if rule and rule.escalation_enabled:
                            # Check if escalation is due
                            created_time = datetime.fromisoformat(alert.created_at)
                            time_since_created = (current_time - created_time).total_seconds() / 60
                            
                            if time_since_created > rule.escalation_timeout_minutes:
                                await self._escalate_alert(alert)
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error processing escalations: {e}")
                await asyncio.sleep(300)
    
    async def _cleanup_old_alerts(self):
        """Clean up old alerts"""
        while True:
            try:
                cutoff_date = datetime.utcnow() - timedelta(days=self.alert_retention_days)
                
                # Clean up alert history
                self.alert_history = [
                    alert for alert in self.alert_history
                    if datetime.fromisoformat(alert.created_at) > cutoff_date
                ]
                
                await asyncio.sleep(86400)  # Check daily
                
            except Exception as e:
                self.logger.error(f"Error cleaning up old alerts: {e}")
                await asyncio.sleep(86400)
    
    async def _health_check_notifications(self):
        """Perform health checks on notification channels"""
        while True:
            try:
                for config_id, config in self.notification_configs.items():
                    if config.enabled:
                        # Perform basic health check
                        # This could be expanded to actually test each channel
                        pass
                
                await asyncio.sleep(3600)  # Check hourly
                
            except Exception as e:
                self.logger.error(f"Error in notification health check: {e}")
                await asyncio.sleep(3600)
    
    # Helper Methods
    async def _check_rate_limit(self, config: NotificationConfig) -> bool:
        """Check if notification is within rate limit"""
        try:
            config_key = f"{config.channel.value}_{id(config)}"
            current_time = datetime.utcnow()
            
            # Initialize if not exists
            if config_key not in self.notification_counts:
                self.notification_counts[config_key] = []
            
            # Remove old entries (older than 1 hour)
            cutoff_time = current_time - timedelta(hours=1)
            self.notification_counts[config_key] = [
                timestamp for timestamp in self.notification_counts[config_key]
                if timestamp > cutoff_time
            ]
            
            # Check rate limit
            if len(self.notification_counts[config_key]) >= config.rate_limit_per_hour:
                return False
            
            # Add current notification
            self.notification_counts[config_key].append(current_time)
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking rate limit: {e}")
            return True  # Allow notification on error
    
    async def _is_alert_suppressed(self, rule_id: str, source_data: Dict[str, Any]) -> bool:
        """Check if alert should be suppressed"""
        try:
            # Check for similar recent alerts
            rule = self.alert_rules[rule_id]
            current_time = datetime.utcnow()
            
            for alert in self.active_alerts.values():
                if alert.rule_id == rule_id and alert.status == AlertStatus.SUPPRESSED:
                    suppressed_until_str = alert.source_data.get("suppressed_until")
                    if suppressed_until_str:
                        suppressed_until = datetime.fromisoformat(suppressed_until_str)
                        if current_time < suppressed_until:
                            return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking alert suppression: {e}")
            return False
    
    async def _escalate_alert(self, alert: Alert):
        """Escalate an alert to the next level"""
        try:
            # Determine next escalation level
            current_level = alert.escalation_level
            next_level = None
            
            if current_level == EscalationLevel.LEVEL_1:
                next_level = EscalationLevel.LEVEL_2
            elif current_level == EscalationLevel.LEVEL_2:
                next_level = EscalationLevel.LEVEL_3
            elif current_level == EscalationLevel.LEVEL_3:
                next_level = EscalationLevel.LEVEL_4
            
            if next_level:
                alert.escalation_level = next_level
                alert.updated_at = datetime.utcnow().isoformat()
                
                # Send escalation notifications
                await self._send_escalation_notifications(alert)
                
                self.logger.info(f"Escalated alert {alert.alert_id} to {next_level.value}")
            
        except Exception as e:
            self.logger.error(f"Error escalating alert: {e}")
    
    async def _send_escalation_notifications(self, alert: Alert):
        """Send escalation notifications"""
        try:
            message = {
                "alert_id": alert.alert_id,
                "title": f"ESCALATED: {alert.title}",
                "description": f"Alert escalated to {alert.escalation_level.value}",
                "severity": alert.severity.value,
                "escalation_level": alert.escalation_level.value,
                "created_at": alert.created_at
            }
            
            # Send to channels configured for this escalation level
            for config in self.notification_configs.values():
                if (config.enabled and 
                    alert.escalation_level in config.escalation_levels and
                    await self._check_rate_limit(config)):
                    
                    await self._send_notification(config, message)
            
        except Exception as e:
            self.logger.error(f"Error sending escalation notifications: {e}")
    
    async def _schedule_escalation(self, alert_id: str, timeout_minutes: int):
        """Schedule alert escalation"""
        try:
            await asyncio.sleep(timeout_minutes * 60)
            
            if alert_id in self.active_alerts:
                alert = self.active_alerts[alert_id]
                if alert.status == AlertStatus.ACTIVE:
                    await self._escalate_alert(alert)
            
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Error in scheduled escalation: {e}")
    
    async def _schedule_unsuppression(self, alert_id: str, duration_minutes: int):
        """Schedule alert unsuppression"""
        try:
            await asyncio.sleep(duration_minutes * 60)
            
            if alert_id in self.active_alerts:
                alert = self.active_alerts[alert_id]
                if alert.status == AlertStatus.SUPPRESSED:
                    alert.status = AlertStatus.ACTIVE
                    alert.updated_at = datetime.utcnow().isoformat()
                    
                    # Remove suppression data
                    alert.source_data.pop("suppressed_by", None)
                    alert.source_data.pop("suppressed_until", None)
                    
                    self.logger.info(f"Alert {alert_id} unsuppressed")
            
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Error in scheduled unsuppression: {e}")
    
    async def _check_system_health_alerts(self, status: Dict[str, Any]):
        """Check for system health alerts"""
        try:
            # Check for system emergency state
            if status.get("system_status") == "emergency":
                await self.create_alert(
                    rule_id="system_emergency",
                    title="System Emergency State",
                    description="The honeypot system has entered emergency state",
                    source="system_monitor",
                    source_data=status
                )
            
            # Check for failed agents
            agent_health = status.get("agent_health", {})
            failed_agents = [agent for agent, health in agent_health.items() if health == "failed"]
            
            if failed_agents:
                await self.create_alert(
                    rule_id="agent_failure",
                    title="Agent Failure Detected",
                    description=f"Failed agents: {', '.join(failed_agents)}",
                    source="agent_monitor",
                    source_data={"failed_agents": failed_agents}
                )
            
        except Exception as e:
            self.logger.error(f"Error checking system health alerts: {e}")
    
    async def _check_honeypot_alerts(self, status: Dict[str, Any]):
        """Check for honeypot-related alerts"""
        try:
            total_honeypots = status.get("total_honeypots", 0)
            
            # Check for high honeypot count
            if total_honeypots > 15:
                await self.create_alert(
                    rule_id="high_honeypot_count",
                    title="High Honeypot Count",
                    description=f"Unusually high number of active honeypots: {total_honeypots}",
                    source="honeypot_monitor",
                    source_data={"honeypot_count": total_honeypots}
                )
            
        except Exception as e:
            self.logger.error(f"Error checking honeypot alerts: {e}")
    
    async def _check_threat_alerts(self, status: Dict[str, Any]):
        """Check for threat-related alerts"""
        try:
            # This would check for high-severity threats, sophisticated attacks, etc.
            # Implementation would depend on threat intelligence data structure
            pass
            
        except Exception as e:
            self.logger.error(f"Error checking threat alerts: {e}")
    
    def _initialize_default_configs(self):
        """Initialize default alert rules and configurations"""
        try:
            # Create default alert rules
            default_rules = [
                {
                    "name": "System Emergency",
                    "description": "Alert when system enters emergency state",
                    "severity": AlertSeverity.CRITICAL,
                    "conditions": {"system_status": "emergency"},
                    "notification_channels": [NotificationChannel.EMAIL, NotificationChannel.SLACK]
                },
                {
                    "name": "Agent Failure",
                    "description": "Alert when agents fail",
                    "severity": AlertSeverity.HIGH,
                    "conditions": {"agent_health": "failed"},
                    "notification_channels": [NotificationChannel.EMAIL, NotificationChannel.SLACK]
                },
                {
                    "name": "High Threat Activity",
                    "description": "Alert for high-severity threat activity",
                    "severity": AlertSeverity.HIGH,
                    "conditions": {"threat_score": ">0.8"},
                    "notification_channels": [NotificationChannel.EMAIL]
                }
            ]
            
            for rule_config in default_rules:
                rule_id = str(uuid4())
                rule = AlertRule(
                    rule_id=rule_id,
                    name=rule_config["name"],
                    description=rule_config["description"],
                    severity=rule_config["severity"],
                    conditions=rule_config["conditions"],
                    enabled=True,
                    notification_channels=rule_config["notification_channels"],
                    escalation_enabled=True,
                    escalation_timeout_minutes=self.default_escalation_timeout,
                    suppression_duration_minutes=60,
                    created_at=datetime.utcnow().isoformat(),
                    updated_at=datetime.utcnow().isoformat()
                )
                
                self.alert_rules[rule_id] = rule
            
            self.logger.info("Initialized default alert configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize default configs: {e}")