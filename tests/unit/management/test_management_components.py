"""
Unit tests for management components
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json

from management.dashboard import DashboardManager
from management.reporting import ReportingManager
from management.alerting import AlertingManager


@pytest.mark.unit
@pytest.mark.management
class TestDashboardManager:
    """Test Dashboard Manager functionality"""

    def test_initialization(self):
        """Test Dashboard Manager initialization"""
        config = {
            "dashboard_port": 8080,
            "real_time_updates": True,
            "authentication_required": True
        }
        
        manager = DashboardManager(config)
        assert manager.config == config
        assert manager.dashboard_port == 8080
        assert manager.real_time_updates is True

    async def test_get_system_status(self):
        """Test system status retrieval"""
        manager = DashboardManager({})
        
        status = await manager.get_system_status()
        
        assert "agents" in status
        assert "honeypots" in status
        assert "system_health" in status
        assert "timestamp" in status

    async def test_get_active_sessions(self):
        """Test active session retrieval"""
        manager = DashboardManager({})
        
        sessions = await manager.get_active_sessions()
        
        assert "active_sessions" in sessions
        assert "total_count" in sessions
        assert isinstance(sessions["active_sessions"], list)

    async def test_get_threat_statistics(self):
        """Test threat statistics retrieval"""
        manager = DashboardManager({})
        
        stats = await manager.get_threat_statistics("24h")
        
        assert "total_threats" in stats
        assert "threat_types" in stats
        assert "confidence_distribution" in stats
        assert "time_range" in stats

    async def test_get_honeypot_metrics(self):
        """Test honeypot metrics retrieval"""
        manager = DashboardManager({})
        
        metrics = await manager.get_honeypot_metrics()
        
        assert "honeypot_status" in metrics
        assert "interaction_counts" in metrics
        assert "performance_metrics" in metrics

    async def test_generate_dashboard_data(self):
        """Test dashboard data generation"""
        manager = DashboardManager({})
        
        dashboard_data = await manager.generate_dashboard_data()
        
        assert "system_overview" in dashboard_data
        assert "recent_activities" in dashboard_data
        assert "alerts" in dashboard_data
        assert "performance_charts" in dashboard_data

    async def test_real_time_updates(self):
        """Test real-time dashboard updates"""
        manager = DashboardManager({"real_time_updates": True})
        
        # Simulate real-time event
        event_data = {
            "type": "new_session",
            "session_id": "session-123",
            "honeypot_type": "ssh",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await manager.process_real_time_event(event_data)
        
        assert result["processed"] is True
        assert "update_id" in result

    async def test_user_authentication(self):
        """Test dashboard user authentication"""
        manager = DashboardManager({"authentication_required": True})
        
        # Test valid credentials
        auth_result = await manager.authenticate_user("admin", "secure_password")
        assert auth_result["authenticated"] is True
        assert "session_token" in auth_result
        
        # Test invalid credentials
        invalid_result = await manager.authenticate_user("admin", "wrong_password")
        assert invalid_result["authenticated"] is False

    async def test_session_management(self):
        """Test dashboard session management"""
        manager = DashboardManager({})
        
        # Create session
        session_result = await manager.create_user_session("admin")
        assert session_result["session_created"] is True
        assert "session_id" in session_result
        
        # Validate session
        validation_result = await manager.validate_session(session_result["session_id"])
        assert validation_result["valid"] is True


@pytest.mark.unit
@pytest.mark.management
class TestReportingManager:
    """Test Reporting Manager functionality"""

    def test_initialization(self):
        """Test Reporting Manager initialization"""
        config = {
            "report_formats": ["json", "pdf", "csv"],
            "automated_reports": True,
            "report_retention_days": 90
        }
        
        manager = ReportingManager(config)
        assert manager.config == config
        assert "json" in manager.report_formats
        assert manager.automated_reports is True

    async def test_generate_intelligence_report(self):
        """Test intelligence report generation"""
        manager = ReportingManager({})
        
        report_params = {
            "time_range": "24h",
            "include_mitre_mapping": True,
            "include_iocs": True,
            "format": "json"
        }
        
        report = await manager.generate_intelligence_report(report_params)
        
        assert "report_id" in report
        assert "executive_summary" in report
        assert "threat_analysis" in report
        assert "mitre_techniques" in report
        assert "iocs" in report

    async def test_generate_system_health_report(self):
        """Test system health report generation"""
        manager = ReportingManager({})
        
        report_params = {
            "time_range": "7d",
            "include_performance_metrics": True,
            "include_error_analysis": True
        }
        
        report = await manager.generate_system_health_report(report_params)
        
        assert "report_id" in report
        assert "system_status" in report
        assert "performance_metrics" in report
        assert "error_analysis" in report

    async def test_generate_honeypot_activity_report(self):
        """Test honeypot activity report generation"""
        manager = ReportingManager({})
        
        report_params = {
            "honeypot_types": ["ssh", "web_admin", "database"],
            "time_range": "30d",
            "include_session_details": True
        }
        
        report = await manager.generate_honeypot_activity_report(report_params)
        
        assert "report_id" in report
        assert "activity_summary" in report
        assert "session_statistics" in report
        assert "interaction_patterns" in report

    async def test_export_report(self):
        """Test report export functionality"""
        manager = ReportingManager({})
        
        # Generate a report first
        report = await manager.generate_intelligence_report({"time_range": "24h"})
        
        # Export in different formats
        export_formats = ["json", "pdf", "csv"]
        
        for format_type in export_formats:
            export_result = await manager.export_report(report["report_id"], format_type)
            
            assert export_result["exported"] is True
            assert export_result["format"] == format_type
            assert "file_path" in export_result or "download_url" in export_result

    async def test_schedule_automated_report(self):
        """Test automated report scheduling"""
        manager = ReportingManager({"automated_reports": True})
        
        schedule_config = {
            "report_type": "intelligence_summary",
            "frequency": "daily",
            "time": "08:00",
            "recipients": ["admin@company.com"],
            "format": "pdf"
        }
        
        result = await manager.schedule_automated_report(schedule_config)
        
        assert result["scheduled"] is True
        assert "schedule_id" in result

    async def test_report_template_management(self):
        """Test report template management"""
        manager = ReportingManager({})
        
        # Create custom template
        template_config = {
            "name": "custom_intelligence_report",
            "sections": ["executive_summary", "threat_landscape", "recommendations"],
            "format": "json",
            "styling": {"theme": "corporate"}
        }
        
        create_result = await manager.create_report_template(template_config)
        assert create_result["created"] is True
        assert "template_id" in create_result
        
        # Use template for report generation
        report_result = await manager.generate_report_from_template(
            create_result["template_id"],
            {"time_range": "24h"}
        )
        assert report_result["report_id"] is not None

    async def test_report_analytics(self):
        """Test report analytics and insights"""
        manager = ReportingManager({})
        
        analytics_params = {
            "time_range": "30d",
            "report_types": ["intelligence", "system_health"],
            "include_trends": True
        }
        
        analytics = await manager.generate_report_analytics(analytics_params)
        
        assert "report_statistics" in analytics
        assert "usage_trends" in analytics
        assert "popular_reports" in analytics


@pytest.mark.unit
@pytest.mark.management
class TestAlertingManager:
    """Test Alerting Manager functionality"""

    def test_initialization(self):
        """Test Alerting Manager initialization"""
        config = {
            "alert_channels": ["email", "sns", "webhook"],
            "escalation_enabled": True,
            "alert_retention_days": 30
        }
        
        manager = AlertingManager(config)
        assert manager.config == config
        assert "email" in manager.alert_channels
        assert manager.escalation_enabled is True

    async def test_create_alert(self):
        """Test alert creation"""
        manager = AlertingManager({})
        
        alert_data = {
            "type": "security_incident",
            "severity": "high",
            "title": "Real data detected in honeypot",
            "description": "Potential real credentials found in SSH session",
            "source": "security_manager",
            "metadata": {
                "session_id": "session-123",
                "honeypot_type": "ssh"
            }
        }
        
        result = await manager.create_alert(alert_data)
        
        assert result["alert_created"] is True
        assert "alert_id" in result
        assert result["severity"] == "high"

    async def test_process_alert_rules(self):
        """Test alert rule processing"""
        manager = AlertingManager({})
        
        # Define alert rules
        rules = [
            {
                "name": "high_confidence_threat",
                "condition": "confidence > 0.9",
                "action": "immediate_notification",
                "channels": ["email", "sns"]
            },
            {
                "name": "real_data_detection",
                "condition": "event_type == 'real_data_detected'",
                "action": "escalate",
                "channels": ["email", "webhook"]
            }
        ]
        
        # Test event that matches rules
        event_data = {
            "event_type": "real_data_detected",
            "confidence": 0.95,
            "severity": "critical"
        }
        
        result = await manager.process_alert_rules(event_data, rules)
        
        assert result["rules_matched"] > 0
        assert result["alerts_generated"] > 0

    async def test_send_notification(self):
        """Test notification sending"""
        manager = AlertingManager({})
        
        notification_data = {
            "alert_id": "alert-123",
            "channel": "email",
            "recipients": ["admin@company.com"],
            "subject": "Security Alert: Real Data Detected",
            "message": "Immediate attention required for security incident"
        }
        
        result = await manager.send_notification(notification_data)
        
        assert result["sent"] is True
        assert result["channel"] == "email"
        assert "delivery_id" in result

    async def test_escalation_workflow(self):
        """Test alert escalation workflow"""
        manager = AlertingManager({"escalation_enabled": True})
        
        escalation_config = {
            "alert_id": "alert-123",
            "escalation_levels": [
                {"level": 1, "delay_minutes": 5, "recipients": ["team-lead@company.com"]},
                {"level": 2, "delay_minutes": 15, "recipients": ["manager@company.com"]},
                {"level": 3, "delay_minutes": 30, "recipients": ["director@company.com"]}
            ]
        }
        
        result = await manager.initiate_escalation(escalation_config)
        
        assert result["escalation_initiated"] is True
        assert "escalation_id" in result

    async def test_alert_acknowledgment(self):
        """Test alert acknowledgment"""
        manager = AlertingManager({})
        
        # Create an alert first
        alert_result = await manager.create_alert({
            "type": "test_alert",
            "severity": "medium",
            "title": "Test Alert"
        })
        
        # Acknowledge the alert
        ack_result = await manager.acknowledge_alert(
            alert_result["alert_id"],
            "admin",
            "Investigating the issue"
        )
        
        assert ack_result["acknowledged"] is True
        assert ack_result["acknowledged_by"] == "admin"

    async def test_alert_resolution(self):
        """Test alert resolution"""
        manager = AlertingManager({})
        
        # Create and acknowledge an alert
        alert_result = await manager.create_alert({
            "type": "test_alert",
            "severity": "low",
            "title": "Test Alert"
        })
        
        await manager.acknowledge_alert(alert_result["alert_id"], "admin", "Working on it")
        
        # Resolve the alert
        resolution_result = await manager.resolve_alert(
            alert_result["alert_id"],
            "admin",
            "Issue resolved - false positive"
        )
        
        assert resolution_result["resolved"] is True
        assert resolution_result["resolved_by"] == "admin"

    async def test_alert_metrics(self):
        """Test alert metrics and statistics"""
        manager = AlertingManager({})
        
        metrics = await manager.get_alert_metrics("24h")
        
        assert "total_alerts" in metrics
        assert "alerts_by_severity" in metrics
        assert "alerts_by_type" in metrics
        assert "response_times" in metrics
        assert "resolution_rates" in metrics


@pytest.mark.unit
@pytest.mark.management
class TestManagementIntegration:
    """Test management component integration"""

    async def test_dashboard_reporting_integration(self):
        """Test dashboard and reporting integration"""
        dashboard = DashboardManager({})
        reporting = ReportingManager({})
        
        # Get dashboard data
        dashboard_data = await dashboard.generate_dashboard_data()
        
        # Generate report based on dashboard insights
        report_params = {
            "time_range": "24h",
            "dashboard_insights": dashboard_data["system_overview"]
        }
        
        report = await reporting.generate_intelligence_report(report_params)
        
        assert report["report_id"] is not None
        assert "executive_summary" in report

    async def test_alerting_dashboard_integration(self):
        """Test alerting and dashboard integration"""
        alerting = AlertingManager({})
        dashboard = DashboardManager({"real_time_updates": True})
        
        # Create an alert
        alert_result = await alerting.create_alert({
            "type": "system_performance",
            "severity": "medium",
            "title": "High CPU usage detected"
        })
        
        # Process alert as real-time dashboard event
        dashboard_result = await dashboard.process_real_time_event({
            "type": "new_alert",
            "alert_id": alert_result["alert_id"],
            "severity": "medium"
        })
        
        assert dashboard_result["processed"] is True

    async def test_comprehensive_management_workflow(self):
        """Test comprehensive management workflow"""
        dashboard = DashboardManager({})
        reporting = ReportingManager({})
        alerting = AlertingManager({})
        
        # 1. Monitor system through dashboard
        system_status = await dashboard.get_system_status()
        
        # 2. Generate alert if issues detected
        if system_status["system_health"]["status"] != "healthy":
            alert_result = await alerting.create_alert({
                "type": "system_health",
                "severity": "medium",
                "title": "System health degraded",
                "metadata": system_status
            })
            assert alert_result["alert_created"] is True
        
        # 3. Generate periodic report
        report_result = await reporting.generate_system_health_report({
            "time_range": "24h",
            "include_alerts": True
        })
        assert report_result["report_id"] is not None
        
        # 4. Update dashboard with latest information
        dashboard_update = await dashboard.generate_dashboard_data()
        assert "recent_activities" in dashboard_update

    async def test_automated_management_processes(self):
        """Test automated management processes"""
        reporting = ReportingManager({"automated_reports": True})
        alerting = AlertingManager({"escalation_enabled": True})
        
        # Schedule automated reporting
        schedule_result = await reporting.schedule_automated_report({
            "report_type": "daily_summary",
            "frequency": "daily",
            "time": "09:00"
        })
        assert schedule_result["scheduled"] is True
        
        # Set up automated alert escalation
        escalation_result = await alerting.initiate_escalation({
            "alert_id": "test-alert",
            "escalation_levels": [
                {"level": 1, "delay_minutes": 5, "recipients": ["team@company.com"]}
            ]
        })
        assert escalation_result["escalation_initiated"] is True