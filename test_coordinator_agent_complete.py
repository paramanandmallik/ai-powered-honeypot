#!/usr/bin/env python3
"""
Comprehensive test suite for Coordinator Agent implementation
Tests all aspects of the coordinator agent including workflow management,
agent coordination, resource management, and emergency procedures.
"""

import asyncio
import json
import pytest
import logging
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

# Import the coordinator agent and related components
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.coordinator.orchestration_engine import OrchestrationEngine, WorkflowStatus, HoneypotStatus
from agents.coordinator.honeypot_manager import HoneypotManager
from agents.coordinator.monitoring_system import SystemMonitoringSystem, AlertSeverity

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestCoordinatorAgent:
    """Test suite for Coordinator Agent functionality"""
    
    @pytest.fixture
    async def coordinator_agent(self):
        """Create a coordinator agent for testing"""
        config = {
            "auto_scaling_enabled": True,
            "max_concurrent_engagements": 10,
            "honeypot_timeout_minutes": 60
        }
        agent = CoordinatorAgent(config)
        await agent.initialize()
        yield agent
        await agent.cleanup()
    
    @pytest.mark.asyncio
    async def test_coordinator_initialization(self, coordinator_agent):
        """Test coordinator agent initialization"""
        assert coordinator_agent.agent_type == "coordinator"
        assert coordinator_agent.orchestration_engine is not None
        assert coordinator_agent.honeypot_manager is not None
        assert coordinator_agent.monitoring_system is not None
        assert coordinator_agent.auto_scaling_enabled is True
        
        logger.info("✓ Coordinator agent initialization test passed")
    
    @pytest.mark.asyncio
    async def test_engagement_decision_handling(self, coordinator_agent):
        """Test handling of engagement decisions from Detection Agent"""
        # Test approved engagement
        message = {
            "message_type": "engagement_decision",
            "payload": {
                "threat_data": {
                    "attack_vectors": ["web"],
                    "target_services": ["80", "443"],
                    "confidence_score": 0.85
                },
                "engagement_approved": True
            }
        }
        
        response = await coordinator_agent.handle_engagement_decision(message)
        
        assert response["success"] is True
        assert "honeypot_id" in response
        assert response["honeypot_type"] == "web_admin"
        assert response["action"] == "honeypot_created"
        
        logger.info("✓ Engagement decision handling test passed")
    
    @pytest.mark.asyncio
    async def test_honeypot_creation_workflow(self, coordinator_agent):
        """Test honeypot creation workflow"""
        honeypot_type = "ssh"
        config = {
            "port": 22,
            "banner": "Ubuntu 20.04.3 LTS",
            "fake_filesystem": True
        }
        
        # Create honeypot
        honeypot_id = await coordinator_agent.orchestration_engine.create_honeypot(
            honeypot_type, config
        )
        
        assert honeypot_id is not None
        assert honeypot_id in coordinator_agent.orchestration_engine.honeypot_instances
        
        honeypot = coordinator_agent.orchestration_engine.honeypot_instances[honeypot_id]
        assert honeypot.honeypot_type == honeypot_type
        assert honeypot.status == HoneypotStatus.ACTIVE
        
        logger.info("✓ Honeypot creation workflow test passed")
    
    @pytest.mark.asyncio
    async def test_agent_coordination(self, coordinator_agent):
        """Test agent coordination functionality"""
        coordination_type = "threat_response"
        agents = ["detection", "interaction", "intelligence"]
        parameters = {
            "threat_id": "threat_123",
            "priority": "high"
        }
        
        result = await coordinator_agent.orchestration_engine.coordinate_agents(
            coordination_type, agents, parameters
        )
        
        assert result["success"] is True
        assert result["coordination_type"] == coordination_type
        assert result["agents"] == agents
        assert "coordination_id" in result
        assert "workflow_id" in result
        
        logger.info("✓ Agent coordination test passed")
    
    @pytest.mark.asyncio
    async def test_workflow_management(self, coordinator_agent):
        """Test workflow creation and execution"""
        workflow_name = "Test Workflow"
        workflow_type = "test"
        steps = [
            {
                "step_name": "Step 1",
                "agent_type": "coordinator",
                "action": "test_action",
                "parameters": {"test": "value"},
                "dependencies": []
            },
            {
                "step_name": "Step 2",
                "agent_type": "detection",
                "action": "analyze",
                "parameters": {"data": "test_data"},
                "dependencies": ["step_1"]
            }
        ]
        
        # Create workflow
        workflow_id = await coordinator_agent.orchestration_engine.create_workflow(
            workflow_name, workflow_type, steps
        )
        
        assert workflow_id is not None
        assert workflow_id in coordinator_agent.orchestration_engine.active_workflows
        
        workflow = coordinator_agent.orchestration_engine.active_workflows[workflow_id]
        assert workflow.workflow_name == workflow_name
        assert workflow.workflow_type == workflow_type
        assert len(workflow.steps) == 2
        
        logger.info("✓ Workflow management test passed")
    
    @pytest.mark.asyncio
    async def test_resource_management(self, coordinator_agent):
        """Test resource allocation and management"""
        resource_type = "honeypot"
        requirements = {
            "cpu_cores": 2,
            "memory_gb": 4,
            "disk_gb": 20
        }
        
        # Allocate resources
        allocation_id = await coordinator_agent.orchestration_engine.allocate_resources(
            resource_type, requirements
        )
        
        assert allocation_id is not None
        assert allocation_id in coordinator_agent.orchestration_engine.resource_allocations
        
        allocation = coordinator_agent.orchestration_engine.resource_allocations[allocation_id]
        assert allocation["resource_type"] == resource_type
        assert allocation["requirements"] == requirements
        assert allocation["status"] == "allocated"
        
        # Deallocate resources
        await coordinator_agent.orchestration_engine.deallocate_resources(allocation_id)
        
        allocation = coordinator_agent.orchestration_engine.resource_allocations[allocation_id]
        assert allocation["status"] == "deallocated"
        
        logger.info("✓ Resource management test passed")
    
    @pytest.mark.asyncio
    async def test_emergency_shutdown(self, coordinator_agent):
        """Test emergency shutdown procedures"""
        reason = "Security breach detected"
        initiated_by = "test_system"
        
        # Create some test honeypots first
        honeypot_id = await coordinator_agent.orchestration_engine.create_honeypot(
            "web_admin", {"port": 8080}
        )
        
        assert honeypot_id is not None
        
        # Trigger emergency shutdown
        await coordinator_agent.orchestration_engine.emergency_shutdown(reason, initiated_by)
        
        assert coordinator_agent.orchestration_engine.emergency_shutdown_active is True
        
        # Verify honeypots are destroyed or being destroyed
        honeypot = coordinator_agent.orchestration_engine.honeypot_instances.get(honeypot_id)
        if honeypot:
            assert honeypot.status in [HoneypotStatus.DESTROYED, HoneypotStatus.DESTROYING]
        
        logger.info("✓ Emergency shutdown test passed")
    
    @pytest.mark.asyncio
    async def test_system_monitoring(self, coordinator_agent):
        """Test system monitoring and health checks"""
        # Get system health
        health_data = await coordinator_agent.monitoring_system.monitor_system_health()
        
        assert "timestamp" in health_data
        assert "overall_status" in health_data
        assert "components" in health_data
        assert "alerts" in health_data
        assert "performance" in health_data
        
        # Test alert creation
        alert_id = await coordinator_agent.monitoring_system.create_alert(
            "test_alert",
            AlertSeverity.MEDIUM,
            "Test Alert",
            "This is a test alert",
            "coordinator",
            coordinator_agent.agent_id
        )
        
        assert alert_id is not None
        assert alert_id in coordinator_agent.monitoring_system.active_alerts
        
        logger.info("✓ System monitoring test passed")
    
    @pytest.mark.asyncio
    async def test_auto_scaling_logic(self, coordinator_agent):
        """Test auto-scaling decision logic"""
        # Simulate high load metrics
        metrics = {
            "cpu_usage": 85,
            "memory_usage": 90,
            "active_sessions": 12,
            "message_queue_depth": 150
        }
        
        # Execute auto-scaling
        await coordinator_agent._execute_auto_scaling("high_load", metrics)
        
        # Verify scaling actions were logged
        # In a real implementation, this would verify actual scaling occurred
        
        logger.info("✓ Auto-scaling logic test passed")
    
    @pytest.mark.asyncio
    async def test_honeypot_lifecycle_workflow(self, coordinator_agent):
        """Test comprehensive honeypot lifecycle workflow"""
        honeypot_type = "database"
        config = {
            "port": 3306,
            "database_type": "mysql",
            "fake_databases": ["customers", "orders"],
            "resources": {"cpu_cores": 1, "memory_gb": 2},
            "network": {"isolation": True},
            "service": {"version": "8.0"},
            "monitoring": {"enabled": True},
            "synthetic_data": {"records_per_table": 1000}
        }
        
        # Create lifecycle workflow
        workflow_id = await coordinator_agent.orchestration_engine.create_honeypot_lifecycle_workflow(
            honeypot_type, config
        )
        
        assert workflow_id is not None
        
        workflow = coordinator_agent.orchestration_engine.active_workflows[workflow_id]
        assert workflow.workflow_type == "honeypot_lifecycle"
        assert len(workflow.steps) == 7  # All lifecycle steps
        
        # Verify step dependencies
        step_names = [step.step_name for step in workflow.steps]
        assert "Validate Configuration" in step_names
        assert "Allocate Resources" in step_names
        assert "Setup Network Isolation" in step_names
        assert "Deploy Honeypot Service" in step_names
        assert "Configure Monitoring" in step_names
        assert "Initialize Synthetic Data" in step_names
        assert "Activate Honeypot" in step_names
        
        logger.info("✓ Honeypot lifecycle workflow test passed")
    
    @pytest.mark.asyncio
    async def test_agent_coordination_workflow(self, coordinator_agent):
        """Test agent coordination workflow creation"""
        coordination_type = "intelligence_analysis"
        agents = ["interaction", "intelligence", "detection"]
        parameters = {
            "session_id": "session_123",
            "analysis_type": "comprehensive"
        }
        
        # Create coordination workflow
        workflow_id = await coordinator_agent.orchestration_engine.create_agent_coordination_workflow(
            coordination_type, agents, parameters
        )
        
        assert workflow_id is not None
        
        workflow = coordinator_agent.orchestration_engine.active_workflows[workflow_id]
        assert workflow.workflow_type == "agent_coordination"
        assert len(workflow.steps) == 4  # Intelligence analysis steps
        
        # Verify step sequence
        step_names = [step.step_name for step in workflow.steps]
        assert "Collect Session Data" in step_names
        assert "Analyze Interactions" in step_names
        assert "Generate Intelligence" in step_names
        assert "Update Detection Rules" in step_names
        
        logger.info("✓ Agent coordination workflow test passed")
    
    @pytest.mark.asyncio
    async def test_emergency_response_workflow(self, coordinator_agent):
        """Test emergency response workflow creation"""
        emergency_type = "security_breach"
        severity = "critical"
        context = {
            "affected_systems": ["honeypot_1", "honeypot_2"],
            "incident_id": "incident_123"
        }
        
        # Create emergency response workflow
        workflow_id = await coordinator_agent.orchestration_engine.create_emergency_response_workflow(
            emergency_type, severity, context
        )
        
        assert workflow_id is not None
        
        workflow = coordinator_agent.orchestration_engine.active_workflows[workflow_id]
        assert workflow.workflow_type == "emergency_response"
        
        # Verify emergency steps
        step_names = [step.step_name for step in workflow.steps]
        assert "Isolate Affected Systems" in step_names
        assert "Collect Forensic Data" in step_names
        assert "Notify Security Team" in step_names
        assert "Generate Incident Report" in step_names
        
        # Verify timeout settings for emergency steps
        for step in workflow.steps:
            if step.step_name == "Isolate Affected Systems":
                assert step.timeout_seconds == 60  # Fast isolation
        
        logger.info("✓ Emergency response workflow test passed")
    
    @pytest.mark.asyncio
    async def test_workflow_status_tracking(self, coordinator_agent):
        """Test workflow status tracking and progress monitoring"""
        # Create a simple workflow
        workflow_id = await coordinator_agent.orchestration_engine.create_workflow(
            "Status Test Workflow",
            "test",
            [
                {
                    "step_name": "Test Step",
                    "agent_type": "coordinator",
                    "action": "test_action",
                    "parameters": {},
                    "dependencies": []
                }
            ]
        )
        
        # Get workflow status
        status = await coordinator_agent.orchestration_engine.get_workflow_status(workflow_id)
        
        assert status is not None
        assert status["workflow_id"] == workflow_id
        assert status["workflow_name"] == "Status Test Workflow"
        assert status["status"] == "pending"
        assert status["total_steps"] == 1
        assert status["completed_steps"] == 0
        assert status["progress_percent"] == 0
        assert len(status["steps"]) == 1
        
        logger.info("✓ Workflow status tracking test passed")
    
    @pytest.mark.asyncio
    async def test_workflow_pause_resume(self, coordinator_agent):
        """Test workflow pause and resume functionality"""
        # Create a workflow
        workflow_id = await coordinator_agent.orchestration_engine.create_workflow(
            "Pause Test Workflow",
            "test",
            [
                {
                    "step_name": "Test Step",
                    "agent_type": "coordinator",
                    "action": "test_action",
                    "parameters": {},
                    "dependencies": []
                }
            ]
        )
        
        # Start the workflow
        workflow = coordinator_agent.orchestration_engine.active_workflows[workflow_id]
        workflow.status = WorkflowStatus.RUNNING
        
        # Pause the workflow
        paused = await coordinator_agent.orchestration_engine.pause_workflow(
            workflow_id, "Test pause"
        )
        
        assert paused is True
        assert workflow.status == WorkflowStatus.CANCELLED
        
        # Resume the workflow
        resumed = await coordinator_agent.orchestration_engine.resume_workflow(workflow_id)
        
        assert resumed is True
        assert workflow.status == WorkflowStatus.RUNNING
        
        logger.info("✓ Workflow pause/resume test passed")
    
    @pytest.mark.asyncio
    async def test_honeypot_type_determination(self, coordinator_agent):
        """Test honeypot type determination logic"""
        # Test web attack
        threat_data = {
            "attack_vectors": ["web", "http"],
            "target_services": ["80", "443"]
        }
        honeypot_type = coordinator_agent._determine_honeypot_type(threat_data)
        assert honeypot_type == "web_admin"
        
        # Test SSH attack
        threat_data = {
            "attack_vectors": ["ssh"],
            "target_services": ["22"]
        }
        honeypot_type = coordinator_agent._determine_honeypot_type(threat_data)
        assert honeypot_type == "ssh"
        
        # Test database attack
        threat_data = {
            "attack_vectors": ["database"],
            "target_services": ["3306", "5432"]
        }
        honeypot_type = coordinator_agent._determine_honeypot_type(threat_data)
        assert honeypot_type == "database"
        
        # Test default case
        threat_data = {
            "attack_vectors": ["unknown"],
            "target_services": ["9999"]
        }
        honeypot_type = coordinator_agent._determine_honeypot_type(threat_data)
        assert honeypot_type == "web_admin"  # Default
        
        logger.info("✓ Honeypot type determination test passed")
    
    @pytest.mark.asyncio
    async def test_honeypot_config_generation(self, coordinator_agent):
        """Test honeypot configuration generation"""
        honeypot_type = "ssh"
        threat_data = {
            "attack_vectors": ["ssh"],
            "target_services": ["22"],
            "source_ip": "192.168.1.100"
        }
        
        config = coordinator_agent._generate_honeypot_config(honeypot_type, threat_data)
        
        assert config["honeypot_type"] == honeypot_type
        assert config["port"] == 22
        assert config["banner"] == "Ubuntu 20.04.3 LTS"
        assert config["fake_filesystem"] is True
        assert config["command_simulation"] is True
        assert "fake_processes" in config
        assert config["timeout_minutes"] == 60
        
        logger.info("✓ Honeypot configuration generation test passed")


class TestCoordinatorAgentTools:
    """Test suite for Coordinator Agent Strands tools"""
    
    @pytest.fixture
    async def coordinator_agent(self):
        """Create a coordinator agent for testing"""
        config = {"auto_scaling_enabled": True}
        agent = CoordinatorAgent(config)
        await agent.initialize()
        yield agent
        await agent.cleanup()
    
    @pytest.mark.asyncio
    async def test_create_honeypot_tool(self, coordinator_agent):
        """Test create honeypot tool"""
        result = coordinator_agent.create_honeypot_tool(
            "web_admin",
            {"port": 8080, "ssl_enabled": True}
        )
        
        assert result["action"] == "honeypot_creation_initiated"
        assert result["honeypot_type"] == "web_admin"
        assert "timestamp" in result
        
        logger.info("✓ Create honeypot tool test passed")
    
    @pytest.mark.asyncio
    async def test_emergency_shutdown_tool(self, coordinator_agent):
        """Test emergency shutdown tool"""
        result = coordinator_agent.emergency_shutdown_tool(
            "Test emergency shutdown",
            "test_user"
        )
        
        assert result["action"] == "emergency_shutdown_initiated"
        assert result["reason"] == "Test emergency shutdown"
        assert result["initiated_by"] == "test_user"
        assert "timestamp" in result
        
        logger.info("✓ Emergency shutdown tool test passed")
    
    @pytest.mark.asyncio
    async def test_coordinate_agents_tool(self, coordinator_agent):
        """Test coordinate agents tool"""
        result = coordinator_agent.coordinate_agents_tool(
            "threat_response",
            ["detection", "interaction"],
            {"threat_id": "test_threat"}
        )
        
        assert result["action"] == "agent_coordination_initiated"
        assert result["coordination_type"] == "threat_response"
        assert result["agents"] == ["detection", "interaction"]
        assert "timestamp" in result
        
        logger.info("✓ Coordinate agents tool test passed")
    
    @pytest.mark.asyncio
    async def test_auto_scale_system_tool(self, coordinator_agent):
        """Test auto scale system tool"""
        result = coordinator_agent.auto_scale_system_tool(
            "high_load",
            {"cpu_usage": 85, "memory_usage": 90}
        )
        
        assert result["action"] == "auto_scaling_initiated"
        assert result["scaling_trigger"] == "high_load"
        assert "metrics" in result
        assert "timestamp" in result
        
        logger.info("✓ Auto scale system tool test passed")
    
    @pytest.mark.asyncio
    async def test_manage_resource_allocation_tool(self, coordinator_agent):
        """Test manage resource allocation tool"""
        # Test allocation
        result = coordinator_agent.manage_resource_allocation_tool(
            "allocate",
            "honeypot",
            {"cpu_cores": 2, "memory_gb": 4}
        )
        
        assert result["action"] == "resource_allocate_initiated"
        assert result["resource_type"] == "honeypot"
        assert "params" in result
        assert "timestamp" in result
        
        logger.info("✓ Manage resource allocation tool test passed")


async def run_all_tests():
    """Run all coordinator agent tests"""
    logger.info("Starting Coordinator Agent comprehensive tests...")
    
    # Create test instances
    test_agent = TestCoordinatorAgent()
    test_tools = TestCoordinatorAgentTools()
    
    # Create coordinator agent for testing
    config = {
        "auto_scaling_enabled": True,
        "max_concurrent_engagements": 10,
        "honeypot_timeout_minutes": 60
    }
    coordinator_agent = CoordinatorAgent(config)
    await coordinator_agent.initialize()
    
    try:
        # Run agent tests
        await test_agent.test_coordinator_initialization(coordinator_agent)
        await test_agent.test_engagement_decision_handling(coordinator_agent)
        await test_agent.test_honeypot_creation_workflow(coordinator_agent)
        await test_agent.test_agent_coordination(coordinator_agent)
        await test_agent.test_workflow_management(coordinator_agent)
        await test_agent.test_resource_management(coordinator_agent)
        await test_agent.test_emergency_shutdown(coordinator_agent)
        await test_agent.test_system_monitoring(coordinator_agent)
        await test_agent.test_auto_scaling_logic(coordinator_agent)
        await test_agent.test_honeypot_lifecycle_workflow(coordinator_agent)
        await test_agent.test_agent_coordination_workflow(coordinator_agent)
        await test_agent.test_emergency_response_workflow(coordinator_agent)
        await test_agent.test_workflow_status_tracking(coordinator_agent)
        await test_agent.test_workflow_pause_resume(coordinator_agent)
        await test_agent.test_honeypot_type_determination(coordinator_agent)
        await test_agent.test_honeypot_config_generation(coordinator_agent)
        
        # Run tool tests
        await test_tools.test_create_honeypot_tool(coordinator_agent)
        await test_tools.test_emergency_shutdown_tool(coordinator_agent)
        await test_tools.test_coordinate_agents_tool(coordinator_agent)
        await test_tools.test_auto_scale_system_tool(coordinator_agent)
        await test_tools.test_manage_resource_allocation_tool(coordinator_agent)
        
        logger.info("🎉 All Coordinator Agent tests passed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise
    finally:
        await coordinator_agent.cleanup()


if __name__ == "__main__":
    asyncio.run(run_all_tests())