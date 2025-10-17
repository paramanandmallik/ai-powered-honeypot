"""
Integration tests for comprehensive workflow testing from threat detection to reporting
"""

import pytest
import pytest_asyncio
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from agents.detection.detection_agent import DetectionAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.interaction.interaction_agent import InteractionAgent
from agents.intelligence.intelligence_agent import IntelligenceAgent
from config.agentcore_sdk import AgentCoreSDK, Message


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.asyncio
class TestWorkflowIntegration:
    """Test complete workflow integration from threat detection to intelligence reporting"""

    @pytest_asyncio.fixture
    async def integrated_system(self, test_config):
        """Setup integrated system with all agents"""
        # Initialize all agents
        detection_agent = DetectionAgent(config=test_config)
        coordinator_agent = CoordinatorAgent(config=test_config)
        interaction_agent = InteractionAgent(config=test_config)
        intelligence_agent = IntelligenceAgent(config=test_config)
        
        # Start all agents
        await detection_agent.start()
        await coordinator_agent.start()
        await interaction_agent.start()
        await intelligence_agent.start()
        
        system = {
            "detection": detection_agent,
            "coordinator": coordinator_agent,
            "interaction": interaction_agent,
            "intelligence": intelligence_agent
        }
        
        yield system
        
        # Cleanup
        await detection_agent.stop()
        await coordinator_agent.stop()
        await interaction_agent.stop()
        await intelligence_agent.stop()

    async def test_complete_threat_response_workflow(self, integrated_system):
        """Test complete workflow from threat detection to intelligence report"""
        detection = integrated_system["detection"]
        coordinator = integrated_system["coordinator"]
        interaction = integrated_system["interaction"]
        intelligence = integrated_system["intelligence"]
        
        # Step 1: Threat Detection
        threat_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.50",
            "indicators": ["ssh_brute_force", "multiple_failed_logins"],
            "confidence": 0.85,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        detection_result = await detection.analyze_threat(threat_data)
        assert detection_result["engagement_decision"] is True
        
        # Step 2: Honeypot Creation
        honeypot_request = {
            "threat_data": threat_data,
            "honeypot_type": "ssh",
            "priority": "high"
        }
        
        honeypot_result = await coordinator.create_honeypot(honeypot_request)
        assert honeypot_result["status"] == "created"
        honeypot_id = honeypot_result["honeypot_id"]
        
        # Step 3: Attacker Interaction Simulation
        session_data = {
            "session_id": f"session-{honeypot_id}",
            "honeypot_id": honeypot_id,
            "attacker_ip": threat_data["source_ip"],
            "honeypot_type": "ssh"
        }
        
        # Simulate attacker interactions
        interactions = [
            "whoami",
            "id", 
            "uname -a",
            "ls -la /etc",
            "cat /etc/passwd",
            "ps aux"
        ]
        
        session_transcript = []
        for command in interactions:
            response = await interaction.simulate_command(session_data["session_id"], command)
            session_transcript.append({
                "timestamp": datetime.utcnow().isoformat(),
                "command": command,
                "response": response,
                "synthetic": True
            })
        
        session_data["interactions"] = session_transcript
        session_data["end_time"] = datetime.utcnow().isoformat()
        
        # Step 4: Intelligence Analysis
        intelligence_result = await intelligence.analyze_session(session_data)
        assert "techniques_identified" in intelligence_result
        assert intelligence_result["confidence_score"] > 0.0
        
        # Step 5: Report Generation
        final_report = await intelligence.generate_intelligence_report(session_data)
        assert "report_id" in final_report
        assert "mitre_techniques" in final_report
        assert "iocs" in final_report
        
        # Step 6: Cleanup
        cleanup_result = await coordinator.destroy_honeypot(honeypot_id)
        assert cleanup_result["status"] == "destroyed"
        
        # Verify complete workflow
        assert len(session_transcript) == len(interactions)
        assert len(intelligence_result["techniques_identified"]) > 0
        assert final_report["confidence_assessment"]["overall_confidence"] > 0.5

    async def test_multi_honeypot_coordination(self, integrated_system):
        """Test coordination across multiple honeypot types"""
        coordinator = integrated_system["coordinator"]
        interaction = integrated_system["interaction"]
        
        # Create multiple honeypots for coordinated attack simulation
        honeypot_types = ["web_admin", "ssh", "database"]
        honeypots = {}
        
        for hp_type in honeypot_types:
            request = {
                "threat_data": {"source_ip": "192.168.1.100"},
                "honeypot_type": hp_type,
                "priority": "medium"
            }
            result = await coordinator.create_honeypot(request)
            honeypots[hp_type] = result["honeypot_id"]
        
        # Simulate coordinated attack across honeypots
        attack_phases = [
            {"honeypot": "web_admin", "action": "reconnaissance"},
            {"honeypot": "ssh", "action": "lateral_movement"},
            {"honeypot": "database", "action": "data_access"}
        ]
        
        session_results = {}
        for phase in attack_phases:
            session_id = f"session-{honeypots[phase['honeypot']]}"
            
            if phase["action"] == "reconnaissance":
                response = await interaction.generate_response(session_id, "What users exist?")
            elif phase["action"] == "lateral_movement":
                response = await interaction.simulate_command(session_id, "ssh admin@database-server")
            elif phase["action"] == "data_access":
                response = await interaction.simulate_command(session_id, "SELECT * FROM users")
            
            session_results[phase["honeypot"]] = response
        
        # Verify all phases completed
        assert len(session_results) == 3
        for hp_type, response in session_results.items():
            assert isinstance(response, str)
            assert len(response) > 0
        
        # Cleanup all honeypots
        for hp_id in honeypots.values():
            await coordinator.destroy_honeypot(hp_id)

    async def test_concurrent_engagement_handling(self, integrated_system):
        """Test handling multiple concurrent attacker engagements"""
        detection = integrated_system["detection"]
        coordinator = integrated_system["coordinator"]
        interaction = integrated_system["interaction"]
        
        # Simulate multiple concurrent threats
        concurrent_threats = []
        for i in range(5):
            threat = {
                "source_ip": f"192.168.1.{100 + i}",
                "indicators": ["ssh_brute_force"],
                "confidence": 0.8,
                "timestamp": datetime.utcnow().isoformat()
            }
            concurrent_threats.append(threat)
        
        # Process threats concurrently
        detection_tasks = [
            detection.analyze_threat(threat) for threat in concurrent_threats
        ]
        detection_results = await asyncio.gather(*detection_tasks)
        
        # Create honeypots for engaged threats
        honeypot_tasks = []
        for i, result in enumerate(detection_results):
            if result["engagement_decision"]:
                request = {
                    "threat_data": concurrent_threats[i],
                    "honeypot_type": "ssh"
                }
                honeypot_tasks.append(coordinator.create_honeypot(request))
        
        honeypot_results = await asyncio.gather(*honeypot_tasks)
        
        # Simulate concurrent interactions
        interaction_tasks = []
        for result in honeypot_results:
            session_id = f"session-{result['honeypot_id']}"
            task = interaction.simulate_command(session_id, "whoami")
            interaction_tasks.append(task)
        
        interaction_results = await asyncio.gather(*interaction_tasks)
        
        # Verify concurrent processing
        assert len(detection_results) == 5
        assert len(honeypot_results) > 0  # At least some should engage
        assert len(interaction_results) == len(honeypot_results)
        
        # Cleanup
        cleanup_tasks = [
            coordinator.destroy_honeypot(result["honeypot_id"])
            for result in honeypot_results
        ]
        await asyncio.gather(*cleanup_tasks)

    async def test_error_recovery_workflow(self, integrated_system):
        """Test error recovery and resilience in workflow"""
        coordinator = integrated_system["coordinator"]
        interaction = integrated_system["interaction"]
        
        # Create honeypot
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh"
        }
        honeypot_result = await coordinator.create_honeypot(request)
        honeypot_id = honeypot_result["honeypot_id"]
        
        # Simulate honeypot failure
        with patch.object(interaction, 'simulate_command') as mock_command:
            mock_command.side_effect = Exception("Honeypot connection failed")
            
            # System should handle the error gracefully
            try:
                await interaction.simulate_command(f"session-{honeypot_id}", "whoami")
            except Exception:
                pass  # Expected to fail
            
            # Coordinator should detect and recover
            recovery_result = await coordinator.recover_failed_honeypot(honeypot_id)
            assert "recovery_action" in recovery_result
        
        # Cleanup
        await coordinator.destroy_honeypot(honeypot_id)

    async def test_performance_under_load(self, integrated_system):
        """Test system performance under realistic load"""
        detection = integrated_system["detection"]
        coordinator = integrated_system["coordinator"]
        
        # Generate high volume of threats
        threat_count = 20
        threats = []
        for i in range(threat_count):
            threat = {
                "source_ip": f"10.0.{i//256}.{i%256}",
                "indicators": ["port_scan", "brute_force"],
                "confidence": 0.6 + (i % 5) * 0.08,  # Varying confidence
                "timestamp": datetime.utcnow().isoformat()
            }
            threats.append(threat)
        
        # Measure processing time
        start_time = datetime.utcnow()
        
        # Process all threats
        detection_tasks = [detection.analyze_threat(threat) for threat in threats]
        results = await asyncio.gather(*detection_tasks)
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        # Verify performance requirements
        assert processing_time < 30  # Should process 20 threats in under 30 seconds
        assert len(results) == threat_count
        
        # Check engagement decisions
        engaged_count = sum(1 for result in results if result["engagement_decision"])
        assert engaged_count > 0  # At least some should engage
        
        # Verify system metrics
        metrics = await detection.get_performance_metrics()
        assert metrics["threats_analyzed"] >= threat_count

    async def test_data_flow_integrity(self, integrated_system):
        """Test data integrity throughout the workflow"""
        detection = integrated_system["detection"]
        coordinator = integrated_system["coordinator"]
        interaction = integrated_system["interaction"]
        intelligence = integrated_system["intelligence"]
        
        # Create threat with specific identifiers
        threat_data = {
            "source_ip": "192.168.1.100",
            "threat_id": "threat-integrity-test-123",
            "indicators": ["ssh_brute_force"],
            "confidence": 0.9,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Track data through workflow
        detection_result = await detection.analyze_threat(threat_data)
        assert detection_result["threat_id"] == threat_data["threat_id"]
        
        # Create honeypot
        honeypot_request = {
            "threat_data": threat_data,
            "honeypot_type": "ssh"
        }
        honeypot_result = await coordinator.create_honeypot(honeypot_request)
        
        # Verify threat data propagation
        honeypot_status = await coordinator.get_honeypot_status(honeypot_result["honeypot_id"])
        assert honeypot_status["associated_threat_id"] == threat_data["threat_id"]
        
        # Create session and verify data linkage
        session_data = {
            "session_id": f"session-{honeypot_result['honeypot_id']}",
            "threat_id": threat_data["threat_id"],
            "honeypot_id": honeypot_result["honeypot_id"],
            "interactions": [
                {"command": "whoami", "response": "root", "synthetic": True}
            ]
        }
        
        # Analyze session
        intelligence_result = await intelligence.analyze_session(session_data)
        assert intelligence_result["threat_id"] == threat_data["threat_id"]
        
        # Generate report and verify data integrity
        report = await intelligence.generate_intelligence_report(session_data)
        assert report["threat_id"] == threat_data["threat_id"]
        assert report["session_id"] == session_data["session_id"]
        
        # Cleanup
        await coordinator.destroy_honeypot(honeypot_result["honeypot_id"])

    async def test_state_synchronization(self, integrated_system):
        """Test state synchronization across all agents"""
        detection = integrated_system["detection"]
        coordinator = integrated_system["coordinator"]
        interaction = integrated_system["interaction"]
        intelligence = integrated_system["intelligence"]
        
        # Update system state
        system_state = {
            "threat_level": "high",
            "active_engagements": 3,
            "system_mode": "defensive",
            "last_update": datetime.utcnow().isoformat()
        }
        
        # Propagate state to all agents
        await coordinator.update_system_state(system_state)
        
        # Verify state synchronization
        detection_state = await detection.get_system_state()
        interaction_state = await interaction.get_system_state()
        intelligence_state = await intelligence.get_system_state()
        
        assert detection_state["threat_level"] == "high"
        assert interaction_state["threat_level"] == "high"
        assert intelligence_state["threat_level"] == "high"
        
        # Test state-based behavior changes
        threat_data = {"source_ip": "192.168.1.100", "confidence": 0.7}
        
        # In high threat level, lower confidence threats should still engage
        result = await detection.analyze_threat(threat_data)
        assert result["engagement_decision"] is True  # Should engage due to high threat level

    async def test_emergency_shutdown_workflow(self, integrated_system):
        """Test emergency shutdown procedures across all components"""
        coordinator = integrated_system["coordinator"]
        
        # Create multiple honeypots
        honeypots = []
        for i in range(3):
            request = {
                "threat_data": {"source_ip": f"192.168.1.{100 + i}"},
                "honeypot_type": "ssh"
            }
            result = await coordinator.create_honeypot(request)
            honeypots.append(result["honeypot_id"])
        
        # Verify honeypots are active
        for hp_id in honeypots:
            status = await coordinator.get_honeypot_status(hp_id)
            assert status["status"] == "active"
        
        # Trigger emergency shutdown
        shutdown_result = await coordinator.emergency_shutdown("security_breach_detected")
        
        # Verify shutdown completed
        assert shutdown_result["status"] == "shutdown_complete"
        assert shutdown_result["honeypots_destroyed"] == len(honeypots)
        
        # Verify all honeypots are destroyed
        for hp_id in honeypots:
            status = await coordinator.get_honeypot_status(hp_id)
            assert status["status"] == "destroyed"