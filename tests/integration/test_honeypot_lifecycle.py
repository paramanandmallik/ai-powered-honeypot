"""
Integration tests for honeypot lifecycle and interaction testing
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.interaction.interaction_agent import InteractionAgent
from honeypots.web_admin.web_admin_honeypot import WebAdminHoneypot
from honeypots.ssh.ssh_honeypot import SSHHoneypot
from honeypots.database.database_honeypot import DatabaseHoneypot


@pytest.mark.integration
@pytest.mark.honeypot
@pytest.mark.asyncio
class TestHoneypotLifecycle:
    """Test honeypot lifecycle and interaction integration"""

    @pytest.fixture
    async def honeypot_system(self, test_config):
        """Setup integrated honeypot system"""
        coordinator = CoordinatorAgent(config=test_config)
        interaction = InteractionAgent(config=test_config)
        
        await coordinator.start()
        await interaction.start()
        
        system = {
            "coordinator": coordinator,
            "interaction": interaction,
            "active_honeypots": {}
        }
        
        yield system
        
        # Cleanup all honeypots
        for hp_id in list(system["active_honeypots"].keys()):
            await coordinator.destroy_honeypot(hp_id)
        
        await coordinator.stop()
        await interaction.stop()

    async def test_complete_honeypot_lifecycle(self, honeypot_system):
        """Test complete honeypot lifecycle from creation to destruction"""
        coordinator = honeypot_system["coordinator"]
        
        # Phase 1: Creation
        creation_request = {
            "threat_data": {
                "source_ip": "192.168.1.100",
                "threat_type": "ssh_brute_force"
            },
            "honeypot_type": "ssh",
            "priority": "high",
            "configuration": {
                "port": 2222,
                "max_connections": 5,
                "session_timeout": 1800
            }
        }
        
        creation_result = await coordinator.create_honeypot(creation_request)
        
        assert creation_result["status"] == "created"
        assert "honeypot_id" in creation_result
        assert creation_result["type"] == "ssh"
        
        honeypot_id = creation_result["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = creation_result
        
        # Phase 2: Configuration and Activation
        config_result = await coordinator.configure_honeypot(honeypot_id, {
            "synthetic_users": 10,
            "file_system_template": "linux_server",
            "response_delay_ms": 200
        })
        
        assert config_result["status"] == "configured"
        
        # Phase 3: Monitoring and Status Checks
        status = await coordinator.get_honeypot_status(honeypot_id)
        
        assert status["status"] == "active"
        assert status["honeypot_id"] == honeypot_id
        assert status["uptime"] > 0
        
        # Phase 4: Health Monitoring
        health = await coordinator.check_honeypot_health(honeypot_id)
        
        assert health["status"] == "healthy"
        assert "cpu_usage" in health
        assert "memory_usage" in health
        assert "connection_count" in health
        
        # Phase 5: Graceful Shutdown
        shutdown_result = await coordinator.destroy_honeypot(honeypot_id)
        
        assert shutdown_result["status"] == "destroyed"
        assert shutdown_result["honeypot_id"] == honeypot_id
        
        # Verify honeypot is no longer accessible
        final_status = await coordinator.get_honeypot_status(honeypot_id)
        assert final_status["status"] == "destroyed"

    async def test_multi_type_honeypot_coordination(self, honeypot_system):
        """Test coordination between different honeypot types"""
        coordinator = honeypot_system["coordinator"]
        interaction = honeypot_system["interaction"]
        
        # Create multiple honeypot types
        honeypot_configs = [
            {"type": "web_admin", "port": 8080},
            {"type": "ssh", "port": 2222},
            {"type": "database", "port": 3306},
            {"type": "file_share", "port": 445}
        ]
        
        created_honeypots = []
        
        for config in honeypot_configs:
            request = {
                "threat_data": {"source_ip": "192.168.1.100"},
                "honeypot_type": config["type"],
                "configuration": {"port": config["port"]}
            }
            
            result = await coordinator.create_honeypot(request)
            created_honeypots.append(result)
            honeypot_system["active_honeypots"][result["honeypot_id"]] = result
        
        # Simulate coordinated attack scenario
        attack_sequence = [
            {"honeypot_type": "web_admin", "action": "login_attempt"},
            {"honeypot_type": "ssh", "action": "lateral_movement"},
            {"honeypot_type": "database", "action": "data_enumeration"},
            {"honeypot_type": "file_share", "action": "file_access"}
        ]
        
        session_results = {}
        
        for step in attack_sequence:
            # Find honeypot of the required type
            target_honeypot = next(
                hp for hp in created_honeypots 
                if hp["type"] == step["honeypot_type"]
            )
            
            session_id = f"session-{target_honeypot['honeypot_id']}"
            
            # Simulate interaction based on action type
            if step["action"] == "login_attempt":
                response = await interaction.simulate_login_attempt(
                    session_id, "admin", "password123"
                )
            elif step["action"] == "lateral_movement":
                response = await interaction.simulate_command(
                    session_id, "ssh user@database-server"
                )
            elif step["action"] == "data_enumeration":
                response = await interaction.simulate_command(
                    session_id, "SHOW DATABASES"
                )
            elif step["action"] == "file_access":
                response = await interaction.simulate_file_access(
                    session_id, "/shares/documents/sensitive.doc"
                )
            
            session_results[step["honeypot_type"]] = response
        
        # Verify all interactions completed successfully
        assert len(session_results) == 4
        for hp_type, response in session_results.items():
            assert response is not None
            assert len(str(response)) > 0
        
        # Cleanup
        for honeypot in created_honeypots:
            await coordinator.destroy_honeypot(honeypot["honeypot_id"])

    async def test_honeypot_scaling_and_load_balancing(self, honeypot_system):
        """Test honeypot auto-scaling and load balancing"""
        coordinator = honeypot_system["coordinator"]
        
        # Create initial honeypot
        base_request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "scaling_config": {
                "min_instances": 1,
                "max_instances": 5,
                "cpu_threshold": 0.8,
                "connection_threshold": 10
            }
        }
        
        initial_honeypot = await coordinator.create_honeypot(base_request)
        honeypot_id = initial_honeypot["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = initial_honeypot
        
        # Simulate high load to trigger scaling
        load_simulation = {
            "cpu_usage": 0.85,
            "active_connections": 12,
            "response_time_ms": 2500
        }
        
        await coordinator.report_honeypot_metrics(honeypot_id, load_simulation)
        
        # Check if scaling was triggered
        scaling_decision = await coordinator.evaluate_scaling_needs(honeypot_id)
        
        assert scaling_decision["scale_up"] is True
        assert scaling_decision["target_instances"] > 1
        
        # Execute scaling
        scaling_result = await coordinator.scale_honeypot(
            honeypot_id, scaling_decision["target_instances"]
        )
        
        assert scaling_result["status"] == "scaled"
        assert scaling_result["new_instance_count"] == scaling_decision["target_instances"]
        
        # Verify load balancing
        load_balance_status = await coordinator.get_load_balance_status(honeypot_id)
        
        assert load_balance_status["active_instances"] == scaling_decision["target_instances"]
        assert load_balance_status["load_distribution"] is not None

    async def test_honeypot_failure_recovery(self, honeypot_system):
        """Test honeypot failure detection and recovery"""
        coordinator = honeypot_system["coordinator"]
        
        # Create honeypot
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "web_admin",
            "recovery_config": {
                "health_check_interval": 30,
                "failure_threshold": 3,
                "auto_recovery": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = honeypot
        
        # Simulate honeypot failure
        failure_simulation = {
            "error_type": "connection_timeout",
            "error_count": 5,
            "last_response": None,
            "health_status": "unhealthy"
        }
        
        await coordinator.report_honeypot_failure(honeypot_id, failure_simulation)
        
        # Check failure detection
        health_status = await coordinator.check_honeypot_health(honeypot_id)
        
        assert health_status["status"] == "unhealthy"
        assert health_status["failure_count"] > 0
        
        # Trigger recovery
        recovery_result = await coordinator.recover_failed_honeypot(honeypot_id)
        
        assert recovery_result["recovery_action"] in ["restart", "replace", "repair"]
        assert recovery_result["status"] in ["recovering", "recovered"]
        
        # Verify recovery success
        if recovery_result["status"] == "recovered":
            post_recovery_health = await coordinator.check_honeypot_health(honeypot_id)
            assert post_recovery_health["status"] == "healthy"

    async def test_session_isolation_and_containment(self, honeypot_system):
        """Test session isolation and containment mechanisms"""
        coordinator = honeypot_system["coordinator"]
        interaction = honeypot_system["interaction"]
        
        # Create honeypot with strict isolation
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "isolation_config": {
                "level": "strict",
                "network_isolation": True,
                "resource_limits": {
                    "cpu": "0.5",
                    "memory": "256MB",
                    "disk": "1GB"
                }
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = honeypot
        
        # Create multiple isolated sessions
        session_count = 3
        sessions = []
        
        for i in range(session_count):
            session_data = {
                "session_id": f"isolated-session-{i}",
                "honeypot_id": honeypot_id,
                "attacker_ip": f"192.168.1.{100 + i}",
                "isolation_level": "strict"
            }
            
            session_result = await interaction.create_isolated_session(session_data)
            sessions.append(session_result)
        
        # Test session isolation
        for i, session in enumerate(sessions):
            session_id = session["session_id"]
            
            # Each session should have isolated environment
            env_info = await interaction.get_session_environment(session_id)
            
            assert env_info["isolation_level"] == "strict"
            assert env_info["resource_limits"] is not None
            assert env_info["network_access"] == "restricted"
            
            # Test cross-session isolation
            other_sessions = [s for j, s in enumerate(sessions) if j != i]
            for other_session in other_sessions:
                # Should not be able to access other session data
                access_result = await interaction.test_cross_session_access(
                    session_id, other_session["session_id"]
                )
                assert access_result["access_granted"] is False

    async def test_honeypot_data_lifecycle(self, honeypot_system):
        """Test honeypot data generation, tracking, and cleanup"""
        coordinator = honeypot_system["coordinator"]
        interaction = honeypot_system["interaction"]
        
        # Create honeypot with data tracking
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "database",
            "data_config": {
                "synthetic_data_volume": "medium",
                "data_retention_days": 30,
                "track_all_interactions": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = honeypot
        
        # Generate synthetic data
        data_generation_result = await interaction.generate_honeypot_data(
            honeypot_id, {
                "data_types": ["users", "orders", "products"],
                "record_count": 1000,
                "include_relationships": True
            }
        )
        
        assert data_generation_result["status"] == "generated"
        assert data_generation_result["total_records"] == 1000
        assert len(data_generation_result["data_fingerprints"]) > 0
        
        # Track data usage during interactions
        session_id = f"session-{honeypot_id}"
        
        # Simulate database queries
        queries = [
            "SELECT * FROM users LIMIT 10",
            "SELECT COUNT(*) FROM orders",
            "SELECT * FROM products WHERE category = 'electronics'"
        ]
        
        interaction_data = []
        for query in queries:
            result = await interaction.simulate_database_query(session_id, query)
            interaction_data.append({
                "query": query,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Verify data tracking
        data_usage = await interaction.get_data_usage_report(honeypot_id)
        
        assert data_usage["total_queries"] == len(queries)
        assert data_usage["synthetic_data_accessed"] > 0
        assert "data_fingerprints_used" in data_usage
        
        # Test data cleanup
        cleanup_result = await coordinator.cleanup_honeypot_data(honeypot_id)
        
        assert cleanup_result["status"] == "cleaned"
        assert cleanup_result["records_removed"] > 0

    async def test_honeypot_performance_monitoring(self, honeypot_system):
        """Test honeypot performance monitoring and optimization"""
        coordinator = honeypot_system["coordinator"]
        interaction = honeypot_system["interaction"]
        
        # Create honeypot with performance monitoring
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "web_admin",
            "monitoring_config": {
                "collect_metrics": True,
                "metric_interval_seconds": 10,
                "performance_alerts": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = honeypot
        
        # Simulate load and collect metrics
        load_tasks = []
        for i in range(10):
            session_id = f"perf-session-{i}"
            task = interaction.simulate_web_interaction(
                session_id, {
                    "action": "login_attempt",
                    "username": f"user{i}",
                    "password": "password123"
                }
            )
            load_tasks.append(task)
        
        # Execute concurrent load
        start_time = datetime.utcnow()
        results = await asyncio.gather(*load_tasks)
        end_time = datetime.utcnow()
        
        # Collect performance metrics
        performance_metrics = await coordinator.get_performance_metrics(honeypot_id)
        
        assert "response_time_ms" in performance_metrics
        assert "throughput_rps" in performance_metrics
        assert "error_rate" in performance_metrics
        assert "resource_utilization" in performance_metrics
        
        # Verify performance requirements
        avg_response_time = performance_metrics["response_time_ms"]["average"]
        assert avg_response_time < 2000  # Should be under 2 seconds
        
        # Test performance optimization
        if avg_response_time > 1000:  # If performance is suboptimal
            optimization_result = await coordinator.optimize_honeypot_performance(honeypot_id)
            
            assert "optimization_applied" in optimization_result
            assert optimization_result["status"] == "optimized"

    async def test_honeypot_security_controls(self, honeypot_system):
        """Test honeypot security controls and breach prevention"""
        coordinator = honeypot_system["coordinator"]
        interaction = honeypot_system["interaction"]
        
        # Create honeypot with enhanced security
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "security_config": {
                "real_data_detection": True,
                "pivot_attempt_detection": True,
                "escalation_monitoring": True,
                "emergency_shutdown": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        honeypot_system["active_honeypots"][honeypot_id] = honeypot
        
        # Test real data detection
        session_id = f"security-session-{honeypot_id}"
        
        # Simulate potential real data exposure
        real_data_tests = [
            "cat /etc/real_passwords.txt",  # Suspicious file access
            "ssh production-server.company.com",  # External pivot attempt
            "curl http://real-api.company.com/data"  # External data access
        ]
        
        security_alerts = []
        
        for command in real_data_tests:
            try:
                response = await interaction.simulate_command(session_id, command)
                
                # Check if security controls triggered
                security_check = await interaction.check_security_violation(
                    session_id, command, response
                )
                
                if security_check["violation_detected"]:
                    security_alerts.append(security_check)
                    
            except SecurityError as e:
                # Expected for security violations
                security_alerts.append({"error": str(e), "command": command})
        
        # Verify security controls are working
        assert len(security_alerts) > 0  # Should detect violations
        
        # Test emergency shutdown trigger
        if len(security_alerts) >= 2:  # Multiple violations
            emergency_result = await coordinator.trigger_emergency_shutdown(
                honeypot_id, "multiple_security_violations"
            )
            
            assert emergency_result["status"] == "emergency_shutdown"
            assert emergency_result["reason"] == "multiple_security_violations"