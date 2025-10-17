"""
Integration tests for performance testing and load simulation
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import statistics

from agents.detection.detection_agent import DetectionAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.interaction.interaction_agent import InteractionAgent
from agents.intelligence.intelligence_agent import IntelligenceAgent


@pytest.mark.integration
@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
class TestPerformanceTesting:
    """Test system performance under various load conditions"""

    @pytest.fixture
    async def performance_system(self, performance_config):
        """Setup system for performance testing"""
        config = {
            "use_mock_ai": True,
            "max_concurrent_sessions": performance_config["max_concurrent_requests"],
            "performance_mode": True
        }
        
        # Initialize all agents
        detection = DetectionAgent(config=config)
        coordinator = CoordinatorAgent(config=config)
        interaction = InteractionAgent(config=config)
        intelligence = IntelligenceAgent(config=config)
        
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
            "config": performance_config
        }
        
        yield system
        
        # Cleanup
        await detection.stop()
        await coordinator.stop()
        await interaction.stop()
        await intelligence.stop()

    async def test_threat_detection_throughput(self, performance_system):
        """Test threat detection agent throughput under load"""
        detection = performance_system["detection"]
        config = performance_system["config"]
        
        # Generate test threats
        threat_count = 100
        threats = []
        
        for i in range(threat_count):
            threat = {
                "source_ip": f"10.0.{i//256}.{i%256}",
                "destination_ip": "192.168.1.100",
                "indicators": ["port_scan", "brute_force"],
                "confidence": 0.5 + (i % 5) * 0.1,
                "timestamp": datetime.utcnow().isoformat()
            }
            threats.append(threat)
        
        # Measure processing time
        start_time = time.time()
        
        # Process threats concurrently
        tasks = [detection.analyze_threat(threat) for threat in threats]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate performance metrics
        throughput = threat_count / total_time  # threats per second
        avg_response_time = total_time / threat_count * 1000  # ms per threat
        
        # Verify performance requirements
        assert throughput >= config["expected_throughput_rps"]
        assert avg_response_time <= config["expected_response_time_ms"]
        assert len(results) == threat_count
        
        # Verify all results are valid
        for result in results:
            assert "engagement_decision" in result
            assert "confidence_score" in result
            assert isinstance(result["confidence_score"], (int, float))

    async def test_concurrent_honeypot_creation(self, performance_system):
        """Test concurrent honeypot creation performance"""
        coordinator = performance_system["coordinator"]
        config = performance_system["config"]
        
        # Create multiple honeypot requests
        request_count = config["max_concurrent_requests"]
        requests = []
        
        for i in range(request_count):
            request = {
                "threat_data": {
                    "source_ip": f"192.168.1.{100 + i}",
                    "threat_type": "ssh_brute_force"
                },
                "honeypot_type": "ssh",
                "priority": "medium"
            }
            requests.append(request)
        
        # Measure creation time
        start_time = time.time()
        
        # Create honeypots concurrently
        creation_tasks = [
            coordinator.create_honeypot(request) for request in requests
        ]
        results = await asyncio.gather(*creation_tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate metrics
        avg_creation_time = total_time / request_count * 1000  # ms per honeypot
        
        # Verify performance
        assert avg_creation_time <= 5000  # Should create honeypot in under 5 seconds
        assert len(results) == request_count
        
        # Verify all honeypots were created successfully
        created_honeypots = []
        for result in results:
            assert result["status"] == "created"
            assert "honeypot_id" in result
            created_honeypots.append(result["honeypot_id"])
        
        # Cleanup honeypots
        cleanup_tasks = [
            coordinator.destroy_honeypot(hp_id) for hp_id in created_honeypots
        ]
        await asyncio.gather(*cleanup_tasks)

    async def test_interaction_agent_response_time(self, performance_system):
        """Test interaction agent response time under load"""
        interaction = performance_system["interaction"]
        config = performance_system["config"]
        
        # Setup test session
        session_id = "performance-test-session"
        await interaction.initialize_session(session_id, {
            "persona": "system_administrator",
            "system_type": "linux_server"
        })
        
        # Test commands with varying complexity
        test_commands = [
            "whoami",           # Simple command
            "ls -la /etc",      # Medium complexity
            "ps aux | grep ssh", # Complex command with pipe
            "find / -name '*.log' -type f", # Resource intensive
            "cat /etc/passwd | head -20"    # File access with processing
        ]
        
        response_times = []
        
        # Test each command multiple times
        for command in test_commands:
            command_times = []
            
            for _ in range(10):  # 10 iterations per command
                start_time = time.time()
                
                response = await interaction.simulate_command(session_id, command)
                
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to ms
                
                command_times.append(response_time)
                
                # Verify response quality
                assert isinstance(response, str)
                assert len(response) > 0
            
            avg_command_time = statistics.mean(command_times)
            response_times.append(avg_command_time)
        
        # Verify response time requirements
        overall_avg = statistics.mean(response_times)
        assert overall_avg <= config["expected_response_time_ms"]
        
        # Verify 95th percentile performance
        all_times = [time for times in [response_times] for time in times]
        p95_time = statistics.quantiles(all_times, n=20)[18]  # 95th percentile
        assert p95_time <= config["expected_response_time_ms"] * 1.5

    async def test_intelligence_analysis_performance(self, performance_system):
        """Test intelligence agent analysis performance"""
        intelligence = performance_system["intelligence"]
        
        # Generate test session data
        session_count = 20
        sessions = []
        
        for i in range(session_count):
            session_data = {
                "session_id": f"perf-session-{i}",
                "attacker_ip": f"192.168.1.{100 + i}",
                "honeypot_type": "ssh",
                "start_time": datetime.utcnow().isoformat(),
                "interactions": [
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "command": "whoami",
                        "response": "root",
                        "synthetic": True
                    },
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "command": "ls -la",
                        "response": "total 24\ndrwxr-xr-x 3 root root",
                        "synthetic": True
                    },
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "command": "cat /etc/passwd",
                        "response": "root:x:0:0:root:/root:/bin/bash",
                        "synthetic": True
                    }
                ]
            }
            sessions.append(session_data)
        
        # Measure analysis time
        start_time = time.time()
        
        # Analyze sessions concurrently
        analysis_tasks = [
            intelligence.analyze_session(session) for session in sessions
        ]
        results = await asyncio.gather(*analysis_tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate performance metrics
        avg_analysis_time = total_time / session_count * 1000  # ms per session
        throughput = session_count / total_time  # sessions per second
        
        # Verify performance requirements
        assert avg_analysis_time <= 5000  # Should analyze session in under 5 seconds
        assert throughput >= 2  # Should handle at least 2 sessions per second
        assert len(results) == session_count
        
        # Verify analysis quality
        for result in results:
            assert "techniques_identified" in result
            assert "confidence_score" in result
            assert result["confidence_score"] >= 0.0

    async def test_system_scalability(self, performance_system):
        """Test system scalability under increasing load"""
        detection = performance_system["detection"]
        coordinator = performance_system["coordinator"]
        
        # Test with increasing load levels
        load_levels = [10, 25, 50, 100]
        performance_results = {}
        
        for load_level in load_levels:
            # Generate threats for this load level
            threats = []
            for i in range(load_level):
                threat = {
                    "source_ip": f"10.{load_level}.{i//256}.{i%256}",
                    "indicators": ["brute_force"],
                    "confidence": 0.8,
                    "timestamp": datetime.utcnow().isoformat()
                }
                threats.append(threat)
            
            # Measure processing time
            start_time = time.time()
            
            # Process threats
            detection_tasks = [detection.analyze_threat(threat) for threat in threats]
            detection_results = await asyncio.gather(*detection_tasks)
            
            # Create honeypots for engaged threats
            honeypot_tasks = []
            for i, result in enumerate(detection_results):
                if result["engagement_decision"]:
                    request = {
                        "threat_data": threats[i],
                        "honeypot_type": "ssh"
                    }
                    honeypot_tasks.append(coordinator.create_honeypot(request))
            
            if honeypot_tasks:
                honeypot_results = await asyncio.gather(*honeypot_tasks)
                
                # Cleanup honeypots
                cleanup_tasks = [
                    coordinator.destroy_honeypot(result["honeypot_id"])
                    for result in honeypot_results
                ]
                await asyncio.gather(*cleanup_tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Record performance metrics
            performance_results[load_level] = {
                "total_time": total_time,
                "throughput": load_level / total_time,
                "avg_response_time": total_time / load_level * 1000
            }
        
        # Verify scalability characteristics
        # Throughput should not degrade significantly with increased load
        base_throughput = performance_results[10]["throughput"]
        max_throughput = performance_results[100]["throughput"]
        
        # Allow for some degradation but not more than 50%
        assert max_throughput >= base_throughput * 0.5
        
        # Response time should remain reasonable
        for load_level, metrics in performance_results.items():
            assert metrics["avg_response_time"] <= 10000  # 10 seconds max

    async def test_memory_usage_under_load(self, performance_system):
        """Test memory usage patterns under sustained load"""
        interaction = performance_system["interaction"]
        
        # Monitor memory usage during sustained operations
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create multiple long-running sessions
        session_count = 20
        sessions = []
        
        for i in range(session_count):
            session_id = f"memory-test-session-{i}"
            await interaction.initialize_session(session_id, {
                "persona": "system_administrator",
                "memory_tracking": True
            })
            sessions.append(session_id)
        
        # Simulate sustained activity
        activity_duration = 60  # seconds
        start_time = time.time()
        
        memory_samples = []
        
        while time.time() - start_time < activity_duration:
            # Perform operations on all sessions
            tasks = []
            for session_id in sessions:
                task = interaction.simulate_command(session_id, "ps aux")
                tasks.append(task)
            
            await asyncio.gather(*tasks)
            
            # Sample memory usage
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_samples.append(current_memory)
            
            # Brief pause between iterations
            await asyncio.sleep(1)
        
        # Analyze memory usage
        max_memory = max(memory_samples)
        avg_memory = statistics.mean(memory_samples)
        memory_growth = max_memory - initial_memory
        
        # Verify memory usage is reasonable
        assert memory_growth <= 500  # Should not grow more than 500MB
        assert max_memory <= 2000  # Should not exceed 2GB total
        
        # Check for memory leaks (memory should stabilize)
        if len(memory_samples) >= 10:
            recent_avg = statistics.mean(memory_samples[-10:])
            early_avg = statistics.mean(memory_samples[:10])
            growth_rate = (recent_avg - early_avg) / early_avg
            
            # Memory growth should be minimal after initial ramp-up
            assert growth_rate <= 0.2  # Less than 20% growth

    async def test_concurrent_session_handling(self, performance_system):
        """Test handling of concurrent interactive sessions"""
        interaction = performance_system["interaction"]
        config = performance_system["config"]
        
        # Create maximum concurrent sessions
        max_sessions = config["max_concurrent_requests"]
        sessions = []
        
        # Initialize all sessions
        init_tasks = []
        for i in range(max_sessions):
            session_id = f"concurrent-session-{i}"
            task = interaction.initialize_session(session_id, {
                "persona": "system_administrator",
                "isolation_level": "strict"
            })
            init_tasks.append(task)
            sessions.append(session_id)
        
        await asyncio.gather(*init_tasks)
        
        # Simulate concurrent interactions
        interaction_rounds = 5
        response_times = []
        
        for round_num in range(interaction_rounds):
            round_start = time.time()
            
            # Each session performs an interaction
            interaction_tasks = []
            for session_id in sessions:
                command = f"echo 'Round {round_num} from {session_id}'"
                task = interaction.simulate_command(session_id, command)
                interaction_tasks.append(task)
            
            results = await asyncio.gather(*interaction_tasks)
            
            round_end = time.time()
            round_time = (round_end - round_start) * 1000  # ms
            response_times.append(round_time)
            
            # Verify all interactions completed
            assert len(results) == max_sessions
            for result in results:
                assert isinstance(result, str)
                assert f"Round {round_num}" in result
        
        # Verify performance under concurrent load
        avg_round_time = statistics.mean(response_times)
        max_round_time = max(response_times)
        
        # Should handle concurrent sessions efficiently
        assert avg_round_time <= 5000  # Average round under 5 seconds
        assert max_round_time <= 10000  # No round over 10 seconds

    async def test_error_handling_performance(self, performance_system):
        """Test performance impact of error handling"""
        detection = performance_system["detection"]
        
        # Mix of valid and invalid threats
        threat_count = 50
        threats = []
        
        for i in range(threat_count):
            if i % 5 == 0:  # Every 5th threat is invalid
                threat = {
                    "invalid_field": "invalid_data",
                    "malformed": True
                }
            else:
                threat = {
                    "source_ip": f"192.168.1.{100 + i}",
                    "confidence": 0.8,
                    "indicators": ["brute_force"]
                }
            threats.append(threat)
        
        # Measure processing time with errors
        start_time = time.time()
        
        tasks = [detection.analyze_threat(threat) for threat in threats]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Analyze results
        successful_results = [r for r in results if not isinstance(r, Exception)]
        error_results = [r for r in results if isinstance(r, Exception)]
        
        # Verify error handling doesn't significantly impact performance
        throughput = len(successful_results) / total_time
        assert throughput >= 10  # Should maintain reasonable throughput
        
        # Verify errors were handled gracefully
        assert len(error_results) <= threat_count * 0.3  # Some errors expected
        assert len(successful_results) >= threat_count * 0.7  # Most should succeed

    async def test_resource_cleanup_performance(self, performance_system):
        """Test performance of resource cleanup operations"""
        coordinator = performance_system["coordinator"]
        
        # Create many honeypots
        honeypot_count = 30
        creation_tasks = []
        
        for i in range(honeypot_count):
            request = {
                "threat_data": {"source_ip": f"192.168.1.{100 + i}"},
                "honeypot_type": "ssh"
            }
            task = coordinator.create_honeypot(request)
            creation_tasks.append(task)
        
        creation_results = await asyncio.gather(*creation_tasks)
        honeypot_ids = [result["honeypot_id"] for result in creation_results]
        
        # Measure cleanup time
        cleanup_start = time.time()
        
        # Cleanup all honeypots concurrently
        cleanup_tasks = [
            coordinator.destroy_honeypot(hp_id) for hp_id in honeypot_ids
        ]
        cleanup_results = await asyncio.gather(*cleanup_tasks)
        
        cleanup_end = time.time()
        cleanup_time = cleanup_end - cleanup_start
        
        # Verify cleanup performance
        avg_cleanup_time = cleanup_time / honeypot_count * 1000  # ms per honeypot
        assert avg_cleanup_time <= 2000  # Should cleanup in under 2 seconds each
        
        # Verify all honeypots were cleaned up
        assert len(cleanup_results) == honeypot_count
        for result in cleanup_results:
            assert result["status"] == "destroyed"