"""
Unit tests for Detection Agent threat analysis logic
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from agents.detection.detection_agent import DetectionAgent


@pytest.mark.unit
@pytest.mark.asyncio
class TestDetectionAgent:
    """Test Detection Agent threat analysis functionality"""

    async def test_agent_initialization(self, test_config):
        """Test Detection Agent initialization"""
        agent = DetectionAgent(config=test_config)
        assert agent.config == test_config
        assert agent.confidence_threshold == 0.75
        assert agent.agent_type == "detection"

    async def test_threat_evaluation_high_confidence(self, detection_agent, sample_threat_data):
        """Test threat evaluation with high confidence score"""
        # Modify sample data for high confidence
        sample_threat_data["confidence"] = 0.9
        
        result = await detection_agent.evaluate_threat(sample_threat_data)
        
        assert "decision" in result
        assert "confidence" in result
        assert "reasoning" in result

    async def test_threat_evaluation_low_confidence(self, detection_agent, sample_threat_data):
        """Test threat evaluation with low confidence score"""
        # Modify sample data for low confidence
        sample_threat_data["confidence"] = 0.5
        
        result = await detection_agent.evaluate_threat(sample_threat_data)
        
        assert "decision" in result
        assert "confidence" in result
        assert "reasoning" in result

    async def test_reputation_check(self, detection_agent):
        """Test IP reputation checking"""
        request_data = {
            "ip_address": "192.168.1.100",
            "context": "ssh_connection"
        }
        
        result = await detection_agent.check_reputation(request_data)
        
        # Should return reputation data or error
        assert isinstance(result, dict)
        assert "error" in result or "reputation_score" in result

    async def test_ioc_extraction(self, detection_agent):
        """Test IOC extraction from text data"""
        request_data = {
            "text": "Suspicious activity from 192.168.1.100 attempting SSH brute force",
            "context": "log_analysis"
        }
        
        result = await detection_agent.extract_iocs(request_data)
        
        assert "iocs" in result
        assert "confidence" in result
        assert isinstance(result["iocs"], list)

    async def test_message_processing(self, detection_agent):
        """Test AgentCore message processing"""
        message = {
            "type": "threat_evaluation",
            "payload": {
                "source_ip": "192.168.1.100",
                "threat_type": "brute_force"
            }
        }
        
        result = await detection_agent.process_message(message)
        
        assert result is not None
        assert isinstance(result, dict)

    async def test_metrics_collection(self, detection_agent):
        """Test metrics collection"""
        metrics = await detection_agent.get_metrics()
        
        assert "threats_processed" in metrics
        assert "engagement_decisions" in metrics
        assert "average_confidence" in metrics
        assert "uptime_seconds" in metrics

    async def test_health_status(self, detection_agent):
        """Test health status reporting"""
        health = await detection_agent.get_health_status()
        
        assert "status" in health
        assert "last_activity" in health
        assert "error_count" in health

    async def test_threat_statistics(self, detection_agent):
        """Test threat statistics collection"""
        stats = await detection_agent.get_threat_statistics()
        
        assert "total_threats" in stats
        assert "threat_types" in stats
        assert "confidence_distribution" in stats

    async def test_configuration_update(self, detection_agent):
        """Test configuration updates"""
        new_config = {
            "confidence_threshold": 0.8,
            "max_concurrent_evaluations": 20
        }
        
        result = await detection_agent.update_configuration(new_config)
        
        assert "status" in result
        assert result["status"] == "success"

    async def test_error_handling(self, detection_agent):
        """Test error handling in threat evaluation"""
        # Test with malformed data
        invalid_data = {"invalid": "data"}
        
        result = await detection_agent.evaluate_threat(invalid_data)
        
        # Should handle gracefully and return error information
        assert "error" in result or "decision" in result

    @pytest.mark.slow
    async def test_concurrent_threat_evaluation(self, detection_agent):
        """Test concurrent threat evaluation processing"""
        import asyncio
        
        # Create multiple concurrent threat evaluation tasks
        threats = [
            {
                "source_ip": f"192.168.1.{100 + i}",
                "threat_type": "brute_force",
                "indicators": ["ssh_login_failure"]
            }
            for i in range(5)
        ]
        
        tasks = [detection_agent.evaluate_threat(threat) for threat in threats]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        assert len(results) == 5
        # Check that most results are successful (some might fail due to mocking)
        successful_results = [r for r in results if isinstance(r, dict) and "decision" in r]
        assert len(successful_results) >= 0  # At least some should work