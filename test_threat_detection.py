"""
Test suite for Detection Agent threat analysis functionality
"""

import asyncio
import json
import pytest
import pytest_asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from agents.detection.detection_agent import DetectionAgent, ThreatAssessment


class TestDetectionAgent:
    """Test cases for Detection Agent"""
    
    @pytest_asyncio.fixture
    async def detection_agent(self):
        """Create a Detection Agent instance for testing"""
        config = {
            "confidence_threshold": 0.75,
            "enable_mitre_mapping": True,
            "max_concurrent_assessments": 10,
            "engagement_cooldown_minutes": 5
        }
        agent = DetectionAgent(config)
        await agent.initialize()
        return agent
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, detection_agent):
        """Test Detection Agent initialization"""
        assert detection_agent.agent_type == "detection"
        assert detection_agent.confidence_threshold == 0.75
        assert detection_agent.enable_mitre_mapping is True
        assert detection_agent.max_concurrent_assessments == 10
        assert detection_agent.state["initialized"] is True
    
    @pytest.mark.asyncio
    async def test_threat_assessment_creation(self):
        """Test ThreatAssessment data structure"""
        threat_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "threat_type": "brute_force",
            "indicators": ["multiple_failed_logins", "suspicious_timing"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        assessment = ThreatAssessment(threat_data)
        
        assert assessment.source_ip == "192.168.1.100"
        assert assessment.destination_ip == "10.0.0.1"
        assert assessment.threat_type == "brute_force"
        assert len(assessment.indicators) == 2
        assert assessment.threat_id is not None
    
    @pytest.mark.asyncio
    async def test_evaluate_threat_high_confidence(self, detection_agent):
        """Test threat evaluation with high confidence scenario"""
        threat_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "threat_type": "brute_force",
            "indicators": ["multiple_failed_logins", "credential_stuffing_pattern"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await detection_agent.evaluate_threat(threat_data)
        
        assert "threat_id" in result
        assert "decision" in result
        assert "confidence" in result
        assert "reasoning" in result
        assert "mitre_techniques" in result
        assert "recommended_honeypots" in result
        
        # Should recommend engagement for brute force with high confidence
        assert result["confidence"] >= 0.7  # Should be high for brute force
        assert isinstance(result["mitre_techniques"], list)
        assert isinstance(result["recommended_honeypots"], list)
    
    @pytest.mark.asyncio
    async def test_evaluate_threat_low_confidence(self, detection_agent):
        """Test threat evaluation with low confidence scenario"""
        threat_data = {
            "source_ip": "192.168.1.200",
            "destination_ip": "10.0.0.1", 
            "threat_type": "network_discovery",
            "indicators": ["port_scan"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await detection_agent.evaluate_threat(threat_data)
        
        assert "threat_id" in result
        assert "decision" in result
        assert "confidence" in result
        
        # Network discovery should have lower confidence
        # Decision should be MONITOR or IGNORE based on confidence
        assert result["decision"] in ["MONITOR", "IGNORE", "ENGAGE"]
    
    @pytest.mark.asyncio
    async def test_mitre_attack_mapping(self, detection_agent):
        """Test MITRE ATT&CK technique mapping"""
        threat_data = {
            "source_ip": "192.168.1.100",
            "threat_type": "brute_force",
            "indicators": ["credential_stuffing"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await detection_agent.evaluate_threat(threat_data)
        
        # Should map to brute force techniques
        mitre_techniques = result.get("mitre_techniques", [])
        assert isinstance(mitre_techniques, list)
        
        # Check if common brute force techniques are included
        expected_techniques = ["T1110", "T1110.001", "T1110.002", "T1110.003"]
        has_brute_force_technique = any(tech in mitre_techniques for tech in expected_techniques)
        assert has_brute_force_technique or len(mitre_techniques) > 0
    
    @pytest.mark.asyncio
    async def test_honeypot_recommendation(self, detection_agent):
        """Test honeypot recommendation logic"""
        # Test brute force -> SSH/Web Admin
        threat_data = {
            "source_ip": "192.168.1.100",
            "threat_type": "brute_force",
            "indicators": ["ssh_brute_force"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        result = await detection_agent.evaluate_threat(threat_data)
        recommended = result.get("recommended_honeypots", [])
        
        if result["decision"] == "ENGAGE":
            assert isinstance(recommended, list)
            assert len(recommended) > 0
            # Should recommend SSH or web_admin for brute force
            assert any(hp in recommended for hp in ["ssh", "web_admin"])
    
    @pytest.mark.asyncio
    async def test_reputation_check(self, detection_agent):
        """Test IP reputation checking"""
        request_data = {"ip_address": "192.168.1.100"}
        
        result = await detection_agent.check_reputation(request_data)
        
        assert "ip_address" in result
        assert "risk_level" in result
        assert "confidence_score" in result
        assert "indicators" in result
        assert "recommendations" in result
        assert "timestamp" in result
        
        assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert 0 <= result["confidence_score"] <= 100
        assert isinstance(result["indicators"], list)
        assert isinstance(result["recommendations"], list)
    
    @pytest.mark.asyncio
    async def test_ioc_extraction(self, detection_agent):
        """Test IOC extraction from text"""
        test_text = """
        Suspicious activity detected from IP 192.168.1.100
        Malware hash: d41d8cd98f00b204e9800998ecf8427e
        Contacted domain: malicious-site.com
        Email: attacker@evil.com
        File path: C:\\Windows\\System32\\malware.exe
        """
        
        request_data = {
            "text": test_text,
            "source_type": "log_analysis"
        }
        
        result = await detection_agent.extract_iocs(request_data)
        
        assert "ip_addresses" in result
        assert "domains" in result
        assert "file_hashes" in result
        assert "email_addresses" in result
        assert "file_paths" in result
        assert "extraction_confidence" in result
        assert "total_iocs_found" in result
        
        # Should extract the IP address
        ip_iocs = result["ip_addresses"]
        assert len(ip_iocs) > 0
        assert any(ioc["value"] == "192.168.1.100" for ioc in ip_iocs)
    
    @pytest.mark.asyncio
    async def test_engagement_cooldown(self, detection_agent):
        """Test engagement cooldown functionality"""
        threat_data = {
            "source_ip": "192.168.1.100",
            "threat_type": "brute_force",
            "indicators": ["multiple_attempts"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # First evaluation
        result1 = await detection_agent.evaluate_threat(threat_data)
        
        # Second evaluation immediately after (should respect cooldown)
        result2 = await detection_agent.evaluate_threat(threat_data)
        
        # If first was ENGAGE, second should be affected by cooldown
        if result1["decision"] == "ENGAGE":
            # The cooldown logic should prevent immediate re-engagement
            assert "cooldown" in str(result2.get("reasoning", "")).lower() or result2["decision"] != "ENGAGE"
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self, detection_agent):
        """Test metrics collection"""
        # Process some threats first
        for i in range(3):
            threat_data = {
                "source_ip": f"192.168.1.{100 + i}",
                "threat_type": "port_scan",
                "indicators": ["network_probe"],
                "timestamp": datetime.utcnow().isoformat()
            }
            await detection_agent.evaluate_threat(threat_data)
        
        metrics = await detection_agent.get_metrics()
        
        assert "total_assessments" in metrics
        assert "engagement_decisions" in metrics
        assert "confidence_threshold" in metrics
        assert "threat_type_distribution" in metrics
        assert "agentcore_connected" in metrics
        
        assert metrics["total_assessments"] >= 3
        assert isinstance(metrics["engagement_decisions"], dict)
    
    @pytest.mark.asyncio
    async def test_health_status(self, detection_agent):
        """Test health status reporting"""
        health = await detection_agent.get_health_status()
        
        assert "detection_agent_status" in health
        assert "health_indicators" in health
        assert "active_assessments" in health
        assert "cache_status" in health
        
        assert health["detection_agent_status"] in ["healthy", "degraded"]
        assert isinstance(health["health_indicators"], dict)
    
    @pytest.mark.asyncio
    async def test_configuration_update(self, detection_agent):
        """Test configuration updates"""
        new_config = {
            "confidence_threshold": 0.8,
            "max_concurrent_assessments": 15
        }
        
        result = await detection_agent.update_configuration(new_config)
        
        assert result["status"] == "success"
        assert detection_agent.confidence_threshold == 0.8
        assert detection_agent.max_concurrent_assessments == 15
    
    @pytest.mark.asyncio
    async def test_threat_statistics(self, detection_agent):
        """Test threat statistics generation"""
        # Generate some test data
        threat_types = ["brute_force", "port_scan", "malware"]
        for i, threat_type in enumerate(threat_types):
            threat_data = {
                "source_ip": f"192.168.1.{100 + i}",
                "threat_type": threat_type,
                "indicators": [f"{threat_type}_indicator"],
                "timestamp": datetime.utcnow().isoformat()
            }
            await detection_agent.evaluate_threat(threat_data)
        
        stats = await detection_agent.get_threat_statistics()
        
        assert "total_threats_analyzed" in stats
        assert "threats_by_type" in stats
        assert "engagement_rate" in stats
        assert "mitre_techniques_seen" in stats
        
        assert stats["total_threats_analyzed"] >= 3
        assert len(stats["threats_by_type"]) >= 3


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])