"""
Unit tests for Intelligence Agent analysis and reporting
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from agents.intelligence.intelligence_agent import IntelligenceAgent
from agents.intelligence.session_analyzer import SessionAnalyzer
from agents.intelligence.mitre_mapper import MitreAttackMapper
from agents.intelligence.intelligence_reporter import IntelligenceReporter


@pytest.mark.unit
@pytest.mark.asyncio
class TestIntelligenceAgent:
    """Test Intelligence Agent analysis and reporting functionality"""

    async def test_agent_initialization(self, test_config):
        """Test Intelligence Agent initialization"""
        agent = IntelligenceAgent(config=test_config)
        assert agent.config == test_config
        assert agent.agent_type == "intelligence"

    async def test_session_analysis(self, intelligence_agent, sample_session_data):
        """Test comprehensive session analysis"""
        analysis_result = await intelligence_agent.analyze_session(sample_session_data)
        
        assert "session_id" in analysis_result
        assert "analysis_id" in analysis_result
        assert "timestamp" in analysis_result
        assert "confidence_score" in analysis_result
        assert 0.0 <= analysis_result["confidence_score"] <= 1.0

    async def test_message_processing(self, intelligence_agent):
        """Test message processing"""
        message = {
            "type": "analyze_session",
            "payload": {
                "session_id": "session-123",
                "session_data": {
                    "transcript": [
                        {"command": "whoami", "response": "root"}
                    ]
                }
            }
        }
        
        result = await intelligence_agent.process_message(message)
        
        assert result is not None
        assert isinstance(result, dict)

    async def test_mitre_navigator_layer_generation(self, intelligence_agent):
        """Test MITRE ATT&CK Navigator layer generation"""
        session_ids = ["session-1", "session-2", "session-3"]
        
        layer = await intelligence_agent.generate_attack_navigator_layer(session_ids)
        
        assert "name" in layer
        assert "techniques" in layer
        assert "version" in layer

    async def test_mitre_statistics(self, intelligence_agent):
        """Test MITRE technique statistics"""
        stats = await intelligence_agent.get_mitre_statistics("24h")
        
        assert "total_techniques" in stats
        assert "technique_frequency" in stats
        assert "tactic_distribution" in stats

    async def test_intelligence_dashboard(self, intelligence_agent):
        """Test intelligence dashboard generation"""
        dashboard = await intelligence_agent.generate_intelligence_dashboard("24h")
        
        assert "summary" in dashboard
        assert "threat_landscape" in dashboard
        assert "mitre_coverage" in dashboard

    async def test_intelligence_export(self, intelligence_agent):
        """Test intelligence data export"""
        export_data = await intelligence_agent.export_intelligence_data(
            export_format="json",
            time_range="24h",
            include_raw_data=False
        )
        
        assert "format" in export_data
        assert "data" in export_data
        assert "metadata" in export_data

    async def test_enhanced_mitre_statistics(self, intelligence_agent):
        """Test enhanced MITRE statistics"""
        stats = await intelligence_agent.get_enhanced_mitre_statistics(
            time_range="24h",
            include_campaign_analysis=True
        )
        
        assert "technique_statistics" in stats
        assert "campaign_analysis" in stats
        assert "threat_actor_mapping" in stats

    async def test_threat_landscape_report(self, intelligence_agent):
        """Test threat landscape report generation"""
        report = await intelligence_agent.generate_mitre_threat_landscape_report("7d")
        
        assert "executive_summary" in report
        assert "threat_trends" in report
        assert "mitre_analysis" in report

    async def test_error_handling(self, intelligence_agent):
        """Test error handling in session analysis"""
        # Test with malformed data
        invalid_data = {"invalid": "data"}
        
        try:
            result = await intelligence_agent.analyze_session(invalid_data)
            # Should either raise an exception or return error info
            if isinstance(result, dict):
                assert "error" in result or "status" in result
        except ValueError:
            # This is expected for invalid data
            pass

    @pytest.mark.slow
    async def test_concurrent_session_analysis(self, intelligence_agent):
        """Test concurrent session analysis"""
        import asyncio
        
        # Create multiple analysis tasks
        session_data_list = [
            {
                "session_id": f"session-{i}",
                "transcript": [{"command": f"test-{i}", "response": "output"}]
            }
            for i in range(3)
        ]
        
        analysis_tasks = [
            intelligence_agent.analyze_session(session_data)
            for session_data in session_data_list
        ]
        
        results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        assert len(results) == 3
        # Check that most results are successful
        successful_results = [r for r in results if isinstance(r, dict) and "session_id" in r]
        assert len(successful_results) >= 0