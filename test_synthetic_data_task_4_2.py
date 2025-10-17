#!/usr/bin/env python3
"""
Test script specifically for Task 4.2: Implement synthetic data generation and management
Tests the enhanced AI-powered synthetic data generation capabilities
"""

import asyncio
import json
from datetime import datetime
from agents.interaction.synthetic_data_generator import SyntheticDataGenerator


def test_ai_powered_credential_generation():
    """Test AI-powered synthetic credential generation"""
    print("🔐 Testing AI-Powered Credential Generation...")
    
    generator = SyntheticDataGenerator()
    
    # Test different complexity levels
    complexities = ["basic", "medium", "complex"]
    contexts = [
        {"honeypot_type": "ssh"},
        {"honeypot_type": "web_admin"},
        {"honeypot_type": "database"}
    ]
    
    for complexity in complexities:
        for context in contexts:
            credentials = generator.generate_synthetic_credentials(
                count=2, 
                complexity=complexity,
                context=context
            )
            
            print(f"  ✓ {complexity} complexity, {context['honeypot_type']} context:")
            for cred in credentials:
                print(f"    - {cred['username']} / {cred['password']}")
                print(f"      Role: {cred['role']}, Department: {cred['department']}")
                print(f"      Fingerprint: {cred['fingerprint'][:16]}...")
                
                # Validate synthetic marker
                assert cred['synthetic_marker'] == generator.synthetic_marker
                assert 'data_id' in cred
                assert len(cred['permissions']) > 0
    
    print("  🎉 AI-Powered Credential Generation test completed!\n")


def test_synthetic_document_creation():
    """Test synthetic document creation with proper tagging"""
    print("📄 Testing Synthetic Document Creation...")
    
    generator = SyntheticDataGenerator()
    
    document_types = ["policy", "procedure", "report", "memo", "manual"]
    complexities = ["basic", "medium", "detailed"]
    
    for doc_type in document_types:
        for complexity in complexities:
            documents = generator.generate_synthetic_documents(
                count=1,
                document_type=doc_type,
                complexity=complexity
            )
            
            doc = documents[0]
            print(f"  ✓ {doc_type} document ({complexity}):")
            print(f"    - Title: {doc['title']}")
            print(f"    - Author: {doc['author']}")
            print(f"    - Size: {doc['size_bytes']} bytes, {doc['word_count']} words")
            print(f"    - Fingerprint: {doc['fingerprint'][:16]}...")
            
            # Validate synthetic marker and tagging
            assert doc['synthetic_marker'] == generator.synthetic_marker
            assert generator.synthetic_marker in doc['content']
            assert 'data_id' in doc
            assert doc['document_type'] == doc_type
            assert doc['complexity'] == complexity
    
    print("  🎉 Synthetic Document Creation test completed!\n")


def test_realistic_command_output_simulation():
    """Test realistic command output and file system simulation"""
    print("💻 Testing Command Output and File System Simulation...")
    
    generator = SyntheticDataGenerator()
    
    # Test various command outputs
    test_commands = [
        "ls -la",
        "ps aux", 
        "netstat -an",
        "whoami",
        "pwd",
        "cat /etc/passwd",
        "grep error /var/log/syslog",
        "find /home -name '*.txt'",
        "sudo su -",
        "df -h"
    ]
    
    for command in test_commands:
        output = generator.generate_command_output(command)
        print(f"  ✓ Command '{command}' -> {len(output)} chars")
        
        # Validate synthetic marker in output
        assert generator.synthetic_marker in output
        assert len(output) > 0
    
    # Test file system simulation
    file_system = generator.generate_file_system_simulation(depth=2, breadth=3)
    print(f"  ✓ File system simulation generated:")
    print(f"    - Root directory with {len(file_system['children'])} children")
    print(f"    - Synthetic marker: {file_system['synthetic_marker']}")
    print(f"    - Fingerprint: {file_system['fingerprint'][:16]}...")
    
    # Validate file system structure
    assert file_system['type'] == 'directory'
    assert file_system['name'] == '/'
    assert file_system['synthetic_marker'] == generator.synthetic_marker
    assert len(file_system['children']) > 0
    
    print("  🎉 Command Output and File System Simulation test completed!\n")


def test_network_simulation_and_restrictions():
    """Test network simulation and external access restrictions"""
    print("🌐 Testing Network Simulation and Access Restrictions...")
    
    generator = SyntheticDataGenerator()
    
    # Test different network topology types
    network_types = ["corporate", "dmz", "internal", "isolated"]
    
    for network_type in network_types:
        topology = generator.generate_network_topology_simulation(network_type)
        print(f"  ✓ {network_type} network topology:")
        print(f"    - Type: {topology['network_type']}")
        print(f"    - Subnets: {len(topology.get('subnets', []))}")
        print(f"    - Devices: {len(topology.get('devices', []))}")
        print(f"    - Fingerprint: {topology['fingerprint'][:16]}...")
        
        # Validate synthetic marker
        assert topology['synthetic_marker'] == generator.synthetic_marker
        assert topology['network_type'] == network_type
    
    # Test external access restrictions
    restriction_levels = ["high", "medium", "low"]
    
    for level in restriction_levels:
        restrictions = generator.implement_external_access_restrictions(level)
        print(f"  ✓ {level} restriction level:")
        print(f"    - Measures: {len(restrictions['measures'])}")
        print(f"    - Status: {restrictions['restriction_level']}")
        
        # Validate restrictions
        assert restrictions['synthetic_marker'] == generator.synthetic_marker
        assert restrictions['restriction_level'] == level
        assert len(restrictions['measures']) > 0
    
    print("  🎉 Network Simulation and Access Restrictions test completed!\n")


def test_data_management_and_tracking():
    """Test synthetic data management and tracking capabilities"""
    print("📊 Testing Data Management and Tracking...")
    
    generator = SyntheticDataGenerator()
    
    # Generate various types of data
    credentials = generator.generate_synthetic_credentials(count=3)
    documents = generator.generate_synthetic_documents(count=2)
    files = generator.generate_synthetic_files(count=5)
    
    # Test data usage tracking
    for cred in credentials:
        generator.mark_data_usage(cred['data_id'], "test_session_1", {"action": "login_attempt"})
    
    for doc in documents:
        generator.mark_data_usage(doc['data_id'], "test_session_2", {"action": "document_access"})
    
    # Test statistics
    stats = generator.get_synthetic_statistics()
    print(f"  ✓ Generation statistics:")
    print(f"    - Credentials generated: {stats['generation_stats']['credentials_generated']}")
    print(f"    - Documents created: {stats['generation_stats']['documents_created']}")
    print(f"    - Cached data items: {stats['cached_data_count']}")
    print(f"    - Data usage tracking: {stats['data_usage_stats']['total_tracked_items']}")
    
    # Test data export
    manifest = generator.export_synthetic_data_manifest()
    print(f"  ✓ Data manifest exported:")
    print(f"    - Total items: {manifest['total_items']}")
    print(f"    - Export timestamp: {manifest['export_timestamp']}")
    
    # Test data cleanup
    cleanup_result = generator.cleanup_unused_data(max_age_days=0)  # Clean all unused
    print(f"  ✓ Data cleanup:")
    print(f"    - Items cleaned: {cleanup_result['cleaned_items']}")
    print(f"    - Items remaining: {cleanup_result['remaining_items']}")
    
    # Validate tracking functionality
    assert stats['cached_data_count'] > 0
    assert stats['generation_stats']['credentials_generated'] >= 3
    assert stats['generation_stats']['documents_created'] >= 2
    assert manifest['total_items'] > 0
    
    print("  🎉 Data Management and Tracking test completed!\n")


def test_synthetic_data_validation():
    """Test synthetic data validation and fingerprinting"""
    print("🔍 Testing Synthetic Data Validation...")
    
    generator = SyntheticDataGenerator()
    
    # Generate test data
    credential = generator.generate_synthetic_credentials(count=1)[0]
    document = generator.generate_synthetic_documents(count=1)[0]
    
    # Test validation
    assert generator.validate_synthetic_data(credential) == True
    assert generator.validate_synthetic_data(document) == True
    
    # Test with non-synthetic data
    fake_data = {"username": "real_user", "password": "real_pass"}
    assert generator.validate_synthetic_data(fake_data) == False
    
    # Test fingerprinting uniqueness
    fingerprints = set()
    for i in range(10):
        cred = generator.generate_synthetic_credentials(count=1)[0]
        fingerprints.add(cred['fingerprint'])
    
    # All fingerprints should be unique
    assert len(fingerprints) == 10
    
    print(f"  ✓ Synthetic data validation working correctly")
    print(f"  ✓ Fingerprint uniqueness verified ({len(fingerprints)} unique)")
    print("  🎉 Synthetic Data Validation test completed!\n")


def main():
    """Run all Task 4.2 specific tests"""
    print("🚀 Starting Task 4.2: Synthetic Data Generation and Management Tests\n")
    print("=" * 80)
    
    try:
        # Run all test suites for Task 4.2
        test_ai_powered_credential_generation()
        test_synthetic_document_creation()
        test_realistic_command_output_simulation()
        test_network_simulation_and_restrictions()
        test_data_management_and_tracking()
        test_synthetic_data_validation()
        
        print("=" * 80)
        print("🎉 ALL TASK 4.2 TESTS COMPLETED SUCCESSFULLY!")
        print("\n✅ Task 4.2: Implement synthetic data generation and management - COMPLETED")
        print("\nImplemented features:")
        print("  🔐 AI-powered synthetic credential and data generation")
        print("  💻 Realistic command output and file system simulation")
        print("  📄 Synthetic document creation with proper tagging")
        print("  🌐 Network simulation and external access restrictions")
        print("  📊 Comprehensive data management and tracking")
        print("  🔍 Data validation and fingerprinting")
        print("  🏷️ Proper synthetic data tagging and identification")
        
        print("\nRequirements satisfied:")
        print("  ✓ 2.2: Dynamic honeypot creation with synthetic data")
        print("  ✓ 2.5: Synthetic data generation and tracking")
        print("  ✓ 2.6: AI-powered data fingerprinting")
        print("  ✓ 3.3: Realistic command outputs and file simulation")
        print("  ✓ 3.4: Network simulation and access restrictions")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()