"""
Tests for isolation breach detection and prevention
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from tests.security.security_test_utils import (
    MockNetworkIsolation as NetworkIsolation,
    MockSecurityManager as SecurityManager,
    MockCoordinatorAgent as CoordinatorAgent
)

# Mock InteractionAgent
class InteractionAgent:
    def __init__(self, config=None):
        self.config = config or {}
    
    async def start(self):
        pass
    
    async def stop(self):
        pass
    
    async def initialize_session(self, session_id: str, config: Dict[str, Any]):
        return {"session_initialized": True}
    
    async def simulate_command(self, session_id: str, command: str):
        return f"Simulated output for: {command}"


@pytest.mark.security
@pytest.mark.asyncio
class TestIsolationBreachDetection:
    """Test isolation breach detection and prevention mechanisms"""

    @pytest.fixture
    async def isolation_system(self, test_config):
        """Setup isolation testing system"""
        config = {
            **test_config,
            "isolation_mode": "strict",
            "breach_detection": True,
            "auto_containment": True
        }
        
        network_isolation = NetworkIsolation(config=config)
        security_manager = SecurityManager(config=config)
        coordinator = CoordinatorAgent(config=config)
        interaction = InteractionAgent(config=config)
        
        await coordinator.start()
        await interaction.start()
        await security_manager.start()
        
        system = {
            "network_isolation": network_isolation,
            "security_manager": security_manager,
            "coordinator": coordinator,
            "interaction": interaction
        }
        
        yield system
        
        await coordinator.stop()
        await interaction.stop()
        await security_manager.stop()

    async def test_network_boundary_breach_detection(self, isolation_system):
        """Test detection of network boundary breaches"""
        network_isolation = isolation_system["network_isolation"]
        security_manager = isolation_system["security_manager"]
        
        # Setup network isolation rules
        isolation_config = {
            "allowed_networks": ["192.168.1.0/24", "10.0.0.0/8"],
            "blocked_networks": ["0.0.0.0/0"],  # Block all external
            "egress_filtering": True,
            "ingress_filtering": True
        }
        
        await network_isolation.configure_isolation("test-honeypot-1", isolation_config)
        
        # Test legitimate internal traffic (should be allowed)
        internal_traffic = [
            {"src": "192.168.1.100", "dst": "192.168.1.200", "port": 22},
            {"src": "10.0.0.50", "dst": "10.0.0.100", "port": 80},
            {"src": "192.168.1.150", "dst": "192.168.1.1", "port": 53}
        ]
        
        for traffic in internal_traffic:
            breach_check = await network_isolation.check_traffic_violation(
                "test-honeypot-1", traffic
            )
            assert breach_check["violation"] is False
            assert breach_check["action"] == "allow"
        
        # Test external traffic (should be blocked and detected)
        external_traffic = [
            {"src": "192.168.1.100", "dst": "8.8.8.8", "port": 53},
            {"src": "10.0.0.50", "dst": "1.1.1.1", "port": 80},
            {"src": "192.168.1.150", "dst": "malicious.com", "port": 4444}
        ]
        
        breach_count = 0
        for traffic in external_traffic:
            breach_check = await network_isolation.check_traffic_violation(
                "test-honeypot-1", traffic
            )
            
            if breach_check["violation"]:
                breach_count += 1
                
                # Verify breach is reported to security manager
                await security_manager.report_isolation_breach(
                    "test-honeypot-1", "network_boundary", traffic
                )
        
        # Should detect all external traffic as breaches
        assert breach_count == len(external_traffic)

    async def test_container_escape_detection(self, isolation_system):
        """Test detection of container escape attempts"""
        interaction = isolation_system["interaction"]
        security_manager = isolation_system["security_manager"]
        
        session_id = "container-escape-test"
        
        # Initialize isolated session
        await interaction.initialize_session(session_id, {
            "container_isolation": True,
            "escape_detection": True,
            "resource_limits": {"cpu": "0.5", "memory": "256MB"}
        })
        
        # Container escape techniques
        escape_attempts = [
            "docker run --privileged -v /:/host alpine chroot /host",
            "runc exec --user 0 container_id /bin/sh",
            "echo 'malicious' > /proc/sys/kernel/core_pattern",
            "mount -t proc proc /proc",
            "unshare -r -p -m -u -i -n /bin/bash",
            "nsenter -t 1 -m -u -i -n -p /bin/bash",
            "capsh --print | grep cap_sys_admin",
            "/usr/bin/newuidmap $$ 0 0 1",
        ]
        
        escape_detected = 0
        
        for attempt in escape_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check for escape detection
            escape_check = await security_manager.detect_container_escape(
                session_id, attempt, response
            )
            
            if escape_check["escape_detected"]:
                escape_detected += 1
                
                # Verify containment action
                assert escape_check["containment_action"] in [
                    "block_command", "terminate_session", "isolate_container"
                ]
        
        # Should detect most escape attempts
        assert escape_detected >= len(escape_attempts) * 0.6

    async def test_process_isolation_breach(self, isolation_system):
        """Test detection of process isolation breaches"""
        interaction = isolation_system["interaction"]
        security_manager = isolation_system["security_manager"]
        
        session_id = "process-isolation-test"
        
        await interaction.initialize_session(session_id, {
            "process_isolation": True,
            "pid_namespace": True,
            "process_monitoring": True
        })
        
        # Process isolation breach attempts
        breach_attempts = [
            "kill -9 1",  # Try to kill init process
            "ps aux | grep -v $(whoami)",  # Try to see other users' processes
            "pgrep -f sshd",  # Try to find system processes
            "lsof -p 1",  # Try to access init process files
            "gdb -p 1",  # Try to attach debugger to init
            "strace -p 1",  # Try to trace init process
            "cat /proc/1/environ",  # Try to read init environment
            "echo 'test' > /proc/1/mem",  # Try to write to init memory
        ]
        
        isolation_violations = 0
        
        for attempt in breach_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check for process isolation violation
            violation_check = await security_manager.check_process_isolation_breach(
                session_id, attempt, response
            )
            
            if violation_check["violation_detected"]:
                isolation_violations += 1
                
                # Should block access to system processes
                assert any(indicator in response for indicator in [
                    "Permission denied", "Operation not permitted",
                    "No such process", "Access denied"
                ])
        
        # Should detect most process isolation breaches
        assert isolation_violations >= len(breach_attempts) * 0.7

    async def test_filesystem_isolation_breach(self, isolation_system):
        """Test detection of filesystem isolation breaches"""
        interaction = isolation_system["interaction"]
        security_manager = isolation_system["security_manager"]
        
        session_id = "filesystem-isolation-test"
        
        await interaction.initialize_session(session_id, {
            "filesystem_isolation": True,
            "chroot_jail": True,
            "mount_namespace": True
        })
        
        # Filesystem isolation breach attempts
        fs_breach_attempts = [
            "chroot /",  # Try to break out of chroot
            "cd ../../../../",  # Directory traversal
            "mount -t tmpfs tmpfs /tmp",  # Try to mount filesystem
            "umount /proc",  # Try to unmount system filesystem
            "ln -s /etc/passwd /tmp/passwd",  # Try to create symlink to system file
            "mknod /tmp/null c 1 3",  # Try to create device node
            "mount --bind /etc /tmp/etc",  # Try bind mount
            "pivot_root /tmp /tmp/old",  # Try to change root
        ]
        
        fs_violations = 0
        
        for attempt in fs_breach_attempts:
            response = await interaction.simulate_command(session_id, attempt)
            
            # Check for filesystem isolation breach
            breach_check = await security_manager.detect_filesystem_breach(
                session_id, attempt, response
            )
            
            if breach_check["breach_detected"]:
                fs_violations += 1
                
                # Should prevent filesystem manipulation
                assert any(indicator in response for indicator in [
                    "Permission denied", "Operation not permitted",
                    "Read-only file system", "Device or resource busy"
                ])
        
        # Should detect most filesystem breaches
        assert fs_violations >= len(fs_breach_attempts) * 0.6

    async def test_resource_limit_bypass_detection(self, isolation_system):
        """Test detection of resource limit bypass attempts"""
        interaction = isolation_system["interaction"]
        security_manager = isolation_system["security_manager"]
        
        session_id = "resource-limit-test"
        
        # Set strict resource limits
        await interaction.initialize_session(session_id, {
            "resource_limits": {
                "cpu": "0.1",  # 10% CPU
                "memory": "64MB",
                "disk": "100MB",
                "processes": 10,
                "file_descriptors": 100
            },
            "limit_enforcement": True
        })
        
        # Resource exhaustion attempts
        resource_attacks = [
            ":(){ :|:& };:",  # Fork bomb
            "dd if=/dev/zero of=/tmp/bigfile bs=1M count=200",  # Disk exhaustion
            "python -c 'a=[0]*999999999'",  # Memory exhaustion
            "while true; do sleep 1 & done",  # Process exhaustion
            "exec 999<>/dev/null",  # File descriptor exhaustion
            "yes > /dev/null &",  # CPU exhaustion
        ]
        
        limit_violations = 0
        
        for attack in resource_attacks:
            response = await interaction.simulate_command(session_id, attack)
            
            # Check for resource limit violation
            limit_check = await security_manager.check_resource_limit_breach(
                session_id, attack, response
            )
            
            if limit_check["limit_exceeded"]:
                limit_violations += 1
                
                # Should enforce resource limits
                assert any(indicator in response for indicator in [
                    "Resource temporarily unavailable",
                    "Cannot allocate memory", "Disk quota exceeded",
                    "Too many processes", "Command terminated"
                ])
        
        # Should detect most resource limit violations
        assert limit_violations >= len(resource_attacks) * 0.5

    async def test_privilege_boundary_breach(self, isolation_system):
        """Test detection of privilege boundary breaches"""
        interaction = isolation_system["interaction"]
        security_manager = isolation_system["security_manager"]
        
        session_id = "privilege-boundary-test"
        
        # Initialize with limited privileges
        await interaction.initialize_session(session_id, {
            "user_privileges": "limited",
            "capability_restrictions": True,
            "privilege_monitoring": True
        })
        
        # Privilege escalation attempts
        privilege_attacks = [
            "sudo su -",
            "su root",
            "sudo -i",
            "pkexec /bin/bash",
            "doas sh",
            "runuser -l root",
            "machinectl shell root@",
            "systemd-run --uid=0 /bin/bash",
        ]
        
        privilege_violations = 0
        
        for attack in privilege_attacks:
            response = await interaction.simulate_command(session_id, attack)
            
            # Check for privilege escalation attempt
            priv_check = await security_manager.detect_privilege_escalation(
                session_id, attack, response
            )
            
            if priv_check["escalation_detected"]:
                privilege_violations += 1
                
                # Should block privilege escalation
                assert any(indicator in response for indicator in [
                    "Permission denied", "Authentication failure",
                    "sudo: incorrect password", "Command not found"
                ])
        
        # Should detect most privilege escalation attempts
        assert privilege_violations >= len(privilege_attacks) * 0.8

    async def test_network_namespace_breach(self, isolation_system):
        """Test detection of network namespace breaches"""
        network_isolation = isolation_system["network_isolation"]
        security_manager = isolation_system["security_manager"]
        
        # Setup network namespace isolation
        namespace_config = {
            "network_namespace": "isolated",
            "interface_restrictions": ["lo", "veth0"],
            "port_restrictions": [22, 80, 443],
            "protocol_restrictions": ["tcp", "udp"]
        }
        
        await network_isolation.setup_network_namespace("test-ns", namespace_config)
        
        # Network namespace breach attempts
        ns_breach_attempts = [
            {"action": "create_interface", "interface": "eth1"},
            {"action": "bind_port", "port": 4444},
            {"action": "raw_socket", "protocol": "icmp"},
            {"action": "packet_injection", "target": "external"},
            {"action": "tunnel_creation", "type": "gre"},
        ]
        
        ns_violations = 0
        
        for attempt in ns_breach_attempts:
            breach_check = await network_isolation.check_namespace_breach(
                "test-ns", attempt
            )
            
            if breach_check["breach_detected"]:
                ns_violations += 1
                
                # Report to security manager
                await security_manager.report_namespace_breach(
                    "test-ns", attempt
                )
        
        # Should detect namespace breaches
        assert ns_violations >= len(ns_breach_attempts) * 0.6

    async def test_syscall_filtering_bypass(self, isolation_system):
        """Test detection of syscall filtering bypass attempts"""
        interaction = isolation_system["interaction"]
        security_manager = isolation_system["security_manager"]
        
        session_id = "syscall-filter-test"
        
        # Initialize with syscall filtering
        await interaction.initialize_session(session_id, {
            "syscall_filtering": True,
            "blocked_syscalls": [
                "mount", "umount", "chroot", "pivot_root",
                "ptrace", "process_vm_readv", "process_vm_writev"
            ],
            "seccomp_enabled": True
        })
        
        # Syscall bypass attempts
        syscall_attacks = [
            "python -c 'import ctypes; ctypes.CDLL(None).mount(...)'",
            "perl -e 'syscall(165, ...)'",  # mount syscall number
            "ruby -e 'require \"fiddle\"; Fiddle.dlopen(nil).sym(\"mount\").call(...)'",
            "strace -e trace=mount /bin/true",
            "gdb -batch -ex 'call mount(...)' /bin/true",
        ]
        
        syscall_violations = 0
        
        for attack in syscall_attacks:
            response = await interaction.simulate_command(session_id, attack)
            
            # Check for syscall filtering bypass
            syscall_check = await security_manager.detect_syscall_bypass(
                session_id, attack, response
            )
            
            if syscall_check["bypass_detected"]:
                syscall_violations += 1
                
                # Should block syscall bypass attempts
                assert any(indicator in response for indicator in [
                    "Operation not permitted", "Bad system call",
                    "Killed", "Segmentation fault"
                ])
        
        # Should detect some syscall bypass attempts
        assert syscall_violations >= len(syscall_attacks) * 0.4

    async def test_isolation_breach_response(self, isolation_system):
        """Test automated response to isolation breaches"""
        coordinator = isolation_system["coordinator"]
        security_manager = isolation_system["security_manager"]
        
        # Create honeypot with breach response enabled
        request = {
            "threat_data": {"source_ip": "192.168.1.100"},
            "honeypot_type": "ssh",
            "breach_response": {
                "auto_containment": True,
                "escalation_enabled": True,
                "emergency_shutdown": True
            }
        }
        
        honeypot = await coordinator.create_honeypot(request)
        honeypot_id = honeypot["honeypot_id"]
        
        # Simulate multiple isolation breaches
        breaches = [
            {"type": "network_boundary", "severity": "high"},
            {"type": "container_escape", "severity": "critical"},
            {"type": "privilege_escalation", "severity": "high"},
        ]
        
        for breach in breaches:
            await security_manager.report_isolation_breach(
                honeypot_id, breach["type"], {"severity": breach["severity"]}
            )
        
        # Check if automated response was triggered
        response_status = await security_manager.get_breach_response_status(honeypot_id)
        
        assert response_status["containment_applied"] is True
        assert response_status["breach_count"] == len(breaches)
        
        # Verify emergency shutdown if critical breach occurred
        critical_breaches = [b for b in breaches if b["severity"] == "critical"]
        if critical_breaches:
            assert response_status["emergency_shutdown"] is True
        
        # Cleanup
        await coordinator.destroy_honeypot(honeypot_id)

    async def test_breach_detection_performance(self, isolation_system):
        """Test performance of breach detection under load"""
        security_manager = isolation_system["security_manager"]
        
        # Generate high volume of potential breaches
        breach_count = 100
        breach_events = []
        
        for i in range(breach_count):
            event = {
                "honeypot_id": f"hp-{i % 10}",
                "breach_type": ["network", "process", "filesystem"][i % 3],
                "severity": ["low", "medium", "high"][i % 3],
                "timestamp": datetime.utcnow().isoformat()
            }
            breach_events.append(event)
        
        # Measure detection processing time
        start_time = datetime.utcnow()
        
        # Process breach events concurrently
        detection_tasks = [
            security_manager.process_breach_event(event)
            for event in breach_events
        ]
        
        results = await asyncio.gather(*detection_tasks)
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        # Verify performance requirements
        throughput = breach_count / processing_time
        assert throughput >= 50  # Should process at least 50 events per second
        
        # Verify all events were processed
        assert len(results) == breach_count
        processed_count = sum(1 for result in results if result["processed"])
        assert processed_count == breach_count