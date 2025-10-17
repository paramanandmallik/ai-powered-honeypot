"""
Synthetic Data Generator for Interaction Agent
Generates realistic but synthetic data for honeypot interactions.
"""

import json
import random
import string
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from uuid import uuid4
import hashlib
import base64


class SyntheticDataGenerator:
    """Generates synthetic data for honeypot interactions with AI-powered generation"""
    
    def __init__(self):
        self.synthetic_marker = "SYNTHETIC_DATA"
        self.fingerprint_salt = str(uuid4())
        
        # Initialize data templates and AI models
        self._initialize_templates()
        self._initialize_ai_generation_models()
        
        # Data management
        self.generated_data_cache = {}
        self.data_usage_tracking = {}
        self.data_relationships = {}
        
        # Generation statistics
        self.generation_stats = {
            "credentials_generated": 0,
            "files_generated": 0,
            "commands_simulated": 0,
            "documents_created": 0,
            "network_simulations": 0
        }
    
    def _initialize_templates(self):
        """Initialize comprehensive synthetic data templates"""
        self.templates = {
            "usernames": [
                "admin", "administrator", "root", "user", "guest", "test",
                "service", "backup", "monitor", "support", "operator", "manager",
                "developer", "analyst", "engineer", "consultant", "specialist", "coordinator"
            ],
            "passwords": [
                "Password123!", "Admin2024", "Welcome123", "System2024!",
                "Backup2024", "Monitor123", "Service2024", "Support123!",
                "Corporate2024", "Secure123!", "Access2024", "Login123!"
            ],
            "company_names": [
                "TechCorp Industries", "Global Systems Inc", "DataFlow Solutions",
                "SecureNet Corp", "CloudTech Systems", "InfoSys Global",
                "Digital Dynamics", "CyberSafe Solutions", "NetWork Enterprises",
                "SystemCore Ltd", "DataVault Corp", "TechFlow Industries"
            ],
            "departments": [
                "IT", "Security", "Operations", "Finance", "HR", "Marketing",
                "Engineering", "Support", "Administration", "Management",
                "Research", "Development", "Quality Assurance", "Sales",
                "Customer Service", "Legal", "Compliance", "Procurement"
            ],
            "file_extensions": [
                ".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
                ".csv", ".log", ".cfg", ".conf", ".ini", ".xml", ".json",
                ".yaml", ".yml", ".properties", ".env", ".bak", ".tmp"
            ],
            "command_outputs": {
                "ls": ["Documents", "Downloads", "Desktop", "Pictures", "Videos", "Music", 
                       "Projects", "Backups", "Configs", "Scripts", "Logs", "Archives"],
                "ps": ["systemd", "kthreadd", "ksoftirqd", "migration", "rcu_gp",
                       "nginx", "apache2", "mysql", "postgres", "redis", "docker"],
                "netstat": ["tcp 0.0.0.0:22", "tcp 0.0.0.0:80", "tcp 0.0.0.0:443",
                           "tcp 127.0.0.1:3306", "tcp 127.0.0.1:5432", "tcp 0.0.0.0:8080"],
                "whoami": ["admin", "root", "user", "service", "www-data", "mysql", "postgres"],
                "pwd": ["/home/admin", "/root", "/var/log", "/etc", "/tmp", "/opt", "/usr/local"]
            },
            "realistic_names": {
                "first_names": ["Alex", "Sarah", "Mike", "Jennifer", "David", "Lisa", 
                               "Robert", "Maria", "James", "Anna", "Chris", "Emma"],
                "last_names": ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
                              "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez"]
            },
            "job_titles": [
                "System Administrator", "Network Engineer", "Database Administrator",
                "Security Analyst", "DevOps Engineer", "Software Developer",
                "IT Manager", "Technical Support", "Infrastructure Engineer",
                "Cloud Architect", "Cybersecurity Specialist", "Data Analyst"
            ],
            "synthetic_domains": [
                "synthetic-corp.local", "test-systems.internal", "demo-network.local",
                "honeypot-env.test", "simulation.local", "fake-enterprise.net"
            ]
        }
    
    def _initialize_ai_generation_models(self):
        """Initialize AI models for synthetic data generation"""
        self.ai_generation_config = {
            "credential_generation": {
                "model_type": "pattern_based_nlp",
                "complexity_levels": {
                    "basic": {"length": 8, "special_chars": 1, "numbers": 2},
                    "medium": {"length": 12, "special_chars": 2, "numbers": 3},
                    "complex": {"length": 16, "special_chars": 3, "numbers": 4}
                },
                "patterns": [
                    "{word}{year}{special}",
                    "{company}{number}{special}",
                    "{role}{season}{number}",
                    "{department}{month}{special}"
                ]
            },
            "document_generation": {
                "model_type": "content_generation_nlp",
                "document_types": {
                    "policy": "Corporate policy document template",
                    "procedure": "Standard operating procedure template", 
                    "report": "Business report template",
                    "memo": "Internal memorandum template",
                    "manual": "Technical manual template"
                },
                "content_complexity": {
                    "basic": 100,  # words
                    "medium": 300,
                    "detailed": 500
                }
            },
            "network_simulation": {
                "model_type": "network_topology_simulation",
                "topology_types": ["corporate", "dmz", "internal", "isolated"],
                "service_simulation": {
                    "web_services": ["nginx", "apache", "iis"],
                    "databases": ["mysql", "postgresql", "mongodb"],
                    "applications": ["jenkins", "gitlab", "confluence"]
                }
            }
        }
    
    def generate_synthetic_credentials(self, count: int = 1, complexity: str = "medium", 
                                     context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Generate AI-powered synthetic user credentials with realistic patterns"""
        credentials = []
        
        for i in range(count):
            # Generate realistic username
            username = self._generate_realistic_username(i, context)
            
            # Generate AI-powered password
            password = self._generate_ai_password(complexity, username, context)
            
            # Generate realistic user profile
            user_profile = self._generate_user_profile(username, context)
            
            credential = {
                "username": username,
                "password": password,
                "full_name": user_profile["full_name"],
                "email": user_profile["email"],
                "department": user_profile["department"],
                "job_title": user_profile["job_title"],
                "created_date": self._generate_random_date(days_back=365),
                "last_login": self._generate_random_date(days_back=30),
                "password_changed": self._generate_random_date(days_back=90),
                "status": random.choice(["active", "inactive", "locked", "disabled"]),
                "role": random.choice(["user", "admin", "service", "guest", "power_user"]),
                "permissions": self._generate_user_permissions(user_profile["job_title"]),
                "login_attempts": random.randint(0, 5),
                "account_locked": random.choice([True, False]) if random.random() < 0.1 else False,
                "fingerprint": self._generate_fingerprint(f"{username}:{password}"),
                "synthetic_marker": self.synthetic_marker,
                "generation_context": context or {},
                "data_id": str(uuid4())
            }
            
            # Track generated data
            self._track_generated_data("credential", credential)
            credentials.append(credential)
        
        self.generation_stats["credentials_generated"] += count
        return credentials
    
    def _generate_realistic_username(self, index: int, context: Optional[Dict[str, Any]]) -> str:
        """Generate realistic username based on context"""
        if context and "honeypot_type" in context:
            honeypot_type = context["honeypot_type"]
            
            # Different username patterns for different honeypot types
            if honeypot_type == "database":
                base_names = ["dbadmin", "dba", "mysql_user", "postgres", "oracle_admin"]
            elif honeypot_type == "web_admin":
                base_names = ["webadmin", "admin", "manager", "operator", "support"]
            elif honeypot_type == "ssh":
                base_names = ["sysadmin", "root", "admin", "user", "developer"]
            else:
                base_names = self.templates["usernames"]
        else:
            base_names = self.templates["usernames"]
        
        base_username = random.choice(base_names)
        
        # Add realistic variations
        variations = [
            base_username,
            f"{base_username}{random.randint(1, 99)}",
            f"{base_username}_{random.choice(['prod', 'dev', 'test', 'backup'])}",
            f"{base_username}.{random.choice(['admin', 'user', 'service'])}"
        ]
        
        return random.choice(variations)
    
    def _generate_ai_password(self, complexity: str, username: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate AI-powered realistic password"""
        config = self.ai_generation_config["credential_generation"]
        complexity_config = config["complexity_levels"].get(complexity, config["complexity_levels"]["medium"])
        
        # Base components for password generation
        words = ["Password", "Admin", "System", "Secure", "Access", "Login", "Corporate", "Network"]
        years = ["2023", "2024", "2025"]
        seasons = ["Spring", "Summer", "Fall", "Winter"]
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        special_chars = ["!", "@", "#", "$", "%", "&", "*"]
        
        # Select pattern
        pattern = random.choice(config["patterns"])
        
        # Generate password components
        components = {
            "word": random.choice(words),
            "year": random.choice(years),
            "company": random.choice(self.templates["company_names"]).split()[0],
            "number": str(random.randint(10, 999)),
            "special": "".join(random.choices(special_chars, k=complexity_config["special_chars"])),
            "role": random.choice(["Admin", "User", "Manager", "Tech"]),
            "season": random.choice(seasons),
            "month": random.choice(months),
            "department": random.choice(self.templates["departments"])[:4]
        }
        
        # Apply pattern
        password = pattern.format(**components)
        
        # Ensure minimum length
        while len(password) < complexity_config["length"]:
            password += str(random.randint(0, 9))
        
        # Truncate if too long
        if len(password) > complexity_config["length"] + 5:
            password = password[:complexity_config["length"] + 5]
        
        return password
    
    def _generate_user_profile(self, username: str, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate realistic user profile"""
        first_name = random.choice(self.templates["realistic_names"]["first_names"])
        last_name = random.choice(self.templates["realistic_names"]["last_names"])
        
        department = random.choice(self.templates["departments"])
        job_title = random.choice(self.templates["job_titles"])
        
        # Generate synthetic email
        domain = random.choice(self.templates["synthetic_domains"])
        email_formats = [
            f"{first_name.lower()}.{last_name.lower()}@{domain}",
            f"{first_name.lower()}{last_name.lower()}@{domain}",
            f"{username}@{domain}",
            f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 99)}@{domain}"
        ]
        
        return {
            "full_name": f"{first_name} {last_name}",
            "first_name": first_name,
            "last_name": last_name,
            "email": random.choice(email_formats),
            "department": department,
            "job_title": job_title
        }
    
    def _generate_user_permissions(self, job_title: str) -> List[str]:
        """Generate realistic user permissions based on job title"""
        permission_mapping = {
            "System Administrator": ["read", "write", "execute", "admin", "sudo", "config"],
            "Database Administrator": ["read", "write", "execute", "db_admin", "backup", "restore"],
            "Security Analyst": ["read", "audit", "security", "monitor", "investigate"],
            "Network Engineer": ["read", "write", "network", "config", "monitor"],
            "Software Developer": ["read", "write", "execute", "deploy", "debug"],
            "IT Manager": ["read", "write", "admin", "approve", "manage"],
            "Technical Support": ["read", "troubleshoot", "assist", "monitor"]
        }
        
        base_permissions = ["read"]  # Everyone gets read
        specific_permissions = permission_mapping.get(job_title, ["read", "write"])
        
        return base_permissions + specific_permissions
    
    def _track_generated_data(self, data_type: str, data: Dict[str, Any]):
        """Track generated synthetic data for management"""
        data_id = data.get("data_id", str(uuid4()))
        
        self.generated_data_cache[data_id] = {
            "type": data_type,
            "data": data,
            "generated_at": datetime.utcnow().isoformat(),
            "usage_count": 0,
            "last_used": None
        }
        
        # Initialize usage tracking
        self.data_usage_tracking[data_id] = {
            "sessions_used": [],
            "contexts_used": [],
            "total_usage": 0
        }
    
    def generate_command_output(self, command: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Generate realistic command output simulation"""
        command_base = command.split()[0] if command else "unknown"
        
        # Handle common commands
        if command_base == "ls":
            output = self._generate_ls_output(command, context)
        elif command_base == "ps":
            output = self._generate_ps_output(command, context)
        elif command_base == "netstat":
            output = self._generate_netstat_output(command, context)
        elif command_base == "whoami":
            output = self._generate_whoami_output(context)
        elif command_base == "pwd":
            output = self._generate_pwd_output(context)
        elif command_base == "cat":
            output = self._generate_cat_output(command, context)
        elif command_base == "grep":
            output = self._generate_grep_output(command, context)
        elif command_base == "find":
            output = self._generate_find_output(command, context)
        elif command_base in ["sudo", "su"]:
            output = self._generate_privilege_output(command, context)
        else:
            output = self._generate_generic_output(command, context)
        
        # Ensure synthetic marker is included in all command outputs
        if output and self.synthetic_marker not in output:
            output += f"\n# {self.synthetic_marker}"
        
        self.generation_stats["commands_simulated"] += 1
        return output
    
    def _generate_ls_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate ls command output"""
        files = random.sample(self.templates["command_outputs"]["ls"], 
                            random.randint(3, 6))
        
        # Add some synthetic files
        synthetic_files = [
            f"backup_{datetime.now().strftime('%Y%m%d')}.tar.gz",
            f"config_{random.randint(1, 10)}.conf",
            f"log_{random.randint(1, 100)}.txt"
        ]
        
        files.extend(random.sample(synthetic_files, random.randint(1, 2)))
        
        if "-l" in command:
            # Long format
            output_lines = []
            for file in files:
                permissions = random.choice(["drwxr-xr-x", "-rw-r--r--", "-rwxr-xr-x"])
                size = random.randint(1024, 1048576)
                date = self._generate_random_date(days_back=365).strftime("%b %d %H:%M")
                output_lines.append(f"{permissions} 1 admin admin {size:>8} {date} {file}")
            return "\n".join(output_lines)
        else:
            return "  ".join(files)
    
    def _generate_ps_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate ps command output"""
        processes = []
        base_processes = self.templates["command_outputs"]["ps"]
        
        for i, process in enumerate(random.sample(base_processes, 4)):
            pid = random.randint(1000, 9999)
            cpu = random.uniform(0.1, 5.0)
            mem = random.uniform(0.5, 10.0)
            processes.append(f"{pid:>5} {cpu:>5.1f} {mem:>5.1f} {process}")
        
        header = "  PID  %CPU  %MEM COMMAND"
        return header + "\n" + "\n".join(processes)
    
    def _generate_netstat_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate netstat command output"""
        connections = []
        base_connections = self.templates["command_outputs"]["netstat"]
        
        for conn in base_connections:
            state = random.choice(["LISTEN", "ESTABLISHED", "TIME_WAIT"])
            connections.append(f"{conn:<25} {state}")
        
        # Add some synthetic connections
        for _ in range(random.randint(2, 4)):
            port = random.randint(8000, 9999)
            ip = f"192.168.1.{random.randint(10, 254)}"
            state = random.choice(["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"])
            connections.append(f"tcp {ip}:{port:<15} {state}")
        
        header = "Proto Local Address           State"
        return header + "\n" + "\n".join(connections)
    
    def _generate_whoami_output(self, context: Optional[Dict[str, Any]]) -> str:
        """Generate whoami command output"""
        if context and "logged_in_user" in context:
            return context["logged_in_user"]
        return random.choice(self.templates["command_outputs"]["whoami"])
    
    def _generate_pwd_output(self, context: Optional[Dict[str, Any]]) -> str:
        """Generate pwd command output"""
        if context and "current_directory" in context:
            return context["current_directory"]
        return random.choice(self.templates["command_outputs"]["pwd"])
    
    def _generate_cat_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate cat command output for files"""
        parts = command.split()
        if len(parts) < 2:
            return "cat: missing file operand"
        
        filename = parts[1]
        
        if "config" in filename.lower():
            return self._generate_config_file_content()
        elif "log" in filename.lower():
            return self._generate_log_file_content()
        elif filename.endswith(".txt"):
            return self._generate_text_file_content()
        else:
            return f"cat: {filename}: No such file or directory"
    
    def _generate_config_file_content(self) -> str:
        """Generate synthetic configuration file content"""
        config_lines = [
            "# Synthetic Configuration File",
            f"# Generated: {datetime.now().isoformat()}",
            f"# Fingerprint: {self._generate_fingerprint('config')}",
            "",
            "server_name=synthetic-server-01",
            "port=8080",
            "max_connections=100",
            "timeout=30",
            "log_level=INFO",
            f"admin_email=admin@{random.choice(['example.com', 'test.org', 'demo.net'])}",
            "",
            f"# {self.synthetic_marker}"
        ]
        return "\n".join(config_lines)
    
    def _generate_log_file_content(self) -> str:
        """Generate synthetic log file content"""
        log_entries = []
        
        for _ in range(random.randint(5, 10)):
            timestamp = self._generate_random_date(days_back=7).strftime("%Y-%m-%d %H:%M:%S")
            level = random.choice(["INFO", "WARN", "ERROR", "DEBUG"])
            message = random.choice([
                "User login successful",
                "Configuration reloaded",
                "Backup completed",
                "Service started",
                "Connection established",
                "Task completed successfully"
            ])
            log_entries.append(f"[{timestamp}] {level}: {message}")
        
        log_entries.append(f"# {self.synthetic_marker}")
        return "\n".join(log_entries)
    
    def _generate_text_file_content(self) -> str:
        """Generate synthetic text file content"""
        content_lines = [
            "Synthetic Document Content",
            f"Created: {datetime.now().strftime('%Y-%m-%d')}",
            "",
            "This is a synthetic document created for testing purposes.",
            "It contains no real or sensitive information.",
            "",
            f"Document ID: {str(uuid4())}",
            f"Fingerprint: {self._generate_fingerprint('document')}",
            "",
            f"# {self.synthetic_marker}"
        ]
        return "\n".join(content_lines)
    
    def _generate_grep_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate grep command output"""
        parts = command.split()
        if len(parts) < 2:
            return "grep: missing search pattern"
        
        pattern = parts[1]
        matches = [
            f"config.txt:5:server_{pattern}=synthetic_value",
            f"log.txt:12:[INFO] {pattern} operation completed",
            f"data.txt:8:synthetic_{pattern}_entry"
        ]
        
        return "\n".join(random.sample(matches, random.randint(1, len(matches))))
    
    def _generate_find_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate find command output"""
        synthetic_paths = [
            "/home/admin/documents/synthetic_file.txt",
            "/var/log/synthetic_app.log",
            "/etc/synthetic_config.conf",
            "/tmp/synthetic_temp.tmp"
        ]
        
        return "\n".join(random.sample(synthetic_paths, random.randint(2, 4)))
    
    def _generate_privilege_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate privilege escalation command output"""
        if "sudo" in command:
            return "[sudo] password for admin: "
        elif "su" in command:
            return "Password: "
        else:
            return "Permission denied"
    
    def _generate_generic_output(self, command: str, context: Optional[Dict[str, Any]]) -> str:
        """Generate generic command output"""
        return f"{command}: command not found or access denied"
    
    def generate_synthetic_files(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate synthetic file and document metadata"""
        files = []
        
        for _ in range(count):
            filename = f"synthetic_{random.choice(['document', 'report', 'data', 'backup'])}_{random.randint(1, 999)}"
            extension = random.choice(self.templates["file_extensions"])
            
            file_data = {
                "filename": filename + extension,
                "size": random.randint(1024, 10485760),  # 1KB to 10MB
                "created_date": self._generate_random_date(days_back=365),
                "modified_date": self._generate_random_date(days_back=30),
                "owner": random.choice(["admin", "user", "service"]),
                "permissions": random.choice(["644", "755", "600", "700"]),
                "content_type": self._get_content_type(extension),
                "fingerprint": self._generate_fingerprint(filename),
                "synthetic_marker": self.synthetic_marker
            }
            
            files.append(file_data)
        
        return files
    
    def generate_network_simulation(self, restriction_type: str = "firewall") -> Dict[str, Any]:
        """Generate network simulation and restriction logic"""
        if restriction_type == "firewall":
            return self._generate_firewall_simulation()
        elif restriction_type == "dns":
            return self._generate_dns_simulation()
        elif restriction_type == "routing":
            return self._generate_routing_simulation()
        else:
            return self._generate_generic_network_simulation()
    
    def _generate_firewall_simulation(self) -> Dict[str, Any]:
        """Generate firewall restriction simulation"""
        blocked_ports = [22, 23, 80, 443, 3389, 5432, 3306]
        allowed_ports = [8080, 8443, 9000, 9090]
        
        return {
            "type": "firewall",
            "status": "active",
            "blocked_ports": random.sample(blocked_ports, random.randint(3, 5)),
            "allowed_ports": random.sample(allowed_ports, random.randint(2, 3)),
            "default_policy": "deny",
            "rules_count": random.randint(10, 50),
            "synthetic_marker": self.synthetic_marker
        }
    
    def _generate_dns_simulation(self) -> Dict[str, Any]:
        """Generate DNS restriction simulation"""
        blocked_domains = [
            "malicious-site.com", "phishing-domain.net", "suspicious-host.org"
        ]
        allowed_domains = [
            "internal-server.local", "backup-system.internal", "monitoring.local"
        ]
        
        return {
            "type": "dns",
            "status": "filtering_enabled",
            "blocked_domains": blocked_domains,
            "allowed_domains": allowed_domains,
            "dns_servers": ["192.168.1.1", "192.168.1.2"],
            "synthetic_marker": self.synthetic_marker
        }
    
    def _generate_routing_simulation(self) -> Dict[str, Any]:
        """Generate routing restriction simulation"""
        return {
            "type": "routing",
            "status": "restricted",
            "allowed_networks": ["192.168.1.0/24", "10.0.0.0/8"],
            "blocked_networks": ["0.0.0.0/0"],  # Block internet
            "gateway": "192.168.1.1",
            "routes_count": random.randint(5, 15),
            "synthetic_marker": self.synthetic_marker
        }
    
    def _generate_generic_network_simulation(self) -> Dict[str, Any]:
        """Generate generic network simulation"""
        return {
            "type": "generic",
            "status": "isolated",
            "message": "Network access restricted by security policy",
            "contact": "admin@synthetic-domain.local",
            "synthetic_marker": self.synthetic_marker
        }
    
    def _generate_random_date(self, days_back: int = 30) -> datetime:
        """Generate random date within specified days back"""
        start_date = datetime.now() - timedelta(days=days_back)
        random_days = random.randint(0, days_back)
        return start_date + timedelta(days=random_days)
    
    def _generate_fingerprint(self, data: str) -> str:
        """Generate unique fingerprint for synthetic data"""
        combined = f"{data}:{self.fingerprint_salt}:{self.synthetic_marker}"
        hash_obj = hashlib.sha256(combined.encode())
        return base64.b64encode(hash_obj.digest()[:16]).decode()
    
    def _get_content_type(self, extension: str) -> str:
        """Get content type based on file extension"""
        content_types = {
            ".txt": "text/plain",
            ".doc": "application/msword", 
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".pdf": "application/pdf",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".csv": "text/csv",
            ".log": "text/plain",
            ".cfg": "text/plain",
            ".conf": "text/plain",
            ".xml": "application/xml",
            ".json": "application/json"
        }
        return content_types.get(extension, "application/octet-stream")
    
    def validate_synthetic_data(self, data: Any) -> bool:
        """Validate that data is properly marked as synthetic"""
        if isinstance(data, dict):
            return data.get("synthetic_marker") == self.synthetic_marker
        elif isinstance(data, str):
            return self.synthetic_marker in data
        elif isinstance(data, list):
            return all(self.validate_synthetic_data(item) for item in data)
        else:
            return False
    
    def tag_synthetic_data(self, data: Any) -> Any:
        """Add synthetic marker to data"""
        if isinstance(data, dict):
            data["synthetic_marker"] = self.synthetic_marker
            data["fingerprint"] = self._generate_fingerprint(str(data))
        elif isinstance(data, str):
            data += f"\n# {self.synthetic_marker}"
        
        return data
    
    def generate_synthetic_documents(self, count: int = 1, document_type: str = "policy", 
                                   complexity: str = "medium", context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Generate AI-powered synthetic documents with realistic content"""
        documents = []
        
        for i in range(count):
            doc = self._generate_document_content(document_type, complexity, context)
            
            # Add metadata
            doc.update({
                "document_id": str(uuid4()),
                "created_date": self._generate_random_date(days_back=365),
                "modified_date": self._generate_random_date(days_back=30),
                "author": self._generate_document_author(),
                "department": random.choice(self.templates["departments"]),
                "classification": random.choice(["public", "internal", "confidential", "restricted"]),
                "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}",
                "fingerprint": self._generate_fingerprint(f"{document_type}_{i}"),
                "synthetic_marker": self.synthetic_marker,
                "generation_context": context or {}
            })
            
            # Track generated document
            self._track_generated_data("document", doc)
            documents.append(doc)
        
        self.generation_stats["documents_created"] += count
        return documents
    
    def _generate_document_content(self, document_type: str, complexity: str, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate realistic document content based on type and complexity"""
        config = self.ai_generation_config["document_generation"]
        word_count = config["content_complexity"][complexity]
        
        if document_type == "policy":
            return self._generate_policy_document(word_count)
        elif document_type == "procedure":
            return self._generate_procedure_document(word_count)
        elif document_type == "report":
            return self._generate_report_document(word_count)
        elif document_type == "memo":
            return self._generate_memo_document(word_count)
        elif document_type == "manual":
            return self._generate_manual_document(word_count)
        else:
            return self._generate_generic_document(word_count, document_type)
    
    def _generate_policy_document(self, word_count: int) -> Dict[str, Any]:
        """Generate synthetic corporate policy document"""
        policy_topics = [
            "Information Security", "Data Protection", "Access Control", 
            "Remote Work", "Software Usage", "Email Security", "Password Management"
        ]
        
        topic = random.choice(policy_topics)
        title = f"Corporate {topic} Policy"
        
        content_sections = [
            f"# {title}",
            f"## Document Information",
            f"- Policy ID: POL-{random.randint(1000, 9999)}",
            f"- Effective Date: {self._generate_random_date(days_back=180).strftime('%Y-%m-%d')}",
            f"- Review Date: {self._generate_random_date(days_back=-180).strftime('%Y-%m-%d')}",
            f"",
            f"## Purpose",
            f"This policy establishes guidelines for {topic.lower()} within the organization.",
            f"All employees must comply with these requirements to maintain security standards.",
            f"",
            f"## Scope",
            f"This policy applies to all employees, contractors, and third-party users.",
            f"",
            f"## Policy Statement",
            f"The organization is committed to protecting information assets and maintaining compliance.",
            f"Users must follow established procedures and report security incidents immediately.",
            f"",
            f"## Responsibilities",
            f"- IT Department: Implement and maintain security controls",
            f"- Employees: Follow security procedures and report incidents",
            f"- Management: Ensure policy compliance and provide resources",
            f"",
            f"## Compliance",
            f"Violations of this policy may result in disciplinary action.",
            f"Regular audits will be conducted to ensure compliance.",
            f"",
            f"## Contact Information",
            f"For questions, contact: security@{random.choice(self.templates['synthetic_domains'])}",
            f"",
            f"# {self.synthetic_marker}"
        ]
        
        content = "\n".join(content_sections)
        
        return {
            "title": title,
            "document_type": "policy",
            "content": content,
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "format": "markdown"
        }
    
    def _generate_procedure_document(self, word_count: int) -> Dict[str, Any]:
        """Generate synthetic standard operating procedure"""
        procedures = [
            "System Backup", "User Account Creation", "Incident Response",
            "Software Installation", "Network Configuration", "Data Recovery"
        ]
        
        procedure = random.choice(procedures)
        title = f"{procedure} Standard Operating Procedure"
        
        steps = [
            "Verify prerequisites and gather required information",
            "Obtain necessary approvals and permissions",
            "Execute the procedure following established guidelines",
            "Document all actions and results",
            "Verify successful completion",
            "Update relevant documentation and logs"
        ]
        
        content_sections = [
            f"# {title}",
            f"## Overview",
            f"This document outlines the standard procedure for {procedure.lower()}.",
            f"",
            f"## Prerequisites",
            f"- Administrative access to relevant systems",
            f"- Completion of required training",
            f"- Approval from department manager",
            f"",
            f"## Procedure Steps"
        ]
        
        for i, step in enumerate(steps, 1):
            content_sections.append(f"{i}. {step}")
        
        content_sections.extend([
            f"",
            f"## Verification",
            f"Confirm all steps completed successfully and document results.",
            f"",
            f"## Troubleshooting",
            f"Contact IT support if issues arise during execution.",
            f"",
            f"# {self.synthetic_marker}"
        ])
        
        content = "\n".join(content_sections)
        
        return {
            "title": title,
            "document_type": "procedure",
            "content": content,
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "format": "markdown"
        }
    
    def _generate_report_document(self, word_count: int) -> Dict[str, Any]:
        """Generate synthetic business report"""
        report_types = [
            "Security Assessment", "Performance Analysis", "Compliance Audit",
            "System Health", "User Activity", "Incident Summary"
        ]
        
        report_type = random.choice(report_types)
        title = f"Monthly {report_type} Report"
        
        content_sections = [
            f"# {title}",
            f"## Executive Summary",
            f"This report provides an overview of {report_type.lower()} for the current period.",
            f"Key findings indicate normal operations with minor recommendations for improvement.",
            f"",
            f"## Key Metrics",
            f"- Total incidents: {random.randint(0, 10)}",
            f"- System uptime: {random.uniform(95, 99.9):.1f}%",
            f"- User satisfaction: {random.uniform(80, 95):.1f}%",
            f"- Compliance score: {random.uniform(85, 100):.1f}%",
            f"",
            f"## Findings",
            f"Analysis shows consistent performance across all monitored systems.",
            f"No critical issues identified during the reporting period.",
            f"",
            f"## Recommendations",
            f"1. Continue current monitoring practices",
            f"2. Schedule routine maintenance activities",
            f"3. Update documentation as needed",
            f"",
            f"## Next Steps",
            f"Implement recommended improvements and schedule follow-up review.",
            f"",
            f"# {self.synthetic_marker}"
        ]
        
        content = "\n".join(content_sections)
        
        return {
            "title": title,
            "document_type": "report",
            "content": content,
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "format": "markdown"
        }
    
    def _generate_memo_document(self, word_count: int) -> Dict[str, Any]:
        """Generate synthetic internal memorandum"""
        memo_topics = [
            "Policy Update", "System Maintenance", "Training Schedule",
            "Security Alert", "Process Change", "Meeting Announcement"
        ]
        
        topic = random.choice(memo_topics)
        title = f"Internal Memo: {topic}"
        
        content_sections = [
            f"# MEMORANDUM",
            f"",
            f"**TO:** All Staff",
            f"**FROM:** {self._generate_document_author()}",
            f"**DATE:** {datetime.now().strftime('%Y-%m-%d')}",
            f"**RE:** {topic}",
            f"",
            f"## Purpose",
            f"This memo provides important information regarding {topic.lower()}.",
            f"",
            f"## Details",
            f"Please review the following information and take appropriate action:",
            f"",
            f"- Effective immediately, new procedures will be implemented",
            f"- All staff must acknowledge receipt of this memo",
            f"- Questions should be directed to the appropriate department",
            f"",
            f"## Action Required",
            f"Please confirm receipt and understanding of this memo by replying to this message.",
            f"",
            f"Thank you for your attention to this matter.",
            f"",
            f"# {self.synthetic_marker}"
        ]
        
        content = "\n".join(content_sections)
        
        return {
            "title": title,
            "document_type": "memo",
            "content": content,
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "format": "markdown"
        }
    
    def _generate_manual_document(self, word_count: int) -> Dict[str, Any]:
        """Generate synthetic technical manual"""
        manual_topics = [
            "System Administration", "Network Configuration", "Software Installation",
            "Troubleshooting Guide", "User Manual", "API Documentation"
        ]
        
        topic = random.choice(manual_topics)
        title = f"{topic} Manual"
        
        content_sections = [
            f"# {title}",
            f"## Table of Contents",
            f"1. Introduction",
            f"2. Getting Started",
            f"3. Configuration",
            f"4. Operations",
            f"5. Troubleshooting",
            f"6. Appendix",
            f"",
            f"## 1. Introduction",
            f"This manual provides comprehensive guidance for {topic.lower()}.",
            f"",
            f"### Prerequisites",
            f"- Basic understanding of system concepts",
            f"- Administrative access to relevant systems",
            f"- Completion of required training",
            f"",
            f"## 2. Getting Started",
            f"Follow these steps to begin:",
            f"1. Verify system requirements",
            f"2. Install necessary software",
            f"3. Configure initial settings",
            f"",
            f"## 3. Configuration",
            f"Detailed configuration instructions are provided in this section.",
            f"",
            f"## 4. Operations",
            f"Standard operational procedures and best practices.",
            f"",
            f"## 5. Troubleshooting",
            f"Common issues and their solutions.",
            f"",
            f"## 6. Appendix",
            f"Additional resources and reference materials.",
            f"",
            f"# {self.synthetic_marker}"
        ]
        
        content = "\n".join(content_sections)
        
        return {
            "title": title,
            "document_type": "manual",
            "content": content,
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "format": "markdown"
        }
    
    def _generate_generic_document(self, word_count: int, document_type: str) -> Dict[str, Any]:
        """Generate generic synthetic document"""
        title = f"Synthetic {document_type.title()} Document"
        
        content_sections = [
            f"# {title}",
            f"",
            f"This is a synthetic document created for testing and demonstration purposes.",
            f"It contains no real or sensitive information.",
            f"",
            f"## Document Properties",
            f"- Type: {document_type}",
            f"- Generated: {datetime.now().isoformat()}",
            f"- Target word count: {word_count}",
            f"",
            f"## Content",
            f"This document serves as a placeholder for {document_type} content.",
            f"In a real scenario, this would contain actual business information.",
            f"",
            f"## Disclaimer",
            f"This is synthetic data created for honeypot purposes.",
            f"No real information is contained within this document.",
            f"",
            f"# {self.synthetic_marker}"
        ]
        
        content = "\n".join(content_sections)
        
        return {
            "title": title,
            "document_type": document_type,
            "content": content,
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "format": "markdown"
        }
    
    def _generate_document_author(self) -> str:
        """Generate realistic document author"""
        first_name = random.choice(self.templates["realistic_names"]["first_names"])
        last_name = random.choice(self.templates["realistic_names"]["last_names"])
        job_title = random.choice(self.templates["job_titles"])
        
        return f"{first_name} {last_name}, {job_title}"
    
    def generate_file_system_simulation(self, depth: int = 3, breadth: int = 5) -> Dict[str, Any]:
        """Generate realistic file system structure simulation"""
        file_system = {
            "type": "directory",
            "name": "/",
            "path": "/",
            "permissions": "drwxr-xr-x",
            "owner": "root",
            "group": "root",
            "size": 4096,
            "modified": self._generate_random_date(days_back=30).isoformat(),
            "children": []
        }
        
        # Generate standard Unix directories
        standard_dirs = [
            {"name": "home", "type": "directory"},
            {"name": "etc", "type": "directory"},
            {"name": "var", "type": "directory"},
            {"name": "usr", "type": "directory"},
            {"name": "tmp", "type": "directory"},
            {"name": "opt", "type": "directory"}
        ]
        
        for dir_info in standard_dirs:
            directory = self._generate_directory_structure(
                dir_info["name"], 
                f"/{dir_info['name']}", 
                depth - 1, 
                breadth
            )
            file_system["children"].append(directory)
        
        # Add synthetic marker to the file system
        file_system["synthetic_marker"] = self.synthetic_marker
        file_system["fingerprint"] = self._generate_fingerprint("filesystem_root")
        
        return file_system
    
    def _generate_directory_structure(self, name: str, path: str, depth: int, breadth: int) -> Dict[str, Any]:
        """Generate directory structure recursively"""
        directory = {
            "type": "directory",
            "name": name,
            "path": path,
            "permissions": random.choice(["drwxr-xr-x", "drwxrwxr-x", "drwx------"]),
            "owner": random.choice(["root", "admin", "user"]),
            "group": random.choice(["root", "admin", "users"]),
            "size": 4096,
            "modified": self._generate_random_date(days_back=90).isoformat(),
            "children": []
        }
        
        if depth > 0:
            # Generate subdirectories
            num_subdirs = random.randint(1, min(breadth, 3))
            for i in range(num_subdirs):
                subdir_name = f"subdir_{i+1}" if name == "tmp" else random.choice([
                    "config", "data", "logs", "backup", "scripts", "docs"
                ])
                subdir_path = f"{path}/{subdir_name}"
                
                subdirectory = self._generate_directory_structure(
                    subdir_name, subdir_path, depth - 1, breadth
                )
                directory["children"].append(subdirectory)
        
        # Generate files in this directory
        num_files = random.randint(2, breadth)
        for i in range(num_files):
            file_obj = self._generate_file_object(path, name)
            directory["children"].append(file_obj)
        
        return directory
    
    def _generate_file_object(self, parent_path: str, parent_name: str) -> Dict[str, Any]:
        """Generate individual file object"""
        # Choose file type based on parent directory
        if parent_name in ["etc", "config"]:
            extensions = [".conf", ".cfg", ".ini", ".yaml"]
            base_names = ["config", "settings", "app", "system"]
        elif parent_name in ["logs", "var"]:
            extensions = [".log", ".txt"]
            base_names = ["system", "app", "error", "access"]
        elif parent_name in ["docs", "documentation"]:
            extensions = [".txt", ".md", ".pdf"]
            base_names = ["readme", "manual", "guide", "help"]
        else:
            extensions = self.templates["file_extensions"]
            base_names = ["file", "document", "data", "backup"]
        
        base_name = random.choice(base_names)
        extension = random.choice(extensions)
        filename = f"{base_name}_{random.randint(1, 99)}{extension}"
        
        return {
            "type": "file",
            "name": filename,
            "path": f"{parent_path}/{filename}",
            "permissions": random.choice(["-rw-r--r--", "-rwxr-xr-x", "-rw-------"]),
            "owner": random.choice(["root", "admin", "user"]),
            "group": random.choice(["root", "admin", "users"]),
            "size": random.randint(100, 1048576),  # 100 bytes to 1MB
            "modified": self._generate_random_date(days_back=180).isoformat(),
            "content_type": self._get_content_type(extension),
            "synthetic_marker": self.synthetic_marker
        }
    
    def generate_network_topology_simulation(self, network_type: str = "corporate") -> Dict[str, Any]:
        """Generate comprehensive network topology simulation"""
        topology_config = self.ai_generation_config["network_simulation"]
        
        if network_type == "corporate":
            return self._generate_corporate_network()
        elif network_type == "dmz":
            return self._generate_dmz_network()
        elif network_type == "internal":
            return self._generate_internal_network()
        elif network_type == "isolated":
            return self._generate_isolated_network()
        else:
            return self._generate_generic_network()
    
    def _generate_corporate_network(self) -> Dict[str, Any]:
        """Generate corporate network topology"""
        return {
            "network_type": "corporate",
            "subnets": [
                {
                    "name": "management",
                    "cidr": "192.168.1.0/24",
                    "vlan": 10,
                    "services": ["dns", "dhcp", "ntp"]
                },
                {
                    "name": "user_workstations", 
                    "cidr": "192.168.10.0/24",
                    "vlan": 100,
                    "services": ["file_share", "print"]
                },
                {
                    "name": "servers",
                    "cidr": "192.168.20.0/24", 
                    "vlan": 200,
                    "services": ["web", "database", "email"]
                }
            ],
            "devices": [
                {
                    "type": "router",
                    "ip": "192.168.1.1",
                    "hostname": "corp-router-01",
                    "model": "Cisco ISR 4000"
                },
                {
                    "type": "switch",
                    "ip": "192.168.1.10", 
                    "hostname": "corp-switch-01",
                    "model": "Cisco Catalyst 9300"
                },
                {
                    "type": "firewall",
                    "ip": "192.168.1.5",
                    "hostname": "corp-fw-01",
                    "model": "Palo Alto PA-220"
                }
            ],
            "access_controls": {
                "firewall_rules": [
                    {"action": "allow", "source": "192.168.10.0/24", "dest": "192.168.20.0/24", "port": "80,443"},
                    {"action": "deny", "source": "any", "dest": "192.168.1.0/24", "port": "any"}
                ],
                "vlans": ["10", "100", "200"],
                "acls": ["MGMT_ACL", "USER_ACL", "SERVER_ACL"]
            },
            "synthetic_marker": self.synthetic_marker,
            "fingerprint": self._generate_fingerprint("corporate_network")
        }
    
    def _generate_dmz_network(self) -> Dict[str, Any]:
        """Generate DMZ network topology"""
        return {
            "network_type": "dmz",
            "subnets": [
                {
                    "name": "external_dmz",
                    "cidr": "10.1.1.0/24",
                    "services": ["web", "email", "dns"]
                },
                {
                    "name": "internal_dmz", 
                    "cidr": "10.1.2.0/24",
                    "services": ["proxy", "monitoring"]
                }
            ],
            "devices": [
                {
                    "type": "web_server",
                    "ip": "10.1.1.10",
                    "hostname": "web-dmz-01",
                    "services": ["nginx", "ssl"]
                },
                {
                    "type": "email_server",
                    "ip": "10.1.1.20",
                    "hostname": "mail-dmz-01", 
                    "services": ["smtp", "imap"]
                }
            ],
            "security_zones": ["external", "dmz", "internal"],
            "synthetic_marker": self.synthetic_marker,
            "fingerprint": self._generate_fingerprint("dmz_network")
        }
    
    def _generate_internal_network(self) -> Dict[str, Any]:
        """Generate internal network topology"""
        return {
            "network_type": "internal",
            "subnets": [
                {
                    "name": "database_tier",
                    "cidr": "172.16.1.0/24",
                    "services": ["mysql", "postgresql", "mongodb"]
                },
                {
                    "name": "application_tier",
                    "cidr": "172.16.2.0/24", 
                    "services": ["tomcat", "nodejs", "python"]
                }
            ],
            "devices": [
                {
                    "type": "database_server",
                    "ip": "172.16.1.10",
                    "hostname": "db-internal-01",
                    "services": ["mysql"]
                },
                {
                    "type": "app_server",
                    "ip": "172.16.2.10",
                    "hostname": "app-internal-01",
                    "services": ["tomcat"]
                }
            ],
            "isolation_level": "high",
            "monitoring": ["snmp", "syslog", "netflow"],
            "synthetic_marker": self.synthetic_marker,
            "fingerprint": self._generate_fingerprint("internal_network")
        }
    
    def _generate_isolated_network(self) -> Dict[str, Any]:
        """Generate isolated network topology"""
        return {
            "network_type": "isolated",
            "subnets": [
                {
                    "name": "honeypot_segment",
                    "cidr": "10.99.99.0/24",
                    "services": ["honeypot", "logging"]
                }
            ],
            "devices": [
                {
                    "type": "honeypot",
                    "ip": "10.99.99.10",
                    "hostname": "honeypot-01",
                    "services": ["ssh", "web", "ftp"]
                }
            ],
            "isolation_controls": {
                "egress_filtering": "enabled",
                "ingress_monitoring": "enabled", 
                "lateral_movement_prevention": "enabled"
            },
            "synthetic_marker": self.synthetic_marker,
            "fingerprint": self._generate_fingerprint("isolated_network")
        }
    
    def _generate_generic_network(self) -> Dict[str, Any]:
        """Generate generic network topology"""
        return {
            "network_type": "generic",
            "message": "Network topology information restricted",
            "contact": "netadmin@synthetic-domain.local",
            "synthetic_marker": self.synthetic_marker,
            "fingerprint": self._generate_fingerprint("generic_network")
        }
    
    def implement_external_access_restrictions(self, restriction_level: str = "high") -> Dict[str, Any]:
        """Implement and simulate external access restrictions"""
        restrictions = {
            "restriction_level": restriction_level,
            "implemented_at": datetime.utcnow().isoformat(),
            "measures": []
        }
        
        if restriction_level == "high":
            restrictions["measures"] = [
                {
                    "type": "egress_filtering",
                    "status": "active",
                    "blocked_protocols": ["http", "https", "ftp", "ssh", "telnet"],
                    "allowed_destinations": ["internal_dns", "ntp_servers"]
                },
                {
                    "type": "dns_filtering", 
                    "status": "active",
                    "blocked_domains": ["*"],
                    "allowed_domains": ["*.local", "*.internal"]
                },
                {
                    "type": "ip_blocking",
                    "status": "active", 
                    "blocked_ranges": ["0.0.0.0/0"],
                    "allowed_ranges": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
                }
            ]
        elif restriction_level == "medium":
            restrictions["measures"] = [
                {
                    "type": "egress_filtering",
                    "status": "active",
                    "blocked_protocols": ["ftp", "telnet", "ssh"],
                    "allowed_protocols": ["http", "https", "dns"]
                },
                {
                    "type": "content_filtering",
                    "status": "active",
                    "blocked_categories": ["malware", "phishing", "suspicious"]
                }
            ]
        else:  # low
            restrictions["measures"] = [
                {
                    "type": "basic_monitoring",
                    "status": "active",
                    "logged_connections": "all_outbound"
                }
            ]
        
        restrictions["synthetic_marker"] = self.synthetic_marker
        restrictions["fingerprint"] = self._generate_fingerprint(f"restrictions_{restriction_level}")
        
        return restrictions
    
    def get_synthetic_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about synthetic data generation"""
        return {
            "synthetic_marker": self.synthetic_marker,
            "fingerprint_salt": self.fingerprint_salt[:8] + "...",  # Partial for security
            "generation_stats": self.generation_stats.copy(),
            "cached_data_count": len(self.generated_data_cache),
            "data_usage_stats": {
                "total_tracked_items": len(self.data_usage_tracking),
                "most_used_data_types": self._get_most_used_data_types(),
                "average_usage_per_item": self._calculate_average_usage()
            },
            "ai_generation_config": {
                "credential_complexity_levels": len(self.ai_generation_config["credential_generation"]["complexity_levels"]),
                "document_types_supported": len(self.ai_generation_config["document_generation"]["document_types"]),
                "network_topology_types": len(self.ai_generation_config["network_simulation"]["topology_types"])
            },
            "data_relationships": len(self.data_relationships),
            "templates_loaded": {
                "usernames": len(self.templates["usernames"]),
                "passwords": len(self.templates["passwords"]),
                "company_names": len(self.templates["company_names"]),
                "departments": len(self.templates["departments"]),
                "job_titles": len(self.templates["job_titles"])
            }
        }
    
    def _get_most_used_data_types(self) -> Dict[str, int]:
        """Get statistics on most used data types"""
        type_counts = {}
        for data_id, cache_entry in self.generated_data_cache.items():
            data_type = cache_entry["type"]
            type_counts[data_type] = type_counts.get(data_type, 0) + cache_entry["usage_count"]
        return dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True))
    
    def _calculate_average_usage(self) -> float:
        """Calculate average usage per data item"""
        if not self.data_usage_tracking:
            return 0.0
        
        total_usage = sum(usage["total_usage"] for usage in self.data_usage_tracking.values())
        return total_usage / len(self.data_usage_tracking)
    
    def mark_data_usage(self, data_id: str, session_id: str, context: Optional[Dict[str, Any]] = None):
        """Mark synthetic data as used in a session"""
        if data_id in self.generated_data_cache:
            self.generated_data_cache[data_id]["usage_count"] += 1
            self.generated_data_cache[data_id]["last_used"] = datetime.utcnow().isoformat()
        
        if data_id in self.data_usage_tracking:
            usage_info = self.data_usage_tracking[data_id]
            usage_info["sessions_used"].append(session_id)
            usage_info["total_usage"] += 1
            if context:
                usage_info["contexts_used"].append(context)
    
    def get_data_by_id(self, data_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve synthetic data by ID"""
        return self.generated_data_cache.get(data_id)
    
    def cleanup_unused_data(self, max_age_days: int = 30) -> Dict[str, Any]:
        """Clean up old unused synthetic data"""
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
        cleaned_items = []
        
        for data_id, cache_entry in list(self.generated_data_cache.items()):
            last_used = cache_entry.get("last_used")
            if not last_used or datetime.fromisoformat(last_used) < cutoff_date:
                if cache_entry["usage_count"] == 0:
                    cleaned_items.append(data_id)
                    del self.generated_data_cache[data_id]
                    if data_id in self.data_usage_tracking:
                        del self.data_usage_tracking[data_id]
        
        return {
            "cleaned_items": len(cleaned_items),
            "remaining_items": len(self.generated_data_cache),
            "cleanup_date": datetime.utcnow().isoformat()
        }
    
    def export_synthetic_data_manifest(self) -> Dict[str, Any]:
        """Export manifest of all generated synthetic data"""
        manifest = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "synthetic_marker": self.synthetic_marker,
            "total_items": len(self.generated_data_cache),
            "data_items": []
        }
        
        for data_id, cache_entry in self.generated_data_cache.items():
            item_info = {
                "data_id": data_id,
                "type": cache_entry["type"],
                "generated_at": cache_entry["generated_at"],
                "usage_count": cache_entry["usage_count"],
                "last_used": cache_entry["last_used"],
                "fingerprint": cache_entry["data"].get("fingerprint", ""),
                "size_estimate": len(str(cache_entry["data"]))
            }
            manifest["data_items"].append(item_info)
        
        return manifest
    
    def generate_synthetic_documents(self, count: int = 1, document_type: str = "report", 
                                   complexity: str = "medium", context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Generate AI-powered synthetic documents"""
        documents = []
        
        for i in range(count):
            document = self._generate_single_document(document_type, complexity, context, i)
            self._track_generated_data("document", document)
            documents.append(document)
        
        self.generation_stats["documents_created"] += count
        return documents
    
    def _generate_single_document(self, doc_type: str, complexity: str, 
                                context: Optional[Dict[str, Any]], index: int) -> Dict[str, Any]:
        """Generate a single synthetic document with AI-powered content"""
        
        # Document metadata
        doc_id = str(uuid4())
        creation_date = self._generate_random_date(days_back=180)
        
        # Generate document title and content based on type
        if doc_type == "policy":
            title, content = self._generate_policy_document(complexity, context)
        elif doc_type == "procedure":
            title, content = self._generate_procedure_document(complexity, context)
        elif doc_type == "report":
            title, content = self._generate_report_document(complexity, context)
        elif doc_type == "memo":
            title, content = self._generate_memo_document(complexity, context)
        elif doc_type == "manual":
            title, content = self._generate_manual_document(complexity, context)
        else:
            title, content = self._generate_generic_document(complexity, context)
        
        # Generate realistic filename
        filename = self._generate_document_filename(title, doc_type, creation_date)
        
        document = {
            "document_id": doc_id,
            "filename": filename,
            "title": title,
            "content": content,
            "document_type": doc_type,
            "complexity": complexity,
            "author": self._generate_document_author(context),
            "department": random.choice(self.templates["departments"]),
            "created_date": creation_date.isoformat(),
            "modified_date": self._generate_random_date(days_back=30).isoformat(),
            "version": f"1.{random.randint(0, 9)}",
            "status": random.choice(["draft", "review", "approved", "archived"]),
            "classification": random.choice(["public", "internal", "confidential", "restricted"]),
            "size_bytes": len(content.encode('utf-8')),
            "word_count": len(content.split()),
            "fingerprint": self._generate_fingerprint(content),
            "synthetic_marker": self.synthetic_marker,
            "data_id": doc_id,
            "generation_context": context or {}
        }
        
        return document
    
    def _generate_policy_document(self, complexity: str, context: Optional[Dict[str, Any]]) -> Tuple[str, str]:
        """Generate synthetic policy document"""
        policy_types = [
            "Information Security Policy",
            "Password Policy", 
            "Remote Access Policy",
            "Data Retention Policy",
            "Incident Response Policy",
            "Acceptable Use Policy"
        ]
        
        title = random.choice(policy_types)
        
        content_templates = {
            "basic": """
{title}

1. Purpose
This policy establishes guidelines for {purpose_area} within the organization.

2. Scope
This policy applies to all employees, contractors, and third parties.

3. Policy Statement
All users must comply with the following requirements:
- Requirement 1: {requirement_1}
- Requirement 2: {requirement_2}
- Requirement 3: {requirement_3}

4. Enforcement
Violations of this policy may result in disciplinary action.

Document ID: {doc_id}
Effective Date: {effective_date}
""",
            "medium": """
{title}

1. Purpose and Objectives
This policy document establishes comprehensive guidelines for {purpose_area} 
to ensure organizational security and compliance.

2. Scope and Applicability
This policy applies to:
- All full-time and part-time employees
- Contractors and consultants
- Third-party vendors with system access
- All organizational IT resources and data

3. Policy Requirements
3.1 General Requirements
All users must adhere to the following mandatory requirements:
- {requirement_1}
- {requirement_2}
- {requirement_3}

3.2 Specific Guidelines
Additional requirements include:
- {specific_req_1}
- {specific_req_2}

4. Roles and Responsibilities
- IT Department: Policy implementation and monitoring
- Security Team: Compliance verification and auditing
- Management: Policy enforcement and approval
- Users: Policy adherence and reporting violations

5. Compliance and Enforcement
Non-compliance may result in:
- Verbal or written warnings
- Suspension of system access
- Disciplinary action up to termination

Document Control:
Document ID: {doc_id}
Version: 1.0
Effective Date: {effective_date}
Review Date: {review_date}
""",
            "detailed": """
{title}

Executive Summary
This comprehensive policy document establishes detailed guidelines and procedures 
for {purpose_area} to maintain organizational security, compliance, and operational efficiency.

1. Introduction and Purpose
1.1 Background
In today's digital environment, proper {purpose_area} management is critical 
for organizational success and security.

1.2 Objectives
- Establish clear guidelines for {purpose_area}
- Ensure compliance with regulatory requirements
- Minimize security risks and operational disruptions
- Provide framework for consistent implementation

2. Scope and Definitions
2.1 Scope
This policy encompasses all aspects of {purpose_area} including:
- Technical implementation requirements
- User responsibilities and obligations
- Management oversight and governance
- Compliance monitoring and reporting

2.2 Key Definitions
- {term_1}: {definition_1}
- {term_2}: {definition_2}
- {term_3}: {definition_3}

3. Policy Framework
3.1 Core Requirements
All organizational members must comply with:
- {requirement_1}
- {requirement_2}
- {requirement_3}
- {requirement_4}

3.2 Implementation Guidelines
Detailed implementation must include:
- {implementation_1}
- {implementation_2}
- {implementation_3}

3.3 Technical Standards
Technical requirements specify:
- {technical_req_1}
- {technical_req_2}

4. Roles, Responsibilities, and Governance
4.1 Executive Leadership
- Policy approval and strategic oversight
- Resource allocation and budget approval
- Organizational culture and compliance emphasis

4.2 IT Management
- Technical implementation and maintenance
- System monitoring and performance optimization
- User support and training coordination

4.3 Security Team
- Risk assessment and vulnerability management
- Compliance auditing and reporting
- Incident response and investigation

4.4 End Users
- Policy adherence and best practice implementation
- Incident reporting and security awareness
- Continuous learning and skill development

5. Compliance, Monitoring, and Enforcement
5.1 Compliance Framework
Regular compliance assessment includes:
- Quarterly policy reviews and updates
- Annual comprehensive audits
- Continuous monitoring and alerting

5.2 Enforcement Procedures
Policy violations will be addressed through:
- Progressive disciplinary measures
- Corrective action plans
- Legal action when appropriate

Document Control Information:
Document ID: {doc_id}
Classification: {classification}
Version: 1.0
Effective Date: {effective_date}
Review Date: {review_date}
Approved By: {approver}
Next Review: {next_review}
"""
        }
        
        template = content_templates.get(complexity, content_templates["medium"])
        
        # Fill template variables
        variables = {
            "title": title,
            "purpose_area": random.choice(["information security", "data protection", "system access", "network security"]),
            "requirement_1": "Users must follow established security procedures",
            "requirement_2": "All activities must be logged and monitored",
            "requirement_3": "Violations must be reported immediately",
            "specific_req_1": "Regular password updates are mandatory",
            "specific_req_2": "Multi-factor authentication is required",
            "doc_id": f"POL-{random.randint(1000, 9999)}",
            "effective_date": datetime.now().strftime("%Y-%m-%d"),
            "review_date": (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
            "classification": random.choice(["Internal", "Confidential", "Restricted"]),
            "approver": f"{random.choice(self.templates['realistic_names']['first_names'])} {random.choice(self.templates['realistic_names']['last_names'])}",
            "next_review": (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
            "term_1": "Authorized User",
            "definition_1": "An individual granted legitimate access to organizational systems",
            "term_2": "Security Incident", 
            "definition_2": "Any event that compromises system integrity or data confidentiality",
            "term_3": "Compliance",
            "definition_3": "Adherence to established policies, procedures, and regulatory requirements",
            "implementation_1": "Comprehensive user training and awareness programs",
            "implementation_2": "Regular system updates and security patches",
            "implementation_3": "Continuous monitoring and incident response procedures",
            "technical_req_1": "Encryption of data in transit and at rest",
            "technical_req_2": "Regular backup and disaster recovery testing",
            "requirement_4": "Immediate reporting of security incidents or policy violations"
        }
        
        content = template.format(**variables)
        # Ensure synthetic marker is included
        if self.synthetic_marker not in content:
            content += f"\n\n# {self.synthetic_marker}"
        return title, content
    
    def _generate_procedure_document(self, complexity: str, context: Optional[Dict[str, Any]]) -> Tuple[str, str]:
        """Generate synthetic procedure document"""
        procedure_types = [
            "System Backup Procedure",
            "User Account Creation Procedure",
            "Incident Response Procedure", 
            "Password Reset Procedure",
            "Software Installation Procedure",
            "Network Maintenance Procedure"
        ]
        
        title = random.choice(procedure_types)
        
        steps = [
            "Verify user authorization and permissions",
            "Access the administrative control panel",
            "Navigate to the appropriate system section",
            "Enter required information and parameters",
            "Review and validate all entered data",
            "Execute the procedure with proper logging",
            "Verify successful completion",
            "Document results and notify stakeholders",
            "Update relevant tracking systems",
            "Archive documentation for audit purposes"
        ]
        
        content = f"""
{title}

Procedure ID: PROC-{random.randint(1000, 9999)}
Version: 1.{random.randint(0, 9)}
Last Updated: {datetime.now().strftime('%Y-%m-%d')}

Purpose:
This procedure provides step-by-step instructions for {title.lower()}.

Prerequisites:
- Appropriate system access and permissions
- Required tools and software availability
- Completion of mandatory training

Procedure Steps:
"""
        
        selected_steps = random.sample(steps, min(len(steps), 6 if complexity == "basic" else 8 if complexity == "medium" else 10))
        
        for i, step in enumerate(selected_steps, 1):
            content += f"{i}. {step}\n"
        
        content += f"""
Notes:
- All activities must be logged in the system audit trail
- Contact IT support for assistance if needed
- Report any anomalies or errors immediately

# {self.synthetic_marker}
"""
        
        return title, content
    
    def _generate_report_document(self, complexity: str, context: Optional[Dict[str, Any]]) -> Tuple[str, str]:
        """Generate synthetic report document"""
        report_types = [
            "Monthly Security Report",
            "System Performance Analysis",
            "Quarterly Compliance Review",
            "Network Traffic Analysis",
            "User Activity Summary",
            "Infrastructure Assessment Report"
        ]
        
        title = random.choice(report_types)
        
        content = f"""
{title}

Report Period: {(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report ID: RPT-{random.randint(10000, 99999)}

Executive Summary:
This report provides analysis of {title.lower()} for the specified period.
Key findings indicate normal operational parameters with {random.randint(1, 5)} minor issues identified.

Key Metrics:
- Total Events Processed: {random.randint(1000, 50000):,}
- Success Rate: {random.randint(95, 99)}.{random.randint(0, 9)}%
- Average Response Time: {random.randint(50, 500)}ms
- System Uptime: {random.randint(98, 100)}.{random.randint(0, 9)}%

Detailed Analysis:
The analysis period showed consistent performance across all monitored systems.
Notable observations include improved efficiency in {random.choice(['user authentication', 'data processing', 'network throughput'])}.

Recommendations:
1. Continue current monitoring procedures
2. Schedule routine maintenance for optimal performance
3. Review and update security configurations quarterly

# {self.synthetic_marker}
"""
        
        return title, content
    
    def _generate_memo_document(self, complexity: str, context: Optional[Dict[str, Any]]) -> Tuple[str, str]:
        """Generate synthetic memo document"""
        memo_subjects = [
            "System Maintenance Window",
            "Security Policy Update",
            "New Software Deployment",
            "Training Schedule Announcement",
            "Network Infrastructure Changes",
            "Compliance Audit Preparation"
        ]
        
        title = f"MEMORANDUM: {random.choice(memo_subjects)}"
        
        author = f"{random.choice(self.templates['realistic_names']['first_names'])} {random.choice(self.templates['realistic_names']['last_names'])}"
        
        content = f"""
{title}

TO: All Staff
FROM: {author}, {random.choice(self.templates['job_titles'])}
DATE: {datetime.now().strftime('%B %d, %Y')}
RE: {random.choice(memo_subjects)}

This memo serves to inform all personnel of upcoming {random.choice(['changes', 'updates', 'procedures', 'requirements'])}.

Effective {(datetime.now() + timedelta(days=random.randint(1, 30))).strftime('%B %d, %Y')}, 
the following will be implemented:

- {random.choice(['Enhanced security measures', 'Updated system procedures', 'New compliance requirements'])}
- {random.choice(['Mandatory training sessions', 'System maintenance windows', 'Policy acknowledgments'])}
- {random.choice(['Documentation updates', 'Process improvements', 'Technology upgrades'])}

Please direct any questions to the IT Help Desk or your immediate supervisor.

Thank you for your cooperation.

{author}
{random.choice(self.templates['departments'])} Department

# {self.synthetic_marker}
"""
        
        return title, content
    
    def _generate_manual_document(self, complexity: str, context: Optional[Dict[str, Any]]) -> Tuple[str, str]:
        """Generate synthetic manual document"""
        manual_types = [
            "User Administration Manual",
            "System Configuration Guide",
            "Troubleshooting Manual",
            "Security Operations Manual",
            "Network Management Guide",
            "Database Administration Manual"
        ]
        
        title = random.choice(manual_types)
        
        content = f"""
{title}

Version: 2.{random.randint(0, 9)}
Last Updated: {datetime.now().strftime('%Y-%m-%d')}
Document ID: MAN-{random.randint(1000, 9999)}

Table of Contents:
1. Introduction
2. System Overview
3. Configuration Procedures
4. Troubleshooting Guide
5. Best Practices
6. Appendices

1. Introduction
This manual provides comprehensive guidance for {title.lower()}.
It is intended for use by qualified technical personnel.

2. System Overview
The system consists of multiple integrated components designed for
{random.choice(['optimal performance', 'maximum security', 'reliable operation'])}.

3. Configuration Procedures
Standard configuration requires the following steps:
- Initial system setup and validation
- User account configuration and permissions
- Security parameter configuration
- Performance optimization settings
- Backup and recovery configuration

4. Troubleshooting Guide
Common issues and their resolutions:
- Connection timeouts: Check network connectivity
- Authentication failures: Verify user credentials
- Performance issues: Review system resources
- Configuration errors: Validate parameter settings

5. Best Practices
- Regular system monitoring and maintenance
- Prompt application of security updates
- Comprehensive documentation of changes
- Regular backup verification and testing

# {self.synthetic_marker}
"""
        
        return title, content
    
    def _generate_generic_document(self, complexity: str, context: Optional[Dict[str, Any]]) -> Tuple[str, str]:
        """Generate generic synthetic document"""
        title = f"Technical Document - {random.choice(['Analysis', 'Review', 'Assessment', 'Summary'])}"
        
        content = f"""
{title}

Document ID: DOC-{random.randint(10000, 99999)}
Created: {datetime.now().strftime('%Y-%m-%d')}
Author: {random.choice(self.templates['realistic_names']['first_names'])} {random.choice(self.templates['realistic_names']['last_names'])}

This document contains technical information and analysis for internal use.

Content Summary:
The document provides detailed information about {random.choice(['system operations', 'security procedures', 'technical specifications'])}.

Key Points:
- Comprehensive analysis of current systems
- Recommendations for improvement
- Implementation guidelines and procedures
- Risk assessment and mitigation strategies

Conclusion:
The analysis indicates satisfactory performance with opportunities for optimization.

# {self.synthetic_marker}
"""
        
        return title, content
    
    def _generate_document_filename(self, title: str, doc_type: str, creation_date: datetime) -> str:
        """Generate realistic document filename"""
        # Clean title for filename
        clean_title = re.sub(r'[^\w\s-]', '', title).strip()
        clean_title = re.sub(r'[-\s]+', '_', clean_title)
        
        # Add date and extension
        date_str = creation_date.strftime('%Y%m%d')
        extension = random.choice(['.pdf', '.docx', '.doc', '.txt'])
        
        filename_formats = [
            f"{clean_title}_{date_str}{extension}",
            f"{doc_type}_{clean_title}{extension}",
            f"{date_str}_{clean_title}_v1{extension}",
            f"{clean_title.lower().replace(' ', '_')}{extension}"
        ]
        
        return random.choice(filename_formats)
    
    def _generate_document_author(self, context: Optional[Dict[str, Any]]) -> str:
        """Generate realistic document author"""
        first_name = random.choice(self.templates["realistic_names"]["first_names"])
        last_name = random.choice(self.templates["realistic_names"]["last_names"])
        return f"{first_name} {last_name}"
    
    def get_cached_data(self, data_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached synthetic data by ID"""
        return self.generated_data_cache.get(data_id)
    
    def mark_data_used(self, data_id: str, session_id: str, context: str):
        """Mark synthetic data as used in a session"""
        if data_id in self.generated_data_cache:
            self.generated_data_cache[data_id]["usage_count"] += 1
            self.generated_data_cache[data_id]["last_used"] = datetime.utcnow().isoformat()
        
        if data_id in self.data_usage_tracking:
            tracking = self.data_usage_tracking[data_id]
            tracking["sessions_used"].append(session_id)
            tracking["contexts_used"].append(context)
            tracking["total_usage"] += 1
    
    def cleanup_old_data(self, max_age_days: int = 7):
        """Clean up old cached synthetic data"""
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
        
        old_data_ids = []
        for data_id, data_info in self.generated_data_cache.items():
            generated_at = datetime.fromisoformat(data_info["generated_at"])
            if generated_at < cutoff_date:
                old_data_ids.append(data_id)
        
        for data_id in old_data_ids:
            del self.generated_data_cache[data_id]
            if data_id in self.data_usage_tracking:
                del self.data_usage_tracking[data_id]
        
        return len(old_data_ids)