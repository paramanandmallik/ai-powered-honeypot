"""
MITRE ATT&CK Mapping Module for Intelligence Agent
Provides comprehensive mapping of attack techniques to MITRE ATT&CK framework.
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from uuid import uuid4
import logging


class MitreAttackMapper:
    """
    MITRE ATT&CK framework mapper for automated technique classification and IOC extraction.
    
    Capabilities:
    - Automated technique mapping algorithms
    - Tactic and technique classification
    - IOC extraction and validation
    - Threat actor profiling capabilities
    """
    
    def __init__(self):
        self.logger = logging.getLogger("mitre_mapper")
        
        # MITRE ATT&CK Enterprise Matrix (subset for honeypot analysis)
        self.attack_matrix = {
            # Reconnaissance (TA0043)
            "T1595": {
                "name": "Active Scanning",
                "tactic": "Reconnaissance",
                "description": "Adversaries may execute active reconnaissance scans to gather information",
                "subtechniques": {
                    "T1595.001": "Scanning IP Blocks",
                    "T1595.002": "Vulnerability Scanning"
                }
            },
            "T1592": {
                "name": "Gather Victim Host Information",
                "tactic": "Reconnaissance", 
                "description": "Adversaries may gather information about the victim's hosts",
                "subtechniques": {
                    "T1592.001": "Hardware",
                    "T1592.002": "Software",
                    "T1592.003": "Firmware",
                    "T1592.004": "Client Configurations"
                }
            },
            
            # Initial Access (TA0001)
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program",
                "subtechniques": {}
            },
            "T1133": {
                "name": "External Remote Services",
                "tactic": "Initial Access",
                "description": "Adversaries may leverage external-facing remote services to initially access",
                "subtechniques": {}
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "Adversaries may obtain and abuse credentials of existing accounts",
                "subtechniques": {
                    "T1078.001": "Default Accounts",
                    "T1078.002": "Domain Accounts",
                    "T1078.003": "Local Accounts",
                    "T1078.004": "Cloud Accounts"
                }
            },
            
            # Execution (TA0002)
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands",
                "subtechniques": {
                    "T1059.001": "PowerShell",
                    "T1059.002": "AppleScript", 
                    "T1059.003": "Windows Command Shell",
                    "T1059.004": "Unix Shell",
                    "T1059.005": "Visual Basic",
                    "T1059.006": "Python",
                    "T1059.007": "JavaScript"
                }
            },
            "T1053": {
                "name": "Scheduled Task/Job",
                "tactic": "Execution",
                "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution",
                "subtechniques": {
                    "T1053.001": "At (Linux)",
                    "T1053.002": "At (Windows)",
                    "T1053.003": "Cron",
                    "T1053.005": "Scheduled Task",
                    "T1053.006": "Systemd Timers"
                }
            },
            
            # Persistence (TA0003)
            "T1543": {
                "name": "Create or Modify System Process",
                "tactic": "Persistence",
                "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads",
                "subtechniques": {
                    "T1543.001": "Launch Agent",
                    "T1543.002": "Systemd Service",
                    "T1543.003": "Windows Service",
                    "T1543.004": "Launch Daemon"
                }
            },
            "T1136": {
                "name": "Create Account",
                "tactic": "Persistence",
                "description": "Adversaries may create an account to maintain access to victim systems",
                "subtechniques": {
                    "T1136.001": "Local Account",
                    "T1136.002": "Domain Account",
                    "T1136.003": "Cloud Account"
                }
            },
            
            # Privilege Escalation (TA0004)
            "T1548": {
                "name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may circumvent mechanisms designed to control elevate privileges",
                "subtechniques": {
                    "T1548.001": "Setuid and Setgid",
                    "T1548.002": "Bypass User Account Control",
                    "T1548.003": "Sudo and Sudo Caching",
                    "T1548.004": "Elevated Execution with Prompt"
                }
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges",
                "subtechniques": {}
            },
            
            # Defense Evasion (TA0005)
            "T1070": {
                "name": "Indicator Removal on Host",
                "tactic": "Defense Evasion",
                "description": "Adversaries may delete or alter generated artifacts on a host system",
                "subtechniques": {
                    "T1070.001": "Clear Windows Event Logs",
                    "T1070.002": "Clear Linux or Mac System Logs",
                    "T1070.003": "Clear Command History",
                    "T1070.004": "File Deletion",
                    "T1070.006": "Timestomp"
                }
            },
            "T1027": {
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze",
                "subtechniques": {
                    "T1027.001": "Binary Padding",
                    "T1027.002": "Software Packing",
                    "T1027.003": "Steganography",
                    "T1027.004": "Compile After Delivery"
                }
            },
            
            # Credential Access (TA0006)
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts",
                "subtechniques": {
                    "T1110.001": "Password Guessing",
                    "T1110.002": "Password Cracking",
                    "T1110.003": "Password Spraying",
                    "T1110.004": "Credential Stuffing"
                }
            },
            "T1555": {
                "name": "Credentials from Password Stores",
                "tactic": "Credential Access",
                "description": "Adversaries may search for common password storage locations",
                "subtechniques": {
                    "T1555.001": "Keychain",
                    "T1555.002": "Securityd Memory",
                    "T1555.003": "Credentials from Web Browsers"
                }
            },
            
            # Discovery (TA0007)
            "T1087": {
                "name": "Account Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment",
                "subtechniques": {
                    "T1087.001": "Local Account",
                    "T1087.002": "Domain Account",
                    "T1087.003": "Email Account",
                    "T1087.004": "Cloud Account"
                }
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may enumerate files and directories or may search in specific locations",
                "subtechniques": {}
            },
            "T1057": {
                "name": "Process Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get information about running processes on a system",
                "subtechniques": {}
            },
            "T1082": {
                "name": "System Information Discovery",
                "tactic": "Discovery",
                "description": "An adversary may attempt to get detailed information about the operating system and hardware",
                "subtechniques": {}
            },
            "T1033": {
                "name": "System Owner/User Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to identify the primary user, currently logged in user, set of users",
                "subtechniques": {}
            },
            "T1049": {
                "name": "System Network Connections Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system",
                "subtechniques": {}
            },
            "T1016": {
                "name": "System Network Configuration Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may look for details about the network configuration and settings",
                "subtechniques": {}
            },
            
            # Lateral Movement (TA0008)
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections",
                "subtechniques": {
                    "T1021.001": "Remote Desktop Protocol",
                    "T1021.002": "SMB/Windows Admin Shares",
                    "T1021.003": "Distributed Component Object Model",
                    "T1021.004": "SSH"
                }
            },
            
            # Collection (TA0009)
            "T1005": {
                "name": "Data from Local System",
                "tactic": "Collection",
                "description": "Adversaries may search local system sources, such as file systems or local databases",
                "subtechniques": {}
            },
            "T1039": {
                "name": "Data from Network Shared Drive",
                "tactic": "Collection",
                "description": "Adversaries may search network shares on computers they have compromised",
                "subtechniques": {}
            },
            
            # Command and Control (TA0011)
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Adversaries may communicate using application layer protocols",
                "subtechniques": {
                    "T1071.001": "Web Protocols",
                    "T1071.002": "File Transfer Protocols",
                    "T1071.003": "Mail Protocols",
                    "T1071.004": "DNS"
                }
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": "Adversaries may transfer tools or other files from an external system",
                "subtechniques": {}
            },
            
            # Exfiltration (TA0010)
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel",
                "subtechniques": {}
            },
            "T1048": {
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel",
                "subtechniques": {
                    "T1048.001": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                    "T1048.002": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                    "T1048.003": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"
                }
            }
        }
        
        # Command to technique mappings
        self.command_mappings = {
            # Discovery techniques
            "whoami": ["T1033"],
            "id": ["T1033"],
            "w": ["T1033"],
            "who": ["T1033"],
            "users": ["T1033"],
            "ps": ["T1057"],
            "ps aux": ["T1057"],
            "ps -ef": ["T1057"],
            "top": ["T1057"],
            "htop": ["T1057"],
            "tasklist": ["T1057"],
            "netstat": ["T1049"],
            "ss": ["T1049"],
            "lsof": ["T1049"],
            "ifconfig": ["T1016"],
            "ip addr": ["T1016"],
            "ip route": ["T1016"],
            "route": ["T1016"],
            "arp": ["T1016"],
            "uname": ["T1082"],
            "hostname": ["T1082"],
            "cat /proc/version": ["T1082"],
            "systeminfo": ["T1082"],
            "ls": ["T1083"],
            "dir": ["T1083"],
            "find": ["T1083"],
            "locate": ["T1083"],
            "cat /etc/passwd": ["T1087.001"],
            "cat /etc/shadow": ["T1087.001"],
            "cat /etc/group": ["T1087.001"],
            "net user": ["T1087.001"],
            "net localgroup": ["T1087.001"],
            
            # Privilege escalation
            "sudo": ["T1548.003"],
            "su": ["T1548.003"],
            "sudo -l": ["T1548.003"],
            "chmod +s": ["T1548.001"],
            "chmod 4755": ["T1548.001"],
            
            # Defense evasion
            "history -c": ["T1070.003"],
            "unset HISTFILE": ["T1070.003"],
            "rm": ["T1070.004"],
            "shred": ["T1070.004"],
            "wipe": ["T1070.004"],
            
            # Persistence
            "crontab": ["T1053.003"],
            "systemctl": ["T1543.002"],
            "service": ["T1543.002"],
            "chkconfig": ["T1543.002"],
            
            # Credential access
            "grep -r password": ["T1555"],
            "find . -name '*.key'": ["T1555"],
            "cat ~/.ssh/id_rsa": ["T1555"],
            
            # Collection
            "cat": ["T1005"],
            "head": ["T1005"],
            "tail": ["T1005"],
            "grep": ["T1005"],
            "awk": ["T1005"],
            "sed": ["T1005"],
            
            # Command and control
            "wget": ["T1105"],
            "curl": ["T1105"],
            "nc": ["T1105"],
            "netcat": ["T1105"],
            "scp": ["T1105"],
            "rsync": ["T1105"],
            
            # Execution
            "bash": ["T1059.004"],
            "sh": ["T1059.004"],
            "zsh": ["T1059.004"],
            "python": ["T1059.006"],
            "perl": ["T1059"],
            "ruby": ["T1059"],
            "php": ["T1059"]
        }
        
        # Web attack patterns to MITRE mappings
        self.web_attack_mappings = {
            "sql_injection": ["T1190"],
            "command_injection": ["T1190"],
            "path_traversal": ["T1190"],
            "xss": ["T1190"],
            "csrf": ["T1190"],
            "file_upload": ["T1190"],
            "authentication_bypass": ["T1078"]
        }
        
        # Threat actor profiles (simplified)
        self.threat_actor_profiles = {
            "APT1": {
                "name": "Comment Crew",
                "country": "China",
                "techniques": ["T1059.003", "T1021.001", "T1083", "T1005"],
                "tools": ["cmd.exe", "net.exe", "ping.exe"],
                "targets": ["Government", "Financial", "Technology"]
            },
            "APT28": {
                "name": "Fancy Bear",
                "country": "Russia", 
                "techniques": ["T1059.001", "T1078", "T1190", "T1105"],
                "tools": ["PowerShell", "X-Agent", "Sofacy"],
                "targets": ["Government", "Military", "Defense"]
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "country": "North Korea",
                "techniques": ["T1190", "T1105", "T1041", "T1070"],
                "tools": ["RATANKBA", "PowerRatankba", "Manuscrypt"],
                "targets": ["Financial", "Cryptocurrency", "Entertainment"]
            }
        }
        
        self.logger.info("MITRE ATT&CK mapper initialized with comprehensive technique database")
    
    def map_techniques_from_session(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Map session data to MITRE ATT&CK techniques using multiple analysis methods.
        
        Args:
            session_data: Complete session data including transcript and metadata
            
        Returns:
            List of mapped techniques with confidence scores and evidence
        """
        try:
            techniques = []
            transcript = session_data.get("transcript", [])
            metadata = session_data.get("metadata", {})
            
            # Method 1: Command-based mapping
            command_techniques = self._map_commands_to_techniques(transcript)
            techniques.extend(command_techniques)
            
            # Method 2: Web attack pattern mapping
            web_techniques = self._map_web_attacks_to_techniques(transcript)
            techniques.extend(web_techniques)
            
            # Method 3: Behavioral pattern mapping
            behavioral_techniques = self._map_behavioral_patterns_to_techniques(transcript, metadata)
            techniques.extend(behavioral_techniques)
            
            # Method 4: IOC-based mapping
            ioc_techniques = self._map_iocs_to_techniques(session_data)
            techniques.extend(ioc_techniques)
            
            # Deduplicate and enrich techniques
            unique_techniques = self._deduplicate_and_enrich_techniques(techniques)
            
            # Add tactic progression analysis
            tactic_progression = self._analyze_tactic_progression(unique_techniques)
            
            # Enhance with kill chain analysis
            kill_chain_analysis = self._analyze_kill_chain_progression(unique_techniques)
            
            # Add metadata to each technique
            for technique in unique_techniques:
                technique["tactic_progression"] = tactic_progression
                technique["kill_chain_analysis"] = kill_chain_analysis
                technique["mapped_at"] = datetime.utcnow().isoformat()
            
            self.logger.info(f"Mapped {len(unique_techniques)} unique MITRE ATT&CK techniques")
            
            return unique_techniques
            
        except Exception as e:
            self.logger.error(f"Error mapping techniques from session: {e}")
            return []
    
    def extract_and_validate_iocs(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract and validate indicators of compromise with MITRE context.
        
        Args:
            session_data: Session data to extract IOCs from
            
        Returns:
            List of validated IOCs with MITRE technique associations
        """
        try:
            iocs = []
            transcript = session_data.get("transcript", [])
            metadata = session_data.get("metadata", {})
            
            # Extract different types of IOCs
            ip_iocs = self._extract_ip_indicators(session_data)
            domain_iocs = self._extract_domain_indicators(transcript)
            file_iocs = self._extract_file_indicators(transcript)
            hash_iocs = self._extract_hash_indicators(transcript)
            url_iocs = self._extract_url_indicators(transcript)
            email_iocs = self._extract_email_indicators(transcript)
            
            # Combine all IOCs
            all_iocs = ip_iocs + domain_iocs + file_iocs + hash_iocs + url_iocs + email_iocs
            
            # Validate and enrich IOCs with MITRE context
            validated_iocs = []
            for ioc in all_iocs:
                validated_ioc = self._validate_and_enrich_ioc(ioc, session_data)
                if validated_ioc:
                    validated_iocs.append(validated_ioc)
            
            self.logger.info(f"Extracted and validated {len(validated_iocs)} IOCs")
            
            return validated_iocs
            
        except Exception as e:
            self.logger.error(f"Error extracting IOCs: {e}")
            return []
    
    def profile_threat_actor(self, techniques: List[Dict[str, Any]], 
                           session_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Profile potential threat actor based on techniques and session characteristics.
        
        Args:
            techniques: List of identified MITRE techniques
            session_metadata: Session metadata for additional context
            
        Returns:
            Threat actor profile with confidence scores
        """
        try:
            technique_ids = [t.get("technique_id", "") for t in techniques]
            
            # Calculate similarity scores with known threat actors
            actor_scores = {}
            
            for actor_name, profile in self.threat_actor_profiles.items():
                actor_techniques = profile.get("techniques", [])
                
                # Calculate technique overlap
                overlap = len(set(technique_ids) & set(actor_techniques))
                total_actor_techniques = len(actor_techniques)
                
                if total_actor_techniques > 0:
                    similarity_score = overlap / total_actor_techniques
                    
                    # Adjust score based on session characteristics
                    adjusted_score = self._adjust_actor_score_by_context(
                        similarity_score, profile, session_metadata
                    )
                    
                    actor_scores[actor_name] = {
                        "similarity_score": similarity_score,
                        "adjusted_score": adjusted_score,
                        "technique_overlap": overlap,
                        "matching_techniques": list(set(technique_ids) & set(actor_techniques)),
                        "profile": profile
                    }
            
            # Sort by adjusted score
            sorted_actors = sorted(
                actor_scores.items(), 
                key=lambda x: x[1]["adjusted_score"], 
                reverse=True
            )
            
            # Generate threat actor assessment
            assessment = {
                "top_matches": sorted_actors[:3],  # Top 3 matches
                "confidence_level": self._calculate_actor_confidence(sorted_actors),
                "assessment_summary": self._generate_actor_assessment_summary(sorted_actors, techniques),
                "recommended_actions": self._generate_actor_based_recommendations(sorted_actors)
            }
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error profiling threat actor: {e}")
            return {"error": str(e)}
    
    def generate_mitre_report(self, techniques: List[Dict[str, Any]], 
                            iocs: List[Dict[str, Any]], 
                            threat_profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive MITRE ATT&CK analysis report.
        
        Args:
            techniques: Mapped MITRE techniques
            iocs: Extracted and validated IOCs
            threat_profile: Threat actor profiling results
            
        Returns:
            Comprehensive MITRE analysis report
        """
        try:
            # Analyze technique distribution by tactic
            tactic_distribution = self._analyze_tactic_distribution(techniques)
            
            # Generate kill chain coverage
            kill_chain_coverage = self._analyze_kill_chain_coverage(techniques)
            
            # Calculate sophistication metrics
            sophistication_metrics = self._calculate_sophistication_metrics(techniques)
            
            # Generate defensive recommendations
            defensive_recommendations = self._generate_defensive_recommendations(techniques, tactic_distribution)
            
            # Create comprehensive report
            report = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "report_type": "MITRE ATT&CK Analysis",
                    "version": "1.0"
                },
                "executive_summary": {
                    "total_techniques": len(techniques),
                    "unique_tactics": len(tactic_distribution),
                    "total_iocs": len(iocs),
                    "sophistication_level": sophistication_metrics.get("level", "Unknown"),
                    "threat_actor_confidence": threat_profile.get("confidence_level", "Low")
                },
                "technique_analysis": {
                    "mapped_techniques": techniques,
                    "tactic_distribution": tactic_distribution,
                    "kill_chain_coverage": kill_chain_coverage,
                    "sophistication_metrics": sophistication_metrics
                },
                "ioc_analysis": {
                    "extracted_iocs": iocs,
                    "ioc_summary": self._summarize_iocs(iocs)
                },
                "threat_actor_profile": threat_profile,
                "defensive_recommendations": defensive_recommendations,
                "mitre_navigator_layer": self._generate_navigator_layer(techniques)
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating MITRE report: {e}")
            return {"error": str(e)}
    
    # Helper methods for technique mapping
    def _map_commands_to_techniques(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map commands to MITRE techniques"""
        techniques = []
        
        for interaction in transcript:
            if interaction.get("type") == "command":
                command = interaction.get("content", "").strip().lower()
                
                # Check for exact matches first
                for cmd_pattern, technique_ids in self.command_mappings.items():
                    if cmd_pattern in command:
                        for technique_id in technique_ids:
                            if technique_id in self.attack_matrix:
                                technique_info = self.attack_matrix[technique_id]
                                techniques.append({
                                    "technique_id": technique_id,
                                    "technique_name": technique_info["name"],
                                    "tactic": technique_info["tactic"],
                                    "confidence": 0.9,
                                    "evidence": command,
                                    "detection_method": "command_mapping",
                                    "timestamp": interaction.get("timestamp", "")
                                })
        
        return techniques
    
    def _map_web_attacks_to_techniques(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map web attack patterns to MITRE techniques"""
        techniques = []
        
        # SQL injection patterns
        sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table",
            r"insert\s+into", r"update\s+.*\s+set", r"delete\s+from"
        ]
        
        # Command injection patterns
        cmd_patterns = [
            r";\s*cat\s+", r";\s*ls\s+", r";\s*id\s*;",
            r"\|\s*nc\s+", r"&&\s*whoami", r"`.*`"
        ]
        
        for interaction in transcript:
            if interaction.get("type") in ["http_request", "web_request"]:
                content = interaction.get("content", "")
                
                # Check for SQL injection
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in sql_patterns):
                    techniques.append({
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access",
                        "confidence": 0.8,
                        "evidence": content,
                        "attack_type": "sql_injection",
                        "detection_method": "web_pattern_matching",
                        "timestamp": interaction.get("timestamp", "")
                    })
                
                # Check for command injection
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in cmd_patterns):
                    techniques.append({
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "tactic": "Initial Access",
                        "confidence": 0.8,
                        "evidence": content,
                        "attack_type": "command_injection",
                        "detection_method": "web_pattern_matching",
                        "timestamp": interaction.get("timestamp", "")
                    })
        
        return techniques
    
    def _map_behavioral_patterns_to_techniques(self, transcript: List[Dict[str, Any]], 
                                             metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map behavioral patterns to MITRE techniques"""
        techniques = []
        
        try:
            # Analyze command sequences for behavioral patterns
            commands = [i.get("content", "") for i in transcript if i.get("type") == "command"]
            
            # Pattern 1: Systematic reconnaissance
            recon_commands = ["whoami", "id", "uname", "ps", "netstat", "ls", "cat /etc/passwd"]
            recon_count = sum(1 for cmd in commands if any(recon in cmd.lower() for recon in recon_commands))
            
            if recon_count >= 3:
                techniques.append({
                    "technique_id": "T1592",
                    "technique_name": "Gather Victim Host Information",
                    "tactic": "Reconnaissance",
                    "confidence": min(0.9, 0.6 + (recon_count * 0.1)),
                    "evidence": f"Systematic reconnaissance with {recon_count} commands",
                    "detection_method": "behavioral_analysis",
                    "pattern_type": "systematic_reconnaissance"
                })
            
            # Pattern 2: Privilege escalation sequence
            priv_esc_sequence = ["sudo -l", "cat /etc/sudoers", "sudo"]
            sequence_matches = 0
            for i, cmd in enumerate(commands[:-2]):
                if any(pe_cmd in cmd.lower() for pe_cmd in priv_esc_sequence):
                    sequence_matches += 1
            
            if sequence_matches >= 2:
                techniques.append({
                    "technique_id": "T1548.003",
                    "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    "tactic": "Privilege Escalation",
                    "confidence": 0.8,
                    "evidence": f"Privilege escalation sequence detected",
                    "detection_method": "behavioral_analysis",
                    "pattern_type": "privilege_escalation_sequence"
                })
            
            # Pattern 3: Data collection and exfiltration
            collection_commands = ["find", "tar", "zip", "nc", "scp", "wget", "curl"]
            collection_count = sum(1 for cmd in commands if any(col in cmd.lower() for col in collection_commands))
            
            if collection_count >= 2:
                techniques.append({
                    "technique_id": "T1005",
                    "technique_name": "Data from Local System",
                    "tactic": "Collection",
                    "confidence": 0.7,
                    "evidence": f"Data collection pattern with {collection_count} commands",
                    "detection_method": "behavioral_analysis",
                    "pattern_type": "data_collection"
                })
        
        except Exception as e:
            self.logger.error(f"Error mapping behavioral patterns: {e}")
        
        return techniques
    
    def _map_iocs_to_techniques(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map IOCs to related MITRE techniques"""
        techniques = []
        
        try:
            # Extract IOCs first
            iocs = self.extract_and_validate_iocs(session_data)
            
            for ioc in iocs:
                ioc_type = ioc.get("type", "")
                confidence = ioc.get("confidence", 0)
                
                # Map IOC types to techniques
                if ioc_type == "ip_address" and confidence > 0.7:
                    techniques.append({
                        "technique_id": "T1071",
                        "technique_name": "Application Layer Protocol",
                        "tactic": "Command and Control",
                        "confidence": confidence * 0.8,  # Reduce confidence for IOC-based detection
                        "evidence": f"Suspicious IP communication: {ioc.get('value', '')}",
                        "detection_method": "ioc_analysis",
                        "ioc_reference": ioc.get("value", "")
                    })
                
                elif ioc_type in ["file_hash_md5", "file_hash_sha1", "file_hash_sha256"] and confidence > 0.8:
                    techniques.append({
                        "technique_id": "T1105",
                        "technique_name": "Ingress Tool Transfer",
                        "tactic": "Command and Control",
                        "confidence": confidence * 0.9,
                        "evidence": f"Malicious file hash detected: {ioc.get('value', '')}",
                        "detection_method": "ioc_analysis",
                        "ioc_reference": ioc.get("value", "")
                    })
                
                elif ioc_type == "url" and confidence > 0.7:
                    techniques.append({
                        "technique_id": "T1105",
                        "technique_name": "Ingress Tool Transfer",
                        "tactic": "Command and Control",
                        "confidence": confidence * 0.8,
                        "evidence": f"Suspicious URL access: {ioc.get('value', '')}",
                        "detection_method": "ioc_analysis",
                        "ioc_reference": ioc.get("value", "")
                    })
        
        except Exception as e:
            self.logger.error(f"Error mapping IOCs to techniques: {e}")
        
        return techniques
    
    def _deduplicate_and_enrich_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate and enrich techniques with additional context"""
        # Deduplicate by technique ID
        unique_techniques = {}
        
        for technique in techniques:
            tech_id = technique.get("technique_id", "")
            if not tech_id:
                continue
            
            if tech_id not in unique_techniques:
                unique_techniques[tech_id] = technique
            else:
                # Merge evidence and keep higher confidence
                existing = unique_techniques[tech_id]
                if technique.get("confidence", 0) > existing.get("confidence", 0):
                    # Keep new technique but merge evidence
                    technique["evidence"] = f"{existing.get('evidence', '')}; {technique.get('evidence', '')}"
                    unique_techniques[tech_id] = technique
                else:
                    # Keep existing but add evidence
                    existing["evidence"] = f"{existing.get('evidence', '')}; {technique.get('evidence', '')}"
        
        # Enrich with MITRE ATT&CK framework data
        enriched_techniques = []
        for technique in unique_techniques.values():
            tech_id = technique.get("technique_id", "")
            
            if tech_id in self.attack_matrix:
                mitre_data = self.attack_matrix[tech_id]
                technique.update({
                    "mitre_description": mitre_data.get("description", ""),
                    "subtechniques": mitre_data.get("subtechniques", {}),
                    "detection_methods": self._get_detection_methods(tech_id),
                    "mitigation_strategies": self._get_mitigation_strategies(tech_id)
                })
            
            enriched_techniques.append(technique)
        
        return enriched_techniques
    
    def _analyze_tactic_progression(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the progression of tactics in the attack"""
        tactic_order = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Exfiltration",
            "Command and Control"
        ]
        
        observed_tactics = {}
        for technique in techniques:
            tactic = technique.get("tactic", "")
            if tactic and tactic not in observed_tactics:
                observed_tactics[tactic] = len(observed_tactics)
        
        # Analyze progression
        progression_analysis = {
            "observed_tactics": list(observed_tactics.keys()),
            "tactic_count": len(observed_tactics),
            "kill_chain_progression": [],
            "progression_score": 0.0
        }
        
        # Calculate progression score based on logical order
        for i, tactic in enumerate(tactic_order):
            if tactic in observed_tactics:
                progression_analysis["kill_chain_progression"].append({
                    "tactic": tactic,
                    "order": i,
                    "observed_order": observed_tactics[tactic]
                })
        
        # Calculate how well the attack follows the kill chain
        if len(progression_analysis["kill_chain_progression"]) > 1:
            ordered_progression = sorted(progression_analysis["kill_chain_progression"], key=lambda x: x["observed_order"])
            expected_order = sorted(progression_analysis["kill_chain_progression"], key=lambda x: x["order"])
            
            # Simple progression score based on order similarity
            progression_analysis["progression_score"] = 1.0 if ordered_progression == expected_order else 0.5
        
        return progression_analysis
    
    def _analyze_kill_chain_progression(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze kill chain progression and coverage"""
        kill_chain_phases = {
            "Reconnaissance": ["T1595", "T1592", "T1590"],
            "Weaponization": [],  # Not typically observed in honeypots
            "Delivery": ["T1566", "T1190"],
            "Exploitation": ["T1068", "T1190"],
            "Installation": ["T1105", "T1543"],
            "Command and Control": ["T1071", "T1105"],
            "Actions on Objectives": ["T1005", "T1041", "T1048"]
        }
        
        observed_phases = {}
        technique_ids = [t.get("technique_id", "") for t in techniques]
        
        for phase, phase_techniques in kill_chain_phases.items():
            matching_techniques = [tid for tid in technique_ids if tid in phase_techniques]
            if matching_techniques:
                observed_phases[phase] = matching_techniques
        
        return {
            "observed_phases": list(observed_phases.keys()),
            "phase_coverage": len(observed_phases) / len(kill_chain_phases),
            "phase_details": observed_phases,
            "kill_chain_completeness": "Complete" if len(observed_phases) >= 5 else "Partial" if len(observed_phases) >= 3 else "Limited"
        }
    
    # IOC extraction methods
    def _extract_ip_indicators(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IP address indicators"""
        iocs = []
        
        # Extract source IP from metadata
        source_ip = session_data.get("metadata", {}).get("source_ip", "")
        if source_ip and not source_ip.startswith(("127.", "10.", "192.168.", "172.")):
            iocs.append({
                "type": "ip_address",
                "value": source_ip,
                "confidence": 0.9,
                "context": "Session source IP",
                "threat_intel": self._lookup_ip_threat_intel(source_ip)
            })
        
        # Extract IPs from transcript content
        transcript = session_data.get("transcript", [])
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            ips = re.findall(ip_pattern, content)
            
            for ip in ips:
                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    iocs.append({
                        "type": "ip_address",
                        "value": ip,
                        "confidence": 0.7,
                        "context": f"Found in command: {content[:50]}...",
                        "threat_intel": self._lookup_ip_threat_intel(ip)
                    })
        
        return iocs
    
    def _extract_domain_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract domain indicators"""
        iocs = []
        
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            domains = re.findall(domain_pattern, content)
            
            for domain in domains:
                # Filter out common legitimate domains
                if not any(legit in domain.lower() for legit in ["ubuntu.com", "debian.org", "redhat.com"]):
                    iocs.append({
                        "type": "domain",
                        "value": domain,
                        "confidence": 0.6,
                        "context": f"Found in command: {content[:50]}...",
                        "threat_intel": self._lookup_domain_threat_intel(domain)
                    })
        
        return iocs
    
    def _extract_file_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract file indicators"""
        iocs = []
        
        suspicious_files = [
            r'\.sh$', r'\.py$', r'\.pl$', r'\.exe$', r'\.bat$',
            r'backdoor', r'payload', r'shell', r'exploit'
        ]
        
        for interaction in transcript:
            content = interaction.get("content", "")
            
            # Look for suspicious file patterns
            for pattern in suspicious_files:
                if re.search(pattern, content, re.IGNORECASE):
                    # Extract potential filenames
                    words = content.split()
                    for word in words:
                        if re.search(pattern, word, re.IGNORECASE):
                            iocs.append({
                                "type": "filename",
                                "value": word,
                                "confidence": 0.7,
                                "context": f"Suspicious file in command: {content[:50]}...",
                                "threat_intel": {}
                            })
        
        return iocs
    
    def _extract_hash_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract file hash indicators"""
        iocs = []
        
        hash_patterns = {
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b'
        }
        
        for interaction in transcript:
            content = interaction.get("content", "")
            
            for hash_type, pattern in hash_patterns.items():
                hashes = re.findall(pattern, content)
                for hash_value in hashes:
                    iocs.append({
                        "type": f"file_hash_{hash_type}",
                        "value": hash_value,
                        "confidence": 0.9,
                        "context": f"Hash found in command: {content[:50]}...",
                        "threat_intel": self._lookup_hash_threat_intel(hash_value)
                    })
        
        return iocs
    
    def _extract_url_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract URL indicators"""
        iocs = []
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            urls = re.findall(url_pattern, content)
            
            for url in urls:
                iocs.append({
                    "type": "url",
                    "value": url,
                    "confidence": 0.8,
                    "context": f"URL found in command: {content[:50]}...",
                    "threat_intel": self._lookup_url_threat_intel(url)
                })
        
        return iocs
    
    def _extract_email_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract email indicators"""
        iocs = []
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            emails = re.findall(email_pattern, content)
            
            for email in emails:
                iocs.append({
                    "type": "email_address",
                    "value": email,
                    "confidence": 0.6,
                    "context": f"Email found in command: {content[:50]}...",
                    "threat_intel": {}
                })
        
        return iocs
    
    def _validate_and_enrich_ioc(self, ioc: Dict[str, Any], session_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and enrich IOC with additional context"""
        try:
            # Basic validation
            if not ioc.get("value") or not ioc.get("type"):
                return None
            
            # Enrich with MITRE technique associations
            ioc["mitre_techniques"] = self._associate_ioc_with_techniques(ioc)
            
            # Add validation timestamp
            ioc["validated_at"] = datetime.utcnow().isoformat()
            
            # Add session context
            ioc["session_context"] = {
                "session_id": session_data.get("session_id", ""),
                "honeypot_type": session_data.get("metadata", {}).get("honeypot_type", ""),
                "source_ip": session_data.get("metadata", {}).get("source_ip", "")
            }
            
            return ioc
            
        except Exception as e:
            self.logger.error(f"Error validating IOC: {e}")
            return None
    
    def _associate_ioc_with_techniques(self, ioc: Dict[str, Any]) -> List[str]:
        """Associate IOC with relevant MITRE techniques"""
        ioc_type = ioc.get("type", "")
        
        # Map IOC types to common techniques
        ioc_technique_map = {
            "ip_address": ["T1071", "T1041"],  # C2 communication
            "domain": ["T1071", "T1105"],     # C2 and tool transfer
            "url": ["T1105", "T1071"],        # Tool transfer and C2
            "file_hash_md5": ["T1105"],       # Tool transfer
            "file_hash_sha1": ["T1105"],      # Tool transfer
            "file_hash_sha256": ["T1105"],    # Tool transfer
            "filename": ["T1105", "T1059"],   # Tool transfer and execution
            "email_address": ["T1566"]        # Phishing
        }
        
        return ioc_technique_map.get(ioc_type, [])
    
    # Threat intelligence lookup methods (placeholders for real implementations)
    def _lookup_ip_threat_intel(self, ip: str) -> Dict[str, Any]:
        """Lookup IP threat intelligence"""
        # Placeholder - in real implementation would query threat intel feeds
        return {
            "reputation": "unknown",
            "categories": [],
            "last_seen": None,
            "confidence": 0.5
        }
    
    def _lookup_domain_threat_intel(self, domain: str) -> Dict[str, Any]:
        """Lookup domain threat intelligence"""
        # Placeholder - in real implementation would query threat intel feeds
        return {
            "reputation": "unknown",
            "categories": [],
            "registration_date": None,
            "confidence": 0.5
        }
    
    def _lookup_hash_threat_intel(self, hash_value: str) -> Dict[str, Any]:
        """Lookup file hash threat intelligence"""
        # Placeholder - in real implementation would query threat intel feeds
        return {
            "malware_family": "unknown",
            "first_seen": None,
            "detection_ratio": 0,
            "confidence": 0.5
        }
    
    def _lookup_url_threat_intel(self, url: str) -> Dict[str, Any]:
        """Lookup URL threat intelligence"""
        # Placeholder - in real implementation would query threat intel feeds
        return {
            "reputation": "unknown",
            "categories": [],
            "last_analyzed": None,
            "confidence": 0.5
        }
    
    # Threat actor profiling helper methods
    def _adjust_actor_score_by_context(self, similarity_score: float, profile: Dict[str, Any], 
                                     session_metadata: Dict[str, Any]) -> float:
        """Adjust actor similarity score based on session context"""
        adjusted_score = similarity_score
        
        # Adjust based on geographic context
        source_ip = session_metadata.get("source_ip", "")
        actor_country = profile.get("country", "")
        
        # Simple geographic correlation (in real implementation would use IP geolocation)
        if actor_country and source_ip:
            # Placeholder logic
            if actor_country in ["China", "Russia", "North Korea"]:
                adjusted_score *= 1.1  # Slight boost for known APT countries
        
        # Adjust based on timing
        session_time = session_metadata.get("start_time", "")
        if session_time:
            try:
                session_dt = datetime.fromisoformat(session_time)
                # Check if attack occurred during typical working hours for actor's country
                # This is a simplified example
                if 9 <= session_dt.hour <= 17:
                    adjusted_score *= 1.05
            except Exception:
                pass
        
        return min(adjusted_score, 1.0)  # Cap at 1.0
    
    def _calculate_actor_confidence(self, sorted_actors: List[Tuple[str, Dict[str, Any]]]) -> str:
        """Calculate confidence level for threat actor attribution"""
        if not sorted_actors:
            return "Low"
        
        top_score = sorted_actors[0][1].get("adjusted_score", 0)
        
        if top_score > 0.8:
            return "High"
        elif top_score > 0.6:
            return "Medium"
        else:
            return "Low"
    
    def _generate_actor_assessment_summary(self, sorted_actors: List[Tuple[str, Dict[str, Any]]], 
                                         techniques: List[Dict[str, Any]]) -> str:
        """Generate threat actor assessment summary"""
        if not sorted_actors:
            return "No significant threat actor matches found based on observed techniques."
        
        top_actor = sorted_actors[0]
        actor_name = top_actor[0]
        actor_data = top_actor[1]
        score = actor_data.get("adjusted_score", 0)
        
        technique_count = len(techniques)
        overlap_count = actor_data.get("technique_overlap", 0)
        
        summary = f"Analysis suggests potential similarity to {actor_name} "
        summary += f"(confidence: {score:.2f}). "
        summary += f"Observed {overlap_count} of {technique_count} techniques "
        summary += f"consistent with this threat actor's known TTPs."
        
        if len(sorted_actors) > 1:
            second_actor = sorted_actors[1]
            summary += f" Secondary match: {second_actor[0]} "
            summary += f"(confidence: {second_actor[1].get('adjusted_score', 0):.2f})."
        
        return summary
    
    def _generate_actor_based_recommendations(self, sorted_actors: List[Tuple[str, Dict[str, Any]]]) -> List[str]:
        """Generate recommendations based on threat actor profile"""
        recommendations = []
        
        if not sorted_actors:
            return ["Continue monitoring for additional threat indicators"]
        
        top_actor = sorted_actors[0]
        actor_profile = top_actor[1].get("profile", {})
        
        # Generic recommendations based on actor type
        targets = actor_profile.get("targets", [])
        if "Financial" in targets:
            recommendations.append("Implement additional financial data protection measures")
        if "Government" in targets:
            recommendations.append("Review and strengthen classified information security")
        if "Technology" in targets:
            recommendations.append("Protect intellectual property and source code")
        
        # Tool-based recommendations
        tools = actor_profile.get("tools", [])
        if any("PowerShell" in tool for tool in tools):
            recommendations.append("Monitor and restrict PowerShell execution")
        if any("Remote" in tool for tool in tools):
            recommendations.append("Strengthen remote access controls and monitoring")
        
        return recommendations
    
    # Helper methods for MITRE framework
    def _get_detection_methods(self, technique_id: str) -> List[str]:
        """Get detection methods for a MITRE technique"""
        # Simplified detection methods - in real implementation would be more comprehensive
        detection_map = {
            "T1033": ["Process monitoring", "Command line analysis"],
            "T1057": ["Process monitoring", "System calls"],
            "T1082": ["System information queries", "Command line analysis"],
            "T1083": ["File system monitoring", "Process monitoring"],
            "T1087": ["Account enumeration detection", "Authentication logs"],
            "T1548": ["Privilege escalation monitoring", "Process monitoring"],
            "T1070": ["File integrity monitoring", "Log analysis"],
            "T1105": ["Network monitoring", "File system monitoring"]
        }
        
        return detection_map.get(technique_id, ["Behavioral analysis", "Anomaly detection"])
    
    def _get_mitigation_strategies(self, technique_id: str) -> List[str]:
        """Get mitigation strategies for a MITRE technique"""
        # Simplified mitigation strategies
        mitigation_map = {
            "T1033": ["Limit information disclosure", "User account management"],
            "T1057": ["Process monitoring", "Execution prevention"],
            "T1082": ["System information protection", "Access controls"],
            "T1083": ["File system permissions", "Access controls"],
            "T1087": ["Account management", "Access controls"],
            "T1548": ["Privileged account management", "User account control"],
            "T1070": ["Audit logging", "File integrity monitoring"],
            "T1105": ["Network segmentation", "Application controls"]
        }
        
        return mitigation_map.get(technique_id, ["Defense in depth", "Monitoring and detection"])
    
    def _map_behavioral_patterns_to_techniques(self, transcript: List[Dict[str, Any]], 
                                             metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map behavioral patterns to MITRE techniques"""
        techniques = []
        
        # Analyze session timing for automation indicators
        timestamps = []
        for interaction in transcript:
            try:
                ts = datetime.fromisoformat(interaction.get("timestamp", ""))
                timestamps.append(ts)
            except Exception:
                continue
        
        if len(timestamps) >= 3:
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            # Detect rapid automation (potential scripting)
            rapid_commands = sum(1 for interval in intervals if interval < 2)
            if rapid_commands > len(intervals) * 0.7:  # 70% rapid commands
                techniques.append({
                    "technique_id": "T1059.004",
                    "technique_name": "Command and Scripting Interpreter: Unix Shell",
                    "tactic": "Execution",
                    "confidence": 0.7,
                    "evidence": f"Rapid command execution pattern: {rapid_commands}/{len(intervals)} commands under 2s",
                    "detection_method": "behavioral_analysis",
                    "pattern_type": "automation_indicator"
                })
        
        # Detect credential stuffing patterns
        login_attempts = [i for i in transcript if "login" in i.get("content", "").lower()]
        if len(login_attempts) > 5:
            techniques.append({
                "technique_id": "T1110.004",
                "technique_name": "Brute Force: Credential Stuffing",
                "tactic": "Credential Access",
                "confidence": 0.8,
                "evidence": f"Multiple login attempts detected: {len(login_attempts)}",
                "detection_method": "behavioral_analysis",
                "pattern_type": "credential_stuffing"
            })
        
        return techniques
    
    def _map_iocs_to_techniques(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map IOCs to relevant MITRE techniques"""
        techniques = []
        
        # This would typically involve threat intelligence feeds
        # For now, we'll do basic IOC-based technique inference
        
        source_ip = session_data.get("metadata", {}).get("source_ip", "")
        
        # Check if IP is from known malicious ranges (simplified)
        if source_ip and self._is_suspicious_ip(source_ip):
            techniques.append({
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "confidence": 0.6,
                "evidence": f"Connection from suspicious IP: {source_ip}",
                "detection_method": "ioc_analysis",
                "ioc_type": "ip_address"
            })
        
        return techniques
    
    def _deduplicate_and_enrich_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates and enrich technique information"""
        unique_techniques = {}
        
        for technique in techniques:
            technique_id = technique.get("technique_id", "")
            
            if technique_id in unique_techniques:
                # Merge evidence and update confidence
                existing = unique_techniques[technique_id]
                existing["confidence"] = max(existing.get("confidence", 0), technique.get("confidence", 0))
                
                # Merge evidence
                existing_evidence = existing.get("evidence", "")
                new_evidence = technique.get("evidence", "")
                if new_evidence and new_evidence not in existing_evidence:
                    existing["evidence"] = f"{existing_evidence}; {new_evidence}"
                
                # Add detection methods
                existing_methods = existing.get("detection_methods", [])
                new_method = technique.get("detection_method", "")
                if new_method and new_method not in existing_methods:
                    existing_methods.append(new_method)
                existing["detection_methods"] = existing_methods
                
            else:
                # Add technique information from MITRE matrix
                if technique_id in self.attack_matrix:
                    matrix_info = self.attack_matrix[technique_id]
                    technique["description"] = matrix_info.get("description", "")
                    technique["subtechniques"] = matrix_info.get("subtechniques", {})
                
                technique["detection_methods"] = [technique.get("detection_method", "")]
                unique_techniques[technique_id] = technique
        
        return list(unique_techniques.values())
    
    # Additional helper methods will be implemented in the next part...    
    
# Analysis helper methods
    def _analyze_tactic_progression(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the progression of tactics in the attack"""
        tactic_timeline = []
        
        for technique in techniques:
            tactic_timeline.append({
                "tactic": technique.get("tactic", "Unknown"),
                "timestamp": technique.get("timestamp", ""),
                "technique": technique.get("technique_name", "")
            })
        
        # Sort by timestamp
        tactic_timeline.sort(key=lambda x: x.get("timestamp", ""))
        
        # Analyze progression
        unique_tactics = []
        for item in tactic_timeline:
            if item["tactic"] not in [t["tactic"] for t in unique_tactics]:
                unique_tactics.append(item)
        
        return {
            "tactic_sequence": [t["tactic"] for t in unique_tactics],
            "timeline": tactic_timeline,
            "progression_analysis": self._assess_tactic_progression(unique_tactics)
        }
    
    def _analyze_kill_chain_progression(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze kill chain progression based on MITRE tactics"""
        kill_chain_phases = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Exfiltration",
            "Command and Control"
        ]
        
        observed_phases = []
        for technique in techniques:
            tactic = technique.get("tactic", "")
            if tactic in kill_chain_phases and tactic not in observed_phases:
                observed_phases.append(tactic)
        
        # Calculate progression score
        progression_score = 0
        for i, phase in enumerate(kill_chain_phases):
            if phase in observed_phases:
                progression_score = i + 1
        
        return {
            "observed_phases": observed_phases,
            "kill_chain_coverage": len(observed_phases) / len(kill_chain_phases),
            "progression_score": progression_score,
            "missing_phases": [p for p in kill_chain_phases if p not in observed_phases]
        }
    
    def _analyze_tactic_distribution(self, techniques: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze distribution of techniques across tactics"""
        tactic_counts = {}
        
        for technique in techniques:
            tactic = technique.get("tactic", "Unknown")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        return tactic_counts
    
    def _analyze_kill_chain_coverage(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze kill chain coverage and gaps"""
        kill_chain_phases = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access", 
            "Discovery", "Lateral Movement", "Collection", "Exfiltration",
            "Command and Control"
        ]
        
        covered_phases = set()
        for technique in techniques:
            tactic = technique.get("tactic", "")
            if tactic in kill_chain_phases:
                covered_phases.add(tactic)
        
        coverage_percentage = len(covered_phases) / len(kill_chain_phases) * 100
        
        return {
            "covered_phases": list(covered_phases),
            "missing_phases": [p for p in kill_chain_phases if p not in covered_phases],
            "coverage_percentage": coverage_percentage,
            "phase_count": len(covered_phases)
        }
    
    def _calculate_sophistication_metrics(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate sophistication metrics based on techniques"""
        total_techniques = len(techniques)
        
        # Count advanced techniques
        advanced_tactics = ["Persistence", "Defense Evasion", "Privilege Escalation", "Lateral Movement"]
        advanced_count = sum(1 for t in techniques if t.get("tactic") in advanced_tactics)
        
        # Calculate sophistication score
        if total_techniques == 0:
            sophistication_score = 0
        else:
            sophistication_score = (advanced_count / total_techniques) * 100
        
        # Determine sophistication level
        if sophistication_score >= 70:
            level = "Advanced"
        elif sophistication_score >= 40:
            level = "Intermediate"
        elif sophistication_score >= 20:
            level = "Novice"
        else:
            level = "Basic"
        
        return {
            "sophistication_score": sophistication_score,
            "sophistication_level": level,
            "total_techniques": total_techniques,
            "advanced_techniques": advanced_count,
            "technique_diversity": len(set(t.get("tactic") for t in techniques))
        }
    
    # IOC extraction methods
    def _extract_ip_indicators(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IP address IOCs"""
        iocs = []
        
        # Source IP from metadata
        source_ip = session_data.get("metadata", {}).get("source_ip")
        if source_ip and source_ip not in ["127.0.0.1", "::1"]:
            iocs.append({
                "type": "ip_address",
                "value": source_ip,
                "confidence": 0.9,
                "context": "Source IP of attacker session",
                "mitre_techniques": ["T1071.001"]  # Application Layer Protocol
            })
        
        # Extract IPs from transcript content
        transcript = session_data.get("transcript", [])
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            ips = re.findall(ip_pattern, content)
            
            for ip in ips:
                if ip not in ["127.0.0.1", "0.0.0.0"]:
                    iocs.append({
                        "type": "ip_address",
                        "value": ip,
                        "confidence": 0.7,
                        "context": f"IP found in command: {content[:50]}...",
                        "mitre_techniques": ["T1105"]  # Ingress Tool Transfer
                    })
        
        return iocs
    
    def _extract_domain_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract domain IOCs"""
        iocs = []
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            domains = re.findall(domain_pattern, content)
            
            for domain_match in domains:
                domain = domain_match[0] if isinstance(domain_match, tuple) else domain_match
                if domain and not domain.endswith(('.local', '.internal')):
                    iocs.append({
                        "type": "domain",
                        "value": domain,
                        "confidence": 0.6,
                        "context": f"Domain found in: {content[:50]}...",
                        "mitre_techniques": ["T1071.001", "T1105"]
                    })
        
        return iocs
    
    def _extract_file_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract file path IOCs"""
        iocs = []
        
        # Common suspicious file patterns
        suspicious_files = [
            r'/tmp/[a-zA-Z0-9]+',
            r'/var/tmp/[a-zA-Z0-9]+',
            r'\.sh$',
            r'\.py$',
            r'\.pl$',
            r'\.exe$',
            r'\.bat$'
        ]
        
        for interaction in transcript:
            content = interaction.get("content", "")
            
            for pattern in suspicious_files:
                matches = re.findall(pattern, content)
                for match in matches:
                    iocs.append({
                        "type": "file_path",
                        "value": match,
                        "confidence": 0.5,
                        "context": f"Suspicious file in: {content[:50]}...",
                        "mitre_techniques": ["T1105", "T1059"]
                    })
        
        return iocs
    
    def _extract_hash_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract file hash IOCs"""
        iocs = []
        
        hash_patterns = {
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b', 
            "sha256": r'\b[a-fA-F0-9]{64}\b'
        }
        
        for interaction in transcript:
            content = interaction.get("content", "")
            
            for hash_type, pattern in hash_patterns.items():
                hashes = re.findall(pattern, content)
                for hash_value in hashes:
                    iocs.append({
                        "type": f"file_hash_{hash_type}",
                        "value": hash_value,
                        "confidence": 0.9,
                        "context": f"Hash found in: {content[:50]}...",
                        "mitre_techniques": ["T1105", "T1027"]
                    })
        
        return iocs
    
    def _extract_url_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract URL IOCs"""
        iocs = []
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            urls = re.findall(url_pattern, content)
            
            for url in urls:
                iocs.append({
                    "type": "url",
                    "value": url,
                    "confidence": 0.8,
                    "context": f"URL found in: {content[:50]}...",
                    "mitre_techniques": ["T1071.001", "T1105"]
                })
        
        return iocs
    
    def _extract_email_indicators(self, transcript: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract email IOCs"""
        iocs = []
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        for interaction in transcript:
            content = interaction.get("content", "")
            emails = re.findall(email_pattern, content)
            
            for email in emails:
                iocs.append({
                    "type": "email_address",
                    "value": email,
                    "confidence": 0.7,
                    "context": f"Email found in: {content[:50]}...",
                    "mitre_techniques": ["T1071.003"]  # Mail Protocols
                })
        
        return iocs
    
    def _validate_and_enrich_ioc(self, ioc: Dict[str, Any], session_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate and enrich IOC with additional context"""
        try:
            # Basic validation
            if not ioc.get("value") or not ioc.get("type"):
                return None
            
            # Enrich with session context
            ioc["session_id"] = session_data.get("session_id", "")
            ioc["honeypot_type"] = session_data.get("metadata", {}).get("honeypot_type", "")
            ioc["first_seen"] = datetime.utcnow().isoformat()
            
            # Add threat intelligence context (simplified)
            ioc["threat_intel"] = self._get_threat_intel_context(ioc)
            
            # Validate IOC format
            if not self._validate_ioc_format(ioc):
                return None
            
            return ioc
            
        except Exception as e:
            self.logger.error(f"Error validating IOC: {e}")
            return None
    
    # Threat actor profiling methods
    def _adjust_actor_score_by_context(self, base_score: float, actor_profile: Dict[str, Any], 
                                     session_metadata: Dict[str, Any]) -> float:
        """Adjust actor similarity score based on session context"""
        adjusted_score = base_score
        
        # Geographic context
        source_ip = session_metadata.get("source_ip", "")
        if source_ip:
            # This would typically use GeoIP lookup
            # For now, we'll use a simplified approach
            actor_country = actor_profile.get("country", "")
            if actor_country and self._ip_matches_country(source_ip, actor_country):
                adjusted_score *= 1.2  # Boost score for geographic match
        
        # Timing context
        honeypot_type = session_metadata.get("honeypot_type", "")
        actor_targets = actor_profile.get("targets", [])
        if honeypot_type in ["web_admin", "database"] and "Financial" in actor_targets:
            adjusted_score *= 1.1  # Boost for target type match
        
        return min(adjusted_score, 1.0)  # Cap at 1.0
    
    def _calculate_actor_confidence(self, sorted_actors: List[Tuple[str, Dict[str, Any]]]) -> str:
        """Calculate confidence level for threat actor attribution"""
        if not sorted_actors:
            return "None"
        
        top_score = sorted_actors[0][1]["adjusted_score"]
        
        if top_score >= 0.8:
            return "High"
        elif top_score >= 0.6:
            return "Medium"
        elif top_score >= 0.4:
            return "Low"
        else:
            return "Very Low"
    
    def _generate_actor_assessment_summary(self, sorted_actors: List[Tuple[str, Dict[str, Any]]], 
                                         techniques: List[Dict[str, Any]]) -> str:
        """Generate threat actor assessment summary"""
        if not sorted_actors:
            return "No significant threat actor matches found based on observed techniques."
        
        top_actor = sorted_actors[0]
        actor_name = top_actor[0]
        score = top_actor[1]["adjusted_score"]
        
        summary = f"Top threat actor match: {actor_name} (confidence: {score:.2f}). "
        
        if score >= 0.6:
            summary += f"Strong similarity in technique usage suggests possible attribution to {actor_name} or similar groups."
        elif score >= 0.4:
            summary += f"Moderate similarity suggests techniques consistent with {actor_name} TTPs."
        else:
            summary += "Low confidence attribution. Techniques may be common across multiple threat actors."
        
        return summary
    
    def _generate_actor_based_recommendations(self, sorted_actors: List[Tuple[str, Dict[str, Any]]]) -> List[str]:
        """Generate recommendations based on threat actor profile"""
        recommendations = []
        
        if not sorted_actors:
            recommendations.append("Continue monitoring for additional technique indicators")
            return recommendations
        
        top_actor = sorted_actors[0]
        actor_profile = top_actor[1]["profile"]
        
        # Add actor-specific recommendations
        actor_techniques = actor_profile.get("techniques", [])
        if "T1021.001" in actor_techniques:  # RDP
            recommendations.append("Monitor and restrict RDP access")
        if "T1059.001" in actor_techniques:  # PowerShell
            recommendations.append("Implement PowerShell logging and monitoring")
        if "T1078" in actor_techniques:  # Valid Accounts
            recommendations.append("Review account access controls and implement MFA")
        
        # Add target-specific recommendations
        targets = actor_profile.get("targets", [])
        if "Financial" in targets:
            recommendations.append("Implement additional financial system monitoring")
        if "Government" in targets:
            recommendations.append("Review classified data access controls")
        
        return recommendations
    
    # Report generation methods
    def _generate_defensive_recommendations(self, techniques: List[Dict[str, Any]], 
                                         tactic_distribution: Dict[str, int]) -> List[Dict[str, Any]]:
        """Generate defensive recommendations based on observed techniques"""
        recommendations = []
        
        # Tactic-based recommendations
        if "Discovery" in tactic_distribution:
            recommendations.append({
                "category": "Detection",
                "priority": "High",
                "recommendation": "Implement comprehensive system monitoring to detect reconnaissance activities",
                "mitre_techniques": ["T1033", "T1057", "T1082", "T1083"]
            })
        
        if "Privilege Escalation" in tactic_distribution:
            recommendations.append({
                "category": "Prevention",
                "priority": "Critical",
                "recommendation": "Review and harden privilege escalation controls, implement least privilege access",
                "mitre_techniques": ["T1548"]
            })
        
        if "Defense Evasion" in tactic_distribution:
            recommendations.append({
                "category": "Detection",
                "priority": "High", 
                "recommendation": "Implement tamper-resistant logging and file integrity monitoring",
                "mitre_techniques": ["T1070"]
            })
        
        if "Credential Access" in tactic_distribution:
            recommendations.append({
                "category": "Prevention",
                "priority": "Critical",
                "recommendation": "Implement multi-factor authentication and credential protection measures",
                "mitre_techniques": ["T1110", "T1555"]
            })
        
        # Technique-specific recommendations
        technique_ids = [t.get("technique_id") for t in techniques]
        
        if "T1190" in technique_ids:
            recommendations.append({
                "category": "Prevention",
                "priority": "Critical",
                "recommendation": "Patch public-facing applications and implement web application firewalls",
                "mitre_techniques": ["T1190"]
            })
        
        if "T1105" in technique_ids:
            recommendations.append({
                "category": "Detection",
                "priority": "High",
                "recommendation": "Monitor network traffic for suspicious file transfers and downloads",
                "mitre_techniques": ["T1105"]
            })
        
        return recommendations
    
    def _generate_navigator_layer(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate MITRE ATT&CK Navigator layer for visualization"""
        layer = {
            "name": "Honeypot Analysis",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "MITRE ATT&CK techniques observed in honeypot session",
            "techniques": []
        }
        
        for technique in techniques:
            technique_id = technique.get("technique_id", "")
            confidence = technique.get("confidence", 0)
            
            # Map confidence to color
            if confidence >= 0.8:
                color = "#ff0000"  # Red for high confidence
            elif confidence >= 0.6:
                color = "#ff8000"  # Orange for medium confidence
            else:
                color = "#ffff00"  # Yellow for low confidence
            
            layer["techniques"].append({
                "techniqueID": technique_id,
                "color": color,
                "score": int(confidence * 100),
                "comment": technique.get("evidence", "")
            })
        
        return layer
    
    def _summarize_iocs(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize IOC analysis results"""
        ioc_types = {}
        high_confidence_iocs = 0
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
            if ioc.get("confidence", 0) >= 0.8:
                high_confidence_iocs += 1
        
        return {
            "total_iocs": len(iocs),
            "ioc_types": ioc_types,
            "high_confidence_count": high_confidence_iocs,
            "confidence_distribution": self._calculate_ioc_confidence_distribution(iocs)
        }
    
    # Utility methods
    def _assess_tactic_progression(self, tactic_sequence: List[Dict[str, Any]]) -> str:
        """Assess the logical progression of tactics"""
        if len(tactic_sequence) < 2:
            return "Insufficient data for progression analysis"
        
        # Check for logical kill chain progression
        expected_order = ["Reconnaissance", "Initial Access", "Execution", "Discovery", "Privilege Escalation"]
        
        observed_tactics = [t["tactic"] for t in tactic_sequence]
        
        # Simple progression check
        progression_score = 0
        for i, expected_tactic in enumerate(expected_order):
            if expected_tactic in observed_tactics:
                actual_position = observed_tactics.index(expected_tactic)
                if actual_position >= i:
                    progression_score += 1
        
        if progression_score >= 4:
            return "Logical attack progression observed"
        elif progression_score >= 2:
            return "Partial attack progression observed"
        else:
            return "Non-standard attack progression"
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is from suspicious ranges (simplified)"""
        # This would typically check against threat intelligence feeds
        # For now, we'll use basic heuristics
        
        # Check for Tor exit nodes, known malicious ranges, etc.
        suspicious_ranges = [
            "10.0.0.0/8",    # Private (could be suspicious in certain contexts)
            "172.16.0.0/12", # Private
            "192.168.0.0/16" # Private
        ]
        
        # In a real implementation, this would check against:
        # - Threat intelligence feeds
        # - Known malicious IP databases
        # - Tor exit node lists
        # - VPN/proxy service ranges
        
        return False  # Simplified for demo
    
    def _get_threat_intel_context(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Get threat intelligence context for IOC (simplified)"""
        return {
            "reputation": "unknown",
            "first_seen_global": None,
            "malware_families": [],
            "threat_actors": []
        }
    
    def _validate_ioc_format(self, ioc: Dict[str, Any]) -> bool:
        """Validate IOC format"""
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        
        if ioc_type == "ip_address":
            # Basic IP validation
            parts = value.split(".")
            if len(parts) != 4:
                return False
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        elif ioc_type == "domain":
            # Basic domain validation
            return "." in value and len(value) > 3
        
        elif ioc_type.startswith("file_hash_"):
            # Hash validation
            if ioc_type == "file_hash_md5":
                return len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value)
            elif ioc_type == "file_hash_sha1":
                return len(value) == 40 and all(c in "0123456789abcdefABCDEF" for c in value)
            elif ioc_type == "file_hash_sha256":
                return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)
        
        return True  # Default to valid for other types
    
    def _ip_matches_country(self, ip: str, country: str) -> bool:
        """Check if IP matches expected country (simplified)"""
        # This would typically use GeoIP lookup
        return False  # Simplified for demo
    
    def _calculate_ioc_confidence_distribution(self, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate confidence distribution for IOCs"""
        distribution = {"high": 0, "medium": 0, "low": 0}
        
        for ioc in iocs:
            confidence = ioc.get("confidence", 0)
            if confidence >= 0.8:
                distribution["high"] += 1
            elif confidence >= 0.6:
                distribution["medium"] += 1
            else:
                distribution["low"] += 1
        
        return distribution
        return distribution
  
  # Enhanced MITRE ATT&CK Classification Algorithms for Task 5.2
    def classify_attack_campaign(self, session_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Classify attack campaign across multiple sessions using advanced MITRE analysis.
        
        Args:
            session_data_list: List of session data from related attacks
            
        Returns:
            Campaign classification with MITRE context
        """
        try:
            all_techniques = []
            all_iocs = []
            campaign_timeline = []
            
            # Analyze each session
            for session_data in session_data_list:
                techniques = self.map_techniques_from_session(session_data)
                iocs = self.extract_and_validate_iocs(session_data)
                
                all_techniques.extend(techniques)
                all_iocs.extend(iocs)
                
                # Build campaign timeline
                session_id = session_data.get("session_id", "unknown")
                start_time = session_data.get("metadata", {}).get("start_time")
                if start_time:
                    campaign_timeline.append({
                        "session_id": session_id,
                        "timestamp": start_time,
                        "technique_count": len(techniques),
                        "primary_tactic": self._get_primary_tactic(techniques)
                    })
            
            # Advanced campaign analysis
            campaign_analysis = {
                "campaign_id": str(uuid4()),
                "session_count": len(session_data_list),
                "total_techniques": len(all_techniques),
                "unique_techniques": len(set(t.get("technique_id") for t in all_techniques)),
                "timeline": sorted(campaign_timeline, key=lambda x: x["timestamp"]),
                "technique_evolution": self._analyze_technique_evolution(all_techniques, campaign_timeline),
                "tactic_progression": self._analyze_campaign_tactic_progression(all_techniques, campaign_timeline),
                "ioc_correlation": self._correlate_campaign_iocs(all_iocs),
                "threat_actor_attribution": self._enhanced_threat_actor_attribution(all_techniques, all_iocs),
                "campaign_sophistication": self._assess_campaign_sophistication(all_techniques, campaign_timeline),
                "attack_pattern_classification": self._classify_attack_patterns(all_techniques),
                "defensive_gaps": self._identify_defensive_gaps(all_techniques),
                "prediction_model": self._generate_attack_predictions(all_techniques, campaign_timeline)
            }
            
            return campaign_analysis
            
        except Exception as e:
            self.logger.error(f"Error classifying attack campaign: {e}")
            return {"error": str(e)}
    
    def advanced_ioc_validation(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhanced IOC validation with advanced threat intelligence correlation.
        
        Args:
            iocs: List of IOCs to validate
            
        Returns:
            Enhanced IOCs with advanced validation results
        """
        try:
            validated_iocs = []
            
            for ioc in iocs:
                enhanced_ioc = ioc.copy()
                
                # Advanced validation algorithms
                enhanced_ioc["validation_results"] = {
                    "format_valid": self._validate_ioc_format(ioc),
                    "reputation_score": self._calculate_ioc_reputation(ioc),
                    "threat_intel_matches": self._check_threat_intel_databases(ioc),
                    "behavioral_indicators": self._analyze_ioc_behavior(ioc),
                    "attribution_confidence": self._calculate_attribution_confidence(ioc),
                    "false_positive_probability": self._calculate_false_positive_probability(ioc)
                }
                
                # Enhanced MITRE technique associations
                enhanced_ioc["mitre_associations"] = {
                    "primary_techniques": self._associate_ioc_with_techniques(ioc),
                    "secondary_techniques": self._infer_secondary_techniques(ioc),
                    "tactic_implications": self._analyze_tactic_implications(ioc),
                    "kill_chain_position": self._determine_kill_chain_position(ioc)
                }
                
                # Threat actor correlation
                enhanced_ioc["threat_actor_correlation"] = self._correlate_ioc_with_actors(ioc)
                
                # Risk assessment
                enhanced_ioc["risk_assessment"] = {
                    "severity": self._assess_ioc_severity(ioc),
                    "urgency": self._assess_ioc_urgency(ioc),
                    "impact_potential": self._assess_impact_potential(ioc),
                    "containment_priority": self._calculate_containment_priority(ioc)
                }
                
                validated_iocs.append(enhanced_ioc)
            
            return validated_iocs
            
        except Exception as e:
            self.logger.error(f"Error in advanced IOC validation: {e}")
            return iocs
    
    def generate_threat_actor_profile_advanced(self, techniques: List[Dict[str, Any]], 
                                             iocs: List[Dict[str, Any]], 
                                             session_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Advanced threat actor profiling with machine learning-like analysis.
        
        Args:
            techniques: MITRE techniques observed
            iocs: IOCs extracted from sessions
            session_metadata: Session metadata for context
            
        Returns:
            Advanced threat actor profile
        """
        try:
            # Multi-dimensional analysis
            profile_analysis = {
                "technique_fingerprint": self._generate_technique_fingerprint(techniques),
                "behavioral_signature": self._generate_behavioral_signature(techniques, iocs),
                "infrastructure_analysis": self._analyze_threat_infrastructure(iocs),
                "temporal_patterns": self._analyze_temporal_patterns(session_metadata),
                "geographic_indicators": self._analyze_geographic_indicators(iocs, session_metadata),
                "tool_usage_patterns": self._analyze_tool_usage_patterns(techniques),
                "sophistication_markers": self._identify_sophistication_markers(techniques, iocs),
                "attribution_confidence": self._calculate_advanced_attribution_confidence(techniques, iocs)
            }
            
            # Enhanced threat actor matching
            actor_matches = []
            for actor_name, actor_profile in self.threat_actor_profiles.items():
                similarity_score = self._calculate_advanced_similarity(
                    profile_analysis, actor_profile, techniques, iocs
                )
                
                actor_matches.append({
                    "actor_name": actor_name,
                    "similarity_score": similarity_score,
                    "confidence_factors": self._analyze_confidence_factors(
                        profile_analysis, actor_profile
                    ),
                    "distinguishing_features": self._identify_distinguishing_features(
                        profile_analysis, actor_profile
                    )
                })
            
            # Sort by similarity
            actor_matches.sort(key=lambda x: x["similarity_score"], reverse=True)
            
            # Generate comprehensive assessment
            assessment = {
                "profile_analysis": profile_analysis,
                "top_actor_matches": actor_matches[:5],
                "attribution_assessment": self._generate_attribution_assessment(actor_matches),
                "confidence_level": self._calculate_overall_confidence(actor_matches, profile_analysis),
                "recommended_actions": self._generate_advanced_recommendations(actor_matches, profile_analysis),
                "intelligence_gaps": self._identify_intelligence_gaps(profile_analysis),
                "monitoring_recommendations": self._generate_monitoring_recommendations(profile_analysis)
            }
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error in advanced threat actor profiling: {e}")
            return {"error": str(e)}
    
    # Helper methods for enhanced functionality
    def _get_primary_tactic(self, techniques: List[Dict[str, Any]]) -> str:
        """Get the primary tactic from a list of techniques"""
        if not techniques:
            return "Unknown"
        
        tactic_counts = {}
        for technique in techniques:
            tactic = technique.get("tactic", "Unknown")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        return max(tactic_counts.items(), key=lambda x: x[1])[0] if tactic_counts else "Unknown"
    
    def _analyze_technique_evolution(self, techniques: List[Dict[str, Any]], 
                                   timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how techniques evolve across campaign sessions"""
        evolution = {
            "technique_progression": [],
            "complexity_trend": "stable",
            "new_techniques_per_session": [],
            "technique_persistence": {}
        }
        
        # Track technique usage across sessions
        session_techniques = {}
        for entry in timeline:
            session_id = entry["session_id"]
            session_techniques[session_id] = [
                t for t in techniques 
                if t.get("session_id") == session_id or session_id in str(t.get("evidence", ""))
            ]
        
        # Analyze progression
        all_seen_techniques = set()
        for session_id in sorted(session_techniques.keys()):
            session_techs = session_techniques[session_id]
            new_techniques = [t for t in session_techs if t.get("technique_id") not in all_seen_techniques]
            
            evolution["new_techniques_per_session"].append({
                "session_id": session_id,
                "new_count": len(new_techniques),
                "total_count": len(session_techs)
            })
            
            all_seen_techniques.update(t.get("technique_id") for t in session_techs)
        
        return evolution
    
    def _analyze_campaign_tactic_progression(self, techniques: List[Dict[str, Any]], 
                                           timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze tactic progression across campaign"""
        progression = {
            "tactic_timeline": [],
            "kill_chain_adherence": 0.0,
            "tactical_shifts": [],
            "progression_pattern": "unknown"
        }
        
        # Expected kill chain order
        kill_chain_order = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Exfiltration",
            "Command and Control"
        ]
        
        # Analyze tactic progression
        for entry in timeline:
            primary_tactic = entry.get("primary_tactic", "Unknown")
            progression["tactic_timeline"].append({
                "session_id": entry["session_id"],
                "timestamp": entry["timestamp"],
                "primary_tactic": primary_tactic,
                "kill_chain_position": kill_chain_order.index(primary_tactic) if primary_tactic in kill_chain_order else -1
            })
        
        return progression
    
    def _correlate_campaign_iocs(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate IOCs across campaign sessions"""
        correlation = {
            "shared_infrastructure": [],
            "ioc_clusters": [],
            "persistence_indicators": [],
            "infrastructure_evolution": []
        }
        
        # Group IOCs by type
        ioc_groups = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in ioc_groups:
                ioc_groups[ioc_type] = []
            ioc_groups[ioc_type].append(ioc)
        
        # Analyze shared infrastructure
        if "ip_address" in ioc_groups:
            ip_counts = {}
            for ioc in ioc_groups["ip_address"]:
                ip = ioc.get("value")
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            correlation["shared_infrastructure"] = [
                {"ip": ip, "usage_count": count}
                for ip, count in ip_counts.items() if count > 1
            ]
        
        return correlation
    
    def _enhanced_threat_actor_attribution(self, techniques: List[Dict[str, Any]], 
                                         iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced threat actor attribution using multiple factors"""
        attribution = {
            "technique_based_attribution": self.profile_threat_actor(techniques, {}),
            "infrastructure_based_attribution": self._attribute_by_infrastructure(iocs),
            "behavioral_attribution": self._attribute_by_behavior(techniques),
            "combined_attribution": {}
        }
        
        # Combine attribution methods
        all_scores = {}
        
        # Weight different attribution methods
        technique_weight = 0.4
        infrastructure_weight = 0.3
        behavioral_weight = 0.3
        
        # Combine scores (simplified)
        technique_matches = attribution["technique_based_attribution"].get("top_matches", [])
        for actor_name, match_data in technique_matches:
            score = match_data.get("adjusted_score", 0) * technique_weight
            all_scores[actor_name] = all_scores.get(actor_name, 0) + score
        
        # Sort combined scores
        sorted_scores = sorted(all_scores.items(), key=lambda x: x[1], reverse=True)
        attribution["combined_attribution"] = {
            "top_match": sorted_scores[0] if sorted_scores else ("Unknown", 0),
            "all_scores": sorted_scores[:5]
        }
        
        return attribution
    
    def _assess_campaign_sophistication(self, techniques: List[Dict[str, Any]], 
                                      timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall campaign sophistication"""
        sophistication = {
            "overall_level": "Unknown",
            "sophistication_score": 0.0,
            "sophistication_factors": [],
            "evolution_trend": "stable"
        }
        
        # Calculate base sophistication from techniques
        base_metrics = self._calculate_sophistication_metrics(techniques)
        sophistication["sophistication_score"] = base_metrics.get("sophistication_score", 0)
        
        # Add campaign-specific factors
        if len(timeline) > 3:
            sophistication["sophistication_factors"].append("Multi-session campaign")
            sophistication["sophistication_score"] += 10
        
        # Determine overall level
        score = sophistication["sophistication_score"]
        if score >= 80:
            sophistication["overall_level"] = "Advanced Persistent Threat"
        elif score >= 60:
            sophistication["overall_level"] = "Advanced"
        elif score >= 40:
            sophistication["overall_level"] = "Intermediate"
        else:
            sophistication["overall_level"] = "Basic"
        
        return sophistication
    
    def _classify_attack_patterns(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify attack patterns based on MITRE techniques"""
        patterns = {
            "primary_pattern": "Unknown",
            "pattern_confidence": 0.0,
            "pattern_indicators": [],
            "attack_type_classification": []
        }
        
        # Define attack patterns
        attack_patterns = {
            "Ransomware": ["T1486", "T1490", "T1083", "T1082"],
            "Data Exfiltration": ["T1041", "T1048", "T1005", "T1039"],
            "Credential Harvesting": ["T1110", "T1555", "T1003", "T1078"],
            "Lateral Movement": ["T1021", "T1570", "T1210", "T1135"],
            "Reconnaissance": ["T1595", "T1592", "T1590", "T1589"]
        }
        
        # Calculate pattern matches
        technique_ids = [t.get("technique_id") for t in techniques]
        pattern_scores = {}
        
        for pattern_name, pattern_techniques in attack_patterns.items():
            matches = len(set(technique_ids) & set(pattern_techniques))
            total_pattern_techniques = len(pattern_techniques)
            
            if total_pattern_techniques > 0:
                score = matches / total_pattern_techniques
                pattern_scores[pattern_name] = score
        
        # Determine primary pattern
        if pattern_scores:
            primary_pattern = max(pattern_scores.items(), key=lambda x: x[1])
            patterns["primary_pattern"] = primary_pattern[0]
            patterns["pattern_confidence"] = primary_pattern[1]
        
        return patterns
    
    def _identify_defensive_gaps(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify defensive gaps based on observed techniques"""
        gaps = []
        
        # Analyze technique coverage
        tactic_coverage = {}
        for technique in techniques:
            tactic = technique.get("tactic", "Unknown")
            tactic_coverage[tactic] = tactic_coverage.get(tactic, 0) + 1
        
        # Identify high-risk gaps
        if tactic_coverage.get("Defense Evasion", 0) > 2:
            gaps.append({
                "gap_type": "Detection Evasion",
                "severity": "High",
                "description": "Multiple defense evasion techniques observed",
                "recommendations": ["Implement behavioral detection", "Enhance log monitoring"]
            })
        
        if tactic_coverage.get("Credential Access", 0) > 1:
            gaps.append({
                "gap_type": "Credential Protection",
                "severity": "Critical",
                "description": "Credential access techniques detected",
                "recommendations": ["Implement MFA", "Monitor credential usage"]
            })
        
        return gaps
    
    def _generate_attack_predictions(self, techniques: List[Dict[str, Any]], 
                                   timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate predictions for likely next attack steps"""
        predictions = {
            "likely_next_techniques": [],
            "prediction_confidence": 0.0,
            "recommended_monitoring": [],
            "attack_progression_forecast": []
        }
        
        # Analyze current attack phase
        current_tactics = set(t.get("tactic") for t in techniques)
        
        # Predict next likely techniques based on kill chain
        kill_chain_progression = {
            "Discovery": ["Lateral Movement", "Credential Access"],
            "Credential Access": ["Lateral Movement", "Privilege Escalation"],
            "Lateral Movement": ["Collection", "Persistence"],
            "Collection": ["Exfiltration", "Command and Control"]
        }
        
        for current_tactic in current_tactics:
            if current_tactic in kill_chain_progression:
                next_tactics = kill_chain_progression[current_tactic]
                predictions["likely_next_techniques"].extend(next_tactics)
        
        return predictions
    
    # Additional helper methods for advanced IOC validation
    def _calculate_ioc_reputation(self, ioc: Dict[str, Any]) -> float:
        """Calculate IOC reputation score"""
        # Simplified reputation calculation
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        
        # Basic reputation scoring
        if ioc_type == "ip_address":
            # Check if it's a private IP (lower reputation for external threats)
            if value.startswith(("10.", "172.", "192.168.")):
                return 0.3
            return 0.7
        
        return 0.5  # Default neutral reputation
    
    def _check_threat_intel_databases(self, ioc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check IOC against threat intelligence databases"""
        # Placeholder for threat intel integration
        return [
            {
                "source": "Internal Database",
                "match_type": "exact",
                "confidence": 0.8,
                "last_seen": datetime.utcnow().isoformat()
            }
        ]
    
    def _analyze_ioc_behavior(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral indicators of IOC"""
        return {
            "behavioral_score": 0.6,
            "indicators": ["Command and Control", "Data Exfiltration"],
            "risk_factors": ["External Communication", "Suspicious Timing"]
        }
    
    def _calculate_attribution_confidence(self, ioc: Dict[str, Any]) -> float:
        """Calculate attribution confidence for IOC"""
        return 0.7  # Simplified
    
    def _calculate_false_positive_probability(self, ioc: Dict[str, Any]) -> float:
        """Calculate false positive probability"""
        return 0.2  # Simplified
    
    def _infer_secondary_techniques(self, ioc: Dict[str, Any]) -> List[str]:
        """Infer secondary MITRE techniques from IOC"""
        ioc_type = ioc.get("type", "")
        
        secondary_mappings = {
            "ip_address": ["T1071.001", "T1090"],
            "domain": ["T1071.001", "T1568"],
            "url": ["T1105", "T1071.001"],
            "file_hash": ["T1027", "T1105"]
        }
        
        return secondary_mappings.get(ioc_type, [])
    
    def _analyze_tactic_implications(self, ioc: Dict[str, Any]) -> List[str]:
        """Analyze tactic implications of IOC"""
        ioc_type = ioc.get("type", "")
        
        tactic_mappings = {
            "ip_address": ["Command and Control", "Exfiltration"],
            "domain": ["Command and Control", "Initial Access"],
            "url": ["Command and Control", "Initial Access"],
            "file_hash": ["Defense Evasion", "Execution"]
        }
        
        return tactic_mappings.get(ioc_type, [])
    
    def _determine_kill_chain_position(self, ioc: Dict[str, Any]) -> str:
        """Determine kill chain position of IOC"""
        ioc_type = ioc.get("type", "")
        
        position_mappings = {
            "ip_address": "Command and Control",
            "domain": "Command and Control", 
            "url": "Delivery",
            "file_hash": "Installation"
        }
        
        return position_mappings.get(ioc_type, "Unknown")
    
    def _correlate_ioc_with_actors(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate IOC with known threat actors"""
        return {
            "potential_actors": ["APT1", "APT28"],
            "correlation_confidence": 0.4,
            "correlation_factors": ["Infrastructure overlap", "TTPs similarity"]
        }
    
    def _assess_ioc_severity(self, ioc: Dict[str, Any]) -> str:
        """Assess IOC severity"""
        confidence = ioc.get("confidence", 0)
        
        if confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        else:
            return "Low"
    
    def _assess_ioc_urgency(self, ioc: Dict[str, Any]) -> str:
        """Assess IOC urgency"""
        ioc_type = ioc.get("type", "")
        
        if ioc_type in ["ip_address", "domain"]:
            return "High"  # Active infrastructure
        else:
            return "Medium"
    
    def _assess_impact_potential(self, ioc: Dict[str, Any]) -> str:
        """Assess potential impact of IOC"""
        return "Medium"  # Simplified
    
    def _calculate_containment_priority(self, ioc: Dict[str, Any]) -> int:
        """Calculate containment priority (1-10)"""
        confidence = ioc.get("confidence", 0)
        return min(int(confidence * 10), 10)
    
    # Advanced threat actor profiling helper methods
    def _generate_technique_fingerprint(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate unique technique fingerprint"""
        technique_ids = [t.get("technique_id") for t in techniques]
        tactic_distribution = {}
        
        for technique in techniques:
            tactic = technique.get("tactic", "Unknown")
            tactic_distribution[tactic] = tactic_distribution.get(tactic, 0) + 1
        
        return {
            "technique_count": len(technique_ids),
            "unique_techniques": len(set(technique_ids)),
            "tactic_distribution": tactic_distribution,
            "technique_diversity_score": len(set(technique_ids)) / len(technique_ids) if technique_ids else 0
        }
    
    def _generate_behavioral_signature(self, techniques: List[Dict[str, Any]], 
                                     iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate behavioral signature"""
        return {
            "command_patterns": self._extract_command_patterns(techniques),
            "timing_patterns": self._extract_timing_patterns(techniques),
            "infrastructure_patterns": self._extract_infrastructure_patterns(iocs),
            "persistence_indicators": self._extract_persistence_indicators(techniques)
        }
    
    def _analyze_threat_infrastructure(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat infrastructure from IOCs"""
        infrastructure = {
            "ip_addresses": [],
            "domains": [],
            "infrastructure_type": "Unknown",
            "geographic_distribution": [],
            "infrastructure_age": "Unknown"
        }
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            
            if ioc_type == "ip_address":
                infrastructure["ip_addresses"].append(value)
            elif ioc_type == "domain":
                infrastructure["domains"].append(value)
        
        return infrastructure
    
    def _analyze_temporal_patterns(self, session_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal attack patterns"""
        return {
            "attack_timing": "Unknown",
            "duration_patterns": "Unknown",
            "frequency_analysis": "Unknown"
        }
    
    def _analyze_geographic_indicators(self, iocs: List[Dict[str, Any]], 
                                     session_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic indicators"""
        return {
            "source_countries": ["Unknown"],
            "infrastructure_countries": ["Unknown"],
            "geographic_consistency": 0.5
        }
    
    def _analyze_tool_usage_patterns(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze tool usage patterns"""
        return {
            "tool_sophistication": "Medium",
            "custom_tools_detected": False,
            "living_off_land_techniques": 0,
            "commercial_tools": []
        }
    
    def _identify_sophistication_markers(self, techniques: List[Dict[str, Any]], 
                                       iocs: List[Dict[str, Any]]) -> List[str]:
        """Identify sophistication markers"""
        markers = []
        
        # Check for advanced techniques
        advanced_techniques = ["T1027", "T1070", "T1548"]
        technique_ids = [t.get("technique_id") for t in techniques]
        
        for tech_id in advanced_techniques:
            if tech_id in technique_ids:
                markers.append(f"Advanced technique: {tech_id}")
        
        return markers
    
    def _calculate_advanced_attribution_confidence(self, techniques: List[Dict[str, Any]], 
                                                 iocs: List[Dict[str, Any]]) -> float:
        """Calculate advanced attribution confidence"""
        # Multi-factor confidence calculation
        technique_confidence = len(techniques) / 10.0  # More techniques = higher confidence
        ioc_confidence = len(iocs) / 5.0  # More IOCs = higher confidence
        
        return min((technique_confidence + ioc_confidence) / 2.0, 1.0)
    
    def _calculate_advanced_similarity(self, profile_analysis: Dict[str, Any], 
                                     actor_profile: Dict[str, Any],
                                     techniques: List[Dict[str, Any]], 
                                     iocs: List[Dict[str, Any]]) -> float:
        """Calculate advanced similarity score"""
        # Multi-dimensional similarity calculation
        technique_similarity = self._calculate_technique_similarity(techniques, actor_profile)
        behavioral_similarity = self._calculate_behavioral_similarity(profile_analysis, actor_profile)
        infrastructure_similarity = self._calculate_infrastructure_similarity(iocs, actor_profile)
        
        # Weighted average
        weights = {"technique": 0.5, "behavioral": 0.3, "infrastructure": 0.2}
        
        total_similarity = (
            technique_similarity * weights["technique"] +
            behavioral_similarity * weights["behavioral"] +
            infrastructure_similarity * weights["infrastructure"]
        )
        
        return min(total_similarity, 1.0)
    
    def _analyze_confidence_factors(self, profile_analysis: Dict[str, Any], 
                                  actor_profile: Dict[str, Any]) -> List[str]:
        """Analyze confidence factors for attribution"""
        factors = []
        
        # Check technique overlap
        if "technique_fingerprint" in profile_analysis:
            factors.append("Technique pattern analysis")
        
        # Check behavioral indicators
        if "behavioral_signature" in profile_analysis:
            factors.append("Behavioral signature matching")
        
        return factors
    
    def _identify_distinguishing_features(self, profile_analysis: Dict[str, Any], 
                                        actor_profile: Dict[str, Any]) -> List[str]:
        """Identify distinguishing features"""
        return [
            "Unique technique combinations",
            "Infrastructure preferences",
            "Timing patterns"
        ]
    
    def _generate_attribution_assessment(self, actor_matches: List[Dict[str, Any]]) -> str:
        """Generate attribution assessment summary"""
        if not actor_matches:
            return "No clear attribution possible with current data"
        
        top_match = actor_matches[0]
        similarity = top_match.get("similarity_score", 0)
        
        if similarity >= 0.8:
            return f"High confidence attribution to {top_match['actor_name']}"
        elif similarity >= 0.6:
            return f"Moderate confidence attribution to {top_match['actor_name']}"
        else:
            return f"Low confidence attribution, {top_match['actor_name']} is possible match"
    
    def _calculate_overall_confidence(self, actor_matches: List[Dict[str, Any]], 
                                    profile_analysis: Dict[str, Any]) -> str:
        """Calculate overall confidence level"""
        if not actor_matches:
            return "Very Low"
        
        top_similarity = actor_matches[0].get("similarity_score", 0)
        
        if top_similarity >= 0.8:
            return "High"
        elif top_similarity >= 0.6:
            return "Medium"
        elif top_similarity >= 0.4:
            return "Low"
        else:
            return "Very Low"
    
    def _generate_advanced_recommendations(self, actor_matches: List[Dict[str, Any]], 
                                         profile_analysis: Dict[str, Any]) -> List[str]:
        """Generate advanced recommendations"""
        recommendations = []
        
        if actor_matches:
            top_actor = actor_matches[0]["actor_name"]
            recommendations.append(f"Monitor for {top_actor}-specific TTPs")
            recommendations.append(f"Review {top_actor} threat intelligence reports")
        
        recommendations.extend([
            "Implement behavioral detection rules",
            "Enhance network monitoring",
            "Review access controls"
        ])
        
        return recommendations
    
    def _identify_intelligence_gaps(self, profile_analysis: Dict[str, Any]) -> List[str]:
        """Identify intelligence gaps"""
        gaps = []
        
        if not profile_analysis.get("infrastructure_analysis", {}).get("ip_addresses"):
            gaps.append("Limited infrastructure intelligence")
        
        if not profile_analysis.get("temporal_patterns", {}).get("attack_timing"):
            gaps.append("Insufficient temporal analysis")
        
        return gaps
    
    def _generate_monitoring_recommendations(self, profile_analysis: Dict[str, Any]) -> List[str]:
        """Generate monitoring recommendations"""
        return [
            "Implement network traffic analysis",
            "Deploy endpoint detection and response",
            "Monitor for specific IOCs",
            "Enhance log correlation"
        ]
    
    # Additional helper methods for behavioral analysis
    def _extract_command_patterns(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Extract command patterns from techniques"""
        patterns = []
        for technique in techniques:
            evidence = technique.get("evidence", "")
            if evidence:
                patterns.append(evidence[:50])  # First 50 chars
        return patterns
    
    def _extract_timing_patterns(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract timing patterns"""
        return {
            "session_duration": "Unknown",
            "command_frequency": "Unknown",
            "pause_patterns": "Unknown"
        }
    
    def _extract_infrastructure_patterns(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract infrastructure patterns"""
        return {
            "ip_ranges": [],
            "domain_patterns": [],
            "infrastructure_reuse": False
        }
    
    def _extract_persistence_indicators(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Extract persistence indicators"""
        persistence_techniques = ["T1543", "T1136", "T1053"]
        indicators = []
        
        for technique in techniques:
            tech_id = technique.get("technique_id", "")
            if any(tech_id.startswith(pt) for pt in persistence_techniques):
                indicators.append(tech_id)
        
        return indicators
    
    def _attribute_by_infrastructure(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Attribute threat actor by infrastructure"""
        return {
            "infrastructure_matches": [],
            "confidence": 0.3,
            "attribution_factors": ["IP geolocation", "Domain registration patterns"]
        }
    
    def _attribute_by_behavior(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Attribute threat actor by behavior"""
        return {
            "behavioral_matches": [],
            "confidence": 0.4,
            "attribution_factors": ["Command patterns", "Timing analysis"]
        }
    
    def _calculate_technique_similarity(self, techniques: List[Dict[str, Any]], 
                                      actor_profile: Dict[str, Any]) -> float:
        """Calculate technique similarity with actor profile"""
        technique_ids = [t.get("technique_id") for t in techniques]
        actor_techniques = actor_profile.get("techniques", [])
        
        if not actor_techniques:
            return 0.0
        
        overlap = len(set(technique_ids) & set(actor_techniques))
        return overlap / len(actor_techniques)
    
    def _calculate_behavioral_similarity(self, profile_analysis: Dict[str, Any], 
                                       actor_profile: Dict[str, Any]) -> float:
        """Calculate behavioral similarity"""
        # Simplified behavioral similarity
        return 0.5
    
    def _calculate_infrastructure_similarity(self, iocs: List[Dict[str, Any]], 
                                           actor_profile: Dict[str, Any]) -> float:
        """Calculate infrastructure similarity"""
        # Simplified infrastructure similarity
        return 0.3