"""
Session Analysis Utilities for Intelligence Agent
Provides specialized analysis functions for different types of session data.
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
import logging


class SessionAnalyzer:
    """Utility class for analyzing attacker session data"""
    
    def __init__(self):
        self.logger = logging.getLogger("session_analyzer")
        
        # MITRE ATT&CK technique mappings
        self.mitre_mappings = {
            # Reconnaissance
            "whoami": {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery"},
            "id": {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery"},
            "ps": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery"},
            "netstat": {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery"},
            "ifconfig": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery"},
            "ip addr": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery"},
            "ls": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
            "dir": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
            "cat /etc/passwd": {"id": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "Discovery"},
            "cat /etc/shadow": {"id": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "Discovery"},
            "uname": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
            "hostname": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
            
            # Credential Access
            "sudo": {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo", "tactic": "Privilege Escalation"},
            "su": {"id": "T1548.002", "name": "Abuse Elevation Control Mechanism: Bypass User Account Control", "tactic": "Privilege Escalation"},
            
            # Persistence
            "crontab": {"id": "T1053.003", "name": "Scheduled Task/Job: Cron", "tactic": "Persistence"},
            "systemctl": {"id": "T1543.002", "name": "Create or Modify System Process: Systemd Service", "tactic": "Persistence"},
            
            # Defense Evasion
            "history -c": {"id": "T1070.003", "name": "Indicator Removal on Host: Clear Command History", "tactic": "Defense Evasion"},
            "rm": {"id": "T1070.004", "name": "Indicator Removal on Host: File Deletion", "tactic": "Defense Evasion"},
            
            # Collection
            "find": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
            "grep": {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
            "cat": {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
            
            # Exfiltration
            "scp": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            "wget": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
            "curl": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            "sql_injection": [
                r"union\s+select",
                r"or\s+1\s*=\s*1",
                r"drop\s+table",
                r"insert\s+into",
                r"update\s+.*\s+set",
                r"delete\s+from"
            ],
            "command_injection": [
                r";\s*cat\s+",
                r";\s*ls\s+",
                r";\s*id\s*;",
                r"\|\s*nc\s+",
                r"&&\s*whoami",
                r"`.*`"
            ],
            "path_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c"
            ],
            "credential_stuffing": [
                r"admin:admin",
                r"root:root",
                r"admin:password",
                r"test:test",
                r"guest:guest"
            ]
        }
    
    def analyze_command_sequence(self, transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the sequence of commands for patterns and techniques"""
        try:
            commands = []
            techniques = []
            
            for interaction in transcript:
                if interaction.get("type") == "command":
                    content = interaction.get("content", "").strip()
                    if content:
                        commands.append(content)
                        
                        # Map to MITRE techniques
                        technique = self._map_command_to_mitre(content)
                        if technique:
                            techniques.append(technique)
            
            # Analyze command patterns
            patterns = self._analyze_command_patterns(commands)
            
            # Detect attack phases
            attack_phases = self._detect_attack_phases(commands, techniques)
            
            return {
                "total_commands": len(commands),
                "unique_commands": len(set(commands)),
                "techniques": techniques,
                "patterns": patterns,
                "attack_phases": attack_phases,
                "command_frequency": dict(Counter(commands))
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing command sequence: {e}")
            return {"error": str(e)}
    
    def analyze_web_interactions(self, transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze web-based interactions for attack patterns"""
        try:
            requests = []
            attack_patterns = []
            
            for interaction in transcript:
                if interaction.get("type") in ["http_request", "web_request"]:
                    content = interaction.get("content", "")
                    requests.append(content)
                    
                    # Check for web attack patterns
                    patterns = self._detect_web_attack_patterns(content)
                    attack_patterns.extend(patterns)
            
            # Analyze request patterns
            request_analysis = self._analyze_request_patterns(requests)
            
            return {
                "total_requests": len(requests),
                "attack_patterns": attack_patterns,
                "request_analysis": request_analysis,
                "suspicious_parameters": self._extract_suspicious_parameters(requests)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing web interactions: {e}")
            return {"error": str(e)}
    
    def analyze_database_interactions(self, transcript: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze database interactions for SQL injection and data access patterns"""
        try:
            queries = []
            injection_attempts = []
            
            for interaction in transcript:
                if interaction.get("type") in ["sql_query", "database_query"]:
                    content = interaction.get("content", "")
                    queries.append(content)
                    
                    # Check for SQL injection patterns
                    if self._detect_sql_injection(content):
                        injection_attempts.append({
                            "query": content,
                            "timestamp": interaction.get("timestamp"),
                            "injection_type": self._classify_sql_injection(content)
                        })
            
            return {
                "total_queries": len(queries),
                "injection_attempts": injection_attempts,
                "query_complexity": self._analyze_query_complexity(queries),
                "data_access_patterns": self._analyze_data_access_patterns(queries)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing database interactions: {e}")
            return {"error": str(e)}
    
    def calculate_sophistication_score(self, session_data: Dict[str, Any]) -> Tuple[float, str]:
        """Calculate attacker sophistication score and level"""
        try:
            score = 0.0
            factors = []
            
            transcript = session_data.get("transcript", [])
            metadata = session_data.get("metadata", {})
            
            # Factor 1: Command diversity and complexity (0-30 points)
            commands = [i.get("content", "") for i in transcript if i.get("type") == "command"]
            unique_commands = len(set(commands))
            if unique_commands > 20:
                score += 30
                factors.append("High command diversity")
            elif unique_commands > 10:
                score += 20
                factors.append("Moderate command diversity")
            elif unique_commands > 5:
                score += 10
                factors.append("Basic command diversity")
            
            # Factor 2: Advanced techniques usage (0-25 points)
            advanced_techniques = ["privilege_escalation", "persistence", "defense_evasion"]
            technique_count = sum(1 for cmd in commands if any(tech in cmd.lower() for tech in advanced_techniques))
            if technique_count > 5:
                score += 25
                factors.append("Advanced technique usage")
            elif technique_count > 2:
                score += 15
                factors.append("Some advanced techniques")
            
            # Factor 3: Error handling and adaptation (0-20 points)
            error_responses = [i for i in transcript if "error" in i.get("content", "").lower()]
            if len(error_responses) > 0:
                # Check if attacker adapted after errors
                adaptation_score = self._analyze_error_adaptation(transcript, error_responses)
                score += adaptation_score
                if adaptation_score > 15:
                    factors.append("Good error adaptation")
                elif adaptation_score > 5:
                    factors.append("Some error adaptation")
            
            # Factor 4: Session duration and persistence (0-15 points)
            duration = metadata.get("duration_seconds", 0)
            if duration > 3600:  # > 1 hour
                score += 15
                factors.append("Extended session duration")
            elif duration > 1800:  # > 30 minutes
                score += 10
                factors.append("Moderate session duration")
            elif duration > 600:  # > 10 minutes
                score += 5
                factors.append("Brief session duration")
            
            # Factor 5: Tool usage and automation (0-10 points)
            automation_indicators = ["wget", "curl", "nc", "nmap", "sqlmap"]
            tool_usage = sum(1 for cmd in commands if any(tool in cmd.lower() for tool in automation_indicators))
            if tool_usage > 3:
                score += 10
                factors.append("Multiple tool usage")
            elif tool_usage > 1:
                score += 5
                factors.append("Some tool usage")
            
            # Determine sophistication level
            if score >= 80:
                level = "Advanced"
            elif score >= 50:
                level = "Intermediate"
            elif score >= 25:
                level = "Novice"
            else:
                level = "Script Kiddie"
            
            return score / 100.0, level  # Normalize to 0-1 scale
            
        except Exception as e:
            self.logger.error(f"Error calculating sophistication score: {e}")
            return 0.5, "Unknown"
    
    def extract_indicators_of_compromise(self, session_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators of compromise from session data"""
        try:
            iocs = []
            transcript = session_data.get("transcript", [])
            metadata = session_data.get("metadata", {})
            
            # Extract IP addresses
            source_ip = metadata.get("source_ip")
            if source_ip and source_ip != "127.0.0.1":
                iocs.append({
                    "type": "ip_address",
                    "value": source_ip,
                    "confidence": 0.9,
                    "context": "Source IP of attacker session"
                })
            
            # Extract URLs and domains from commands
            for interaction in transcript:
                content = interaction.get("content", "")
                
                # Extract URLs
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                urls = re.findall(url_pattern, content)
                for url in urls:
                    iocs.append({
                        "type": "url",
                        "value": url,
                        "confidence": 0.8,
                        "context": f"URL found in command: {content[:50]}..."
                    })
                
                # Extract file hashes (MD5, SHA1, SHA256)
                hash_patterns = {
                    "md5": r'\b[a-fA-F0-9]{32}\b',
                    "sha1": r'\b[a-fA-F0-9]{40}\b',
                    "sha256": r'\b[a-fA-F0-9]{64}\b'
                }
                
                for hash_type, pattern in hash_patterns.items():
                    hashes = re.findall(pattern, content)
                    for hash_value in hashes:
                        iocs.append({
                            "type": f"file_hash_{hash_type}",
                            "value": hash_value,
                            "confidence": 0.9,
                            "context": f"Hash found in command: {content[:50]}..."
                        })
                
                # Extract email addresses
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, content)
                for email in emails:
                    iocs.append({
                        "type": "email_address",
                        "value": email,
                        "confidence": 0.7,
                        "context": f"Email found in command: {content[:50]}..."
                    })
            
            return iocs
            
        except Exception as e:
            self.logger.error(f"Error extracting IOCs: {e}")
            return []
    
    # Helper methods
    def _map_command_to_mitre(self, command: str) -> Optional[Dict[str, Any]]:
        """Map command to MITRE ATT&CK technique"""
        command_lower = command.lower().strip()
        
        for pattern, technique in self.mitre_mappings.items():
            if pattern in command_lower:
                return {
                    "mitre_id": technique["id"],
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "command": command,
                    "confidence": 0.8
                }
        
        return None
    
    def _analyze_command_patterns(self, commands: List[str]) -> List[Dict[str, Any]]:
        """Analyze patterns in command usage"""
        patterns = []
        
        # Sequential pattern analysis
        if len(commands) >= 3:
            # Look for reconnaissance sequences
            recon_commands = ["whoami", "id", "uname", "ps", "netstat", "ls"]
            recon_count = sum(1 for cmd in commands[:5] if any(recon in cmd.lower() for recon in recon_commands))
            
            if recon_count >= 3:
                patterns.append({
                    "name": "Systematic Reconnaissance",
                    "description": "Sequential execution of reconnaissance commands",
                    "confidence": 0.8,
                    "evidence": commands[:5]
                })
        
        # Privilege escalation attempts
        priv_esc_commands = ["sudo", "su", "chmod +s", "setuid"]
        priv_esc_count = sum(1 for cmd in commands if any(pe in cmd.lower() for pe in priv_esc_commands))
        
        if priv_esc_count > 0:
            patterns.append({
                "name": "Privilege Escalation Attempts",
                "description": f"Found {priv_esc_count} privilege escalation attempts",
                "confidence": 0.9,
                "evidence": [cmd for cmd in commands if any(pe in cmd.lower() for pe in priv_esc_commands)]
            })
        
        return patterns
    
    def _detect_attack_phases(self, commands: List[str], techniques: List[Dict[str, Any]]) -> List[str]:
        """Detect attack phases based on commands and techniques"""
        phases = []
        
        # Group techniques by tactic
        tactics = {}
        for technique in techniques:
            tactic = technique.get("tactic", "Unknown")
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(technique)
        
        # Map tactics to attack phases
        if "Discovery" in tactics:
            phases.append("Reconnaissance")
        if "Initial Access" in tactics:
            phases.append("Initial Access")
        if "Execution" in tactics:
            phases.append("Execution")
        if "Persistence" in tactics:
            phases.append("Persistence")
        if "Privilege Escalation" in tactics:
            phases.append("Privilege Escalation")
        if "Defense Evasion" in tactics:
            phases.append("Defense Evasion")
        if "Credential Access" in tactics:
            phases.append("Credential Access")
        if "Lateral Movement" in tactics:
            phases.append("Lateral Movement")
        if "Collection" in tactics:
            phases.append("Collection")
        if "Exfiltration" in tactics:
            phases.append("Exfiltration")
        
        return phases
    
    def _detect_web_attack_patterns(self, request_content: str) -> List[Dict[str, Any]]:
        """Detect web attack patterns in HTTP requests"""
        patterns = []
        
        for attack_type, pattern_list in self.suspicious_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, request_content, re.IGNORECASE):
                    patterns.append({
                        "attack_type": attack_type,
                        "pattern": pattern,
                        "confidence": 0.8,
                        "evidence": request_content
                    })
        
        return patterns
    
    def _analyze_request_patterns(self, requests: List[str]) -> Dict[str, Any]:
        """Analyze HTTP request patterns"""
        analysis = {
            "total_requests": len(requests),
            "unique_paths": set(),
            "methods": Counter(),
            "suspicious_requests": 0
        }
        
        for request in requests:
            # Extract HTTP method and path (simplified)
            parts = request.split()
            if len(parts) >= 2:
                method = parts[0]
                path = parts[1]
                analysis["methods"][method] += 1
                analysis["unique_paths"].add(path)
            
            # Check for suspicious content
            if any(re.search(pattern, request, re.IGNORECASE) 
                  for pattern_list in self.suspicious_patterns.values() 
                  for pattern in pattern_list):
                analysis["suspicious_requests"] += 1
        
        analysis["unique_paths"] = len(analysis["unique_paths"])
        return analysis
    
    def _extract_suspicious_parameters(self, requests: List[str]) -> List[Dict[str, Any]]:
        """Extract suspicious parameters from HTTP requests"""
        suspicious_params = []
        
        for request in requests:
            # Look for common injection parameters
            injection_params = ["id", "user", "page", "file", "cmd", "exec"]
            
            for param in injection_params:
                if f"{param}=" in request.lower():
                    # Extract parameter value
                    match = re.search(f"{param}=([^&\\s]+)", request, re.IGNORECASE)
                    if match:
                        value = match.group(1)
                        suspicious_params.append({
                            "parameter": param,
                            "value": value,
                            "request": request[:100] + "..." if len(request) > 100 else request
                        })
        
        return suspicious_params
    
    def _detect_sql_injection(self, query: str) -> bool:
        """Detect SQL injection patterns in database queries"""
        sql_injection_patterns = self.suspicious_patterns["sql_injection"]
        
        return any(re.search(pattern, query, re.IGNORECASE) for pattern in sql_injection_patterns)
    
    def _classify_sql_injection(self, query: str) -> str:
        """Classify the type of SQL injection"""
        query_lower = query.lower()
        
        if "union" in query_lower and "select" in query_lower:
            return "Union-based"
        elif "or" in query_lower and ("1=1" in query_lower or "true" in query_lower):
            return "Boolean-based"
        elif "sleep(" in query_lower or "waitfor" in query_lower:
            return "Time-based"
        elif "error" in query_lower or "convert" in query_lower:
            return "Error-based"
        else:
            return "Generic"
    
    def _analyze_query_complexity(self, queries: List[str]) -> Dict[str, Any]:
        """Analyze the complexity of SQL queries"""
        if not queries:
            return {"average_length": 0, "complex_queries": 0}
        
        total_length = sum(len(query) for query in queries)
        average_length = total_length / len(queries)
        
        # Count complex queries (joins, subqueries, etc.)
        complex_count = 0
        for query in queries:
            query_lower = query.lower()
            if any(keyword in query_lower for keyword in ["join", "union", "subquery", "exists"]):
                complex_count += 1
        
        return {
            "average_length": average_length,
            "complex_queries": complex_count,
            "total_queries": len(queries)
        }
    
    def _analyze_data_access_patterns(self, queries: List[str]) -> Dict[str, Any]:
        """Analyze data access patterns in SQL queries"""
        patterns = {
            "select_queries": 0,
            "insert_queries": 0,
            "update_queries": 0,
            "delete_queries": 0,
            "tables_accessed": set()
        }
        
        for query in queries:
            query_lower = query.lower()
            
            if query_lower.startswith("select"):
                patterns["select_queries"] += 1
            elif query_lower.startswith("insert"):
                patterns["insert_queries"] += 1
            elif query_lower.startswith("update"):
                patterns["update_queries"] += 1
            elif query_lower.startswith("delete"):
                patterns["delete_queries"] += 1
            
            # Extract table names (simplified)
            table_match = re.search(r"from\s+(\w+)", query_lower)
            if table_match:
                patterns["tables_accessed"].add(table_match.group(1))
        
        patterns["tables_accessed"] = len(patterns["tables_accessed"])
        return patterns
    
    def _analyze_error_adaptation(self, transcript: List[Dict[str, Any]], 
                                error_responses: List[Dict[str, Any]]) -> int:
        """Analyze how well the attacker adapted to errors"""
        adaptation_score = 0
        
        for i, error_response in enumerate(error_responses):
            error_time = error_response.get("timestamp")
            
            # Look for subsequent commands that might indicate adaptation
            subsequent_commands = []
            for interaction in transcript:
                if (interaction.get("timestamp", "") > error_time and 
                    interaction.get("type") == "command"):
                    subsequent_commands.append(interaction)
                    if len(subsequent_commands) >= 3:  # Look at next 3 commands
                        break
            
            # Check if subsequent commands show adaptation
            if len(subsequent_commands) > 0:
                # Simple heuristic: different commands after error indicate adaptation
                error_command = error_response.get("content", "")
                adapted = any(cmd.get("content", "") != error_command 
                            for cmd in subsequent_commands)
                if adapted:
                    adaptation_score += 5
        
        return min(adaptation_score, 20)  # Cap at 20 points