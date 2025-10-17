"""
Intelligence Validation and Verification Tools
Validates the accuracy and quality of intelligence extracted by the AI agents
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import difflib

logger = logging.getLogger(__name__)

class ValidationResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"

@dataclass
class IntelligenceReport:
    report_id: str
    session_id: str
    timestamp: datetime
    mitre_techniques: List[str]
    iocs: List[Dict[str, Any]]
    threat_assessment: str
    confidence_score: float
    raw_session_data: Dict[str, Any]
    extracted_commands: List[str] = field(default_factory=list)
    extracted_credentials: List[Dict[str, str]] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)

@dataclass
class ValidationTest:
    test_name: str
    description: str
    test_function: str
    expected_result: ValidationResult
    weight: float = 1.0
    category: str = "general"

@dataclass
class ValidationReport:
    report_id: str
    timestamp: datetime
    intelligence_report: IntelligenceReport
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    overall_score: float = 0.0
    passed_tests: int = 0
    failed_tests: int = 0
    warning_tests: int = 0
    recommendations: List[str] = field(default_factory=list)

class IntelligenceValidator:
    """Validates intelligence reports for accuracy and completeness"""
    
    def __init__(self):
        self.validation_tests = self._create_validation_tests()
        self.mitre_techniques_db = self._load_mitre_techniques()
        self.known_malware_signatures = self._load_malware_signatures()
        self.common_attack_patterns = self._load_attack_patterns()
        
    def _create_validation_tests(self) -> List[ValidationTest]:
        """Create validation test suite"""
        return [
            # MITRE ATT&CK Validation Tests
            ValidationTest(
                test_name="mitre_technique_format",
                description="Validate MITRE technique format (T####)",
                test_function="validate_mitre_format",
                expected_result=ValidationResult.PASS,
                weight=1.0,
                category="mitre"
            ),
            
            ValidationTest(
                test_name="mitre_technique_existence",
                description="Verify MITRE techniques exist in framework",
                test_function="validate_mitre_existence",
                expected_result=ValidationResult.PASS,
                weight=2.0,
                category="mitre"
            ),
            
            ValidationTest(
                test_name="mitre_technique_relevance",
                description="Check if MITRE techniques match observed behavior",
                test_function="validate_mitre_relevance",
                expected_result=ValidationResult.PASS,
                weight=3.0,
                category="mitre"
            ),
            
            # IOC Validation Tests
            ValidationTest(
                test_name="ioc_format_validation",
                description="Validate IOC formats (IP, hash, URL, etc.)",
                test_function="validate_ioc_formats",
                expected_result=ValidationResult.PASS,
                weight=2.0,
                category="ioc"
            ),
            
            ValidationTest(
                test_name="ioc_uniqueness",
                description="Check for duplicate IOCs",
                test_function="validate_ioc_uniqueness",
                expected_result=ValidationResult.PASS,
                weight=1.0,
                category="ioc"
            ),
            
            ValidationTest(
                test_name="ioc_context_relevance",
                description="Verify IOCs are relevant to session context",
                test_function="validate_ioc_context",
                expected_result=ValidationResult.PASS,
                weight=2.5,
                category="ioc"
            ),
            
            # Confidence Score Tests
            ValidationTest(
                test_name="confidence_score_range",
                description="Validate confidence score is between 0.0 and 1.0",
                test_function="validate_confidence_range",
                expected_result=ValidationResult.PASS,
                weight=1.0,
                category="confidence"
            ),
            
            ValidationTest(
                test_name="confidence_score_justification",
                description="Check if confidence score matches evidence quality",
                test_function="validate_confidence_justification",
                expected_result=ValidationResult.PASS,
                weight=2.0,
                category="confidence"
            ),
            
            # Content Quality Tests
            ValidationTest(
                test_name="threat_assessment_quality",
                description="Validate threat assessment content quality",
                test_function="validate_threat_assessment",
                expected_result=ValidationResult.PASS,
                weight=2.0,
                category="content"
            ),
            
            ValidationTest(
                test_name="command_extraction_accuracy",
                description="Verify accuracy of extracted commands",
                test_function="validate_command_extraction",
                expected_result=ValidationResult.PASS,
                weight=2.5,
                category="extraction"
            ),
            
            ValidationTest(
                test_name="credential_extraction_accuracy",
                description="Verify accuracy of extracted credentials",
                test_function="validate_credential_extraction",
                expected_result=ValidationResult.PASS,
                weight=3.0,
                category="extraction"
            ),
            
            # Completeness Tests
            ValidationTest(
                test_name="report_completeness",
                description="Check if all required fields are present",
                test_function="validate_report_completeness",
                expected_result=ValidationResult.PASS,
                weight=1.5,
                category="completeness"
            ),
            
            ValidationTest(
                test_name="timeline_consistency",
                description="Verify timeline consistency in report",
                test_function="validate_timeline_consistency",
                expected_result=ValidationResult.PASS,
                weight=1.5,
                category="consistency"
            )
        ]
    
    def _load_mitre_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK techniques database"""
        # Simplified MITRE techniques for validation
        return {
            "T1110": {
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access",
                "tactics": ["credential-access"],
                "platforms": ["Linux", "Windows", "macOS"],
                "keywords": ["brute", "force", "password", "login", "authentication"]
            },
            "T1078": {
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts",
                "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                "platforms": ["Linux", "Windows", "macOS", "SaaS", "IaaS", "Network"],
                "keywords": ["account", "credential", "login", "user", "valid"]
            },
            "T1021": {
                "name": "Remote Services",
                "description": "Adversaries may use valid accounts to log into a service",
                "tactics": ["lateral-movement"],
                "platforms": ["Linux", "Windows", "macOS"],
                "keywords": ["remote", "ssh", "rdp", "service", "lateral"]
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to take advantage of a weakness",
                "tactics": ["initial-access"],
                "platforms": ["Linux", "Windows", "macOS", "Network"],
                "keywords": ["exploit", "vulnerability", "web", "application", "public"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters",
                "tactics": ["execution"],
                "platforms": ["Linux", "Windows", "macOS"],
                "keywords": ["command", "script", "shell", "interpreter", "execution"]
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols",
                "tactics": ["command-and-control"],
                "platforms": ["Linux", "Windows", "macOS"],
                "keywords": ["http", "https", "dns", "protocol", "communication"]
            },
            "T1595": {
                "name": "Active Scanning",
                "description": "Adversaries may execute active reconnaissance scans",
                "tactics": ["reconnaissance"],
                "platforms": ["PRE"],
                "keywords": ["scan", "reconnaissance", "probe", "discovery", "enumeration"]
            }
        }
    
    def _load_malware_signatures(self) -> Dict[str, List[str]]:
        """Load known malware signatures and patterns"""
        return {
            "command_patterns": [
                r"wget\s+http://.*\.sh",
                r"curl\s+.*\|\s*sh",
                r"nc\s+-e\s+/bin/sh",
                r"python\s+-c\s+.*socket",
                r"/bin/sh\s+-i",
                r"bash\s+-i",
                r"powershell\s+.*-enc",
                r"cmd\.exe\s+/c"
            ],
            "file_patterns": [
                r".*\.exe$",
                r".*\.bat$",
                r".*\.ps1$",
                r".*\.vbs$",
                r".*\.scr$",
                r".*\.pif$"
            ],
            "network_patterns": [
                r"\d+\.\d+\.\d+\.\d+:\d+",
                r"https?://[^\s]+",
                r"ftp://[^\s]+",
                r".*\.onion",
                r".*\.bit"
            ]
        }
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load common attack patterns"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "UNION SELECT",
                "DROP TABLE",
                "'; --",
                "admin'--"
            ],
            "xss": [
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "alert("
            ],
            "command_injection": [
                "; ls",
                "| whoami",
                "&& cat",
                "; nc",
                "| wget"
            ],
            "brute_force": [
                "admin:admin",
                "root:password",
                "user:user",
                "test:test",
                "guest:guest"
            ]
        }
    
    # Validation Test Functions
    
    def validate_mitre_format(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Validate MITRE technique format"""
        mitre_pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
        
        invalid_techniques = []
        for technique in report.mitre_techniques:
            if not mitre_pattern.match(technique):
                invalid_techniques.append(technique)
        
        if invalid_techniques:
            return ValidationResult.FAIL, f"Invalid MITRE format: {invalid_techniques}"
        
        return ValidationResult.PASS, "All MITRE techniques have valid format"
    
    def validate_mitre_existence(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Validate MITRE techniques exist in framework"""
        unknown_techniques = []
        
        for technique in report.mitre_techniques:
            base_technique = technique.split('.')[0]  # Remove sub-technique
            if base_technique not in self.mitre_techniques_db:
                unknown_techniques.append(technique)
        
        if unknown_techniques:
            return ValidationResult.FAIL, f"Unknown MITRE techniques: {unknown_techniques}"
        
        return ValidationResult.PASS, "All MITRE techniques exist in framework"
    
    def validate_mitre_relevance(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Check if MITRE techniques match observed behavior"""
        session_text = json.dumps(report.raw_session_data).lower()
        
        relevant_count = 0
        total_count = len(report.mitre_techniques)
        
        for technique in report.mitre_techniques:
            base_technique = technique.split('.')[0]
            technique_info = self.mitre_techniques_db.get(base_technique, {})
            keywords = technique_info.get("keywords", [])
            
            # Check if any keywords appear in session data
            if any(keyword in session_text for keyword in keywords):
                relevant_count += 1
        
        relevance_ratio = relevant_count / total_count if total_count > 0 else 0
        
        if relevance_ratio >= 0.8:
            return ValidationResult.PASS, f"High relevance: {relevance_ratio:.2f}"
        elif relevance_ratio >= 0.5:
            return ValidationResult.WARNING, f"Medium relevance: {relevance_ratio:.2f}"
        else:
            return ValidationResult.FAIL, f"Low relevance: {relevance_ratio:.2f}"
    
    def validate_ioc_formats(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Validate IOC formats"""
        format_patterns = {
            "ip": re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'),
            "domain": re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'),
            "url": re.compile(r'^https?://[^\s]+$'),
            "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
            "sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
            "sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
            "email": re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
        }
        
        invalid_iocs = []
        
        for ioc in report.iocs:
            ioc_type = ioc.get("type", "").lower()
            ioc_value = ioc.get("value", "")
            
            if ioc_type in format_patterns:
                if not format_patterns[ioc_type].match(ioc_value):
                    invalid_iocs.append(f"{ioc_type}: {ioc_value}")
        
        if invalid_iocs:
            return ValidationResult.FAIL, f"Invalid IOC formats: {invalid_iocs}"
        
        return ValidationResult.PASS, "All IOCs have valid formats"
    
    def validate_ioc_uniqueness(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Check for duplicate IOCs"""
        seen_iocs = set()
        duplicates = []
        
        for ioc in report.iocs:
            ioc_key = f"{ioc.get('type', '')}:{ioc.get('value', '')}"
            if ioc_key in seen_iocs:
                duplicates.append(ioc_key)
            else:
                seen_iocs.add(ioc_key)
        
        if duplicates:
            return ValidationResult.WARNING, f"Duplicate IOCs found: {duplicates}"
        
        return ValidationResult.PASS, "No duplicate IOCs found"
    
    def validate_ioc_context(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Verify IOCs are relevant to session context"""
        session_text = json.dumps(report.raw_session_data).lower()
        
        relevant_iocs = 0
        total_iocs = len(report.iocs)
        
        for ioc in report.iocs:
            ioc_value = ioc.get("value", "").lower()
            
            # Check if IOC appears in session data
            if ioc_value in session_text:
                relevant_iocs += 1
        
        relevance_ratio = relevant_iocs / total_iocs if total_iocs > 0 else 1
        
        if relevance_ratio >= 0.7:
            return ValidationResult.PASS, f"High IOC relevance: {relevance_ratio:.2f}"
        elif relevance_ratio >= 0.4:
            return ValidationResult.WARNING, f"Medium IOC relevance: {relevance_ratio:.2f}"
        else:
            return ValidationResult.FAIL, f"Low IOC relevance: {relevance_ratio:.2f}"
    
    def validate_confidence_range(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Validate confidence score range"""
        if not (0.0 <= report.confidence_score <= 1.0):
            return ValidationResult.FAIL, f"Confidence score {report.confidence_score} out of range [0.0, 1.0]"
        
        return ValidationResult.PASS, f"Confidence score {report.confidence_score} in valid range"
    
    def validate_confidence_justification(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Check if confidence score matches evidence quality"""
        evidence_score = 0.0
        
        # Score based on number and quality of IOCs
        if report.iocs:
            evidence_score += min(len(report.iocs) * 0.1, 0.3)
        
        # Score based on MITRE techniques
        if report.mitre_techniques:
            evidence_score += min(len(report.mitre_techniques) * 0.15, 0.4)
        
        # Score based on extracted commands
        if report.extracted_commands:
            evidence_score += min(len(report.extracted_commands) * 0.05, 0.2)
        
        # Score based on threat assessment quality
        if len(report.threat_assessment) > 100:
            evidence_score += 0.1
        
        # Compare with reported confidence
        confidence_diff = abs(report.confidence_score - evidence_score)
        
        if confidence_diff <= 0.2:
            return ValidationResult.PASS, f"Confidence justified (diff: {confidence_diff:.2f})"
        elif confidence_diff <= 0.4:
            return ValidationResult.WARNING, f"Confidence questionable (diff: {confidence_diff:.2f})"
        else:
            return ValidationResult.FAIL, f"Confidence unjustified (diff: {confidence_diff:.2f})"
    
    def validate_threat_assessment(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Validate threat assessment content quality"""
        assessment = report.threat_assessment
        
        if len(assessment) < 50:
            return ValidationResult.FAIL, "Threat assessment too short"
        
        # Check for key elements
        key_elements = ["attack", "threat", "technique", "impact", "recommendation"]
        found_elements = sum(1 for element in key_elements if element.lower() in assessment.lower())
        
        if found_elements >= 3:
            return ValidationResult.PASS, f"Good threat assessment ({found_elements}/5 key elements)"
        elif found_elements >= 2:
            return ValidationResult.WARNING, f"Basic threat assessment ({found_elements}/5 key elements)"
        else:
            return ValidationResult.FAIL, f"Poor threat assessment ({found_elements}/5 key elements)"
    
    def validate_command_extraction(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Verify accuracy of extracted commands"""
        session_text = json.dumps(report.raw_session_data)
        
        # Look for command patterns in session data
        command_patterns = [
            r'command["\']?\s*:\s*["\']([^"\']+)["\']',
            r'cmd["\']?\s*:\s*["\']([^"\']+)["\']',
            r'executed["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        found_commands = set()
        for pattern in command_patterns:
            matches = re.findall(pattern, session_text, re.IGNORECASE)
            found_commands.update(matches)
        
        extracted_commands = set(report.extracted_commands)
        
        if not found_commands and not extracted_commands:
            return ValidationResult.PASS, "No commands to extract"
        
        if not found_commands:
            return ValidationResult.WARNING, "Commands extracted but none found in session"
        
        # Calculate accuracy
        correct_extractions = len(extracted_commands.intersection(found_commands))
        total_found = len(found_commands)
        
        accuracy = correct_extractions / total_found if total_found > 0 else 0
        
        if accuracy >= 0.8:
            return ValidationResult.PASS, f"High command extraction accuracy: {accuracy:.2f}"
        elif accuracy >= 0.5:
            return ValidationResult.WARNING, f"Medium command extraction accuracy: {accuracy:.2f}"
        else:
            return ValidationResult.FAIL, f"Low command extraction accuracy: {accuracy:.2f}"
    
    def validate_credential_extraction(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Verify accuracy of extracted credentials"""
        session_text = json.dumps(report.raw_session_data)
        
        # Look for credential patterns
        credential_patterns = [
            r'username["\']?\s*:\s*["\']([^"\']+)["\']',
            r'password["\']?\s*:\s*["\']([^"\']+)["\']',
            r'user["\']?\s*:\s*["\']([^"\']+)["\']',
            r'pass["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        found_credentials = set()
        for pattern in credential_patterns:
            matches = re.findall(pattern, session_text, re.IGNORECASE)
            found_credentials.update(matches)
        
        extracted_creds = set()
        for cred in report.extracted_credentials:
            extracted_creds.add(cred.get("username", ""))
            extracted_creds.add(cred.get("password", ""))
        
        extracted_creds.discard("")  # Remove empty strings
        
        if not found_credentials and not extracted_creds:
            return ValidationResult.PASS, "No credentials to extract"
        
        if not found_credentials:
            return ValidationResult.WARNING, "Credentials extracted but none found in session"
        
        # Calculate accuracy
        correct_extractions = len(extracted_creds.intersection(found_credentials))
        total_found = len(found_credentials)
        
        accuracy = correct_extractions / total_found if total_found > 0 else 0
        
        if accuracy >= 0.8:
            return ValidationResult.PASS, f"High credential extraction accuracy: {accuracy:.2f}"
        elif accuracy >= 0.5:
            return ValidationResult.WARNING, f"Medium credential extraction accuracy: {accuracy:.2f}"
        else:
            return ValidationResult.FAIL, f"Low credential extraction accuracy: {accuracy:.2f}"
    
    def validate_report_completeness(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Check if all required fields are present"""
        required_fields = [
            "report_id", "session_id", "timestamp", "mitre_techniques",
            "iocs", "threat_assessment", "confidence_score"
        ]
        
        missing_fields = []
        for field in required_fields:
            if not hasattr(report, field) or getattr(report, field) is None:
                missing_fields.append(field)
        
        # Check for empty collections
        if hasattr(report, "mitre_techniques") and len(report.mitre_techniques) == 0:
            missing_fields.append("mitre_techniques (empty)")
        
        if hasattr(report, "iocs") and len(report.iocs) == 0:
            missing_fields.append("iocs (empty)")
        
        if missing_fields:
            return ValidationResult.FAIL, f"Missing required fields: {missing_fields}"
        
        return ValidationResult.PASS, "All required fields present"
    
    def validate_timeline_consistency(self, report: IntelligenceReport) -> Tuple[ValidationResult, str]:
        """Verify timeline consistency in report"""
        report_time = report.timestamp
        
        # Check if report timestamp is reasonable (not too far in future/past)
        now = datetime.utcnow()
        time_diff = abs((report_time - now).total_seconds())
        
        if time_diff > 86400:  # More than 24 hours
            return ValidationResult.WARNING, f"Report timestamp unusual: {time_diff/3600:.1f} hours from now"
        
        # Check IOC timestamps if available
        for ioc in report.iocs:
            if "timestamp" in ioc:
                try:
                    ioc_time = datetime.fromisoformat(ioc["timestamp"].replace("Z", "+00:00"))
                    if ioc_time > report_time:
                        return ValidationResult.FAIL, "IOC timestamp after report timestamp"
                except Exception:
                    pass  # Skip invalid timestamps
        
        return ValidationResult.PASS, "Timeline consistency validated"
    
    # Main validation methods
    
    async def validate_report(self, report: IntelligenceReport) -> ValidationReport:
        """Validate a complete intelligence report"""
        validation_report = ValidationReport(
            report_id=f"validation-{report.report_id}",
            timestamp=datetime.utcnow(),
            intelligence_report=report
        )
        
        total_weight = 0.0
        weighted_score = 0.0
        
        for test in self.validation_tests:
            try:
                # Get validation function
                test_func = getattr(self, test.test_function)
                
                # Run validation test
                result, message = test_func(report)
                
                # Calculate score for this test
                if result == ValidationResult.PASS:
                    test_score = 1.0
                    validation_report.passed_tests += 1
                elif result == ValidationResult.WARNING:
                    test_score = 0.5
                    validation_report.warning_tests += 1
                elif result == ValidationResult.FAIL:
                    test_score = 0.0
                    validation_report.failed_tests += 1
                else:  # UNKNOWN
                    test_score = 0.0
                
                # Add to weighted score
                weighted_score += test_score * test.weight
                total_weight += test.weight
                
                # Record test result
                test_result = {
                    "test_name": test.test_name,
                    "description": test.description,
                    "category": test.category,
                    "result": result.value,
                    "message": message,
                    "weight": test.weight,
                    "score": test_score
                }
                
                validation_report.test_results.append(test_result)
                
            except Exception as e:
                logger.error(f"Validation test {test.test_name} failed: {e}")
                
                # Record error
                test_result = {
                    "test_name": test.test_name,
                    "description": test.description,
                    "category": test.category,
                    "result": ValidationResult.FAIL.value,
                    "message": f"Test error: {str(e)}",
                    "weight": test.weight,
                    "score": 0.0
                }
                
                validation_report.test_results.append(test_result)
                validation_report.failed_tests += 1
                total_weight += test.weight
        
        # Calculate overall score
        validation_report.overall_score = weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Generate recommendations
        validation_report.recommendations = self._generate_recommendations(validation_report)
        
        return validation_report
    
    def _generate_recommendations(self, validation_report: ValidationReport) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        # Analyze failed tests by category
        failed_by_category = {}
        for test_result in validation_report.test_results:
            if test_result["result"] == ValidationResult.FAIL.value:
                category = test_result["category"]
                if category not in failed_by_category:
                    failed_by_category[category] = []
                failed_by_category[category].append(test_result)
        
        # Generate category-specific recommendations
        if "mitre" in failed_by_category:
            recommendations.append("Improve MITRE ATT&CK technique mapping accuracy")
            recommendations.append("Validate MITRE techniques against framework database")
        
        if "ioc" in failed_by_category:
            recommendations.append("Enhance IOC extraction and validation")
            recommendations.append("Improve IOC format validation")
        
        if "confidence" in failed_by_category:
            recommendations.append("Calibrate confidence scoring algorithm")
            recommendations.append("Align confidence scores with evidence quality")
        
        if "extraction" in failed_by_category:
            recommendations.append("Improve command and credential extraction accuracy")
            recommendations.append("Enhance pattern matching for data extraction")
        
        if "content" in failed_by_category:
            recommendations.append("Improve threat assessment content quality")
            recommendations.append("Include more detailed analysis and recommendations")
        
        # Overall score recommendations
        if validation_report.overall_score < 0.6:
            recommendations.append("Overall intelligence quality needs significant improvement")
        elif validation_report.overall_score < 0.8:
            recommendations.append("Intelligence quality is acceptable but could be enhanced")
        
        return recommendations
    
    def export_validation_report(self, validation_report: ValidationReport,
                               filename: str = None) -> str:
        """Export validation report to JSON"""
        if not filename:
            filename = f"validation_report_{validation_report.report_id}.json"
        
        # Convert to serializable format
        report_data = {
            "report_id": validation_report.report_id,
            "timestamp": validation_report.timestamp.isoformat(),
            "intelligence_report_id": validation_report.intelligence_report.report_id,
            "overall_score": validation_report.overall_score,
            "passed_tests": validation_report.passed_tests,
            "failed_tests": validation_report.failed_tests,
            "warning_tests": validation_report.warning_tests,
            "test_results": validation_report.test_results,
            "recommendations": validation_report.recommendations
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Exported validation report to {filename}")
        return filename
    
    def generate_validation_summary(self, validation_reports: List[ValidationReport]) -> str:
        """Generate a summary of multiple validation reports"""
        if not validation_reports:
            return "No validation reports to summarize"
        
        summary = []
        summary.append("Intelligence Validation Summary")
        summary.append("=" * 40)
        summary.append(f"Reports analyzed: {len(validation_reports)}")
        summary.append("")
        
        # Calculate aggregate statistics
        total_score = sum(report.overall_score for report in validation_reports)
        avg_score = total_score / len(validation_reports)
        
        total_passed = sum(report.passed_tests for report in validation_reports)
        total_failed = sum(report.failed_tests for report in validation_reports)
        total_warnings = sum(report.warning_tests for report in validation_reports)
        total_tests = total_passed + total_failed + total_warnings
        
        summary.append(f"Average Score: {avg_score:.3f}")
        summary.append(f"Pass Rate: {(total_passed / total_tests * 100):.1f}%")
        summary.append(f"Fail Rate: {(total_failed / total_tests * 100):.1f}%")
        summary.append(f"Warning Rate: {(total_warnings / total_tests * 100):.1f}%")
        summary.append("")
        
        # Category analysis
        category_stats = {}
        for report in validation_reports:
            for test_result in report.test_results:
                category = test_result["category"]
                if category not in category_stats:
                    category_stats[category] = {"pass": 0, "fail": 0, "warning": 0}
                
                result = test_result["result"]
                if result == ValidationResult.PASS.value:
                    category_stats[category]["pass"] += 1
                elif result == ValidationResult.FAIL.value:
                    category_stats[category]["fail"] += 1
                elif result == ValidationResult.WARNING.value:
                    category_stats[category]["warning"] += 1
        
        summary.append("Category Performance:")
        for category, stats in category_stats.items():
            total_cat = sum(stats.values())
            pass_rate = (stats["pass"] / total_cat * 100) if total_cat > 0 else 0
            summary.append(f"  {category}: {pass_rate:.1f}% pass rate")
        
        summary.append("")
        
        # Common recommendations
        all_recommendations = []
        for report in validation_reports:
            all_recommendations.extend(report.recommendations)
        
        # Count recommendation frequency
        rec_counts = {}
        for rec in all_recommendations:
            rec_counts[rec] = rec_counts.get(rec, 0) + 1
        
        # Sort by frequency
        common_recs = sorted(rec_counts.items(), key=lambda x: x[1], reverse=True)
        
        summary.append("Most Common Recommendations:")
        for rec, count in common_recs[:5]:
            summary.append(f"  {rec} ({count} reports)")
        
        return "\n".join(summary)

# Convenience functions for testing
async def validate_sample_report():
    """Validate a sample intelligence report"""
    # Create sample report
    sample_report = IntelligenceReport(
        report_id="sample-001",
        session_id="session-001",
        timestamp=datetime.utcnow(),
        mitre_techniques=["T1110", "T1078", "T1021"],
        iocs=[
            {"type": "ip", "value": "192.168.1.100"},
            {"type": "domain", "value": "malicious.com"},
            {"type": "md5", "value": "5d41402abc4b2a76b9719d911017c592"}
        ],
        threat_assessment="Brute force attack detected against SSH service. Attacker used common credentials and successfully gained access. Recommend implementing account lockout policies.",
        confidence_score=0.85,
        raw_session_data={
            "commands": ["whoami", "ls -la", "cat /etc/passwd"],
            "login_attempts": 25,
            "successful_login": True,
            "username": "admin",
            "password": "password"
        },
        extracted_commands=["whoami", "ls -la", "cat /etc/passwd"],
        extracted_credentials=[{"username": "admin", "password": "password"}]
    )
    
    # Validate report
    validator = IntelligenceValidator()
    validation_report = await validator.validate_report(sample_report)
    
    # Export results
    validator.export_validation_report(validation_report, "sample_validation.json")
    
    print(f"Validation Score: {validation_report.overall_score:.3f}")
    print(f"Passed: {validation_report.passed_tests}")
    print(f"Failed: {validation_report.failed_tests}")
    print(f"Warnings: {validation_report.warning_tests}")
    
    return validation_report

if __name__ == "__main__":
    # Example usage
    asyncio.run(validate_sample_report())