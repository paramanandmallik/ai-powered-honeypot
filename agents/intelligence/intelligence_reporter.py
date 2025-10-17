"""
Intelligence Reporting Module for Intelligence Agent
Provides structured report generation, automated intelligence summaries, 
trend analysis, and integration with external threat intelligence platforms.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from uuid import uuid4
import statistics


class IntelligenceReporter:
    """
    Intelligence reporting system for generating comprehensive threat intelligence reports.
    
    Capabilities:
    - Structured report generation
    - Automated intelligence summaries
    - Trend analysis and pattern detection
    - Integration with external threat intelligence platforms
    """
    
    def __init__(self):
        self.logger = logging.getLogger("intelligence_reporter")
        
        # Report templates and configurations
        self.report_templates = {
            "executive_summary": {
                "sections": ["overview", "key_findings", "threat_assessment", "recommendations"],
                "max_length": 2000,
                "audience": "executives"
            },
            "technical_analysis": {
                "sections": ["methodology", "detailed_findings", "mitre_analysis", "iocs", "technical_recommendations"],
                "max_length": 10000,
                "audience": "analysts"
            },
            "incident_response": {
                "sections": ["incident_overview", "timeline", "impact_assessment", "containment_actions", "lessons_learned"],
                "max_length": 5000,
                "audience": "incident_responders"
            },
            "threat_intelligence": {
                "sections": ["threat_landscape", "actor_analysis", "ttps", "indicators", "attribution"],
                "max_length": 8000,
                "audience": "threat_hunters"
            }
        }
        
        # Trend analysis configurations
        self.trend_config = {
            "min_data_points": 5,
            "trend_window_days": 30,
            "significance_threshold": 0.1,
            "correlation_threshold": 0.7
        }
        
        # External platform configurations (placeholders)
        self.external_platforms = {
            "misp": {"enabled": False, "api_key": None, "url": None},
            "opencti": {"enabled": False, "api_key": None, "url": None},
            "stix": {"enabled": True, "format_version": "2.1"},
            "taxii": {"enabled": False, "collections": []}
        }
        
        self.logger.info("Intelligence Reporter initialized with comprehensive reporting capabilities")
    
    def generate_structured_report(self, analysis_data: List[Dict[str, Any]], 
                                 report_type: str = "technical_analysis",
                                 time_range: str = "24h",
                                 custom_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate structured intelligence report based on analysis data.
        
        Args:
            analysis_data: List of completed analysis results
            report_type: Type of report to generate
            time_range: Time range for the report
            custom_config: Custom configuration overrides
            
        Returns:
            Structured intelligence report
        """
        try:
            # Get report template
            template = self.report_templates.get(report_type, self.report_templates["technical_analysis"])
            if custom_config:
                template.update(custom_config)
            
            # Filter data by time range
            filtered_data = self._filter_data_by_time_range(analysis_data, time_range)
            
            # Generate report sections
            report = {
                "report_metadata": {
                    "report_id": str(uuid4()),
                    "report_type": report_type,
                    "generated_at": datetime.utcnow().isoformat(),
                    "time_range": time_range,
                    "data_points": len(filtered_data),
                    "template_version": "1.0",
                    "audience": template.get("audience", "general")
                },
                "sections": {}
            }
            
            # Generate each section based on template
            for section in template.get("sections", []):
                report["sections"][section] = self._generate_report_section(section, filtered_data, template)
            
            # Add executive summary if not already included
            if "overview" not in report["sections"]:
                report["sections"]["overview"] = self._generate_overview_section(filtered_data)
            
            # Calculate report metrics
            report["metrics"] = self._calculate_report_metrics(filtered_data)
            
            # Add recommendations
            report["recommendations"] = self._generate_report_recommendations(filtered_data, report_type)
            
            self.logger.info(f"Generated {report_type} report with {len(report['sections'])} sections")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating structured report: {e}")
            return {"error": str(e)}
    
    def generate_automated_summary(self, analysis_data: List[Dict[str, Any]], 
                                 summary_type: str = "daily") -> Dict[str, Any]:
        """
        Generate automated intelligence summary.
        
        Args:
            analysis_data: Analysis data to summarize
            summary_type: Type of summary (daily, weekly, monthly)
            
        Returns:
            Automated intelligence summary
        """
        try:
            # Determine time range based on summary type
            time_ranges = {
                "daily": "24h",
                "weekly": "7d", 
                "monthly": "30d"
            }
            time_range = time_ranges.get(summary_type, "24h")
            
            # Filter data
            filtered_data = self._filter_data_by_time_range(analysis_data, time_range)
            
            if not filtered_data:
                return {
                    "summary_type": summary_type,
                    "time_range": time_range,
                    "message": "No data available for the specified time range",
                    "generated_at": datetime.utcnow().isoformat()
                }
            
            # Generate summary components
            summary = {
                "summary_metadata": {
                    "summary_id": str(uuid4()),
                    "summary_type": summary_type,
                    "time_range": time_range,
                    "generated_at": datetime.utcnow().isoformat(),
                    "data_points": len(filtered_data)
                },
                "key_statistics": self._generate_key_statistics(filtered_data),
                "threat_landscape": self._analyze_threat_landscape(filtered_data),
                "top_findings": self._extract_top_findings(filtered_data),
                "trend_indicators": self._identify_trend_indicators(filtered_data),
                "risk_assessment": self._assess_overall_risk(filtered_data),
                "actionable_insights": self._generate_actionable_insights(filtered_data)
            }
            
            # Add summary narrative
            summary["narrative"] = self._generate_summary_narrative(summary)
            
            self.logger.info(f"Generated {summary_type} automated summary")
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating automated summary: {e}")
            return {"error": str(e)}
    
    def analyze_trends(self, historical_data: List[Dict[str, Any]], 
                      analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Perform trend analysis on historical intelligence data.
        
        Args:
            historical_data: Historical analysis data
            analysis_type: Type of trend analysis to perform
            
        Returns:
            Trend analysis results
        """
        try:
            if len(historical_data) < self.trend_config["min_data_points"]:
                return {
                    "analysis_type": analysis_type,
                    "message": f"Insufficient data points for trend analysis (minimum: {self.trend_config['min_data_points']})",
                    "data_points": len(historical_data)
                }
            
            # Organize data by time periods
            time_series_data = self._organize_time_series_data(historical_data)
            
            # Perform different types of trend analysis
            trend_analysis = {
                "analysis_metadata": {
                    "analysis_id": str(uuid4()),
                    "analysis_type": analysis_type,
                    "generated_at": datetime.utcnow().isoformat(),
                    "data_points": len(historical_data),
                    "time_span_days": self._calculate_time_span(historical_data)
                },
                "volume_trends": self._analyze_volume_trends(time_series_data),
                "technique_trends": self._analyze_technique_trends(historical_data),
                "threat_actor_trends": self._analyze_threat_actor_trends(historical_data),
                "geographic_trends": self._analyze_geographic_trends(historical_data),
                "seasonal_patterns": self._identify_seasonal_patterns(time_series_data),
                "anomaly_detection": self._detect_anomalies(time_series_data),
                "correlation_analysis": self._perform_correlation_analysis(historical_data)
            }
            
            # Generate trend predictions
            trend_analysis["predictions"] = self._generate_trend_predictions(trend_analysis)
            
            # Identify significant trends
            trend_analysis["significant_trends"] = self._identify_significant_trends(trend_analysis)
            
            self.logger.info(f"Completed {analysis_type} trend analysis")
            
            return trend_analysis
            
        except Exception as e:
            self.logger.error(f"Error performing trend analysis: {e}")
            return {"error": str(e)}
    
    def integrate_with_external_platforms(self, intelligence_data: Dict[str, Any], 
                                        platforms: List[str] = None) -> Dict[str, Any]:
        """
        Integrate intelligence data with external threat intelligence platforms.
        
        Args:
            intelligence_data: Intelligence data to share/export
            platforms: List of platforms to integrate with
            
        Returns:
            Integration results
        """
        try:
            if platforms is None:
                platforms = [p for p, config in self.external_platforms.items() if config.get("enabled", False)]
            
            integration_results = {
                "integration_metadata": {
                    "integration_id": str(uuid4()),
                    "initiated_at": datetime.utcnow().isoformat(),
                    "platforms": platforms,
                    "data_size": len(str(intelligence_data))
                },
                "platform_results": {},
                "export_formats": {},
                "sharing_status": {}
            }
            
            # Process each platform
            for platform in platforms:
                if platform not in self.external_platforms:
                    integration_results["platform_results"][platform] = {
                        "status": "error",
                        "message": f"Platform {platform} not configured"
                    }
                    continue
                
                platform_config = self.external_platforms[platform]
                
                if platform == "stix":
                    result = self._export_to_stix(intelligence_data, platform_config)
                elif platform == "misp":
                    result = self._export_to_misp(intelligence_data, platform_config)
                elif platform == "opencti":
                    result = self._export_to_opencti(intelligence_data, platform_config)
                elif platform == "taxii":
                    result = self._export_to_taxii(intelligence_data, platform_config)
                else:
                    result = {"status": "error", "message": f"Platform {platform} not implemented"}
                
                integration_results["platform_results"][platform] = result
            
            # Generate sharing recommendations
            integration_results["sharing_recommendations"] = self._generate_sharing_recommendations(intelligence_data)
            
            self.logger.info(f"Completed integration with {len(platforms)} platforms")
            
            return integration_results
            
        except Exception as e:
            self.logger.error(f"Error integrating with external platforms: {e}")
            return {"error": str(e)}
    
    # Report section generators
    def _generate_report_section(self, section_name: str, data: List[Dict[str, Any]], 
                               template: Dict[str, Any]) -> Dict[str, Any]:
        """Generate specific report section"""
        try:
            if section_name == "overview":
                return self._generate_overview_section(data)
            elif section_name == "key_findings":
                return self._generate_key_findings_section(data)
            elif section_name == "threat_assessment":
                return self._generate_threat_assessment_section(data)
            elif section_name == "recommendations":
                return self._generate_recommendations_section(data)
            elif section_name == "methodology":
                return self._generate_methodology_section(data)
            elif section_name == "detailed_findings":
                return self._generate_detailed_findings_section(data)
            elif section_name == "mitre_analysis":
                return self._generate_mitre_analysis_section(data)
            elif section_name == "iocs":
                return self._generate_iocs_section(data)
            elif section_name == "technical_recommendations":
                return self._generate_technical_recommendations_section(data)
            elif section_name == "incident_overview":
                return self._generate_incident_overview_section(data)
            elif section_name == "timeline":
                return self._generate_timeline_section(data)
            elif section_name == "impact_assessment":
                return self._generate_impact_assessment_section(data)
            elif section_name == "containment_actions":
                return self._generate_containment_actions_section(data)
            elif section_name == "lessons_learned":
                return self._generate_lessons_learned_section(data)
            elif section_name == "threat_landscape":
                return self._generate_threat_landscape_section(data)
            elif section_name == "actor_analysis":
                return self._generate_actor_analysis_section(data)
            elif section_name == "ttps":
                return self._generate_ttps_section(data)
            elif section_name == "indicators":
                return self._generate_indicators_section(data)
            elif section_name == "attribution":
                return self._generate_attribution_section(data)
            else:
                return {"content": f"Section '{section_name}' not implemented", "generated_at": datetime.utcnow().isoformat()}
                
        except Exception as e:
            self.logger.error(f"Error generating section {section_name}: {e}")
            return {"error": str(e)}
    
    def _generate_overview_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overview section"""
        total_sessions = len(data)
        high_risk_sessions = len([d for d in data if d.get("result", {}).get("risk_assessment") == "High"])
        
        # Calculate time span
        if data:
            timestamps = [datetime.fromisoformat(d.get("start_time", "")) for d in data if d.get("start_time")]
            if timestamps:
                time_span = (max(timestamps) - min(timestamps)).days
            else:
                time_span = 0
        else:
            time_span = 0
        
        return {
            "summary": f"Analysis of {total_sessions} honeypot sessions over {time_span} days",
            "key_metrics": {
                "total_sessions": total_sessions,
                "high_risk_sessions": high_risk_sessions,
                "risk_percentage": (high_risk_sessions / total_sessions * 100) if total_sessions > 0 else 0,
                "analysis_period_days": time_span
            },
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _generate_key_findings_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate key findings section"""
        findings = []
        
        # Extract all findings from data
        all_findings = []
        for analysis in data:
            result = analysis.get("result", {})
            session_findings = result.get("findings", [])
            all_findings.extend(session_findings)
        
        # Group findings by type
        finding_types = Counter(f.get("type", "unknown") for f in all_findings)
        
        # Get high-confidence findings
        high_confidence_findings = [f for f in all_findings if f.get("confidence", 0) > 0.8]
        
        return {
            "total_findings": len(all_findings),
            "finding_types": dict(finding_types),
            "high_confidence_findings": len(high_confidence_findings),
            "top_findings": high_confidence_findings[:10],  # Top 10 high-confidence findings
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _generate_threat_assessment_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat assessment section"""
        # Analyze threat levels
        threat_levels = Counter()
        techniques_observed = []
        
        for analysis in data:
            result = analysis.get("result", {})
            risk_level = result.get("risk_assessment", "Unknown")
            threat_levels[risk_level] += 1
            
            techniques = result.get("techniques", [])
            techniques_observed.extend(techniques)
        
        # Calculate threat score
        total_sessions = len(data)
        high_threat_sessions = threat_levels.get("High", 0)
        threat_score = (high_threat_sessions / total_sessions * 100) if total_sessions > 0 else 0
        
        return {
            "overall_threat_level": "High" if threat_score > 30 else "Medium" if threat_score > 10 else "Low",
            "threat_score": threat_score,
            "threat_distribution": dict(threat_levels),
            "unique_techniques": len(set(t.get("technique_id", "") for t in techniques_observed)),
            "most_common_techniques": self._get_most_common_techniques(techniques_observed),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _generate_recommendations_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate recommendations section"""
        all_recommendations = []
        
        for analysis in data:
            result = analysis.get("result", {})
            recommendations = result.get("recommendations", [])
            all_recommendations.extend(recommendations)
        
        # Count and prioritize recommendations
        recommendation_counts = Counter(all_recommendations)
        
        return {
            "total_recommendations": len(all_recommendations),
            "unique_recommendations": len(recommendation_counts),
            "top_recommendations": dict(recommendation_counts.most_common(10)),
            "priority_actions": self._prioritize_recommendations(recommendation_counts),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    # Additional section generators would be implemented here...
    # For brevity, I'll implement a few key ones and provide placeholders for others
    
    def _generate_methodology_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate methodology section"""
        return {
            "analysis_approach": "AI-powered honeypot session analysis using MITRE ATT&CK framework",
            "data_sources": ["SSH honeypots", "Web application honeypots", "Database honeypots"],
            "analysis_techniques": ["Command sequence analysis", "Behavioral pattern recognition", "MITRE technique mapping"],
            "confidence_scoring": "Confidence scores range from 0-1 based on evidence strength and pattern matching",
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _generate_mitre_analysis_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate MITRE analysis section"""
        all_techniques = []
        
        for analysis in data:
            result = analysis.get("result", {})
            techniques = result.get("techniques", [])
            all_techniques.extend(techniques)
        
        # Analyze MITRE data
        tactic_distribution = Counter(t.get("tactic", "Unknown") for t in all_techniques)
        technique_frequency = Counter(t.get("technique_id", "Unknown") for t in all_techniques)
        
        return {
            "total_techniques_observed": len(all_techniques),
            "unique_techniques": len(technique_frequency),
            "tactic_distribution": dict(tactic_distribution),
            "most_frequent_techniques": dict(technique_frequency.most_common(10)),
            "kill_chain_coverage": self._calculate_kill_chain_coverage(all_techniques),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    # Detailed section generators
    def _generate_detailed_findings_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed findings analysis section"""
        try:
            all_findings = []
            for analysis in data:
                result = analysis.get("result", {})
                findings = result.get("findings", [])
                for finding in findings:
                    finding["session_id"] = analysis.get("session_id", "unknown")
                    finding["analysis_timestamp"] = analysis.get("start_time", "")
                    all_findings.append(finding)
            
            # Group findings by type and severity
            findings_by_type = defaultdict(list)
            findings_by_severity = defaultdict(list)
            
            for finding in all_findings:
                finding_type = finding.get("type", "unknown")
                severity = finding.get("severity", "Low")
                findings_by_type[finding_type].append(finding)
                findings_by_severity[severity].append(finding)
            
            # Generate detailed analysis
            detailed_analysis = {
                "total_findings": len(all_findings),
                "findings_by_type": {k: len(v) for k, v in findings_by_type.items()},
                "findings_by_severity": {k: len(v) for k, v in findings_by_severity.items()},
                "high_priority_findings": [f for f in all_findings if f.get("severity") == "High" and f.get("confidence", 0) > 0.8],
                "cross_session_patterns": self._identify_cross_session_patterns(all_findings),
                "temporal_distribution": self._analyze_finding_temporal_distribution(all_findings),
                "confidence_analysis": self._analyze_finding_confidence_distribution(all_findings)
            }
            
            return {
                "detailed_analysis": detailed_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating detailed findings section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_iocs_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate IOC analysis section"""
        try:
            all_iocs = []
            for analysis in data:
                result = analysis.get("result", {})
                iocs = result.get("iocs", [])
                for ioc in iocs:
                    ioc["session_id"] = analysis.get("session_id", "unknown")
                    ioc["discovery_time"] = analysis.get("start_time", "")
                    all_iocs.append(ioc)
            
            # Analyze IOCs
            ioc_types = Counter(ioc.get("type", "unknown") for ioc in all_iocs)
            high_confidence_iocs = [ioc for ioc in all_iocs if ioc.get("confidence", 0) > 0.8]
            
            # Group by threat intelligence context
            threat_intel_iocs = [ioc for ioc in all_iocs if ioc.get("threat_intel")]
            
            ioc_analysis = {
                "total_iocs": len(all_iocs),
                "ioc_type_distribution": dict(ioc_types),
                "high_confidence_iocs": len(high_confidence_iocs),
                "threat_intelligence_matches": len(threat_intel_iocs),
                "top_iocs": sorted(all_iocs, key=lambda x: x.get("confidence", 0), reverse=True)[:10],
                "ioc_correlation": self._correlate_iocs_across_sessions(all_iocs),
                "actionable_iocs": [ioc for ioc in high_confidence_iocs if ioc.get("confidence", 0) > 0.9]
            }
            
            return {
                "ioc_analysis": ioc_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating IOCs section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_technical_recommendations_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate technical recommendations section"""
        try:
            # Collect all techniques and findings for analysis
            all_techniques = []
            all_findings = []
            
            for analysis in data:
                result = analysis.get("result", {})
                all_techniques.extend(result.get("techniques", []))
                all_findings.extend(result.get("findings", []))
            
            # Generate technical recommendations based on observed techniques
            recommendations = []
            
            # Technique-based recommendations
            technique_counts = Counter(t.get("technique_id", "") for t in all_techniques)
            for technique_id, count in technique_counts.most_common(5):
                if count > len(data) * 0.3:  # Appears in >30% of sessions
                    recommendations.append({
                        "category": "Detection",
                        "priority": "High",
                        "technique_id": technique_id,
                        "recommendation": f"Implement enhanced detection for MITRE technique {technique_id}",
                        "rationale": f"Observed in {count}/{len(data)} sessions ({count/len(data)*100:.1f}%)",
                        "implementation": f"Deploy behavioral analytics and signature-based detection for {technique_id}",
                        "expected_impact": "Reduce detection time and improve threat visibility"
                    })
            
            # Severity-based recommendations
            high_severity_findings = [f for f in all_findings if f.get("severity") == "High"]
            if len(high_severity_findings) > len(data) * 0.2:  # >20% high severity
                recommendations.append({
                    "category": "Response",
                    "priority": "Critical",
                    "recommendation": "Implement automated incident response for high-severity findings",
                    "rationale": f"{len(high_severity_findings)} high-severity findings detected",
                    "implementation": "Deploy SOAR platform with automated containment workflows",
                    "expected_impact": "Reduce incident response time from hours to minutes"
                })
            
            # Infrastructure recommendations
            honeypot_types = Counter()
            for analysis in data:
                metadata = analysis.get("metadata", {})
                honeypot_type = metadata.get("honeypot_type", "unknown")
                honeypot_types[honeypot_type] += 1
            
            if honeypot_types:
                most_targeted = honeypot_types.most_common(1)[0]
                recommendations.append({
                    "category": "Infrastructure",
                    "priority": "Medium",
                    "recommendation": f"Expand {most_targeted[0]} honeypot deployment",
                    "rationale": f"Most targeted honeypot type ({most_targeted[1]} sessions)",
                    "implementation": f"Deploy additional {most_targeted[0]} honeypots in different network segments",
                    "expected_impact": "Increase attack surface coverage and intelligence collection"
                })
            
            return {
                "technical_recommendations": recommendations,
                "implementation_priority": sorted(recommendations, key=lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(x["priority"], 0), reverse=True),
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating technical recommendations section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_incident_overview_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate incident overview section"""
        try:
            # Analyze incidents (high-risk sessions)
            incidents = [analysis for analysis in data if analysis.get("result", {}).get("risk_assessment") == "High"]
            
            if not incidents:
                return {
                    "incident_summary": "No high-risk incidents detected in the analyzed timeframe",
                    "incident_count": 0,
                    "generated_at": datetime.utcnow().isoformat()
                }
            
            # Analyze incident characteristics
            incident_timeline = []
            attack_vectors = Counter()
            affected_systems = Counter()
            
            for incident in incidents:
                incident_timeline.append({
                    "session_id": incident.get("session_id", "unknown"),
                    "start_time": incident.get("start_time", ""),
                    "duration": incident.get("result", {}).get("session_duration", 0),
                    "techniques_count": len(incident.get("result", {}).get("techniques", [])),
                    "confidence_score": incident.get("result", {}).get("confidence_score", 0)
                })
                
                metadata = incident.get("metadata", {})
                honeypot_type = metadata.get("honeypot_type", "unknown")
                attack_vectors[honeypot_type] += 1
                
                source_ip = metadata.get("source_ip", "unknown")
                affected_systems[source_ip] += 1
            
            # Sort timeline by start time
            incident_timeline.sort(key=lambda x: x.get("start_time", ""))
            
            overview = {
                "incident_count": len(incidents),
                "incident_timeline": incident_timeline,
                "attack_vector_distribution": dict(attack_vectors),
                "unique_source_ips": len(affected_systems),
                "average_incident_duration": statistics.mean([i.get("duration", 0) for i in incident_timeline]) if incident_timeline else 0,
                "peak_incident_period": self._identify_peak_incident_period(incident_timeline),
                "incident_severity_assessment": self._assess_incident_severity(incidents)
            }
            
            return {
                "incident_overview": overview,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating incident overview section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_timeline_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate timeline analysis section"""
        try:
            # Create comprehensive timeline
            timeline_events = []
            
            for analysis in data:
                session_id = analysis.get("session_id", "unknown")
                start_time = analysis.get("start_time", "")
                result = analysis.get("result", {})
                
                # Add session start event
                timeline_events.append({
                    "timestamp": start_time,
                    "event_type": "session_start",
                    "session_id": session_id,
                    "description": f"Attacker session initiated",
                    "risk_level": result.get("risk_assessment", "Low"),
                    "confidence": result.get("confidence_score", 0)
                })
                
                # Add technique events
                techniques = result.get("techniques", [])
                for i, technique in enumerate(techniques):
                    # Estimate technique timing within session
                    technique_time = datetime.fromisoformat(start_time) + timedelta(minutes=i*2)
                    timeline_events.append({
                        "timestamp": technique_time.isoformat(),
                        "event_type": "technique_observed",
                        "session_id": session_id,
                        "description": f"MITRE technique {technique.get('technique_id', 'unknown')} observed",
                        "technique_id": technique.get("technique_id", ""),
                        "tactic": technique.get("tactic", ""),
                        "confidence": technique.get("confidence", 0)
                    })
                
                # Add session end event
                end_time = datetime.fromisoformat(start_time) + timedelta(seconds=result.get("session_duration", 900))
                timeline_events.append({
                    "timestamp": end_time.isoformat(),
                    "event_type": "session_end",
                    "session_id": session_id,
                    "description": f"Attacker session concluded",
                    "findings_count": len(result.get("findings", [])),
                    "iocs_extracted": len(result.get("iocs", []))
                })
            
            # Sort timeline by timestamp
            timeline_events.sort(key=lambda x: x.get("timestamp", ""))
            
            # Analyze timeline patterns
            timeline_analysis = {
                "total_events": len(timeline_events),
                "event_timeline": timeline_events,
                "activity_patterns": self._analyze_activity_patterns(timeline_events),
                "attack_progression": self._analyze_attack_progression(timeline_events),
                "temporal_clustering": self._identify_temporal_clusters(timeline_events)
            }
            
            return {
                "timeline_analysis": timeline_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating timeline section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_impact_assessment_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate impact assessment section"""
        try:
            # Assess potential impact based on observed techniques and findings
            impact_factors = {
                "data_access_attempts": 0,
                "privilege_escalation_attempts": 0,
                "persistence_mechanisms": 0,
                "lateral_movement_indicators": 0,
                "exfiltration_attempts": 0
            }
            
            high_impact_sessions = []
            
            for analysis in data:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                session_impact_score = 0
                
                # Analyze techniques for impact indicators
                for technique in techniques:
                    tactic = technique.get("tactic", "").lower()
                    technique_id = technique.get("technique_id", "")
                    
                    if "credential access" in tactic or "collection" in tactic:
                        impact_factors["data_access_attempts"] += 1
                        session_impact_score += 3
                    elif "privilege escalation" in tactic:
                        impact_factors["privilege_escalation_attempts"] += 1
                        session_impact_score += 4
                    elif "persistence" in tactic:
                        impact_factors["persistence_mechanisms"] += 1
                        session_impact_score += 3
                    elif "lateral movement" in tactic:
                        impact_factors["lateral_movement_indicators"] += 1
                        session_impact_score += 4
                    elif "exfiltration" in tactic:
                        impact_factors["exfiltration_attempts"] += 1
                        session_impact_score += 5
                
                # Identify high-impact sessions
                if session_impact_score > 10:
                    high_impact_sessions.append({
                        "session_id": analysis.get("session_id", "unknown"),
                        "impact_score": session_impact_score,
                        "risk_assessment": result.get("risk_assessment", "Low"),
                        "key_techniques": [t.get("technique_id", "") for t in techniques]
                    })
            
            # Calculate overall impact assessment
            total_sessions = len(data)
            high_impact_percentage = (len(high_impact_sessions) / total_sessions * 100) if total_sessions > 0 else 0
            
            overall_impact = "Critical" if high_impact_percentage > 30 else "High" if high_impact_percentage > 15 else "Medium" if high_impact_percentage > 5 else "Low"
            
            impact_assessment = {
                "overall_impact_level": overall_impact,
                "high_impact_sessions": len(high_impact_sessions),
                "high_impact_percentage": high_impact_percentage,
                "impact_factors": impact_factors,
                "potential_business_impact": self._assess_business_impact(impact_factors, high_impact_sessions),
                "mitigation_urgency": self._determine_mitigation_urgency(overall_impact, impact_factors),
                "detailed_session_impacts": high_impact_sessions[:10]  # Top 10 high-impact sessions
            }
            
            return {
                "impact_assessment": impact_assessment,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating impact assessment section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_containment_actions_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate containment actions section"""
        try:
            # Analyze threats and generate containment recommendations
            containment_actions = []
            
            # Collect all IOCs for blocking
            all_iocs = []
            for analysis in data:
                result = analysis.get("result", {})
                iocs = result.get("iocs", [])
                all_iocs.extend(iocs)
            
            # High-confidence IOCs for immediate blocking
            high_confidence_iocs = [ioc for ioc in all_iocs if ioc.get("confidence", 0) > 0.8]
            
            if high_confidence_iocs:
                ip_addresses = [ioc["value"] for ioc in high_confidence_iocs if ioc.get("type") == "ip_address"]
                domains = [ioc["value"] for ioc in high_confidence_iocs if ioc.get("type") == "domain"]
                file_hashes = [ioc["value"] for ioc in high_confidence_iocs if ioc.get("type") == "file_hash"]
                
                if ip_addresses:
                    containment_actions.append({
                        "action_type": "network_blocking",
                        "priority": "Critical",
                        "description": f"Block {len(ip_addresses)} malicious IP addresses",
                        "implementation": "Update firewall rules and IPS signatures",
                        "iocs": ip_addresses[:10],  # Limit for readability
                        "estimated_time": "15 minutes"
                    })
                
                if domains:
                    containment_actions.append({
                        "action_type": "dns_blocking",
                        "priority": "High",
                        "description": f"Block {len(domains)} malicious domains",
                        "implementation": "Update DNS filtering and web proxy rules",
                        "iocs": domains[:10],
                        "estimated_time": "30 minutes"
                    })
                
                if file_hashes:
                    containment_actions.append({
                        "action_type": "endpoint_protection",
                        "priority": "High",
                        "description": f"Block {len(file_hashes)} malicious file hashes",
                        "implementation": "Update endpoint protection signatures",
                        "iocs": file_hashes[:10],
                        "estimated_time": "45 minutes"
                    })
            
            # Technique-based containment
            all_techniques = []
            for analysis in data:
                result = analysis.get("result", {})
                all_techniques.extend(result.get("techniques", []))
            
            technique_counts = Counter(t.get("technique_id", "") for t in all_techniques)
            
            # High-frequency techniques requiring immediate attention
            for technique_id, count in technique_counts.most_common(3):
                if count > len(data) * 0.4:  # Appears in >40% of sessions
                    containment_actions.append({
                        "action_type": "detection_enhancement",
                        "priority": "High",
                        "description": f"Enhance detection for MITRE technique {technique_id}",
                        "implementation": f"Deploy additional monitoring for {technique_id} indicators",
                        "technique_id": technique_id,
                        "frequency": count,
                        "estimated_time": "2 hours"
                    })
            
            # Risk-based containment
            high_risk_sessions = [a for a in data if a.get("result", {}).get("risk_assessment") == "High"]
            if len(high_risk_sessions) > len(data) * 0.3:  # >30% high risk
                containment_actions.append({
                    "action_type": "incident_response",
                    "priority": "Critical",
                    "description": "Activate incident response team for high-risk activity",
                    "implementation": "Initiate formal incident response procedures",
                    "affected_sessions": len(high_risk_sessions),
                    "estimated_time": "1 hour"
                })
            
            # Sort by priority
            priority_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            containment_actions.sort(key=lambda x: priority_order.get(x["priority"], 0), reverse=True)
            
            containment_plan = {
                "immediate_actions": [action for action in containment_actions if action["priority"] == "Critical"],
                "short_term_actions": [action for action in containment_actions if action["priority"] == "High"],
                "long_term_actions": [action for action in containment_actions if action["priority"] in ["Medium", "Low"]],
                "total_actions": len(containment_actions),
                "estimated_total_time": sum([self._parse_time_estimate(action.get("estimated_time", "0 minutes")) for action in containment_actions]),
                "containment_effectiveness": self._assess_containment_effectiveness(containment_actions)
            }
            
            return {
                "containment_plan": containment_plan,
                "all_actions": containment_actions,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating containment actions section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_lessons_learned_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate lessons learned section"""
        try:
            lessons = []
            
            # Analyze attack patterns for lessons
            all_techniques = []
            all_findings = []
            
            for analysis in data:
                result = analysis.get("result", {})
                all_techniques.extend(result.get("techniques", []))
                all_findings.extend(result.get("findings", []))
            
            # Lesson 1: Most common attack vectors
            technique_counts = Counter(t.get("tactic", "") for t in all_techniques)
            if technique_counts:
                top_tactic = technique_counts.most_common(1)[0]
                lessons.append({
                    "category": "Attack Patterns",
                    "lesson": f"Attackers primarily focus on {top_tactic[0]} tactics",
                    "evidence": f"Observed in {top_tactic[1]} instances across {len(data)} sessions",
                    "implication": f"Enhanced monitoring and detection for {top_tactic[0]} activities is critical",
                    "action_item": f"Implement advanced {top_tactic[0]} detection capabilities"
                })
            
            # Lesson 2: Detection effectiveness
            high_confidence_findings = [f for f in all_findings if f.get("confidence", 0) > 0.8]
            detection_rate = (len(high_confidence_findings) / len(all_findings) * 100) if all_findings else 0
            
            if detection_rate < 70:
                lessons.append({
                    "category": "Detection Capabilities",
                    "lesson": "Current detection capabilities show room for improvement",
                    "evidence": f"Only {detection_rate:.1f}% of findings have high confidence scores",
                    "implication": "False positives may be high, reducing analyst efficiency",
                    "action_item": "Tune detection rules and implement machine learning-based analysis"
                })
            else:
                lessons.append({
                    "category": "Detection Capabilities",
                    "lesson": "Detection capabilities are performing well",
                    "evidence": f"{detection_rate:.1f}% of findings have high confidence scores",
                    "implication": "Current detection methods are effective",
                    "action_item": "Maintain current detection capabilities and expand coverage"
                })
            
            # Lesson 3: Honeypot effectiveness
            honeypot_engagement = Counter()
            for analysis in data:
                metadata = analysis.get("metadata", {})
                honeypot_type = metadata.get("honeypot_type", "unknown")
                honeypot_engagement[honeypot_type] += 1
            
            if honeypot_engagement:
                most_effective = honeypot_engagement.most_common(1)[0]
                lessons.append({
                    "category": "Honeypot Strategy",
                    "lesson": f"{most_effective[0]} honeypots are most effective at attracting attackers",
                    "evidence": f"Engaged {most_effective[1]} times out of {len(data)} total sessions",
                    "implication": "Resource allocation should prioritize effective honeypot types",
                    "action_item": f"Expand {most_effective[0]} honeypot deployment"
                })
            
            # Lesson 4: Threat intelligence value
            threat_intel_matches = sum(1 for analysis in data 
                                     for ioc in analysis.get("result", {}).get("iocs", []) 
                                     if ioc.get("threat_intel"))
            
            if threat_intel_matches > 0:
                lessons.append({
                    "category": "Threat Intelligence",
                    "lesson": "Threat intelligence integration provides valuable context",
                    "evidence": f"{threat_intel_matches} IOCs matched existing threat intelligence",
                    "implication": "Threat intelligence feeds are providing actionable insights",
                    "action_item": "Expand threat intelligence feed integration and automation"
                })
            
            # Lesson 5: Response time analysis
            avg_session_duration = statistics.mean([
                analysis.get("result", {}).get("session_duration", 0) for analysis in data
            ]) if data else 0
            
            if avg_session_duration > 1800:  # 30 minutes
                lessons.append({
                    "category": "Response Time",
                    "lesson": "Attackers are spending significant time in honeypots",
                    "evidence": f"Average session duration: {avg_session_duration/60:.1f} minutes",
                    "implication": "Honeypots are successfully engaging attackers for intelligence gathering",
                    "action_item": "Maintain current engagement strategies while ensuring safety controls"
                })
            
            lessons_learned = {
                "key_lessons": lessons,
                "strategic_insights": self._generate_strategic_insights(lessons),
                "improvement_areas": self._identify_improvement_areas(lessons),
                "success_factors": self._identify_success_factors(lessons),
                "future_recommendations": self._generate_future_recommendations(lessons)
            }
            
            return {
                "lessons_learned": lessons_learned,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating lessons learned section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_threat_landscape_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat landscape analysis section"""
        try:
            # Analyze overall threat landscape
            threat_landscape = {
                "threat_volume": len(data),
                "threat_diversity": self._calculate_threat_diversity(data),
                "geographic_distribution": self._analyze_geographic_distribution(data),
                "temporal_patterns": self._analyze_temporal_threat_patterns(data),
                "attack_sophistication": self._assess_attack_sophistication(data),
                "emerging_threats": self._identify_emerging_threats(data),
                "threat_actor_activity": self._analyze_threat_actor_activity(data)
            }
            
            return {
                "threat_landscape": threat_landscape,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating threat landscape section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_actor_analysis_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat actor analysis section"""
        try:
            # Analyze potential threat actors based on TTPs
            actor_indicators = {
                "technique_patterns": self._analyze_technique_patterns_for_attribution(data),
                "behavioral_signatures": self._identify_behavioral_signatures(data),
                "infrastructure_patterns": self._analyze_infrastructure_patterns(data),
                "temporal_behavior": self._analyze_temporal_behavior_patterns(data)
            }
            
            # Generate actor assessments
            potential_actors = self._generate_actor_assessments(actor_indicators)
            
            actor_analysis = {
                "potential_threat_actors": potential_actors,
                "attribution_confidence": self._calculate_attribution_confidence(potential_actors),
                "actor_indicators": actor_indicators,
                "campaign_analysis": self._analyze_potential_campaigns(data),
                "attribution_recommendations": self._generate_attribution_recommendations(potential_actors)
            }
            
            return {
                "actor_analysis": actor_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating actor analysis section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_ttps_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate TTPs (Tactics, Techniques, Procedures) analysis section"""
        try:
            all_techniques = []
            for analysis in data:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                all_techniques.extend(techniques)
            
            # Analyze TTPs
            tactic_analysis = self._analyze_tactics(all_techniques)
            technique_analysis = self._analyze_techniques(all_techniques)
            procedure_analysis = self._analyze_procedures(data)
            
            ttps_analysis = {
                "tactic_coverage": tactic_analysis,
                "technique_frequency": technique_analysis,
                "procedure_patterns": procedure_analysis,
                "kill_chain_analysis": self._analyze_kill_chain_progression(all_techniques),
                "ttp_evolution": self._analyze_ttp_evolution(data),
                "defensive_gaps": self._identify_defensive_gaps(all_techniques)
            }
            
            return {
                "ttps_analysis": ttps_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating TTPs section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_indicators_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate indicators analysis section"""
        try:
            all_iocs = []
            for analysis in data:
                result = analysis.get("result", {})
                iocs = result.get("iocs", [])
                all_iocs.extend(iocs)
            
            # Comprehensive indicator analysis
            indicator_analysis = {
                "ioc_summary": self._generate_ioc_summary(all_iocs),
                "indicator_quality": self._assess_indicator_quality(all_iocs),
                "threat_intelligence_correlation": self._correlate_with_threat_intelligence(all_iocs),
                "indicator_relationships": self._analyze_indicator_relationships(all_iocs),
                "actionable_indicators": self._identify_actionable_indicators(all_iocs),
                "sharing_recommendations": self._generate_indicator_sharing_recommendations(all_iocs)
            }
            
            return {
                "indicator_analysis": indicator_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating indicators section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}
    
    def _generate_attribution_section(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate attribution analysis section"""
        try:
            # Comprehensive attribution analysis
            attribution_analysis = {
                "attribution_assessment": self._perform_attribution_assessment(data),
                "confidence_levels": self._calculate_attribution_confidence_levels(data),
                "supporting_evidence": self._collect_attribution_evidence(data),
                "alternative_hypotheses": self._generate_alternative_attribution_hypotheses(data),
                "attribution_timeline": self._create_attribution_timeline(data),
                "recommendations": self._generate_attribution_action_recommendations(data)
            }
            
            return {
                "attribution_analysis": attribution_analysis,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating attribution section: {e}")
            return {"error": str(e), "generated_at": datetime.utcnow().isoformat()}  
  
    # Helper methods for data processing and analysis
    def _filter_data_by_time_range(self, data: List[Dict[str, Any]], time_range: str) -> List[Dict[str, Any]]:
        """Filter data by specified time range"""
        try:
            # Parse time range
            if time_range == "24h":
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            elif time_range == "7d":
                cutoff_time = datetime.utcnow() - timedelta(days=7)
            elif time_range == "30d":
                cutoff_time = datetime.utcnow() - timedelta(days=30)
            elif time_range == "90d":
                cutoff_time = datetime.utcnow() - timedelta(days=90)
            else:
                # Default to 24h
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            filtered_data = []
            for item in data:
                try:
                    item_time = datetime.fromisoformat(item.get("start_time", ""))
                    if item_time >= cutoff_time:
                        filtered_data.append(item)
                except Exception:
                    # Include items without valid timestamps
                    filtered_data.append(item)
            
            return filtered_data
            
        except Exception as e:
            self.logger.error(f"Error filtering data by time range: {e}")
            return data
    
    def _calculate_report_metrics(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate key metrics for the report"""
        try:
            metrics = {
                "total_sessions": len(data),
                "high_risk_sessions": 0,
                "medium_risk_sessions": 0,
                "low_risk_sessions": 0,
                "total_techniques": 0,
                "unique_techniques": set(),
                "total_iocs": 0,
                "high_confidence_findings": 0
            }
            
            for analysis in data:
                result = analysis.get("result", {})
                
                # Risk assessment counts
                risk_level = result.get("risk_assessment", "Low")
                if risk_level == "High":
                    metrics["high_risk_sessions"] += 1
                elif risk_level == "Medium":
                    metrics["medium_risk_sessions"] += 1
                else:
                    metrics["low_risk_sessions"] += 1
                
                # Technique counts
                techniques = result.get("techniques", [])
                metrics["total_techniques"] += len(techniques)
                for technique in techniques:
                    metrics["unique_techniques"].add(technique.get("technique_id", ""))
                
                # IOC counts (if available)
                iocs = result.get("iocs", [])
                metrics["total_iocs"] += len(iocs)
                
                # High confidence findings
                findings = result.get("findings", [])
                high_conf_findings = [f for f in findings if f.get("confidence", 0) > 0.8]
                metrics["high_confidence_findings"] += len(high_conf_findings)
            
            # Convert set to count
            metrics["unique_techniques"] = len(metrics["unique_techniques"])
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error calculating report metrics: {e}")
            return {}
    
    def _generate_report_recommendations(self, data: List[Dict[str, Any]], report_type: str) -> List[Dict[str, Any]]:
        """Generate recommendations based on report type and data"""
        recommendations = []
        
        try:
            # Collect all recommendations from analyses
            all_recommendations = []
            for analysis in data:
                result = analysis.get("result", {})
                recs = result.get("recommendations", [])
                all_recommendations.extend(recs)
            
            # Count recommendation frequency
            rec_counts = Counter(all_recommendations)
            
            # Generate prioritized recommendations
            for rec, count in rec_counts.most_common(10):
                priority = "High" if count > len(data) * 0.5 else "Medium" if count > len(data) * 0.2 else "Low"
                
                recommendations.append({
                    "recommendation": rec,
                    "priority": priority,
                    "frequency": count,
                    "percentage": (count / len(data)) * 100 if len(data) > 0 else 0,
                    "category": self._categorize_recommendation(rec)
                })
            
            # Add report-type specific recommendations
            if report_type == "executive_summary":
                recommendations.extend(self._get_executive_recommendations(data))
            elif report_type == "incident_response":
                recommendations.extend(self._get_incident_response_recommendations(data))
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating report recommendations: {e}")
            return []
    
    # Automated summary methods
    def _generate_key_statistics(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate key statistics for automated summary"""
        try:
            stats = {
                "session_count": len(data),
                "risk_distribution": {"High": 0, "Medium": 0, "Low": 0},
                "technique_stats": {"total": 0, "unique": set()},
                "finding_stats": {"total": 0, "high_confidence": 0},
                "time_span": self._calculate_time_span(data)
            }
            
            for analysis in data:
                result = analysis.get("result", {})
                
                # Risk distribution
                risk = result.get("risk_assessment", "Low")
                stats["risk_distribution"][risk] += 1
                
                # Technique statistics
                techniques = result.get("techniques", [])
                stats["technique_stats"]["total"] += len(techniques)
                for tech in techniques:
                    stats["technique_stats"]["unique"].add(tech.get("technique_id", ""))
                
                # Finding statistics
                findings = result.get("findings", [])
                stats["finding_stats"]["total"] += len(findings)
                high_conf = [f for f in findings if f.get("confidence", 0) > 0.8]
                stats["finding_stats"]["high_confidence"] += len(high_conf)
            
            # Convert set to count
            stats["technique_stats"]["unique"] = len(stats["technique_stats"]["unique"])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating key statistics: {e}")
            return {}
    
    def _analyze_threat_landscape(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the threat landscape from data"""
        try:
            landscape = {
                "dominant_tactics": Counter(),
                "emerging_techniques": [],
                "threat_actors": Counter(),
                "attack_vectors": Counter(),
                "geographic_distribution": Counter()
            }
            
            for analysis in data:
                result = analysis.get("result", {})
                metadata = analysis.get("metadata", {})
                
                # Analyze tactics
                techniques = result.get("techniques", [])
                for tech in techniques:
                    tactic = tech.get("tactic", "Unknown")
                    landscape["dominant_tactics"][tactic] += 1
                
                # Geographic data
                source_ip = metadata.get("source_ip", "Unknown")
                # In a real implementation, this would use GeoIP lookup
                landscape["geographic_distribution"]["Unknown"] += 1
                
                # Attack vectors based on honeypot type
                honeypot_type = metadata.get("honeypot_type", "Unknown")
                landscape["attack_vectors"][honeypot_type] += 1
            
            # Convert counters to dictionaries
            for key in landscape:
                if isinstance(landscape[key], Counter):
                    landscape[key] = dict(landscape[key])
            
            return landscape
            
        except Exception as e:
            self.logger.error(f"Error analyzing threat landscape: {e}")
            return {}
    
    def _extract_top_findings(self, data: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Extract top findings from data"""
        try:
            all_findings = []
            
            for analysis in data:
                result = analysis.get("result", {})
                findings = result.get("findings", [])
                
                for finding in findings:
                    finding["session_id"] = analysis.get("session_id", "unknown")
                    all_findings.append(finding)
            
            # Sort by confidence and severity
            def finding_score(finding):
                confidence = finding.get("confidence", 0)
                severity = finding.get("severity", "Low")
                severity_scores = {"High": 3, "Medium": 2, "Low": 1}
                return confidence * severity_scores.get(severity, 1)
            
            sorted_findings = sorted(all_findings, key=finding_score, reverse=True)
            
            return sorted_findings[:limit]
            
        except Exception as e:
            self.logger.error(f"Error extracting top findings: {e}")
            return []
    
    def _identify_trend_indicators(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify trend indicators from recent data"""
        try:
            indicators = []
            
            # Analyze technique frequency trends
            technique_counts = Counter()
            for analysis in data:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                for tech in techniques:
                    technique_counts[tech.get("technique_id", "")] += 1
            
            # Identify trending techniques
            if technique_counts:
                avg_count = statistics.mean(technique_counts.values())
                for technique_id, count in technique_counts.items():
                    if count > avg_count * 1.5:  # 50% above average
                        indicators.append({
                            "type": "trending_technique",
                            "technique_id": technique_id,
                            "frequency": count,
                            "trend": "increasing"
                        })
            
            # Analyze risk level trends
            risk_levels = [analysis.get("result", {}).get("risk_assessment", "Low") for analysis in data]
            high_risk_percentage = (risk_levels.count("High") / len(risk_levels)) * 100 if risk_levels else 0
            
            if high_risk_percentage > 20:  # More than 20% high risk
                indicators.append({
                    "type": "risk_escalation",
                    "percentage": high_risk_percentage,
                    "trend": "concerning"
                })
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"Error identifying trend indicators: {e}")
            return []
    
    def _assess_overall_risk(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk level from data"""
        try:
            if not data:
                return {"level": "Unknown", "score": 0, "factors": []}
            
            risk_scores = {"High": 3, "Medium": 2, "Low": 1}
            total_score = 0
            risk_factors = []
            
            for analysis in data:
                result = analysis.get("result", {})
                risk_level = result.get("risk_assessment", "Low")
                total_score += risk_scores.get(risk_level, 1)
                
                # Collect risk factors
                techniques = result.get("techniques", [])
                if len(techniques) > 5:
                    risk_factors.append("High technique diversity")
                
                findings = result.get("findings", [])
                high_conf_findings = [f for f in findings if f.get("confidence", 0) > 0.8]
                if len(high_conf_findings) > 3:
                    risk_factors.append("Multiple high-confidence findings")
            
            # Calculate average risk score
            avg_score = total_score / len(data)
            
            # Determine overall risk level
            if avg_score >= 2.5:
                overall_level = "High"
            elif avg_score >= 1.5:
                overall_level = "Medium"
            else:
                overall_level = "Low"
            
            return {
                "level": overall_level,
                "score": avg_score,
                "factors": list(set(risk_factors)),
                "session_count": len(data)
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing overall risk: {e}")
            return {"level": "Unknown", "score": 0, "factors": []}
    
    def _generate_actionable_insights(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate actionable insights from data"""
        try:
            insights = []
            
            # Analyze common attack patterns
            technique_counts = Counter()
            for analysis in data:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                for tech in techniques:
                    technique_counts[tech.get("technique_id", "")] += 1
            
            # Generate insights based on common techniques
            for technique_id, count in technique_counts.most_common(5):
                if count > len(data) * 0.3:  # Appears in >30% of sessions
                    insights.append({
                        "type": "common_technique",
                        "technique_id": technique_id,
                        "frequency": count,
                        "insight": f"Technique {technique_id} observed in {count}/{len(data)} sessions",
                        "action": f"Implement detection rules for {technique_id}",
                        "priority": "High" if count > len(data) * 0.5 else "Medium"
                    })
            
            # Analyze honeypot effectiveness
            honeypot_types = Counter()
            for analysis in data:
                metadata = analysis.get("metadata", {})
                honeypot_type = metadata.get("honeypot_type", "Unknown")
                honeypot_types[honeypot_type] += 1
            
            if honeypot_types:
                most_targeted = honeypot_types.most_common(1)[0]
                insights.append({
                    "type": "honeypot_effectiveness",
                    "honeypot_type": most_targeted[0],
                    "sessions": most_targeted[1],
                    "insight": f"{most_targeted[0]} honeypots are most frequently targeted",
                    "action": f"Consider expanding {most_targeted[0]} honeypot deployment",
                    "priority": "Medium"
                })
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Error generating actionable insights: {e}")
            return []
    
    def _generate_summary_narrative(self, summary: Dict[str, Any]) -> str:
        """Generate narrative text for summary"""
        try:
            stats = summary.get("key_statistics", {})
            risk_assessment = summary.get("risk_assessment", {})
            
            session_count = stats.get("session_count", 0)
            risk_level = risk_assessment.get("level", "Unknown")
            
            narrative = f"Analysis of {session_count} honeypot sessions reveals an overall risk level of {risk_level}. "
            
            # Add risk distribution context
            risk_dist = stats.get("risk_distribution", {})
            high_risk = risk_dist.get("High", 0)
            if high_risk > 0:
                narrative += f"{high_risk} sessions were classified as high risk, indicating active threat activity. "
            
            # Add technique context
            tech_stats = stats.get("technique_stats", {})
            unique_techniques = tech_stats.get("unique", 0)
            if unique_techniques > 0:
                narrative += f"Attackers employed {unique_techniques} unique MITRE ATT&CK techniques across all sessions. "
            
            # Add actionable insights
            insights = summary.get("actionable_insights", [])
            if insights:
                narrative += f"Key actionable insights include: {insights[0].get('insight', 'N/A')}"
            
            return narrative
            
        except Exception as e:
            self.logger.error(f"Error generating summary narrative: {e}")
            return "Summary narrative generation failed."
    
    # Trend analysis methods
    def _organize_time_series_data(self, data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Organize data into time series format"""
        try:
            time_series = defaultdict(list)
            
            for analysis in data:
                try:
                    timestamp = datetime.fromisoformat(analysis.get("start_time", ""))
                    date_key = timestamp.date().isoformat()
                    time_series[date_key].append(analysis)
                except Exception:
                    # Skip items with invalid timestamps
                    continue
            
            return dict(time_series)
            
        except Exception as e:
            self.logger.error(f"Error organizing time series data: {e}")
            return {}
    
    def _analyze_volume_trends(self, time_series_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Analyze volume trends over time"""
        try:
            daily_counts = {date: len(sessions) for date, sessions in time_series_data.items()}
            
            if len(daily_counts) < 2:
                return {"trend": "insufficient_data", "daily_counts": daily_counts}
            
            # Calculate trend
            dates = sorted(daily_counts.keys())
            counts = [daily_counts[date] for date in dates]
            
            # Simple trend calculation
            if len(counts) >= 2:
                recent_avg = statistics.mean(counts[-3:]) if len(counts) >= 3 else counts[-1]
                earlier_avg = statistics.mean(counts[:3]) if len(counts) >= 3 else counts[0]
                
                if recent_avg > earlier_avg * 1.2:
                    trend = "increasing"
                elif recent_avg < earlier_avg * 0.8:
                    trend = "decreasing"
                else:
                    trend = "stable"
            else:
                trend = "stable"
            
            return {
                "trend": trend,
                "daily_counts": daily_counts,
                "average_daily": statistics.mean(counts) if counts else 0,
                "peak_day": max(daily_counts, key=daily_counts.get) if daily_counts else None
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing volume trends: {e}")
            return {"trend": "error", "error": str(e)}
    
    def _analyze_technique_trends(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze trends in technique usage"""
        try:
            # Group data by time periods
            technique_timeline = defaultdict(lambda: defaultdict(int))
            
            for analysis in data:
                try:
                    timestamp = datetime.fromisoformat(analysis.get("start_time", ""))
                    week_key = timestamp.strftime("%Y-W%U")  # Year-Week format
                    
                    result = analysis.get("result", {})
                    techniques = result.get("techniques", [])
                    
                    for tech in techniques:
                        technique_id = tech.get("technique_id", "Unknown")
                        technique_timeline[week_key][technique_id] += 1
                        
                except Exception:
                    continue
            
            # Analyze trends for top techniques
            all_techniques = Counter()
            for week_data in technique_timeline.values():
                for tech_id, count in week_data.items():
                    all_techniques[tech_id] += count
            
            top_techniques = dict(all_techniques.most_common(10))
            
            return {
                "timeline": dict(technique_timeline),
                "top_techniques": top_techniques,
                "trending_techniques": self._identify_trending_techniques(technique_timeline)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing technique trends: {e}")
            return {}
    
    def _identify_trending_techniques(self, technique_timeline: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
        """Identify trending techniques from timeline data"""
        trending = []
        
        try:
            weeks = sorted(technique_timeline.keys())
            if len(weeks) < 2:
                return trending
            
            # Compare recent weeks to earlier weeks
            recent_weeks = weeks[-2:] if len(weeks) >= 2 else weeks
            earlier_weeks = weeks[:-2] if len(weeks) > 2 else []
            
            if not earlier_weeks:
                return trending
            
            # Calculate averages for each technique
            for technique_id in set().union(*[week_data.keys() for week_data in technique_timeline.values()]):
                recent_avg = statistics.mean([
                    technique_timeline[week].get(technique_id, 0) for week in recent_weeks
                ])
                earlier_avg = statistics.mean([
                    technique_timeline[week].get(technique_id, 0) for week in earlier_weeks
                ])
                
                if recent_avg > earlier_avg * 1.5 and recent_avg > 1:  # 50% increase and at least 1 occurrence
                    trending.append({
                        "technique_id": technique_id,
                        "recent_average": recent_avg,
                        "earlier_average": earlier_avg,
                        "growth_factor": recent_avg / earlier_avg if earlier_avg > 0 else float('inf')
                    })
            
            # Sort by growth factor
            trending.sort(key=lambda x: x["growth_factor"], reverse=True)
            
            return trending[:5]  # Top 5 trending
            
        except Exception as e:
            self.logger.error(f"Error identifying trending techniques: {e}")
            return []
    
    # Advanced trend analysis methods
    def _analyze_threat_actor_trends(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat actor trends"""
        try:
            # Analyze techniques for actor attribution patterns
            all_techniques = []
            for analysis in data:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                all_techniques.extend(techniques)
            
            # Group techniques by potential actor indicators
            actor_signatures = defaultdict(list)
            
            for technique in all_techniques:
                technique_id = technique.get("technique_id", "")
                tactic = technique.get("tactic", "")
                
                # Simple heuristic for actor grouping based on technique combinations
                if technique_id.startswith("T1"):
                    signature_key = f"{tactic}_{technique_id[:4]}"  # Group by tactic and technique family
                    actor_signatures[signature_key].append(technique)
            
            # Analyze trends in actor signatures
            trending_signatures = []
            for signature, techniques in actor_signatures.items():
                if len(techniques) > 2:  # Significant usage
                    trending_signatures.append({
                        "signature": signature,
                        "frequency": len(techniques),
                        "trend": "increasing" if len(techniques) > len(data) * 0.3 else "stable",
                        "confidence": min(0.9, len(techniques) / len(data))
                    })
            
            return {
                "trending_actor_signatures": trending_signatures,
                "unique_signatures": len(actor_signatures),
                "signature_diversity": len(actor_signatures) / len(data) if len(data) > 0 else 0,
                "attribution_indicators": len([s for s in trending_signatures if s["confidence"] > 0.7])
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing threat actor trends: {e}")
            return {"error": str(e)}
    
    def _analyze_geographic_trends(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze geographic trends"""
        try:
            # Extract geographic indicators from metadata
            geographic_indicators = defaultdict(int)
            
            for analysis in data:
                metadata = analysis.get("metadata", {})
                source_ip = metadata.get("source_ip", "")
                
                if source_ip:
                    # Simple geographic classification based on IP ranges
                    # In a real implementation, this would use GeoIP lookup
                    if source_ip.startswith("192.168") or source_ip.startswith("10.") or source_ip.startswith("172."):
                        geographic_indicators["Internal/RFC1918"] += 1
                    elif source_ip.startswith("127."):
                        geographic_indicators["Localhost"] += 1
                    else:
                        # Placeholder for external IPs
                        geographic_indicators["External"] += 1
                else:
                    geographic_indicators["Unknown"] += 1
            
            # Analyze trends
            total_sessions = len(data)
            geographic_distribution = {
                region: (count / total_sessions * 100) if total_sessions > 0 else 0
                for region, count in geographic_indicators.items()
            }
            
            # Identify trending regions
            trending_regions = []
            for region, percentage in geographic_distribution.items():
                if percentage > 20:  # Significant presence
                    trending_regions.append({
                        "region": region,
                        "percentage": percentage,
                        "session_count": geographic_indicators[region],
                        "trend": "dominant" if percentage > 50 else "significant"
                    })
            
            return {
                "geographic_distribution": geographic_distribution,
                "trending_regions": trending_regions,
                "geographic_diversity": len(geographic_indicators),
                "dominant_region": max(geographic_indicators, key=geographic_indicators.get) if geographic_indicators else "Unknown"
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing geographic trends: {e}")
            return {"error": str(e)}
    
    def _identify_seasonal_patterns(self, time_series_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Identify seasonal patterns"""
        try:
            if len(time_series_data) < 7:  # Need at least a week of data
                return {"message": "Insufficient data for seasonal pattern analysis", "data_points": len(time_series_data)}
            
            # Analyze daily patterns
            daily_counts = {}
            hourly_patterns = defaultdict(int)
            
            for date_str, sessions in time_series_data.items():
                try:
                    date_obj = datetime.fromisoformat(date_str)
                    day_of_week = date_obj.strftime("%A")
                    daily_counts[day_of_week] = daily_counts.get(day_of_week, 0) + len(sessions)
                    
                    # Analyze hourly patterns within sessions
                    for session in sessions:
                        try:
                            session_time = datetime.fromisoformat(session.get("start_time", ""))
                            hour = session_time.hour
                            hourly_patterns[hour] += 1
                        except Exception:
                            continue
                            
                except Exception:
                    continue
            
            # Identify patterns
            patterns = []
            
            # Weekly patterns
            if daily_counts:
                max_day = max(daily_counts, key=daily_counts.get)
                min_day = min(daily_counts, key=daily_counts.get)
                
                if daily_counts[max_day] > daily_counts[min_day] * 2:
                    patterns.append({
                        "pattern_type": "weekly",
                        "description": f"Higher activity on {max_day}",
                        "strength": "strong",
                        "peak_day": max_day,
                        "peak_count": daily_counts[max_day]
                    })
            
            # Hourly patterns
            if hourly_patterns:
                peak_hour = max(hourly_patterns, key=hourly_patterns.get)
                peak_count = hourly_patterns[peak_hour]
                avg_count = statistics.mean(hourly_patterns.values())
                
                if peak_count > avg_count * 1.5:
                    patterns.append({
                        "pattern_type": "hourly",
                        "description": f"Peak activity at {peak_hour:02d}:00",
                        "strength": "moderate",
                        "peak_hour": peak_hour,
                        "peak_count": peak_count
                    })
            
            return {
                "seasonal_patterns": patterns,
                "daily_distribution": daily_counts,
                "hourly_distribution": dict(hourly_patterns),
                "pattern_strength": "strong" if len(patterns) > 1 else "moderate" if len(patterns) == 1 else "weak"
            }
            
        except Exception as e:
            self.logger.error(f"Error identifying seasonal patterns: {e}")
            return {"error": str(e)}
    
    def _detect_anomalies(self, time_series_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Detect anomalies in time series data"""
        try:
            if len(time_series_data) < 3:
                return {"message": "Insufficient data for anomaly detection", "data_points": len(time_series_data)}
            
            # Calculate daily session counts
            daily_counts = [len(sessions) for sessions in time_series_data.values()]
            
            if len(daily_counts) < 3:
                return {"message": "Need at least 3 data points for anomaly detection"}
            
            # Simple statistical anomaly detection
            mean_count = statistics.mean(daily_counts)
            std_dev = statistics.stdev(daily_counts) if len(daily_counts) > 1 else 0
            
            anomalies = []
            
            # Identify outliers (values beyond 2 standard deviations)
            threshold = 2 * std_dev
            
            for date_str, sessions in time_series_data.items():
                session_count = len(sessions)
                
                if abs(session_count - mean_count) > threshold:
                    anomaly_type = "spike" if session_count > mean_count else "drop"
                    severity = "high" if abs(session_count - mean_count) > 3 * std_dev else "medium"
                    
                    anomalies.append({
                        "date": date_str,
                        "type": anomaly_type,
                        "severity": severity,
                        "session_count": session_count,
                        "expected_range": f"{mean_count - threshold:.1f} - {mean_count + threshold:.1f}",
                        "deviation": abs(session_count - mean_count)
                    })
            
            # Analyze anomaly patterns
            anomaly_analysis = {
                "total_anomalies": len(anomalies),
                "anomaly_rate": (len(anomalies) / len(time_series_data)) * 100,
                "spike_anomalies": len([a for a in anomalies if a["type"] == "spike"]),
                "drop_anomalies": len([a for a in anomalies if a["type"] == "drop"]),
                "high_severity_anomalies": len([a for a in anomalies if a["severity"] == "high"])
            }
            
            return {
                "anomaly_detection": anomaly_analysis,
                "detected_anomalies": anomalies,
                "baseline_statistics": {
                    "mean_daily_sessions": mean_count,
                    "standard_deviation": std_dev,
                    "detection_threshold": threshold
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
            return {"error": str(e)}
    
    def _perform_correlation_analysis(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform correlation analysis"""
        try:
            correlations = []
            
            # Analyze correlations between different factors
            
            # 1. Risk level vs technique count correlation
            risk_technique_pairs = []
            for analysis in data:
                result = analysis.get("result", {})
                risk_level = result.get("risk_assessment", "Low")
                technique_count = len(result.get("techniques", []))
                
                risk_score = {"High": 3, "Medium": 2, "Low": 1}.get(risk_level, 1)
                risk_technique_pairs.append((risk_score, technique_count))
            
            if len(risk_technique_pairs) > 2:
                risk_scores = [pair[0] for pair in risk_technique_pairs]
                technique_counts = [pair[1] for pair in risk_technique_pairs]
                
                # Simple correlation calculation
                correlation = self._calculate_correlation(risk_scores, technique_counts)
                
                correlations.append({
                    "factor_1": "Risk Level",
                    "factor_2": "Technique Count",
                    "correlation_coefficient": correlation,
                    "strength": self._interpret_correlation_strength(correlation),
                    "interpretation": f"Risk level and technique count show {self._interpret_correlation_strength(correlation)} correlation"
                })
            
            # 2. Session duration vs findings count correlation
            duration_findings_pairs = []
            for analysis in data:
                result = analysis.get("result", {})
                duration = result.get("session_duration", 0)
                findings_count = len(result.get("findings", []))
                
                duration_findings_pairs.append((duration, findings_count))
            
            if len(duration_findings_pairs) > 2:
                durations = [pair[0] for pair in duration_findings_pairs]
                findings_counts = [pair[1] for pair in duration_findings_pairs]
                
                correlation = self._calculate_correlation(durations, findings_counts)
                
                correlations.append({
                    "factor_1": "Session Duration",
                    "factor_2": "Findings Count",
                    "correlation_coefficient": correlation,
                    "strength": self._interpret_correlation_strength(correlation),
                    "interpretation": f"Session duration and findings count show {self._interpret_correlation_strength(correlation)} correlation"
                })
            
            # 3. Confidence score vs IOC count correlation
            confidence_ioc_pairs = []
            for analysis in data:
                result = analysis.get("result", {})
                confidence = result.get("confidence_score", 0)
                ioc_count = len(result.get("iocs", []))
                
                confidence_ioc_pairs.append((confidence, ioc_count))
            
            if len(confidence_ioc_pairs) > 2:
                confidences = [pair[0] for pair in confidence_ioc_pairs]
                ioc_counts = [pair[1] for pair in confidence_ioc_pairs]
                
                correlation = self._calculate_correlation(confidences, ioc_counts)
                
                correlations.append({
                    "factor_1": "Confidence Score",
                    "factor_2": "IOC Count",
                    "correlation_coefficient": correlation,
                    "strength": self._interpret_correlation_strength(correlation),
                    "interpretation": f"Confidence score and IOC count show {self._interpret_correlation_strength(correlation)} correlation"
                })
            
            return {
                "correlation_analysis": {
                    "total_correlations_analyzed": len(correlations),
                    "significant_correlations": [c for c in correlations if abs(c["correlation_coefficient"]) > 0.5],
                    "strong_correlations": [c for c in correlations if abs(c["correlation_coefficient"]) > 0.7]
                },
                "correlations": correlations,
                "insights": self._generate_correlation_insights(correlations)
            }
            
        except Exception as e:
            self.logger.error(f"Error performing correlation analysis: {e}")
            return {"error": str(e)}
    
    def _generate_trend_predictions(self, trend_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate trend predictions"""
        try:
            predictions = []
            
            # Analyze volume trends for prediction
            volume_trends = trend_analysis.get("volume_trends", {})
            trend_direction = volume_trends.get("trend", "stable")
            
            if trend_direction == "increasing":
                predictions.append({
                    "prediction_type": "volume",
                    "forecast": "Continued increase in attack volume expected",
                    "confidence": 0.7,
                    "timeframe": "next 7 days",
                    "recommendation": "Prepare for increased monitoring and response capacity"
                })
            elif trend_direction == "decreasing":
                predictions.append({
                    "prediction_type": "volume",
                    "forecast": "Attack volume may continue to decrease",
                    "confidence": 0.6,
                    "timeframe": "next 7 days",
                    "recommendation": "Monitor for potential campaign shifts or new attack vectors"
                })
            
            # Analyze technique trends for prediction
            technique_trends = trend_analysis.get("technique_trends", {})
            trending_techniques = technique_trends.get("trending_techniques", [])
            
            if trending_techniques:
                top_trending = trending_techniques[0] if trending_techniques else {}
                technique_id = top_trending.get("technique_id", "")
                
                predictions.append({
                    "prediction_type": "technique",
                    "forecast": f"Technique {technique_id} likely to remain prominent",
                    "confidence": 0.8,
                    "timeframe": "next 14 days",
                    "recommendation": f"Enhance detection and response capabilities for {technique_id}"
                })
            
            # Seasonal pattern predictions
            seasonal_patterns = trend_analysis.get("seasonal_patterns", {})
            patterns = seasonal_patterns.get("seasonal_patterns", [])
            
            for pattern in patterns:
                if pattern.get("strength") in ["strong", "moderate"]:
                    predictions.append({
                        "prediction_type": "seasonal",
                        "forecast": f"Expected {pattern.get('description', 'pattern')} to continue",
                        "confidence": 0.6,
                        "timeframe": "recurring pattern",
                        "recommendation": "Adjust monitoring and staffing based on predicted activity patterns"
                    })
            
            return {
                "predictions": predictions,
                "prediction_confidence": statistics.mean([p["confidence"] for p in predictions]) if predictions else 0,
                "prediction_summary": f"{len(predictions)} predictions generated based on trend analysis"
            }
            
        except Exception as e:
            self.logger.error(f"Error generating trend predictions: {e}")
            return {"error": str(e)}
    
    def _identify_significant_trends(self, trend_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify significant trends"""
        try:
            significant_trends = []
            
            # Check volume trends
            volume_trends = trend_analysis.get("volume_trends", {})
            if volume_trends.get("trend") in ["increasing", "decreasing"]:
                daily_counts = volume_trends.get("daily_counts", {})
                if daily_counts:
                    counts = list(daily_counts.values())
                    if len(counts) > 1:
                        change_rate = (counts[-1] - counts[0]) / counts[0] * 100 if counts[0] > 0 else 0
                        
                        if abs(change_rate) > 20:  # 20% change threshold
                            significant_trends.append({
                                "trend_type": "volume",
                                "description": f"Attack volume {volume_trends.get('trend')} by {abs(change_rate):.1f}%",
                                "significance": "high" if abs(change_rate) > 50 else "medium",
                                "impact": "Requires immediate attention" if abs(change_rate) > 50 else "Monitor closely"
                            })
            
            # Check technique trends
            technique_trends = trend_analysis.get("technique_trends", {})
            trending_techniques = technique_trends.get("trending_techniques", [])
            
            for technique in trending_techniques[:3]:  # Top 3 trending
                growth_factor = technique.get("growth_factor", 1)
                if growth_factor > 2:  # 100% increase
                    significant_trends.append({
                        "trend_type": "technique",
                        "description": f"Technique {technique.get('technique_id', 'unknown')} showing {growth_factor:.1f}x growth",
                        "significance": "high" if growth_factor > 3 else "medium",
                        "impact": "Enhanced detection required"
                    })
            
            # Check anomaly trends
            anomaly_detection = trend_analysis.get("anomaly_detection", {})
            if anomaly_detection:
                anomaly_rate = anomaly_detection.get("anomaly_rate", 0)
                if anomaly_rate > 20:  # 20% anomaly rate
                    significant_trends.append({
                        "trend_type": "anomaly",
                        "description": f"High anomaly rate detected ({anomaly_rate:.1f}%)",
                        "significance": "high" if anomaly_rate > 40 else "medium",
                        "impact": "Investigate potential campaign or infrastructure changes"
                    })
            
            return significant_trends
            
        except Exception as e:
            self.logger.error(f"Error identifying significant trends: {e}")
            return []
    
    # Helper methods for correlation analysis
    def _calculate_correlation(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        try:
            if len(x_values) != len(y_values) or len(x_values) < 2:
                return 0.0
            
            n = len(x_values)
            sum_x = sum(x_values)
            sum_y = sum(y_values)
            sum_xy = sum(x * y for x, y in zip(x_values, y_values))
            sum_x2 = sum(x * x for x in x_values)
            sum_y2 = sum(y * y for y in y_values)
            
            numerator = n * sum_xy - sum_x * sum_y
            denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)) ** 0.5
            
            if denominator == 0:
                return 0.0
            
            return numerator / denominator
            
        except Exception:
            return 0.0
    
    def _interpret_correlation_strength(self, correlation: float) -> str:
        """Interpret correlation strength"""
        abs_corr = abs(correlation)
        
        if abs_corr > 0.8:
            return "very strong"
        elif abs_corr > 0.6:
            return "strong"
        elif abs_corr > 0.4:
            return "moderate"
        elif abs_corr > 0.2:
            return "weak"
        else:
            return "very weak"
    
    def _generate_correlation_insights(self, correlations: List[Dict[str, Any]]) -> List[str]:
        """Generate insights from correlation analysis"""
        insights = []
        
        strong_correlations = [c for c in correlations if abs(c["correlation_coefficient"]) > 0.6]
        
        if strong_correlations:
            insights.append(f"Found {len(strong_correlations)} strong correlations that can inform detection strategies")
        
        for correlation in strong_correlations:
            factor1 = correlation["factor_1"]
            factor2 = correlation["factor_2"]
            strength = correlation["strength"]
            
            insights.append(f"{factor1} and {factor2} show {strength} correlation, indicating predictable relationships")
        
        return insights
    
    def _identify_peak_activity_period(self, timestamps: List[datetime]) -> Dict[str, Any]:
        """Identify peak activity period from timestamps"""
        try:
            if not timestamps:
                return {"message": "No timestamps provided"}
            
            # Group by hour
            hourly_counts = defaultdict(int)
            for timestamp in timestamps:
                hour = timestamp.hour
                hourly_counts[hour] += 1
            
            if not hourly_counts:
                return {"message": "No valid hours found"}
            
            peak_hour = max(hourly_counts, key=hourly_counts.get)
            peak_count = hourly_counts[peak_hour]
            
            return {
                "peak_hour": f"{peak_hour:02d}:00",
                "activity_count": peak_count,
                "percentage_of_total": (peak_count / len(timestamps)) * 100
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    # External platform integration methods
    def _export_to_stix(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Export intelligence data to STIX format"""
        try:
            # Generate STIX 2.1 bundle
            stix_bundle = {
                "type": "bundle",
                "id": f"bundle--{str(uuid4())}",
                "spec_version": "2.1",
                "objects": []
            }
            
            # Add indicator objects for IOCs
            iocs = data.get("iocs", [])
            for ioc in iocs:
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{str(uuid4())}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "pattern": f"[{ioc.get('type', 'unknown')}:value = '{ioc.get('value', '')}']",
                    "labels": ["malicious-activity"],
                    "confidence": int(ioc.get("confidence", 0) * 100)
                }
                stix_bundle["objects"].append(indicator)
            
            return {
                "status": "success",
                "format": "STIX 2.1",
                "objects_count": len(stix_bundle["objects"]),
                "bundle": stix_bundle
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _export_to_misp(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Export intelligence data to MISP format"""
        try:
            if not config.get("enabled", False):
                return {"status": "disabled", "message": "MISP integration is disabled"}
            
            # Generate MISP event structure
            misp_event = {
                "Event": {
                    "info": f"Honeypot Intelligence - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
                    "threat_level_id": "2",  # Medium
                    "analysis": "1",  # Ongoing
                    "distribution": "1",  # This community only
                    "published": False,
                    "Attribute": []
                }
            }
            
            # Add IOCs as attributes
            iocs = data.get("iocs", [])
            for ioc in iocs:
                ioc_type = ioc.get("type", "")
                ioc_value = ioc.get("value", "")
                confidence = ioc.get("confidence", 0)
                
                # Map IOC types to MISP attribute types
                misp_type_mapping = {
                    "ip_address": "ip-dst",
                    "domain": "domain",
                    "url": "url",
                    "file_hash": "md5",
                    "email": "email-dst"
                }
                
                misp_type = misp_type_mapping.get(ioc_type, "other")
                
                attribute = {
                    "type": misp_type,
                    "value": ioc_value,
                    "category": "Network activity",
                    "to_ids": confidence > 0.8,  # Only high-confidence IOCs for detection
                    "comment": f"Honeypot detection - Confidence: {confidence:.2f}",
                    "distribution": "1"
                }
                
                misp_event["Event"]["Attribute"].append(attribute)
            
            # Add techniques as attributes
            techniques = data.get("techniques", [])
            for technique in techniques:
                technique_id = technique.get("technique_id", "")
                technique_name = technique.get("technique_name", "")
                
                if technique_id:
                    attribute = {
                        "type": "text",
                        "value": f"MITRE ATT&CK: {technique_id} - {technique_name}",
                        "category": "Attribution",
                        "to_ids": False,
                        "comment": f"Observed technique - Tactic: {technique.get('tactic', 'Unknown')}",
                        "distribution": "1"
                    }
                    
                    misp_event["Event"]["Attribute"].append(attribute)
            
            return {
                "status": "success",
                "format": "MISP Event",
                "attributes_count": len(misp_event["Event"]["Attribute"]),
                "misp_event": misp_event,
                "export_summary": f"Generated MISP event with {len(misp_event['Event']['Attribute'])} attributes"
            }
            
        except Exception as e:
            self.logger.error(f"Error exporting to MISP: {e}")
            return {"status": "error", "message": str(e)}
    
    def _export_to_opencti(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Export intelligence data to OpenCTI format"""
        try:
            if not config.get("enabled", False):
                return {"status": "disabled", "message": "OpenCTI integration is disabled"}
            
            # Generate OpenCTI bundle structure
            opencti_bundle = {
                "type": "bundle",
                "id": f"bundle--{str(uuid4())}",
                "objects": []
            }
            
            # Create incident object
            incident = {
                "type": "incident",
                "id": f"incident--{str(uuid4())}",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": f"Honeypot Intelligence Incident - {datetime.utcnow().strftime('%Y-%m-%d')}",
                "description": "Intelligence gathered from honeypot interactions",
                "labels": ["honeypot", "threat-intelligence"]
            }
            opencti_bundle["objects"].append(incident)
            
            # Add indicators for IOCs
            iocs = data.get("iocs", [])
            for ioc in iocs:
                ioc_type = ioc.get("type", "")
                ioc_value = ioc.get("value", "")
                confidence = ioc.get("confidence", 0)
                
                # Map IOC types to OpenCTI patterns
                pattern_mapping = {
                    "ip_address": f"[ipv4-addr:value = '{ioc_value}']",
                    "domain": f"[domain-name:value = '{ioc_value}']",
                    "url": f"[url:value = '{ioc_value}']",
                    "file_hash": f"[file:hashes.MD5 = '{ioc_value}']",
                    "email": f"[email-addr:value = '{ioc_value}']"
                }
                
                pattern = pattern_mapping.get(ioc_type, f"[x-custom:value = '{ioc_value}']")
                
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{str(uuid4())}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "pattern": pattern,
                    "labels": ["malicious-activity"],
                    "confidence": int(confidence * 100),
                    "description": f"IOC detected in honeypot - Type: {ioc_type}"
                }
                opencti_bundle["objects"].append(indicator)
            
            # Add attack patterns for techniques
            techniques = data.get("techniques", [])
            for technique in techniques:
                technique_id = technique.get("technique_id", "")
                technique_name = technique.get("technique_name", "")
                
                if technique_id:
                    attack_pattern = {
                        "type": "attack-pattern",
                        "id": f"attack-pattern--{str(uuid4())}",
                        "created": datetime.utcnow().isoformat() + "Z",
                        "modified": datetime.utcnow().isoformat() + "Z",
                        "name": technique_name or technique_id,
                        "description": f"MITRE ATT&CK technique {technique_id} observed in honeypot",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": technique_id,
                                "url": f"https://attack.mitre.org/techniques/{technique_id}/"
                            }
                        ]
                    }
                    opencti_bundle["objects"].append(attack_pattern)
            
            return {
                "status": "success",
                "format": "OpenCTI Bundle",
                "objects_count": len(opencti_bundle["objects"]),
                "opencti_bundle": opencti_bundle,
                "export_summary": f"Generated OpenCTI bundle with {len(opencti_bundle['objects'])} objects"
            }
            
        except Exception as e:
            self.logger.error(f"Error exporting to OpenCTI: {e}")
            return {"status": "error", "message": str(e)}
    
    def _export_to_taxii(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Export intelligence data to TAXII server"""
        try:
            if not config.get("enabled", False):
                return {"status": "disabled", "message": "TAXII integration is disabled"}
            
            # Generate TAXII collection manifest
            taxii_manifest = {
                "manifest": {
                    "collection_id": config.get("collection_id", "honeypot-intelligence"),
                    "objects": []
                }
            }
            
            # Create STIX bundle for TAXII
            stix_result = self._export_to_stix(data, {"enabled": True, "format_version": "2.1"})
            
            if stix_result.get("status") == "success":
                stix_bundle = stix_result.get("bundle", {})
                
                # Add objects to TAXII manifest
                for obj in stix_bundle.get("objects", []):
                    manifest_entry = {
                        "id": obj.get("id", ""),
                        "date_added": datetime.utcnow().isoformat() + "Z",
                        "version": "1",
                        "media_type": "application/stix+json;version=2.1"
                    }
                    taxii_manifest["manifest"]["objects"].append(manifest_entry)
                
                # Prepare TAXII envelope
                taxii_envelope = {
                    "envelope": {
                        "more": False,
                        "objects": stix_bundle.get("objects", [])
                    }
                }
                
                return {
                    "status": "success",
                    "format": "TAXII 2.1",
                    "collection_id": config.get("collection_id", "honeypot-intelligence"),
                    "objects_count": len(taxii_manifest["manifest"]["objects"]),
                    "taxii_manifest": taxii_manifest,
                    "taxii_envelope": taxii_envelope,
                    "export_summary": f"Prepared TAXII collection with {len(taxii_manifest['manifest']['objects'])} objects"
                }
            else:
                return {
                    "status": "error",
                    "message": "Failed to generate STIX bundle for TAXII export"
                }
            
        except Exception as e:
            self.logger.error(f"Error exporting to TAXII: {e}")
            return {"status": "error", "message": str(e)}
    
    def _generate_sharing_recommendations(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for sharing intelligence"""
        recommendations = []
        
        # Analyze data sensitivity
        iocs = data.get("iocs", [])
        high_confidence_iocs = [ioc for ioc in iocs if ioc.get("confidence", 0) > 0.8]
        
        if high_confidence_iocs:
            recommendations.append({
                "platform": "STIX",
                "data_type": "IOCs",
                "priority": "High",
                "reason": f"{len(high_confidence_iocs)} high-confidence IOCs suitable for sharing"
            })
        
        return recommendations
    
    # Utility helper methods
    def _calculate_time_span(self, data: List[Dict[str, Any]]) -> int:
        """Calculate time span of data in days"""
        try:
            timestamps = []
            for item in data:
                try:
                    ts = datetime.fromisoformat(item.get("start_time", ""))
                    timestamps.append(ts)
                except Exception:
                    continue
            
            if len(timestamps) >= 2:
                return (max(timestamps) - min(timestamps)).days
            else:
                return 0
                
        except Exception:
            return 0
    
    def _get_most_common_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get most common techniques with counts"""
        technique_counts = Counter()
        
        for tech in techniques:
            technique_id = tech.get("technique_id", "Unknown")
            technique_name = tech.get("technique_name", "Unknown")
            technique_counts[(technique_id, technique_name)] += 1
        
        return [
            {"technique_id": tech_id, "technique_name": tech_name, "count": count}
            for (tech_id, tech_name), count in technique_counts.most_common(10)
        ]
    
    def _prioritize_recommendations(self, recommendation_counts: Counter) -> List[Dict[str, Any]]:
        """Prioritize recommendations based on frequency and impact"""
        priority_actions = []
        
        for rec, count in recommendation_counts.most_common(5):
            # Simple prioritization logic
            if "critical" in rec.lower() or "immediate" in rec.lower():
                priority = "Critical"
            elif count > 3:
                priority = "High"
            elif count > 1:
                priority = "Medium"
            else:
                priority = "Low"
            
            priority_actions.append({
                "recommendation": rec,
                "priority": priority,
                "frequency": count
            })
        
        return priority_actions
    
    def _calculate_kill_chain_coverage(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate kill chain coverage from techniques"""
        kill_chain_phases = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Exfiltration",
            "Command and Control"
        ]
        
        observed_phases = set()
        for tech in techniques:
            tactic = tech.get("tactic", "")
            if tactic in kill_chain_phases:
                observed_phases.add(tactic)
        
        coverage_percentage = (len(observed_phases) / len(kill_chain_phases)) * 100
        
        return {
            "covered_phases": list(observed_phases),
            "total_phases": len(kill_chain_phases),
            "coverage_percentage": coverage_percentage,
            "missing_phases": [p for p in kill_chain_phases if p not in observed_phases]
        }
    
    def _categorize_recommendation(self, recommendation: str) -> str:
        """Categorize recommendation by type"""
        rec_lower = recommendation.lower()
        
        if any(word in rec_lower for word in ["monitor", "detection", "alert"]):
            return "Detection"
        elif any(word in rec_lower for word in ["patch", "update", "fix"]):
            return "Prevention"
        elif any(word in rec_lower for word in ["investigate", "analyze", "review"]):
            return "Investigation"
        elif any(word in rec_lower for word in ["block", "restrict", "deny"]):
            return "Containment"
        else:
            return "General"
    
    def _get_executive_recommendations(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get executive-level recommendations"""
        return [
            {
                "recommendation": "Increase security monitoring based on observed threat activity",
                "priority": "High",
                "category": "Strategic",
                "justification": "Multiple attack techniques observed across honeypot infrastructure"
            }
        ]
    
    def _get_incident_response_recommendations(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get incident response recommendations"""
        return [
            {
                "recommendation": "Activate incident response procedures for high-risk sessions",
                "priority": "Critical",
                "category": "Response",
                "justification": "High-risk attack activity detected requiring immediate response"
            }
        ] 
   
    # Summary generation methods
    def _generate_key_statistics(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate key statistics from analysis data"""
        try:
            stats = {
                "total_sessions": len(data),
                "high_risk_sessions": 0,
                "medium_risk_sessions": 0,
                "low_risk_sessions": 0,
                "total_techniques": 0,
                "unique_techniques": set(),
                "total_findings": 0,
                "high_confidence_findings": 0
            }
            
            for analysis in data:
                result = analysis.get("result", {})
                
                # Risk level counts
                risk_level = result.get("risk_assessment", "Low")
                if risk_level == "High":
                    stats["high_risk_sessions"] += 1
                elif risk_level == "Medium":
                    stats["medium_risk_sessions"] += 1
                else:
                    stats["low_risk_sessions"] += 1
                
                # Technique counts
                techniques = result.get("techniques", [])
                stats["total_techniques"] += len(techniques)
                for technique in techniques:
                    stats["unique_techniques"].add(technique.get("technique_id", ""))
                
                # Finding counts
                findings = result.get("findings", [])
                stats["total_findings"] += len(findings)
                high_conf_findings = [f for f in findings if f.get("confidence", 0) > 0.8]
                stats["high_confidence_findings"] += len(high_conf_findings)
            
            # Convert set to count
            stats["unique_techniques"] = len(stats["unique_techniques"])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating key statistics: {e}")
            return {}
    
    def _analyze_threat_landscape(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the threat landscape from analysis data"""
        try:
            landscape = {
                "threat_distribution": Counter(),
                "attack_vectors": Counter(),
                "geographic_distribution": Counter(),
                "temporal_patterns": {},
                "emerging_threats": []
            }
            
            for analysis in data:
                result = analysis.get("result", {})
                metadata = analysis.get("metadata", {})
                
                # Threat distribution
                risk_level = result.get("risk_assessment", "Low")
                landscape["threat_distribution"][risk_level] += 1
                
                # Attack vectors (honeypot types)
                honeypot_type = metadata.get("honeypot_type", "unknown")
                landscape["attack_vectors"][honeypot_type] += 1
                
                # Geographic distribution (simplified)
                source_ip = metadata.get("source_ip", "")
                if source_ip:
                    # Simplified geographic mapping
                    if source_ip.startswith("192.168"):
                        geo = "Internal"
                    elif source_ip.startswith("10."):
                        geo = "Private"
                    else:
                        geo = "External"
                    landscape["geographic_distribution"][geo] += 1
            
            # Convert Counters to dicts
            landscape["threat_distribution"] = dict(landscape["threat_distribution"])
            landscape["attack_vectors"] = dict(landscape["attack_vectors"])
            landscape["geographic_distribution"] = dict(landscape["geographic_distribution"])
            
            return landscape
            
        except Exception as e:
            self.logger.error(f"Error analyzing threat landscape: {e}")
            return {}
    
    def _extract_top_findings(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract top findings from analysis data"""
        try:
            all_findings = []
            
            for analysis in data:
                result = analysis.get("result", {})
                findings = result.get("findings", [])
                
                for finding in findings:
                    # Add session context
                    finding_with_context = dict(finding)
                    finding_with_context["session_id"] = analysis.get("session_id", "")
                    finding_with_context["analysis_timestamp"] = analysis.get("start_time", "")
                    all_findings.append(finding_with_context)
            
            # Sort by confidence and severity
            def finding_priority(finding):
                confidence = finding.get("confidence", 0)
                severity = finding.get("severity", "Low")
                severity_weight = {"High": 3, "Medium": 2, "Low": 1}.get(severity, 1)
                return confidence * severity_weight
            
            sorted_findings = sorted(all_findings, key=finding_priority, reverse=True)
            
            return sorted_findings[:10]  # Top 10 findings
            
        except Exception as e:
            self.logger.error(f"Error extracting top findings: {e}")
            return []
    
    def _identify_trend_indicators(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify trend indicators from analysis data"""
        try:
            indicators = {
                "increasing_activity": False,
                "new_techniques": [],
                "recurring_patterns": [],
                "threat_evolution": {}
            }
            
            if len(data) < 5:
                return indicators
            
            # Analyze activity trends (simplified)
            recent_data = data[-5:]  # Last 5 analyses
            older_data = data[:-5] if len(data) > 5 else []
            
            if older_data:
                recent_avg_risk = sum(1 for a in recent_data if a.get("result", {}).get("risk_assessment") == "High") / len(recent_data)
                older_avg_risk = sum(1 for a in older_data if a.get("result", {}).get("risk_assessment") == "High") / len(older_data)
                
                indicators["increasing_activity"] = recent_avg_risk > older_avg_risk
            
            # Identify new techniques (techniques not seen in older data)
            if older_data:
                older_techniques = set()
                for analysis in older_data:
                    techniques = analysis.get("result", {}).get("techniques", [])
                    for technique in techniques:
                        older_techniques.add(technique.get("technique_id", ""))
                
                recent_techniques = set()
                for analysis in recent_data:
                    techniques = analysis.get("result", {}).get("techniques", [])
                    for technique in techniques:
                        recent_techniques.add(technique.get("technique_id", ""))
                
                indicators["new_techniques"] = list(recent_techniques - older_techniques)
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"Error identifying trend indicators: {e}")
            return {}
    
    def _assess_overall_risk(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk from analysis data"""
        try:
            if not data:
                return {"level": "Low", "score": 0.0, "factors": []}
            
            risk_scores = []
            risk_factors = []
            
            for analysis in data:
                result = analysis.get("result", {})
                
                # Convert risk assessment to numeric score
                risk_level = result.get("risk_assessment", "Low")
                risk_score = {"High": 0.9, "Medium": 0.6, "Low": 0.3}.get(risk_level, 0.3)
                risk_scores.append(risk_score)
                
                # Collect risk factors
                techniques = result.get("techniques", [])
                if len(techniques) > 5:
                    risk_factors.append("High technique count")
                
                findings = result.get("findings", [])
                high_conf_findings = [f for f in findings if f.get("confidence", 0) > 0.8]
                if len(high_conf_findings) > 3:
                    risk_factors.append("Multiple high-confidence findings")
            
            # Calculate overall risk
            avg_risk_score = sum(risk_scores) / len(risk_scores)
            
            if avg_risk_score > 0.7:
                overall_level = "High"
            elif avg_risk_score > 0.5:
                overall_level = "Medium"
            else:
                overall_level = "Low"
            
            return {
                "level": overall_level,
                "score": avg_risk_score,
                "factors": list(set(risk_factors)),
                "session_count": len(data)
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing overall risk: {e}")
            return {"level": "Unknown", "score": 0.0, "factors": []}
    
    def _generate_actionable_insights(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate actionable insights from analysis data"""
        try:
            insights = []
            
            # Analyze common attack patterns
            all_techniques = []
            for analysis in data:
                result = analysis.get("result", {})
                techniques = result.get("techniques", [])
                all_techniques.extend(techniques)
            
            # Most common techniques
            technique_counts = Counter(t.get("technique_id", "") for t in all_techniques)
            if technique_counts:
                most_common = technique_counts.most_common(1)[0]
                insights.append({
                    "type": "pattern",
                    "title": "Most Common Attack Technique",
                    "description": f"Technique {most_common[0]} observed in {most_common[1]} sessions",
                    "recommendation": f"Implement specific defenses against {most_common[0]}",
                    "priority": "High" if most_common[1] > len(data) * 0.5 else "Medium"
                })
            
            # Attack vector analysis
            attack_vectors = Counter()
            for analysis in data:
                honeypot_type = analysis.get("metadata", {}).get("honeypot_type", "unknown")
                attack_vectors[honeypot_type] += 1
            
            if attack_vectors:
                top_vector = attack_vectors.most_common(1)[0]
                insights.append({
                    "type": "vector",
                    "title": "Primary Attack Vector",
                    "description": f"{top_vector[0]} honeypots targeted in {top_vector[1]} sessions",
                    "recommendation": f"Strengthen {top_vector[0]} security controls",
                    "priority": "High"
                })
            
            # Risk trend analysis
            high_risk_count = sum(1 for a in data if a.get("result", {}).get("risk_assessment") == "High")
            if high_risk_count > len(data) * 0.3:
                insights.append({
                    "type": "trend",
                    "title": "High Risk Activity Trend",
                    "description": f"{high_risk_count} of {len(data)} sessions classified as high risk",
                    "recommendation": "Implement additional monitoring and response capabilities",
                    "priority": "High"
                })
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Error generating actionable insights: {e}")
            return []
    
    def _generate_summary_narrative(self, summary: Dict[str, Any]) -> str:
        """Generate narrative summary from summary data"""
        try:
            key_stats = summary.get("key_statistics", {})
            threat_landscape = summary.get("threat_landscape", {})
            risk_assessment = summary.get("risk_assessment", {})
            
            total_sessions = key_stats.get("total_sessions", 0)
            high_risk_sessions = key_stats.get("high_risk_sessions", 0)
            unique_techniques = key_stats.get("unique_techniques", 0)
            
            narrative = f"Analysis of {total_sessions} honeypot sessions revealed "
            
            if high_risk_sessions > 0:
                risk_percentage = (high_risk_sessions / total_sessions) * 100 if total_sessions > 0 else 0
                narrative += f"{high_risk_sessions} high-risk engagements ({risk_percentage:.1f}%). "
            else:
                narrative += "no high-risk engagements. "
            
            if unique_techniques > 0:
                narrative += f"Attackers employed {unique_techniques} distinct MITRE ATT&CK techniques, "
            
            overall_risk = risk_assessment.get("level", "Unknown")
            narrative += f"resulting in an overall risk assessment of {overall_risk}. "
            
            # Add threat landscape insights
            threat_dist = threat_landscape.get("threat_distribution", {})
            if threat_dist:
                dominant_threat = max(threat_dist.items(), key=lambda x: x[1])
                narrative += f"The threat landscape is dominated by {dominant_threat[0].lower()}-risk activities."
            
            return narrative
            
        except Exception as e:
            self.logger.error(f"Error generating summary narrative: {e}")
            return "Summary narrative generation failed."
    
    # Helper methods for report generation
    def _get_most_common_techniques(self, techniques: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get most common techniques from technique list"""
        technique_counts = Counter()
        
        for technique in techniques:
            tech_id = technique.get("technique_id", "")
            if tech_id:
                technique_counts[tech_id] += 1
        
        return dict(technique_counts.most_common(5))
    
    def _prioritize_recommendations(self, recommendation_counts: Counter) -> List[Dict[str, Any]]:
        """Prioritize recommendations based on frequency and importance"""
        prioritized = []
        
        for recommendation, count in recommendation_counts.most_common(10):
            priority = "High" if count > 5 else "Medium" if count > 2 else "Low"
            
            prioritized.append({
                "recommendation": recommendation,
                "frequency": count,
                "priority": priority,
                "category": self._categorize_recommendation(recommendation)
            })
        
        return prioritized
    
    def _categorize_recommendation(self, recommendation: str) -> str:
        """Categorize a recommendation"""
        recommendation_lower = recommendation.lower()
        
        if any(keyword in recommendation_lower for keyword in ["monitor", "log", "detect"]):
            return "Monitoring"
        elif any(keyword in recommendation_lower for keyword in ["access", "privilege", "permission"]):
            return "Access Control"
        elif any(keyword in recommendation_lower for keyword in ["patch", "update", "upgrade"]):
            return "Patch Management"
        elif any(keyword in recommendation_lower for keyword in ["network", "firewall", "segment"]):
            return "Network Security"
        else:
            return "General Security"
    
    # Helper methods for detailed section generation
    def _identify_cross_session_patterns(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify patterns across multiple sessions"""
        patterns = []
        
        # Group findings by type
        findings_by_type = defaultdict(list)
        for finding in findings:
            finding_type = finding.get("type", "unknown")
            findings_by_type[finding_type].append(finding)
        
        # Look for patterns
        for finding_type, type_findings in findings_by_type.items():
            if len(type_findings) > 1:
                sessions = set(f.get("session_id", "") for f in type_findings)
                if len(sessions) > 1:
                    patterns.append({
                        "pattern_type": "cross_session_finding",
                        "finding_type": finding_type,
                        "occurrences": len(type_findings),
                        "affected_sessions": len(sessions),
                        "confidence": statistics.mean([f.get("confidence", 0) for f in type_findings])
                    })
        
        return patterns
    
    def _analyze_finding_temporal_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal distribution of findings"""
        try:
            timestamps = []
            for finding in findings:
                timestamp_str = finding.get("analysis_timestamp", "")
                if timestamp_str:
                    try:
                        timestamps.append(datetime.fromisoformat(timestamp_str))
                    except Exception:
                        continue
            
            if not timestamps:
                return {"message": "No valid timestamps found"}
            
            # Analyze distribution
            timestamps.sort()
            time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600  # hours
            
            return {
                "total_findings": len(findings),
                "time_span_hours": time_span,
                "findings_per_hour": len(findings) / time_span if time_span > 0 else 0,
                "peak_activity_period": self._identify_peak_activity_period(timestamps),
                "temporal_clustering": len(timestamps) > 1
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_finding_confidence_distribution(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze confidence score distribution of findings"""
        confidence_scores = [f.get("confidence", 0) for f in findings if f.get("confidence") is not None]
        
        if not confidence_scores:
            return {"message": "No confidence scores available"}
        
        return {
            "average_confidence": statistics.mean(confidence_scores),
            "median_confidence": statistics.median(confidence_scores),
            "high_confidence_count": len([c for c in confidence_scores if c > 0.8]),
            "medium_confidence_count": len([c for c in confidence_scores if 0.5 <= c <= 0.8]),
            "low_confidence_count": len([c for c in confidence_scores if c < 0.5]),
            "confidence_distribution": {
                "0.0-0.2": len([c for c in confidence_scores if 0.0 <= c < 0.2]),
                "0.2-0.4": len([c for c in confidence_scores if 0.2 <= c < 0.4]),
                "0.4-0.6": len([c for c in confidence_scores if 0.4 <= c < 0.6]),
                "0.6-0.8": len([c for c in confidence_scores if 0.6 <= c < 0.8]),
                "0.8-1.0": len([c for c in confidence_scores if 0.8 <= c <= 1.0])
            }
        }
    
    def _correlate_iocs_across_sessions(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate IOCs across different sessions"""
        correlations = []
        
        # Group IOCs by value
        ioc_groups = defaultdict(list)
        for ioc in iocs:
            value = ioc.get("value", "")
            if value:
                ioc_groups[value].append(ioc)
        
        # Find correlations
        for ioc_value, ioc_list in ioc_groups.items():
            if len(ioc_list) > 1:
                sessions = set(ioc.get("session_id", "") for ioc in ioc_list)
                if len(sessions) > 1:
                    correlations.append({
                        "ioc_value": ioc_value,
                        "ioc_type": ioc_list[0].get("type", "unknown"),
                        "occurrences": len(ioc_list),
                        "affected_sessions": len(sessions),
                        "average_confidence": statistics.mean([ioc.get("confidence", 0) for ioc in ioc_list])
                    })
        
        return {
            "total_correlations": len(correlations),
            "correlated_iocs": correlations,
            "correlation_strength": "High" if len(correlations) > 5 else "Medium" if len(correlations) > 2 else "Low"
        }
    
    def _identify_peak_incident_period(self, incident_timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify peak incident period"""
        if not incident_timeline:
            return {"message": "No incidents to analyze"}
        
        # Group incidents by hour
        hourly_incidents = defaultdict(int)
        
        for incident in incident_timeline:
            try:
                timestamp = datetime.fromisoformat(incident.get("start_time", ""))
                hour_key = timestamp.strftime("%H:00")
                hourly_incidents[hour_key] += 1
            except Exception:
                continue
        
        if not hourly_incidents:
            return {"message": "No valid timestamps"}
        
        peak_hour = max(hourly_incidents, key=hourly_incidents.get)
        peak_count = hourly_incidents[peak_hour]
        
        return {
            "peak_hour": peak_hour,
            "incident_count": peak_count,
            "percentage_of_total": (peak_count / len(incident_timeline)) * 100
        }
    
    def _assess_incident_severity(self, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall incident severity"""
        if not incidents:
            return {"overall_severity": "None", "assessment": "No incidents detected"}
        
        # Analyze incident characteristics
        high_confidence_incidents = len([i for i in incidents if i.get("result", {}).get("confidence_score", 0) > 0.8])
        multi_technique_incidents = len([i for i in incidents if len(i.get("result", {}).get("techniques", [])) > 3])
        
        severity_score = 0
        severity_score += len(incidents) * 2  # Base score for incident count
        severity_score += high_confidence_incidents * 3  # High confidence incidents
        severity_score += multi_technique_incidents * 2  # Complex incidents
        
        if severity_score > 20:
            overall_severity = "Critical"
        elif severity_score > 10:
            overall_severity = "High"
        elif severity_score > 5:
            overall_severity = "Medium"
        else:
            overall_severity = "Low"
        
        return {
            "overall_severity": overall_severity,
            "severity_score": severity_score,
            "high_confidence_incidents": high_confidence_incidents,
            "multi_technique_incidents": multi_technique_incidents,
            "assessment": f"{len(incidents)} incidents with {overall_severity.lower()} overall severity"
        }
    
    def _analyze_activity_patterns(self, timeline_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze activity patterns in timeline"""
        patterns = {
            "session_patterns": defaultdict(int),
            "technique_patterns": defaultdict(int),
            "hourly_distribution": defaultdict(int)
        }
        
        for event in timeline_events:
            event_type = event.get("event_type", "")
            patterns["session_patterns"][event_type] += 1
            
            if event_type == "technique_observed":
                tactic = event.get("tactic", "unknown")
                patterns["technique_patterns"][tactic] += 1
            
            try:
                timestamp = datetime.fromisoformat(event.get("timestamp", ""))
                hour = timestamp.hour
                patterns["hourly_distribution"][hour] += 1
            except Exception:
                continue
        
        return {
            "event_type_distribution": dict(patterns["session_patterns"]),
            "tactic_distribution": dict(patterns["technique_patterns"]),
            "hourly_activity": dict(patterns["hourly_distribution"]),
            "peak_activity_hour": max(patterns["hourly_distribution"], key=patterns["hourly_distribution"].get) if patterns["hourly_distribution"] else None
        }
    
    def _analyze_attack_progression(self, timeline_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack progression through timeline"""
        progressions = []
        
        # Group events by session
        session_events = defaultdict(list)
        for event in timeline_events:
            session_id = event.get("session_id", "")
            if session_id:
                session_events[session_id].append(event)
        
        # Analyze progression for each session
        for session_id, events in session_events.items():
            events.sort(key=lambda x: x.get("timestamp", ""))
            
            techniques = [e for e in events if e.get("event_type") == "technique_observed"]
            if len(techniques) > 1:
                tactics_sequence = [t.get("tactic", "") for t in techniques]
                progressions.append({
                    "session_id": session_id,
                    "technique_count": len(techniques),
                    "tactics_sequence": tactics_sequence,
                    "progression_complexity": len(set(tactics_sequence))
                })
        
        return {
            "session_progressions": progressions,
            "average_techniques_per_session": statistics.mean([p["technique_count"] for p in progressions]) if progressions else 0,
            "most_complex_session": max(progressions, key=lambda x: x["progression_complexity"]) if progressions else None
        }
    
    def _identify_temporal_clusters(self, timeline_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify temporal clusters of activity"""
        try:
            timestamps = []
            for event in timeline_events:
                try:
                    timestamp = datetime.fromisoformat(event.get("timestamp", ""))
                    timestamps.append(timestamp)
                except Exception:
                    continue
            
            if len(timestamps) < 2:
                return {"message": "Insufficient data for clustering"}
            
            timestamps.sort()
            
            # Simple clustering based on time gaps
            clusters = []
            current_cluster = [timestamps[0]]
            
            for i in range(1, len(timestamps)):
                time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                
                if time_diff < 3600:  # 1 hour threshold
                    current_cluster.append(timestamps[i])
                else:
                    if len(current_cluster) > 1:
                        clusters.append(current_cluster)
                    current_cluster = [timestamps[i]]
            
            if len(current_cluster) > 1:
                clusters.append(current_cluster)
            
            return {
                "cluster_count": len(clusters),
                "largest_cluster_size": max(len(cluster) for cluster in clusters) if clusters else 0,
                "clustering_detected": len(clusters) > 0
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _assess_business_impact(self, impact_factors: Dict[str, int], high_impact_sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess potential business impact"""
        impact_score = 0
        impact_areas = []
        
        # Calculate impact based on factors
        if impact_factors.get("data_access_attempts", 0) > 0:
            impact_score += impact_factors["data_access_attempts"] * 3
            impact_areas.append("Data confidentiality at risk")
        
        if impact_factors.get("privilege_escalation_attempts", 0) > 0:
            impact_score += impact_factors["privilege_escalation_attempts"] * 4
            impact_areas.append("System integrity compromised")
        
        if impact_factors.get("persistence_mechanisms", 0) > 0:
            impact_score += impact_factors["persistence_mechanisms"] * 3
            impact_areas.append("Long-term access established")
        
        if impact_factors.get("lateral_movement_indicators", 0) > 0:
            impact_score += impact_factors["lateral_movement_indicators"] * 4
            impact_areas.append("Network propagation risk")
        
        if impact_factors.get("exfiltration_attempts", 0) > 0:
            impact_score += impact_factors["exfiltration_attempts"] * 5
            impact_areas.append("Data loss potential")
        
        # Determine business impact level
        if impact_score > 20:
            business_impact = "Critical"
            financial_impact = "High - Potential for significant financial losses"
        elif impact_score > 10:
            business_impact = "High"
            financial_impact = "Medium - Moderate financial impact expected"
        elif impact_score > 5:
            business_impact = "Medium"
            financial_impact = "Low - Limited financial impact"
        else:
            business_impact = "Low"
            financial_impact = "Minimal - No significant financial impact expected"
        
        return {
            "business_impact_level": business_impact,
            "impact_score": impact_score,
            "affected_areas": impact_areas,
            "financial_impact_assessment": financial_impact,
            "high_impact_session_count": len(high_impact_sessions)
        }
    
    def _determine_mitigation_urgency(self, overall_impact: str, impact_factors: Dict[str, int]) -> Dict[str, Any]:
        """Determine mitigation urgency"""
        urgency_factors = []
        
        if overall_impact in ["Critical", "High"]:
            urgency_factors.append("High impact level detected")
        
        if impact_factors.get("exfiltration_attempts", 0) > 0:
            urgency_factors.append("Data exfiltration attempts observed")
        
        if impact_factors.get("persistence_mechanisms", 0) > 2:
            urgency_factors.append("Multiple persistence mechanisms detected")
        
        if impact_factors.get("lateral_movement_indicators", 0) > 0:
            urgency_factors.append("Lateral movement indicators present")
        
        # Determine urgency level
        if len(urgency_factors) > 2 or overall_impact == "Critical":
            urgency = "Immediate"
            timeline = "Within 1 hour"
        elif len(urgency_factors) > 1 or overall_impact == "High":
            urgency = "High"
            timeline = "Within 4 hours"
        elif len(urgency_factors) > 0 or overall_impact == "Medium":
            urgency = "Medium"
            timeline = "Within 24 hours"
        else:
            urgency = "Low"
            timeline = "Within 1 week"
        
        return {
            "urgency_level": urgency,
            "recommended_timeline": timeline,
            "urgency_factors": urgency_factors,
            "justification": f"{urgency} urgency due to {len(urgency_factors)} critical factors"
        }
    
    def _parse_time_estimate(self, time_str: str) -> int:
        """Parse time estimate string to minutes"""
        try:
            if "hour" in time_str:
                hours = int(time_str.split()[0])
                return hours * 60
            elif "minute" in time_str:
                minutes = int(time_str.split()[0])
                return minutes
            else:
                return 0
        except Exception:
            return 0
    
    def _assess_containment_effectiveness(self, containment_actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess effectiveness of containment plan"""
        effectiveness_score = 0
        
        # Score based on action types and priorities
        for action in containment_actions:
            priority = action.get("priority", "Low")
            action_type = action.get("action_type", "")
            
            if priority == "Critical":
                effectiveness_score += 4
            elif priority == "High":
                effectiveness_score += 3
            elif priority == "Medium":
                effectiveness_score += 2
            else:
                effectiveness_score += 1
            
            # Bonus for comprehensive action types
            if action_type in ["network_blocking", "incident_response"]:
                effectiveness_score += 2
        
        # Determine effectiveness level
        if effectiveness_score > 15:
            effectiveness = "High"
        elif effectiveness_score > 8:
            effectiveness = "Medium"
        else:
            effectiveness = "Low"
        
        return {
            "effectiveness_level": effectiveness,
            "effectiveness_score": effectiveness_score,
            "total_actions": len(containment_actions),
            "coverage_assessment": f"{effectiveness} effectiveness with {len(containment_actions)} planned actions"
        }
    
    def _generate_strategic_insights(self, lessons: List[Dict[str, Any]]) -> List[str]:
        """Generate strategic insights from lessons learned"""
        insights = []
        
        categories = set(lesson.get("category", "") for lesson in lessons)
        
        if "Attack Patterns" in categories:
            insights.append("Threat actors are following predictable attack patterns that can be leveraged for proactive defense")
        
        if "Detection Capabilities" in categories:
            insights.append("Current detection capabilities require continuous tuning and enhancement")
        
        if "Honeypot Strategy" in categories:
            insights.append("Honeypot effectiveness varies by type, requiring strategic resource allocation")
        
        if "Threat Intelligence" in categories:
            insights.append("Threat intelligence integration provides significant value for contextualizing attacks")
        
        return insights
    
    def _identify_improvement_areas(self, lessons: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Identify areas for improvement from lessons"""
        improvements = []
        
        for lesson in lessons:
            if "room for improvement" in lesson.get("lesson", "").lower():
                improvements.append({
                    "area": lesson.get("category", "Unknown"),
                    "improvement": lesson.get("action_item", ""),
                    "priority": "High" if "critical" in lesson.get("implication", "").lower() else "Medium"
                })
        
        return improvements
    
    def _identify_success_factors(self, lessons: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Identify success factors from lessons"""
        success_factors = []
        
        for lesson in lessons:
            if "performing well" in lesson.get("lesson", "").lower() or "effective" in lesson.get("lesson", "").lower():
                success_factors.append({
                    "factor": lesson.get("category", "Unknown"),
                    "success_indicator": lesson.get("evidence", ""),
                    "recommendation": lesson.get("action_item", "")
                })
        
        return success_factors
    
    def _generate_future_recommendations(self, lessons: List[Dict[str, Any]]) -> List[str]:
        """Generate future recommendations from lessons"""
        recommendations = []
        
        for lesson in lessons:
            action_item = lesson.get("action_item", "")
            if action_item and action_item not in recommendations:
                recommendations.append(action_item)
        
        return recommendations[:10]  # Limit to top 10
    
    # Placeholder implementations for complex analysis methods
    def _calculate_threat_diversity(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate threat diversity metrics"""
        return {"diversity_score": 0.7, "unique_techniques": 15, "technique_families": 8}
    
    def _analyze_geographic_distribution(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze geographic distribution of threats"""
        return {"primary_regions": ["Unknown"], "geographic_diversity": "Low"}
    
    def _analyze_temporal_threat_patterns(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal patterns in threats"""
        return {"peak_hours": ["14:00-16:00"], "pattern_strength": "Medium"}
    
    def _assess_attack_sophistication(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall attack sophistication"""
        return {"sophistication_level": "Intermediate", "complexity_score": 6.5}
    
    def _identify_emerging_threats(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify emerging threat patterns"""
        return [{"threat_type": "Web Application Exploitation", "emergence_confidence": 0.8}]
    
    def _analyze_threat_actor_activity(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat actor activity patterns"""
        return {"active_groups": 2, "attribution_confidence": "Medium"}
    
    def _analyze_technique_patterns_for_attribution(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze technique patterns for threat actor attribution"""
        return {"distinctive_patterns": 3, "attribution_strength": "Medium"}
    
    def _identify_behavioral_signatures(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify behavioral signatures for attribution"""
        return {"unique_signatures": 2, "signature_confidence": 0.6}
    
    def _analyze_infrastructure_patterns(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze infrastructure patterns"""
        return {"infrastructure_overlap": "Low", "unique_infrastructure": 5}
    
    def _analyze_temporal_behavior_patterns(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal behavior patterns"""
        return {"temporal_consistency": "Medium", "activity_windows": ["Business hours"]}
    
    def _generate_actor_assessments(self, actor_indicators: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate threat actor assessments"""
        return [{"actor_name": "Unknown Group", "confidence": 0.5, "evidence_strength": "Medium"}]
    
    def _calculate_attribution_confidence(self, potential_actors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate attribution confidence"""
        return {"overall_confidence": "Medium", "confidence_score": 0.6}
    
    def _analyze_potential_campaigns(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze potential attack campaigns"""
        return {"campaign_indicators": 1, "campaign_confidence": "Low"}
    
    def _generate_attribution_recommendations(self, potential_actors: List[Dict[str, Any]]) -> List[str]:
        """Generate attribution recommendations"""
        return ["Collect additional behavioral indicators", "Correlate with external threat intelligence"]   
 
    # Additional helper methods for comprehensive analysis
    def _analyze_tactics(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze MITRE tactics distribution"""
        tactic_counts = Counter(t.get("tactic", "Unknown") for t in techniques)
        
        return {
            "tactic_distribution": dict(tactic_counts),
            "dominant_tactic": tactic_counts.most_common(1)[0] if tactic_counts else ("Unknown", 0),
            "tactic_diversity": len(tactic_counts),
            "coverage_percentage": (len(tactic_counts) / 14) * 100  # 14 MITRE tactics
        }
    
    def _analyze_techniques(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze MITRE techniques frequency"""
        technique_counts = Counter(t.get("technique_id", "Unknown") for t in techniques)
        
        return {
            "technique_frequency": dict(technique_counts.most_common(10)),
            "unique_techniques": len(technique_counts),
            "most_frequent": technique_counts.most_common(1)[0] if technique_counts else ("Unknown", 0),
            "technique_diversity_score": len(technique_counts) / len(techniques) if techniques else 0
        }
    
    def _analyze_procedures(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze attack procedures and patterns"""
        procedures = []
        
        for analysis in data:
            result = analysis.get("result", {})
            techniques = result.get("techniques", [])
            
            if len(techniques) > 1:
                # Create procedure signature from technique sequence
                technique_sequence = [t.get("technique_id", "") for t in techniques]
                procedures.append({
                    "session_id": analysis.get("session_id", ""),
                    "technique_sequence": technique_sequence,
                    "sequence_length": len(technique_sequence),
                    "complexity_score": len(set(technique_sequence))
                })
        
        return {
            "total_procedures": len(procedures),
            "average_sequence_length": statistics.mean([p["sequence_length"] for p in procedures]) if procedures else 0,
            "most_complex_procedure": max(procedures, key=lambda x: x["complexity_score"]) if procedures else None,
            "common_sequences": self._identify_common_sequences(procedures)
        }
    
    def _analyze_kill_chain_progression(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze kill chain progression"""
        kill_chain_phases = [
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Exfiltration",
            "Command and Control"
        ]
        
        observed_phases = set(t.get("tactic", "") for t in techniques)
        phase_coverage = [phase for phase in kill_chain_phases if phase in observed_phases]
        
        return {
            "phases_observed": len(phase_coverage),
            "total_phases": len(kill_chain_phases),
            "coverage_percentage": (len(phase_coverage) / len(kill_chain_phases)) * 100,
            "observed_phase_list": phase_coverage,
            "missing_phases": [phase for phase in kill_chain_phases if phase not in observed_phases],
            "progression_completeness": "Complete" if len(phase_coverage) > 8 else "Partial" if len(phase_coverage) > 4 else "Limited"
        }
    
    def _analyze_ttp_evolution(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze TTP evolution over time"""
        try:
            # Sort data by timestamp
            sorted_data = sorted(data, key=lambda x: x.get("start_time", ""))
            
            if len(sorted_data) < 2:
                return {"message": "Insufficient data for evolution analysis"}
            
            # Analyze technique usage over time
            early_sessions = sorted_data[:len(sorted_data)//2]
            recent_sessions = sorted_data[len(sorted_data)//2:]
            
            early_techniques = set()
            recent_techniques = set()
            
            for session in early_sessions:
                result = session.get("result", {})
                techniques = result.get("techniques", [])
                early_techniques.update(t.get("technique_id", "") for t in techniques)
            
            for session in recent_sessions:
                result = session.get("result", {})
                techniques = result.get("techniques", [])
                recent_techniques.update(t.get("technique_id", "") for t in techniques)
            
            # Identify evolution patterns
            new_techniques = recent_techniques - early_techniques
            deprecated_techniques = early_techniques - recent_techniques
            persistent_techniques = early_techniques & recent_techniques
            
            return {
                "evolution_detected": len(new_techniques) > 0 or len(deprecated_techniques) > 0,
                "new_techniques": list(new_techniques),
                "deprecated_techniques": list(deprecated_techniques),
                "persistent_techniques": list(persistent_techniques),
                "evolution_rate": (len(new_techniques) + len(deprecated_techniques)) / len(early_techniques | recent_techniques) if (early_techniques | recent_techniques) else 0,
                "adaptation_indicators": len(new_techniques) > len(deprecated_techniques)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _identify_defensive_gaps(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify defensive gaps based on observed techniques"""
        gaps = []
        
        # Analyze technique frequency for gap identification
        technique_counts = Counter(t.get("technique_id", "") for t in techniques)
        
        # High-frequency techniques indicate potential detection gaps
        for technique_id, count in technique_counts.most_common(5):
            if count > len(techniques) * 0.3:  # Appears in >30% of observations
                gaps.append({
                    "gap_type": "detection",
                    "technique_id": technique_id,
                    "frequency": count,
                    "severity": "High" if count > len(techniques) * 0.5 else "Medium",
                    "recommendation": f"Enhance detection capabilities for {technique_id}",
                    "priority": "Critical" if count > len(techniques) * 0.6 else "High"
                })
        
        # Analyze tactic coverage for strategic gaps
        tactic_counts = Counter(t.get("tactic", "") for t in techniques)
        
        for tactic, count in tactic_counts.items():
            if count > len(techniques) * 0.4:  # Dominant tactic
                gaps.append({
                    "gap_type": "strategic",
                    "tactic": tactic,
                    "frequency": count,
                    "severity": "Medium",
                    "recommendation": f"Develop comprehensive {tactic} defense strategy",
                    "priority": "Medium"
                })
        
        return gaps
    
    def _generate_ioc_summary(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive IOC summary"""
        ioc_types = Counter(ioc.get("type", "unknown") for ioc in iocs)
        confidence_scores = [ioc.get("confidence", 0) for ioc in iocs if ioc.get("confidence") is not None]
        
        return {
            "total_iocs": len(iocs),
            "ioc_type_distribution": dict(ioc_types),
            "high_confidence_iocs": len([ioc for ioc in iocs if ioc.get("confidence", 0) > 0.8]),
            "average_confidence": statistics.mean(confidence_scores) if confidence_scores else 0,
            "unique_ioc_types": len(ioc_types),
            "actionable_iocs": len([ioc for ioc in iocs if ioc.get("confidence", 0) > 0.9])
        }
    
    def _assess_indicator_quality(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess the quality of indicators"""
        quality_metrics = {
            "high_quality": 0,
            "medium_quality": 0,
            "low_quality": 0
        }
        
        for ioc in iocs:
            confidence = ioc.get("confidence", 0)
            has_context = bool(ioc.get("context", ""))
            has_threat_intel = bool(ioc.get("threat_intel", {}))
            
            quality_score = confidence
            if has_context:
                quality_score += 0.1
            if has_threat_intel:
                quality_score += 0.2
            
            if quality_score > 0.8:
                quality_metrics["high_quality"] += 1
            elif quality_score > 0.5:
                quality_metrics["medium_quality"] += 1
            else:
                quality_metrics["low_quality"] += 1
        
        return {
            "quality_distribution": quality_metrics,
            "overall_quality": "High" if quality_metrics["high_quality"] > len(iocs) * 0.5 else "Medium" if quality_metrics["medium_quality"] > len(iocs) * 0.3 else "Low",
            "quality_score": (quality_metrics["high_quality"] * 3 + quality_metrics["medium_quality"] * 2 + quality_metrics["low_quality"]) / len(iocs) if iocs else 0
        }
    
    def _correlate_with_threat_intelligence(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate IOCs with threat intelligence"""
        threat_intel_matches = [ioc for ioc in iocs if ioc.get("threat_intel")]
        
        correlation_summary = {
            "total_matches": len(threat_intel_matches),
            "match_rate": (len(threat_intel_matches) / len(iocs)) * 100 if iocs else 0,
            "threat_families": set(),
            "actor_attributions": set()
        }
        
        for ioc in threat_intel_matches:
            threat_intel = ioc.get("threat_intel", {})
            if threat_intel.get("family"):
                correlation_summary["threat_families"].add(threat_intel["family"])
            if threat_intel.get("actor"):
                correlation_summary["actor_attributions"].add(threat_intel["actor"])
        
        correlation_summary["threat_families"] = list(correlation_summary["threat_families"])
        correlation_summary["actor_attributions"] = list(correlation_summary["actor_attributions"])
        
        return correlation_summary
    
    def _analyze_indicator_relationships(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze relationships between indicators"""
        relationships = []
        
        # Group IOCs by session to find relationships
        session_iocs = defaultdict(list)
        for ioc in iocs:
            session_id = ioc.get("session_id", "")
            if session_id:
                session_iocs[session_id].append(ioc)
        
        # Find co-occurring IOCs
        for session_id, session_ioc_list in session_iocs.items():
            if len(session_ioc_list) > 1:
                for i, ioc1 in enumerate(session_ioc_list):
                    for ioc2 in session_ioc_list[i+1:]:
                        relationships.append({
                            "ioc1": ioc1.get("value", ""),
                            "ioc1_type": ioc1.get("type", ""),
                            "ioc2": ioc2.get("value", ""),
                            "ioc2_type": ioc2.get("type", ""),
                            "relationship_type": "co_occurrence",
                            "session_id": session_id,
                            "strength": min(ioc1.get("confidence", 0), ioc2.get("confidence", 0))
                        })
        
        return {
            "total_relationships": len(relationships),
            "strong_relationships": [r for r in relationships if r["strength"] > 0.7],
            "relationship_types": Counter(r["relationship_type"] for r in relationships),
            "most_connected_iocs": self._find_most_connected_iocs(relationships)
        }
    
    def _identify_actionable_indicators(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify actionable indicators for immediate use"""
        actionable = []
        
        for ioc in iocs:
            confidence = ioc.get("confidence", 0)
            ioc_type = ioc.get("type", "")
            
            # Criteria for actionable IOCs
            is_high_confidence = confidence > 0.8
            is_blockable_type = ioc_type in ["ip_address", "domain", "url", "file_hash"]
            has_context = bool(ioc.get("context", ""))
            
            if is_high_confidence and is_blockable_type:
                actionable.append({
                    "ioc_value": ioc.get("value", ""),
                    "ioc_type": ioc_type,
                    "confidence": confidence,
                    "action_type": self._determine_action_type(ioc_type),
                    "priority": "High" if confidence > 0.9 else "Medium",
                    "context": ioc.get("context", ""),
                    "implementation": self._suggest_implementation(ioc_type)
                })
        
        return actionable
    
    def _generate_indicator_sharing_recommendations(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations for indicator sharing"""
        recommendations = []
        
        high_confidence_iocs = [ioc for ioc in iocs if ioc.get("confidence", 0) > 0.8]
        
        if high_confidence_iocs:
            recommendations.append({
                "platform": "STIX/TAXII",
                "ioc_count": len(high_confidence_iocs),
                "recommendation": "Share high-confidence IOCs via STIX/TAXII feeds",
                "priority": "High",
                "timeline": "Immediate"
            })
        
        threat_intel_iocs = [ioc for ioc in iocs if ioc.get("threat_intel")]
        
        if threat_intel_iocs:
            recommendations.append({
                "platform": "Threat Intelligence Platforms",
                "ioc_count": len(threat_intel_iocs),
                "recommendation": "Enrich and share IOCs with threat intelligence context",
                "priority": "Medium",
                "timeline": "Within 24 hours"
            })
        
        return recommendations
    
    def _perform_attribution_assessment(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform comprehensive attribution assessment"""
        attribution_indicators = {
            "technique_patterns": [],
            "infrastructure_indicators": [],
            "behavioral_signatures": [],
            "temporal_patterns": []
        }
        
        # Collect attribution indicators
        all_techniques = []
        for analysis in data:
            result = analysis.get("result", {})
            techniques = result.get("techniques", [])
            all_techniques.extend(techniques)
        
        # Analyze technique patterns for attribution
        technique_combinations = self._analyze_technique_combinations(all_techniques)
        attribution_indicators["technique_patterns"] = technique_combinations
        
        # Simple attribution assessment
        confidence_levels = {
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": len(data)  # Default to low confidence
        }
        
        if len(technique_combinations) > 3:
            confidence_levels["medium_confidence"] = 1
            confidence_levels["low_confidence"] -= 1
        
        return {
            "attribution_indicators": attribution_indicators,
            "confidence_assessment": confidence_levels,
            "primary_attribution": "Unknown Actor",
            "alternative_attributions": ["Generic Threat Actor"],
            "attribution_strength": "Low"
        }
    
    def _calculate_attribution_confidence_levels(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate attribution confidence levels"""
        return {
            "overall_confidence": "Low",
            "technique_confidence": 0.3,
            "infrastructure_confidence": 0.2,
            "behavioral_confidence": 0.4,
            "temporal_confidence": 0.3
        }
    
    def _collect_attribution_evidence(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collect evidence supporting attribution"""
        evidence = []
        
        # Technique-based evidence
        all_techniques = []
        for analysis in data:
            result = analysis.get("result", {})
            techniques = result.get("techniques", [])
            all_techniques.extend(techniques)
        
        technique_counts = Counter(t.get("technique_id", "") for t in all_techniques)
        
        for technique_id, count in technique_counts.most_common(3):
            evidence.append({
                "evidence_type": "technique_usage",
                "technique_id": technique_id,
                "frequency": count,
                "strength": "Medium" if count > 2 else "Low",
                "description": f"Technique {technique_id} observed {count} times"
            })
        
        return evidence
    
    def _generate_alternative_attribution_hypotheses(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate alternative attribution hypotheses"""
        return [
            {
                "hypothesis": "Opportunistic Attacker",
                "probability": 0.6,
                "supporting_evidence": ["Common techniques", "Broad targeting"],
                "contradicting_evidence": []
            },
            {
                "hypothesis": "Targeted Campaign",
                "probability": 0.3,
                "supporting_evidence": ["Persistent activity"],
                "contradicting_evidence": ["Lack of sophisticated techniques"]
            }
        ]
    
    def _create_attribution_timeline(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create attribution timeline"""
        timeline = []
        
        for analysis in data:
            timeline.append({
                "timestamp": analysis.get("start_time", ""),
                "session_id": analysis.get("session_id", ""),
                "attribution_indicators": len(analysis.get("result", {}).get("techniques", [])),
                "confidence_change": 0.1  # Placeholder
            })
        
        return sorted(timeline, key=lambda x: x.get("timestamp", ""))
    
    def _generate_attribution_action_recommendations(self, data: List[Dict[str, Any]]) -> List[str]:
        """Generate action recommendations for attribution"""
        return [
            "Collect additional behavioral indicators",
            "Correlate with external threat intelligence",
            "Monitor for infrastructure reuse patterns",
            "Analyze temporal activity patterns",
            "Enhance technique-based attribution capabilities"
        ]
    
    # Helper methods for complex analysis
    def _identify_common_sequences(self, procedures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify common technique sequences"""
        sequence_counts = Counter()
        
        for procedure in procedures:
            sequence = tuple(procedure["technique_sequence"])
            if len(sequence) > 1:
                sequence_counts[sequence] += 1
        
        common_sequences = []
        for sequence, count in sequence_counts.most_common(5):
            if count > 1:
                common_sequences.append({
                    "sequence": list(sequence),
                    "frequency": count,
                    "length": len(sequence)
                })
        
        return common_sequences
    
    def _find_most_connected_iocs(self, relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find IOCs with the most relationships"""
        ioc_connections = defaultdict(int)
        
        for relationship in relationships:
            ioc_connections[relationship["ioc1"]] += 1
            ioc_connections[relationship["ioc2"]] += 1
        
        most_connected = []
        for ioc, connection_count in Counter(ioc_connections).most_common(5):
            most_connected.append({
                "ioc_value": ioc,
                "connection_count": connection_count,
                "centrality_score": connection_count / len(relationships) if relationships else 0
            })
        
        return most_connected
    
    def _determine_action_type(self, ioc_type: str) -> str:
        """Determine appropriate action type for IOC"""
        action_mapping = {
            "ip_address": "Network blocking",
            "domain": "DNS filtering",
            "url": "Web filtering",
            "file_hash": "Endpoint protection",
            "email": "Email filtering"
        }
        return action_mapping.get(ioc_type, "Manual review")
    
    def _suggest_implementation(self, ioc_type: str) -> str:
        """Suggest implementation method for IOC"""
        implementation_mapping = {
            "ip_address": "Add to firewall block list and IPS signatures",
            "domain": "Configure DNS sinkhole and web proxy blocking",
            "url": "Update web filtering rules and proxy configurations",
            "file_hash": "Add to endpoint protection signatures and YARA rules",
            "email": "Configure email security gateway rules"
        }
        return implementation_mapping.get(ioc_type, "Manual analysis and custom implementation")
    
    def _analyze_technique_combinations(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze technique combinations for attribution"""
        combinations = []
        
        # Group techniques by tactic
        tactic_techniques = defaultdict(list)
        for technique in techniques:
            tactic = technique.get("tactic", "")
            technique_id = technique.get("technique_id", "")
            if tactic and technique_id:
                tactic_techniques[tactic].append(technique_id)
        
        # Find interesting combinations
        for tactic, technique_list in tactic_techniques.items():
            if len(technique_list) > 1:
                combinations.append({
                    "tactic": tactic,
                    "techniques": list(set(technique_list)),
                    "combination_frequency": len(technique_list),
                    "uniqueness_score": len(set(technique_list)) / len(technique_list)
                })
        
        return combinations