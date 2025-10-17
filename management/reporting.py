"""
Intelligence Reporting System for AI-Powered Honeypot System
Provides automated intelligence report generation, trend analysis, visualization,
and export capabilities for external systems.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from uuid import uuid4
from dataclasses import dataclass, asdict
from enum import Enum
import csv
import io
import base64

from jinja2 import Template
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np
from wordcloud import WordCloud


class ReportType(Enum):
    """Types of intelligence reports"""
    DAILY_SUMMARY = "daily_summary"
    WEEKLY_ANALYSIS = "weekly_analysis"
    MONTHLY_TRENDS = "monthly_trends"
    THREAT_ACTOR_PROFILE = "threat_actor_profile"
    TECHNIQUE_ANALYSIS = "technique_analysis"
    IOC_REPORT = "ioc_report"
    CUSTOM = "custom"


class ReportFormat(Enum):
    """Report output formats"""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    STIX = "stix"
    MISP = "misp"


class TrendDirection(Enum):
    """Trend analysis directions"""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"


@dataclass
class ThreatTrend:
    """Threat trend analysis data"""
    technique_id: str
    technique_name: str
    current_count: int
    previous_count: int
    percentage_change: float
    direction: TrendDirection
    confidence: float
    first_seen: str
    last_seen: str


@dataclass
class ThreatActorProfile:
    """Threat actor profile data"""
    actor_id: str
    ip_addresses: List[str]
    countries: List[str]
    techniques_used: List[str]
    tools_identified: List[str]
    attack_patterns: List[str]
    session_count: int
    total_interactions: int
    average_session_duration: float
    sophistication_score: float
    first_seen: str
    last_seen: str


@dataclass
class IOCData:
    """Indicator of Compromise data"""
    ioc_type: str
    value: str
    confidence: float
    first_seen: str
    last_seen: str
    honeypot_types: List[str]
    mitre_techniques: List[str]
    threat_score: float
    context: str


@dataclass
class IntelligenceReport:
    """Intelligence report structure"""
    report_id: str
    report_type: ReportType
    title: str
    description: str
    generated_at: str
    time_range_start: str
    time_range_end: str
    summary: Dict[str, Any]
    threat_trends: List[ThreatTrend]
    threat_actors: List[ThreatActorProfile]
    iocs: List[IOCData]
    recommendations: List[str]
    charts: Dict[str, str]  # Base64 encoded chart images
    raw_data: Dict[str, Any]
    confidence_score: float


class IntelligenceReportingSystem:
    """
    Intelligence Reporting System
    Provides automated intelligence report generation, trend analysis,
    visualization, and export capabilities for external systems.
    """
    
    def __init__(self, intelligence_agent=None, config: Optional[Dict[str, Any]] = None):
        self.intelligence_agent = intelligence_agent
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.report_storage_path = self.config.get("report_storage_path", "reports/")
        self.chart_style = self.config.get("chart_style", "seaborn")
        self.auto_generate_enabled = self.config.get("auto_generate_enabled", True)
        self.retention_days = self.config.get("retention_days", 90)
        
        # Report templates
        self.report_templates = {}
        self._load_report_templates()
        
        # Data storage
        self.generated_reports: Dict[str, IntelligenceReport] = {}
        self.report_history: List[Dict[str, Any]] = []
        
        # Chart configuration
        plt.style.use(self.chart_style)
        sns.set_palette("husl")
        
        # Background tasks
        self._background_tasks = []
        
        self.logger.info("Intelligence Reporting System initialized")
    
    async def start(self):
        """Start the intelligence reporting system"""
        try:
            # Start background report generation
            if self.auto_generate_enabled:
                self._background_tasks.append(
                    asyncio.create_task(self._auto_generate_reports())
                )
            
            # Start report cleanup task
            self._background_tasks.append(
                asyncio.create_task(self._cleanup_old_reports())
            )
            
            self.logger.info("Intelligence Reporting System started")
            
        except Exception as e:
            self.logger.error(f"Failed to start intelligence reporting system: {e}")
            raise
    
    async def stop(self):
        """Stop the intelligence reporting system"""
        try:
            # Cancel background tasks
            for task in self._background_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            
            self.logger.info("Intelligence Reporting System stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping intelligence reporting system: {e}")
    
    async def generate_report(self, report_type: ReportType, 
                            time_range_start: Optional[datetime] = None,
                            time_range_end: Optional[datetime] = None,
                            custom_config: Optional[Dict[str, Any]] = None) -> IntelligenceReport:
        """Generate intelligence report"""
        try:
            # Set default time range if not provided
            if not time_range_end:
                time_range_end = datetime.utcnow()
            
            if not time_range_start:
                if report_type == ReportType.DAILY_SUMMARY:
                    time_range_start = time_range_end - timedelta(days=1)
                elif report_type == ReportType.WEEKLY_ANALYSIS:
                    time_range_start = time_range_end - timedelta(days=7)
                elif report_type == ReportType.MONTHLY_TRENDS:
                    time_range_start = time_range_end - timedelta(days=30)
                else:
                    time_range_start = time_range_end - timedelta(days=7)
            
            # Generate report ID
            report_id = str(uuid4())
            
            # Collect intelligence data
            intelligence_data = await self._collect_intelligence_data(
                time_range_start, time_range_end
            )
            
            # Analyze trends
            threat_trends = await self._analyze_threat_trends(
                intelligence_data, time_range_start, time_range_end
            )
            
            # Profile threat actors
            threat_actors = await self._profile_threat_actors(
                intelligence_data, time_range_start, time_range_end
            )
            
            # Extract IOCs
            iocs = await self._extract_iocs(
                intelligence_data, time_range_start, time_range_end
            )
            
            # Generate summary
            summary = await self._generate_summary(
                intelligence_data, threat_trends, threat_actors, iocs
            )
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(
                threat_trends, threat_actors, iocs
            )
            
            # Generate charts
            charts = await self._generate_charts(
                intelligence_data, threat_trends, threat_actors
            )
            
            # Calculate confidence score
            confidence_score = await self._calculate_confidence_score(
                intelligence_data, threat_trends, threat_actors, iocs
            )
            
            # Create report
            report = IntelligenceReport(
                report_id=report_id,
                report_type=report_type,
                title=self._generate_report_title(report_type, time_range_start, time_range_end),
                description=self._generate_report_description(report_type),
                generated_at=datetime.utcnow().isoformat(),
                time_range_start=time_range_start.isoformat(),
                time_range_end=time_range_end.isoformat(),
                summary=summary,
                threat_trends=threat_trends,
                threat_actors=threat_actors,
                iocs=iocs,
                recommendations=recommendations,
                charts=charts,
                raw_data=intelligence_data,
                confidence_score=confidence_score
            )
            
            # Store report
            self.generated_reports[report_id] = report
            
            # Add to history
            self.report_history.append({
                "report_id": report_id,
                "report_type": report_type.value,
                "generated_at": report.generated_at,
                "time_range": f"{time_range_start.isoformat()} to {time_range_end.isoformat()}",
                "confidence_score": confidence_score
            })
            
            self.logger.info(f"Generated {report_type.value} report: {report_id}")
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            raise
    
    async def export_report(self, report_id: str, format: ReportFormat) -> Union[str, bytes]:
        """Export report in specified format"""
        try:
            if report_id not in self.generated_reports:
                raise ValueError(f"Report {report_id} not found")
            
            report = self.generated_reports[report_id]
            
            if format == ReportFormat.HTML:
                return await self._export_html(report)
            elif format == ReportFormat.PDF:
                return await self._export_pdf(report)
            elif format == ReportFormat.JSON:
                return await self._export_json(report)
            elif format == ReportFormat.CSV:
                return await self._export_csv(report)
            elif format == ReportFormat.STIX:
                return await self._export_stix(report)
            elif format == ReportFormat.MISP:
                return await self._export_misp(report)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            raise
    
    async def get_report_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get list of generated reports"""
        try:
            # Return most recent reports first
            return sorted(
                self.report_history[-limit:],
                key=lambda x: x["generated_at"],
                reverse=True
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get report list: {e}")
            return []
    
    async def get_report(self, report_id: str) -> Optional[IntelligenceReport]:
        """Get specific report by ID"""
        return self.generated_reports.get(report_id)
    
    async def delete_report(self, report_id: str) -> bool:
        """Delete specific report"""
        try:
            if report_id in self.generated_reports:
                del self.generated_reports[report_id]
                
                # Remove from history
                self.report_history = [
                    r for r in self.report_history if r["report_id"] != report_id
                ]
                
                self.logger.info(f"Deleted report: {report_id}")
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to delete report: {e}")
            return False
    
    async def get_trend_analysis(self, days: int = 30) -> Dict[str, Any]:
        """Get trend analysis for specified time period"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            # Collect data
            intelligence_data = await self._collect_intelligence_data(start_time, end_time)
            
            # Analyze trends
            trends = await self._analyze_threat_trends(intelligence_data, start_time, end_time)
            
            # Generate trend summary
            trend_summary = {
                "time_period": f"{days} days",
                "start_date": start_time.isoformat(),
                "end_date": end_time.isoformat(),
                "total_techniques": len(trends),
                "increasing_trends": len([t for t in trends if t.direction == TrendDirection.INCREASING]),
                "decreasing_trends": len([t for t in trends if t.direction == TrendDirection.DECREASING]),
                "stable_trends": len([t for t in trends if t.direction == TrendDirection.STABLE]),
                "volatile_trends": len([t for t in trends if t.direction == TrendDirection.VOLATILE]),
                "top_techniques": [
                    {
                        "technique_id": t.technique_id,
                        "technique_name": t.technique_name,
                        "current_count": t.current_count,
                        "change_percentage": t.percentage_change
                    }
                    for t in sorted(trends, key=lambda x: x.current_count, reverse=True)[:10]
                ],
                "emerging_threats": [
                    {
                        "technique_id": t.technique_id,
                        "technique_name": t.technique_name,
                        "change_percentage": t.percentage_change
                    }
                    for t in sorted(trends, key=lambda x: x.percentage_change, reverse=True)[:5]
                    if t.direction == TrendDirection.INCREASING
                ]
            }
            
            return trend_summary
            
        except Exception as e:
            self.logger.error(f"Failed to get trend analysis: {e}")
            return {}
    
    # Data Collection Methods
    async def _collect_intelligence_data(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Collect intelligence data for the specified time range"""
        try:
            # This would typically query the Intelligence Agent for data
            # For now, we'll simulate some intelligence data
            
            intelligence_data = {
                "sessions": [],
                "interactions": [],
                "techniques": {},
                "iocs": [],
                "threat_actors": {},
                "honeypot_stats": {},
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                }
            }
            
            # If intelligence agent is available, get real data
            if self.intelligence_agent:
                try:
                    # Get session data
                    sessions_data = await self.intelligence_agent.get_sessions_in_range(
                        start_time, end_time
                    )
                    intelligence_data["sessions"] = sessions_data
                    
                    # Get interaction data
                    interactions_data = await self.intelligence_agent.get_interactions_in_range(
                        start_time, end_time
                    )
                    intelligence_data["interactions"] = interactions_data
                    
                    # Get technique analysis
                    techniques_data = await self.intelligence_agent.get_technique_analysis(
                        start_time, end_time
                    )
                    intelligence_data["techniques"] = techniques_data
                    
                except Exception as e:
                    self.logger.warning(f"Failed to get data from intelligence agent: {e}")
            
            return intelligence_data
            
        except Exception as e:
            self.logger.error(f"Failed to collect intelligence data: {e}")
            return {}
    
    async def _analyze_threat_trends(self, intelligence_data: Dict[str, Any],
                                   start_time: datetime, end_time: datetime) -> List[ThreatTrend]:
        """Analyze threat trends from intelligence data"""
        try:
            trends = []
            techniques = intelligence_data.get("techniques", {})
            
            # Calculate trends for each technique
            for technique_id, technique_data in techniques.items():
                current_count = technique_data.get("current_count", 0)
                previous_count = technique_data.get("previous_count", 0)
                
                # Calculate percentage change
                if previous_count > 0:
                    percentage_change = ((current_count - previous_count) / previous_count) * 100
                else:
                    percentage_change = 100.0 if current_count > 0 else 0.0
                
                # Determine trend direction
                if abs(percentage_change) < 5:
                    direction = TrendDirection.STABLE
                elif percentage_change > 50:
                    direction = TrendDirection.VOLATILE
                elif percentage_change > 0:
                    direction = TrendDirection.INCREASING
                else:
                    direction = TrendDirection.DECREASING
                
                # Calculate confidence based on data volume
                confidence = min(1.0, (current_count + previous_count) / 100)
                
                trend = ThreatTrend(
                    technique_id=technique_id,
                    technique_name=technique_data.get("name", technique_id),
                    current_count=current_count,
                    previous_count=previous_count,
                    percentage_change=percentage_change,
                    direction=direction,
                    confidence=confidence,
                    first_seen=technique_data.get("first_seen", start_time.isoformat()),
                    last_seen=technique_data.get("last_seen", end_time.isoformat())
                )
                
                trends.append(trend)
            
            return sorted(trends, key=lambda x: x.current_count, reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to analyze threat trends: {e}")
            return []
    
    async def _profile_threat_actors(self, intelligence_data: Dict[str, Any],
                                   start_time: datetime, end_time: datetime) -> List[ThreatActorProfile]:
        """Profile threat actors from intelligence data"""
        try:
            profiles = []
            threat_actors = intelligence_data.get("threat_actors", {})
            
            for actor_id, actor_data in threat_actors.items():
                profile = ThreatActorProfile(
                    actor_id=actor_id,
                    ip_addresses=actor_data.get("ip_addresses", []),
                    countries=actor_data.get("countries", []),
                    techniques_used=actor_data.get("techniques_used", []),
                    tools_identified=actor_data.get("tools_identified", []),
                    attack_patterns=actor_data.get("attack_patterns", []),
                    session_count=actor_data.get("session_count", 0),
                    total_interactions=actor_data.get("total_interactions", 0),
                    average_session_duration=actor_data.get("average_session_duration", 0.0),
                    sophistication_score=actor_data.get("sophistication_score", 0.0),
                    first_seen=actor_data.get("first_seen", start_time.isoformat()),
                    last_seen=actor_data.get("last_seen", end_time.isoformat())
                )
                
                profiles.append(profile)
            
            return sorted(profiles, key=lambda x: x.sophistication_score, reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to profile threat actors: {e}")
            return []
    
    async def _extract_iocs(self, intelligence_data: Dict[str, Any],
                          start_time: datetime, end_time: datetime) -> List[IOCData]:
        """Extract Indicators of Compromise from intelligence data"""
        try:
            iocs = []
            ioc_data = intelligence_data.get("iocs", [])
            
            for ioc_item in ioc_data:
                ioc = IOCData(
                    ioc_type=ioc_item.get("type", "unknown"),
                    value=ioc_item.get("value", ""),
                    confidence=ioc_item.get("confidence", 0.0),
                    first_seen=ioc_item.get("first_seen", start_time.isoformat()),
                    last_seen=ioc_item.get("last_seen", end_time.isoformat()),
                    honeypot_types=ioc_item.get("honeypot_types", []),
                    mitre_techniques=ioc_item.get("mitre_techniques", []),
                    threat_score=ioc_item.get("threat_score", 0.0),
                    context=ioc_item.get("context", "")
                )
                
                iocs.append(ioc)
            
            return sorted(iocs, key=lambda x: x.threat_score, reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to extract IOCs: {e}")
            return []
    
    async def _generate_summary(self, intelligence_data: Dict[str, Any],
                              threat_trends: List[ThreatTrend],
                              threat_actors: List[ThreatActorProfile],
                              iocs: List[IOCData]) -> Dict[str, Any]:
        """Generate intelligence summary"""
        try:
            sessions = intelligence_data.get("sessions", [])
            interactions = intelligence_data.get("interactions", [])
            
            summary = {
                "total_sessions": len(sessions),
                "total_interactions": len(interactions),
                "unique_threat_actors": len(threat_actors),
                "total_techniques": len(threat_trends),
                "total_iocs": len(iocs),
                "high_confidence_iocs": len([ioc for ioc in iocs if ioc.confidence > 0.8]),
                "emerging_threats": len([t for t in threat_trends if t.direction == TrendDirection.INCREASING]),
                "top_techniques": [
                    {
                        "id": t.technique_id,
                        "name": t.technique_name,
                        "count": t.current_count
                    }
                    for t in threat_trends[:5]
                ],
                "top_threat_actors": [
                    {
                        "id": a.actor_id,
                        "sophistication": a.sophistication_score,
                        "sessions": a.session_count
                    }
                    for a in threat_actors[:5]
                ],
                "honeypot_engagement": {
                    "web_admin": len([s for s in sessions if s.get("honeypot_type") == "web_admin"]),
                    "ssh": len([s for s in sessions if s.get("honeypot_type") == "ssh"]),
                    "database": len([s for s in sessions if s.get("honeypot_type") == "database"]),
                    "file_share": len([s for s in sessions if s.get("honeypot_type") == "file_share"]),
                    "email": len([s for s in sessions if s.get("honeypot_type") == "email"])
                }
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to generate summary: {e}")
            return {}
    
    async def _generate_recommendations(self, threat_trends: List[ThreatTrend],
                                      threat_actors: List[ThreatActorProfile],
                                      iocs: List[IOCData]) -> List[str]:
        """Generate security recommendations based on intelligence"""
        try:
            recommendations = []
            
            # Analyze emerging threats
            emerging_threats = [t for t in threat_trends if t.direction == TrendDirection.INCREASING]
            if emerging_threats:
                recommendations.append(
                    f"Monitor for increased activity in {len(emerging_threats)} emerging threat techniques, "
                    f"particularly {emerging_threats[0].technique_name} which shows {emerging_threats[0].percentage_change:.1f}% increase."
                )
            
            # Analyze high-sophistication actors
            sophisticated_actors = [a for a in threat_actors if a.sophistication_score > 0.7]
            if sophisticated_actors:
                recommendations.append(
                    f"Implement enhanced monitoring for {len(sophisticated_actors)} high-sophistication threat actors. "
                    f"Focus on IP ranges and attack patterns associated with these actors."
                )
            
            # Analyze high-confidence IOCs
            high_confidence_iocs = [ioc for ioc in iocs if ioc.confidence > 0.8]
            if high_confidence_iocs:
                recommendations.append(
                    f"Block or monitor {len(high_confidence_iocs)} high-confidence IOCs in security controls. "
                    f"Prioritize IP addresses and file hashes with threat scores above 0.8."
                )
            
            # Analyze honeypot effectiveness
            if threat_trends:
                most_active_technique = threat_trends[0]
                recommendations.append(
                    f"Consider deploying additional honeypots targeting {most_active_technique.technique_name} "
                    f"to gather more intelligence on this prevalent technique."
                )
            
            # General recommendations
            recommendations.extend([
                "Review and update threat hunting queries based on observed attack patterns.",
                "Share IOCs with threat intelligence platforms and security community.",
                "Conduct tabletop exercises based on observed threat actor behaviors.",
                "Update security awareness training to include latest attack techniques."
            ])
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            return []
    
    async def _generate_charts(self, intelligence_data: Dict[str, Any],
                             threat_trends: List[ThreatTrend],
                             threat_actors: List[ThreatActorProfile]) -> Dict[str, str]:
        """Generate charts for the report"""
        try:
            charts = {}
            
            # Threat trends chart
            if threat_trends:
                charts["threat_trends"] = await self._create_threat_trends_chart(threat_trends)
            
            # Honeypot activity chart
            sessions = intelligence_data.get("sessions", [])
            if sessions:
                charts["honeypot_activity"] = await self._create_honeypot_activity_chart(sessions)
            
            # Threat actor sophistication chart
            if threat_actors:
                charts["threat_actors"] = await self._create_threat_actor_chart(threat_actors)
            
            # Technique frequency chart
            techniques = intelligence_data.get("techniques", {})
            if techniques:
                charts["technique_frequency"] = await self._create_technique_frequency_chart(techniques)
            
            return charts
            
        except Exception as e:
            self.logger.error(f"Failed to generate charts: {e}")
            return {}
    
    async def _create_threat_trends_chart(self, threat_trends: List[ThreatTrend]) -> str:
        """Create threat trends chart"""
        try:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Prepare data
            techniques = [t.technique_name[:20] + "..." if len(t.technique_name) > 20 else t.technique_name 
                         for t in threat_trends[:10]]
            current_counts = [t.current_count for t in threat_trends[:10]]
            previous_counts = [t.previous_count for t in threat_trends[:10]]
            
            x = np.arange(len(techniques))
            width = 0.35
            
            # Create bars
            bars1 = ax.bar(x - width/2, previous_counts, width, label='Previous Period', alpha=0.7)
            bars2 = ax.bar(x + width/2, current_counts, width, label='Current Period', alpha=0.7)
            
            # Customize chart
            ax.set_xlabel('MITRE ATT&CK Techniques')
            ax.set_ylabel('Occurrence Count')
            ax.set_title('Threat Technique Trends Comparison')
            ax.set_xticks(x)
            ax.set_xticklabels(techniques, rotation=45, ha='right')
            ax.legend()
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            buffer.seek(0)
            chart_data = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return chart_data
            
        except Exception as e:
            self.logger.error(f"Failed to create threat trends chart: {e}")
            return ""
    
    async def _create_honeypot_activity_chart(self, sessions: List[Dict[str, Any]]) -> str:
        """Create honeypot activity chart"""
        try:
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Count sessions by honeypot type
            honeypot_counts = {}
            for session in sessions:
                honeypot_type = session.get("honeypot_type", "unknown")
                honeypot_counts[honeypot_type] = honeypot_counts.get(honeypot_type, 0) + 1
            
            # Create pie chart
            labels = list(honeypot_counts.keys())
            sizes = list(honeypot_counts.values())
            colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
            
            wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                            startangle=90, textprops={'fontsize': 10})
            
            ax.set_title('Honeypot Activity Distribution')
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            buffer.seek(0)
            chart_data = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return chart_data
            
        except Exception as e:
            self.logger.error(f"Failed to create honeypot activity chart: {e}")
            return ""
    
    async def _create_threat_actor_chart(self, threat_actors: List[ThreatActorProfile]) -> str:
        """Create threat actor sophistication chart"""
        try:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Prepare data
            actor_ids = [a.actor_id[:10] + "..." if len(a.actor_id) > 10 else a.actor_id 
                        for a in threat_actors[:15]]
            sophistication_scores = [a.sophistication_score for a in threat_actors[:15]]
            session_counts = [a.session_count for a in threat_actors[:15]]
            
            # Create scatter plot
            scatter = ax.scatter(sophistication_scores, session_counts, 
                               s=100, alpha=0.6, c=sophistication_scores, cmap='viridis')
            
            # Add labels
            for i, actor_id in enumerate(actor_ids):
                ax.annotate(actor_id, (sophistication_scores[i], session_counts[i]),
                           xytext=(5, 5), textcoords='offset points', fontsize=8)
            
            ax.set_xlabel('Sophistication Score')
            ax.set_ylabel('Session Count')
            ax.set_title('Threat Actor Analysis: Sophistication vs Activity')
            
            # Add colorbar
            plt.colorbar(scatter, label='Sophistication Score')
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            buffer.seek(0)
            chart_data = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return chart_data
            
        except Exception as e:
            self.logger.error(f"Failed to create threat actor chart: {e}")
            return ""
    
    async def _create_technique_frequency_chart(self, techniques: Dict[str, Any]) -> str:
        """Create technique frequency word cloud"""
        try:
            # Prepare word frequency data
            word_freq = {}
            for technique_id, technique_data in techniques.items():
                technique_name = technique_data.get("name", technique_id)
                count = technique_data.get("current_count", 0)
                word_freq[technique_name] = count
            
            if not word_freq:
                return ""
            
            # Create word cloud
            wordcloud = WordCloud(width=800, height=400, 
                                background_color='white',
                                colormap='viridis',
                                max_words=50).generate_from_frequencies(word_freq)
            
            fig, ax = plt.subplots(figsize=(12, 6))
            ax.imshow(wordcloud, interpolation='bilinear')
            ax.axis('off')
            ax.set_title('Most Frequent Attack Techniques')
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            buffer.seek(0)
            chart_data = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return chart_data
            
        except Exception as e:
            self.logger.error(f"Failed to create technique frequency chart: {e}")
            return ""
    
    async def _calculate_confidence_score(self, intelligence_data: Dict[str, Any],
                                        threat_trends: List[ThreatTrend],
                                        threat_actors: List[ThreatActorProfile],
                                        iocs: List[IOCData]) -> float:
        """Calculate overall confidence score for the report"""
        try:
            # Factors that contribute to confidence
            data_volume = len(intelligence_data.get("sessions", [])) + len(intelligence_data.get("interactions", []))
            trend_confidence = np.mean([t.confidence for t in threat_trends]) if threat_trends else 0.0
            ioc_confidence = np.mean([ioc.confidence for ioc in iocs]) if iocs else 0.0
            
            # Normalize data volume (assume 100+ interactions is high confidence)
            volume_confidence = min(1.0, data_volume / 100)
            
            # Calculate weighted average
            confidence_score = (
                volume_confidence * 0.4 +
                trend_confidence * 0.3 +
                ioc_confidence * 0.3
            )
            
            return round(confidence_score, 3)
            
        except Exception as e:
            self.logger.error(f"Failed to calculate confidence score: {e}")
            return 0.0
    
    # Export Methods
    async def _export_html(self, report: IntelligenceReport) -> str:
        """Export report as HTML"""
        try:
            template_str = self.report_templates.get("html", self._get_default_html_template())
            template = Template(template_str)
            
            html_content = template.render(
                report=report,
                charts=report.charts,
                generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            )
            
            return html_content
            
        except Exception as e:
            self.logger.error(f"Failed to export HTML: {e}")
            return ""
    
    async def _export_json(self, report: IntelligenceReport) -> str:
        """Export report as JSON"""
        try:
            # Convert dataclasses to dict
            report_dict = asdict(report)
            return json.dumps(report_dict, indent=2, default=str)
            
        except Exception as e:
            self.logger.error(f"Failed to export JSON: {e}")
            return ""
    
    async def _export_csv(self, report: IntelligenceReport) -> str:
        """Export report data as CSV"""
        try:
            output = io.StringIO()
            
            # Write threat trends
            writer = csv.writer(output)
            writer.writerow(["Report Section", "Threat Trends"])
            writer.writerow(["Technique ID", "Technique Name", "Current Count", "Previous Count", "Change %", "Direction"])
            
            for trend in report.threat_trends:
                writer.writerow([
                    trend.technique_id,
                    trend.technique_name,
                    trend.current_count,
                    trend.previous_count,
                    trend.percentage_change,
                    trend.direction.value
                ])
            
            # Write IOCs
            writer.writerow([])
            writer.writerow(["Report Section", "Indicators of Compromise"])
            writer.writerow(["Type", "Value", "Confidence", "Threat Score", "Context"])
            
            for ioc in report.iocs:
                writer.writerow([
                    ioc.ioc_type,
                    ioc.value,
                    ioc.confidence,
                    ioc.threat_score,
                    ioc.context
                ])
            
            return output.getvalue()
            
        except Exception as e:
            self.logger.error(f"Failed to export CSV: {e}")
            return ""
    
    async def _export_pdf(self, report: IntelligenceReport) -> bytes:
        """Export report as PDF"""
        try:
            # This would require a PDF library like reportlab or weasyprint
            # For now, return empty bytes
            self.logger.warning("PDF export not implemented")
            return b""
            
        except Exception as e:
            self.logger.error(f"Failed to export PDF: {e}")
            return b""
    
    async def _export_stix(self, report: IntelligenceReport) -> str:
        """Export report as STIX format"""
        try:
            # This would require STIX library implementation
            # For now, return basic STIX-like structure
            stix_data = {
                "type": "report",
                "id": f"report--{report.report_id}",
                "created": report.generated_at,
                "modified": report.generated_at,
                "name": report.title,
                "description": report.description,
                "published": report.generated_at,
                "object_refs": []
            }
            
            return json.dumps(stix_data, indent=2)
            
        except Exception as e:
            self.logger.error(f"Failed to export STIX: {e}")
            return ""
    
    async def _export_misp(self, report: IntelligenceReport) -> str:
        """Export report as MISP format"""
        try:
            # This would require MISP library implementation
            # For now, return basic MISP-like structure
            misp_data = {
                "Event": {
                    "id": report.report_id,
                    "info": report.title,
                    "date": report.generated_at.split("T")[0],
                    "threat_level_id": "2",
                    "analysis": "2",
                    "distribution": "1",
                    "Attribute": []
                }
            }
            
            # Add IOCs as attributes
            for ioc in report.iocs:
                misp_data["Event"]["Attribute"].append({
                    "type": ioc.ioc_type,
                    "value": ioc.value,
                    "comment": ioc.context,
                    "to_ids": True if ioc.confidence > 0.7 else False
                })
            
            return json.dumps(misp_data, indent=2)
            
        except Exception as e:
            self.logger.error(f"Failed to export MISP: {e}")
            return ""
    
    # Background Tasks
    async def _auto_generate_reports(self):
        """Automatically generate scheduled reports with enhanced automation"""
        while True:
            try:
                current_time = datetime.utcnow()
                
                # Generate daily reports at midnight
                if current_time.hour == 0 and current_time.minute < 5:
                    daily_report = await self.generate_report(ReportType.DAILY_SUMMARY)
                    # Auto-export daily reports
                    await self._auto_export_report(daily_report.report_id, [ReportFormat.JSON, ReportFormat.HTML])
                
                # Generate weekly reports on Mondays
                if current_time.weekday() == 0 and current_time.hour == 1 and current_time.minute < 5:
                    weekly_report = await self.generate_report(ReportType.WEEKLY_ANALYSIS)
                    # Auto-export weekly reports with more formats
                    await self._auto_export_report(weekly_report.report_id, [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.PDF, ReportFormat.STIX])
                
                # Generate monthly reports on the 1st of each month
                if current_time.day == 1 and current_time.hour == 2 and current_time.minute < 5:
                    monthly_report = await self.generate_report(ReportType.MONTHLY_TRENDS)
                    # Auto-export monthly reports with all formats
                    await self._auto_export_report(monthly_report.report_id, list(ReportFormat))
                
                # Generate threat actor profiles when significant activity is detected
                if current_time.hour % 6 == 0 and current_time.minute < 5:  # Every 6 hours
                    await self._check_and_generate_threat_profiles()
                
                # Generate IOC reports when new indicators are found
                if current_time.hour % 4 == 0 and current_time.minute < 5:  # Every 4 hours
                    await self._check_and_generate_ioc_reports()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in auto report generation: {e}")
                await asyncio.sleep(300)
    
    async def _cleanup_old_reports(self):
        """Clean up old reports based on retention policy"""
        while True:
            try:
                cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
                
                # Find reports to delete
                reports_to_delete = []
                for report_id, report in self.generated_reports.items():
                    report_date = datetime.fromisoformat(report.generated_at)
                    if report_date < cutoff_date:
                        reports_to_delete.append(report_id)
                
                # Delete old reports
                for report_id in reports_to_delete:
                    await self.delete_report(report_id)
                
                if reports_to_delete:
                    self.logger.info(f"Cleaned up {len(reports_to_delete)} old reports")
                
                await asyncio.sleep(86400)  # Check daily
                
            except Exception as e:
                self.logger.error(f"Error in report cleanup: {e}")
                await asyncio.sleep(86400)
    
    # Helper Methods
    def _load_report_templates(self):
        """Load report templates"""
        try:
            # Load default templates
            self.report_templates["html"] = self._get_default_html_template()
            
        except Exception as e:
            self.logger.error(f"Failed to load report templates: {e}")
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template for reports"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>{{ report.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .chart { text-align: center; margin: 20px 0; }
        .chart img { max-width: 100%; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .recommendation { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ report.title }}</h1>
        <p><strong>Report ID:</strong> {{ report.report_id }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>
        <p><strong>Time Range:</strong> {{ report.time_range_start }} to {{ report.time_range_end }}</p>
        <p><strong>Confidence Score:</strong> {{ "%.1f"|format(report.confidence_score * 100) }}%</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>{{ report.description }}</p>
        <ul>
            <li>Total Sessions: {{ report.summary.total_sessions }}</li>
            <li>Total Interactions: {{ report.summary.total_interactions }}</li>
            <li>Unique Threat Actors: {{ report.summary.unique_threat_actors }}</li>
            <li>Total Techniques: {{ report.summary.total_techniques }}</li>
            <li>Total IOCs: {{ report.summary.total_iocs }}</li>
        </ul>
    </div>
    
    {% if charts.threat_trends %}
    <div class="section">
        <h2>Threat Trends</h2>
        <div class="chart">
            <img src="data:image/png;base64,{{ charts.threat_trends }}" alt="Threat Trends Chart">
        </div>
    </div>
    {% endif %}
    
    <div class="section">
        <h2>Top Threat Techniques</h2>
        <table>
            <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Current Count</th>
                <th>Change %</th>
                <th>Direction</th>
            </tr>
            {% for trend in report.threat_trends[:10] %}
            <tr>
                <td>{{ trend.technique_id }}</td>
                <td>{{ trend.technique_name }}</td>
                <td>{{ trend.current_count }}</td>
                <td>{{ "%.1f"|format(trend.percentage_change) }}%</td>
                <td>{{ trend.direction.value }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        {% for recommendation in report.recommendations %}
        <div class="recommendation">{{ recommendation }}</div>
        {% endfor %}
    </div>
</body>
</html>
        """
    
    def _generate_report_title(self, report_type: ReportType, start_time: datetime, end_time: datetime) -> str:
        """Generate report title based on type and time range"""
        date_str = end_time.strftime("%Y-%m-%d")
        
        if report_type == ReportType.DAILY_SUMMARY:
            return f"Daily Intelligence Summary - {date_str}"
        elif report_type == ReportType.WEEKLY_ANALYSIS:
            return f"Weekly Threat Analysis - Week of {date_str}"
        elif report_type == ReportType.MONTHLY_TRENDS:
            return f"Monthly Threat Trends - {end_time.strftime('%B %Y')}"
        elif report_type == ReportType.THREAT_ACTOR_PROFILE:
            return f"Threat Actor Profile Analysis - {date_str}"
        elif report_type == ReportType.TECHNIQUE_ANALYSIS:
            return f"Attack Technique Analysis - {date_str}"
        elif report_type == ReportType.IOC_REPORT:
            return f"Indicators of Compromise Report - {date_str}"
        else:
            return f"Intelligence Report - {date_str}"
    
    def _generate_report_description(self, report_type: ReportType) -> str:
        """Generate report description based on type"""
        descriptions = {
            ReportType.DAILY_SUMMARY: "Daily summary of threat intelligence gathered from honeypot interactions.",
            ReportType.WEEKLY_ANALYSIS: "Weekly analysis of threat trends and attacker behaviors.",
            ReportType.MONTHLY_TRENDS: "Monthly trend analysis showing threat landscape evolution.",
            ReportType.THREAT_ACTOR_PROFILE: "Detailed profiling of threat actors and their capabilities.",
            ReportType.TECHNIQUE_ANALYSIS: "Analysis of attack techniques and their prevalence.",
            ReportType.IOC_REPORT: "Compilation of indicators of compromise for threat hunting.",
            ReportType.CUSTOM: "Custom intelligence report based on specific requirements."
        }
        
        return descriptions.get(report_type, "Intelligence report generated from honeypot system data.")    

    # Enhanced Reporting Methods
    async def _auto_export_report(self, report_id: str, formats: List[ReportFormat]):
        """Automatically export report in specified formats"""
        try:
            for format in formats:
                exported_data = await self.export_report(report_id, format)
                
                # Save to configured export destinations
                await self._save_exported_report(report_id, format, exported_data)
                
                # Send to external systems if configured
                await self._send_to_external_systems(report_id, format, exported_data)
                
        except Exception as e:
            self.logger.error(f"Failed to auto-export report {report_id}: {e}")
    
    async def _check_and_generate_threat_profiles(self):
        """Check for significant threat actor activity and generate profiles"""
        try:
            # Get recent intelligence data
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=6)
            
            intelligence_data = await self._collect_intelligence_data(start_time, end_time)
            threat_actors = intelligence_data.get("threat_actors", {})
            
            # Check for high-activity threat actors
            for actor_id, actor_data in threat_actors.items():
                if (actor_data.get("session_count", 0) > 5 or 
                    actor_data.get("sophistication_score", 0) > 0.8):
                    
                    # Generate threat actor profile report
                    profile_report = await self.generate_report(
                        ReportType.THREAT_ACTOR_PROFILE,
                        start_time,
                        end_time,
                        {"focus_actor": actor_id}
                    )
                    
                    # Auto-export threat profiles
                    await self._auto_export_report(
                        profile_report.report_id, 
                        [ReportFormat.JSON, ReportFormat.STIX, ReportFormat.MISP]
                    )
                    
        except Exception as e:
            self.logger.error(f"Failed to check and generate threat profiles: {e}")
    
    async def _check_and_generate_ioc_reports(self):
        """Check for new IOCs and generate reports"""
        try:
            # Get recent intelligence data
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=4)
            
            intelligence_data = await self._collect_intelligence_data(start_time, end_time)
            iocs = intelligence_data.get("iocs", [])
            
            # Check for high-confidence IOCs
            high_confidence_iocs = [ioc for ioc in iocs if ioc.get("confidence", 0) > 0.8]
            
            if len(high_confidence_iocs) > 0:
                # Generate IOC report
                ioc_report = await self.generate_report(
                    ReportType.IOC_REPORT,
                    start_time,
                    end_time,
                    {"min_confidence": 0.8}
                )
                
                # Auto-export IOC reports
                await self._auto_export_report(
                    ioc_report.report_id,
                    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.STIX]
                )
                
        except Exception as e:
            self.logger.error(f"Failed to check and generate IOC reports: {e}")
    
    async def _save_exported_report(self, report_id: str, format: ReportFormat, data: Union[str, bytes]):
        """Save exported report to configured storage"""
        try:
            import os
            
            # Create export directory if it doesn't exist
            export_dir = os.path.join(self.report_storage_path, "exports", format.value)
            os.makedirs(export_dir, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{report_id}_{timestamp}.{format.value}"
            filepath = os.path.join(export_dir, filename)
            
            # Save file
            mode = 'wb' if isinstance(data, bytes) else 'w'
            with open(filepath, mode) as f:
                f.write(data)
            
            self.logger.info(f"Saved exported report: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save exported report: {e}")
    
    async def _send_to_external_systems(self, report_id: str, format: ReportFormat, data: Union[str, bytes]):
        """Send exported report to external systems"""
        try:
            external_configs = self.config.get("external_systems", {})
            
            for system_name, system_config in external_configs.items():
                if format.value in system_config.get("supported_formats", []):
                    await self._send_to_system(system_name, system_config, report_id, format, data)
                    
        except Exception as e:
            self.logger.error(f"Failed to send to external systems: {e}")
    
    async def _send_to_system(self, system_name: str, config: Dict[str, Any], 
                            report_id: str, format: ReportFormat, data: Union[str, bytes]):
        """Send report to specific external system"""
        try:
            system_type = config.get("type")
            
            if system_type == "siem":
                await self._send_to_siem(config, report_id, format, data)
            elif system_type == "threat_intelligence":
                await self._send_to_threat_intel_platform(config, report_id, format, data)
            elif system_type == "webhook":
                await self._send_to_webhook(config, report_id, format, data)
            elif system_type == "s3":
                await self._send_to_s3(config, report_id, format, data)
            else:
                self.logger.warning(f"Unknown external system type: {system_type}")
                
        except Exception as e:
            self.logger.error(f"Failed to send to {system_name}: {e}")
    
    async def _send_to_siem(self, config: Dict[str, Any], report_id: str, 
                          format: ReportFormat, data: Union[str, bytes]):
        """Send report to SIEM system"""
        try:
            import aiohttp
            
            siem_url = config.get("url")
            headers = config.get("headers", {})
            auth = config.get("auth", {})
            
            if not siem_url:
                return
            
            # Prepare payload based on SIEM type
            if config.get("siem_type") == "splunk":
                payload = {
                    "sourcetype": "honeypot_intelligence",
                    "source": "ai_honeypot_system",
                    "event": data if isinstance(data, str) else data.decode('utf-8')
                }
            elif config.get("siem_type") == "elastic":
                payload = json.loads(data) if isinstance(data, str) else json.loads(data.decode('utf-8'))
            else:
                payload = {"report_id": report_id, "format": format.value, "data": data}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(siem_url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        self.logger.info(f"Successfully sent report {report_id} to SIEM")
                    else:
                        self.logger.error(f"Failed to send to SIEM: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Failed to send to SIEM: {e}")
    
    async def _send_to_threat_intel_platform(self, config: Dict[str, Any], report_id: str,
                                           format: ReportFormat, data: Union[str, bytes]):
        """Send report to threat intelligence platform"""
        try:
            import aiohttp
            
            platform_url = config.get("url")
            api_key = config.get("api_key")
            platform_type = config.get("platform_type")
            
            if not all([platform_url, api_key]):
                return
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Format data based on platform type
            if platform_type == "misp":
                # MISP-specific formatting
                payload = self._format_for_misp(data)
            elif platform_type == "opencti":
                # OpenCTI-specific formatting
                payload = self._format_for_opencti(data)
            else:
                # Generic format
                payload = {
                    "report_id": report_id,
                    "format": format.value,
                    "data": data if isinstance(data, str) else data.decode('utf-8'),
                    "source": "ai_honeypot_system",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(platform_url, json=payload, headers=headers) as response:
                    if response.status in [200, 201]:
                        self.logger.info(f"Successfully sent report {report_id} to threat intel platform")
                    else:
                        self.logger.error(f"Failed to send to threat intel platform: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Failed to send to threat intel platform: {e}")
    
    async def _send_to_webhook(self, config: Dict[str, Any], report_id: str,
                             format: ReportFormat, data: Union[str, bytes]):
        """Send report to webhook endpoint"""
        try:
            import aiohttp
            
            webhook_url = config.get("url")
            headers = config.get("headers", {})
            
            if not webhook_url:
                return
            
            payload = {
                "report_id": report_id,
                "format": format.value,
                "data": data if isinstance(data, str) else data.decode('utf-8'),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        self.logger.info(f"Successfully sent report {report_id} to webhook")
                    else:
                        self.logger.error(f"Failed to send to webhook: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Failed to send to webhook: {e}")
    
    async def _send_to_s3(self, config: Dict[str, Any], report_id: str,
                         format: ReportFormat, data: Union[str, bytes]):
        """Send report to S3 bucket"""
        try:
            import boto3
            
            bucket_name = config.get("bucket_name")
            key_prefix = config.get("key_prefix", "honeypot-reports")
            
            if not bucket_name:
                return
            
            s3_client = boto3.client('s3')
            
            # Generate S3 key
            timestamp = datetime.utcnow().strftime("%Y/%m/%d")
            key = f"{key_prefix}/{timestamp}/{report_id}.{format.value}"
            
            # Upload to S3
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            s3_client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=data,
                ContentType=self._get_content_type(format)
            )
            
            self.logger.info(f"Successfully uploaded report {report_id} to S3: s3://{bucket_name}/{key}")
            
        except Exception as e:
            self.logger.error(f"Failed to send to S3: {e}")
    
    def _format_for_misp(self, data: Union[str, bytes]) -> Dict[str, Any]:
        """Format data for MISP platform"""
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            
            report_data = json.loads(data)
            
            # Convert to MISP event format
            misp_event = {
                "Event": {
                    "info": report_data.get("title", "AI Honeypot Intelligence Report"),
                    "threat_level_id": "2",  # Medium
                    "analysis": "1",  # Initial
                    "distribution": "1",  # This community only
                    "Attribute": []
                }
            }
            
            # Add IOCs as attributes
            for ioc in report_data.get("iocs", []):
                attribute = {
                    "type": ioc.get("ioc_type", "other"),
                    "value": ioc.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                    "comment": ioc.get("context", "")
                }
                misp_event["Event"]["Attribute"].append(attribute)
            
            return misp_event
            
        except Exception as e:
            self.logger.error(f"Failed to format for MISP: {e}")
            return {}
    
    def _format_for_opencti(self, data: Union[str, bytes]) -> Dict[str, Any]:
        """Format data for OpenCTI platform"""
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            
            report_data = json.loads(data)
            
            # Convert to OpenCTI format
            opencti_data = {
                "type": "report",
                "name": report_data.get("title", "AI Honeypot Intelligence Report"),
                "description": report_data.get("description", ""),
                "published": report_data.get("generated_at", datetime.utcnow().isoformat()),
                "confidence": int(report_data.get("confidence_score", 0.5) * 100),
                "labels": ["honeypot", "threat-intelligence"],
                "objects": []
            }
            
            # Add threat actors
            for actor in report_data.get("threat_actors", []):
                opencti_data["objects"].append({
                    "type": "threat-actor",
                    "name": actor.get("actor_id", "Unknown"),
                    "sophistication": actor.get("sophistication_score", 0.0)
                })
            
            # Add indicators
            for ioc in report_data.get("iocs", []):
                opencti_data["objects"].append({
                    "type": "indicator",
                    "pattern": f"[{ioc.get('ioc_type', 'other')}:value = '{ioc.get('value', '')}']",
                    "labels": ["malicious-activity"]
                })
            
            return opencti_data
            
        except Exception as e:
            self.logger.error(f"Failed to format for OpenCTI: {e}")
            return {}
    
    def _get_content_type(self, format: ReportFormat) -> str:
        """Get content type for report format"""
        content_types = {
            ReportFormat.HTML: "text/html",
            ReportFormat.PDF: "application/pdf",
            ReportFormat.JSON: "application/json",
            ReportFormat.CSV: "text/csv",
            ReportFormat.STIX: "application/json",
            ReportFormat.MISP: "application/json"
        }
        return content_types.get(format, "application/octet-stream")
    
    async def generate_custom_report(self, template_name: str, parameters: Dict[str, Any]) -> IntelligenceReport:
        """Generate custom report using specified template"""
        try:
            if template_name not in self.report_templates:
                raise ValueError(f"Template {template_name} not found")
            
            template = self.report_templates[template_name]
            
            # Extract time range from parameters
            time_range_start = parameters.get("time_range_start")
            time_range_end = parameters.get("time_range_end")
            
            if isinstance(time_range_start, str):
                time_range_start = datetime.fromisoformat(time_range_start)
            if isinstance(time_range_end, str):
                time_range_end = datetime.fromisoformat(time_range_end)
            
            # Generate report using custom template
            report = await self.generate_report(
                ReportType.CUSTOM,
                time_range_start,
                time_range_end,
                parameters
            )
            
            # Apply template customizations
            report.title = template.get("title_template", "Custom Report").format(**parameters)
            report.description = template.get("description_template", "").format(**parameters)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate custom report: {e}")
            raise
    
    async def schedule_report(self, report_type: ReportType, schedule: str, 
                            export_formats: List[ReportFormat] = None,
                            external_systems: List[str] = None) -> str:
        """Schedule automatic report generation"""
        try:
            schedule_id = str(uuid4())
            
            schedule_config = {
                "schedule_id": schedule_id,
                "report_type": report_type,
                "schedule": schedule,  # Cron-like schedule
                "export_formats": export_formats or [ReportFormat.JSON],
                "external_systems": external_systems or [],
                "created_at": datetime.utcnow().isoformat(),
                "enabled": True
            }
            
            # Store schedule configuration
            # In a real implementation, this would be stored in a database
            self.logger.info(f"Scheduled report {report_type.value} with schedule {schedule}")
            
            return schedule_id
            
        except Exception as e:
            self.logger.error(f"Failed to schedule report: {e}")
            raise
    
    async def get_report_templates(self) -> Dict[str, Any]:
        """Get available report templates"""
        return self.report_templates.copy()
    
    async def create_report_template(self, name: str, template_config: Dict[str, Any]) -> str:
        """Create a new report template"""
        try:
            template_id = str(uuid4())
            
            template = {
                "template_id": template_id,
                "name": name,
                "title_template": template_config.get("title_template", "Custom Report"),
                "description_template": template_config.get("description_template", ""),
                "sections": template_config.get("sections", []),
                "filters": template_config.get("filters", {}),
                "visualizations": template_config.get("visualizations", []),
                "export_formats": template_config.get("export_formats", [ReportFormat.JSON]),
                "created_at": datetime.utcnow().isoformat()
            }
            
            self.report_templates[name] = template
            
            self.logger.info(f"Created report template: {name}")
            return template_id
            
        except Exception as e:
            self.logger.error(f"Failed to create report template: {e}")
            raise