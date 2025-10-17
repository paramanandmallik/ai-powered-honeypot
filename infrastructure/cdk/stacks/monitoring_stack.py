"""
Monitoring Stack for AI Honeypot AgentCore Infrastructure
Provides CloudWatch monitoring, metrics, dashboards, and alerting
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_cloudwatch as cloudwatch,
    aws_logs as logs,
    aws_sns as sns,
    aws_cloudwatch_actions as cw_actions,
    aws_iam as iam,
    Stack
)
from constructs import Construct


class MonitoringStack(Stack):
    """Monitoring infrastructure stack for AI Honeypot system"""
    
    def __init__(self, scope: Construct, construct_id: str, vpc, database, 
                 storage_buckets: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.vpc = vpc
        self.database = database
        self.storage_buckets = storage_buckets
        
        # Create SNS topic for alerts (will be used in integration stack too)
        self.alerts_topic = sns.Topic(
            self, "HoneypotAlertsTopic",
            topic_name="ai-honeypot-alerts",
            display_name="AI Honeypot System Alerts"
        )
        
        # Create CloudWatch Log Groups for different components
        self.create_log_groups()
        
        # Create custom metrics and alarms
        self.create_custom_metrics()
        
        # Create CloudWatch Dashboard
        self.create_dashboard()
        
        # Create alarms for system monitoring
        self.create_alarms()
        
        # Output monitoring resources
        cdk.CfnOutput(
            self, "AlertsTopicArn",
            value=self.alerts_topic.topic_arn,
            description="SNS topic ARN for system alerts"
        )
        
        cdk.CfnOutput(
            self, "DashboardUrl",
            value=f"https://{cdk.Aws.REGION}.console.aws.amazon.com/cloudwatch/home?region={cdk.Aws.REGION}#dashboards:name={self.dashboard.dashboard_name}",
            description="CloudWatch Dashboard URL"
        )
    
    def create_log_groups(self):
        """Create CloudWatch Log Groups for different system components"""
        
        # AgentCore Runtime logs
        self.agentcore_logs = logs.LogGroup(
            self, "AgentCoreRuntimeLogs",
            log_group_name="/aws/agentcore/honeypot-system",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Detection Agent logs
        self.detection_agent_logs = logs.LogGroup(
            self, "DetectionAgentLogs",
            log_group_name="/aws/agentcore/detection-agent",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Coordinator Agent logs
        self.coordinator_agent_logs = logs.LogGroup(
            self, "CoordinatorAgentLogs",
            log_group_name="/aws/agentcore/coordinator-agent",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Interaction Agent logs
        self.interaction_agent_logs = logs.LogGroup(
            self, "InteractionAgentLogs",
            log_group_name="/aws/agentcore/interaction-agent",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Intelligence Agent logs
        self.intelligence_agent_logs = logs.LogGroup(
            self, "IntelligenceAgentLogs",
            log_group_name="/aws/agentcore/intelligence-agent",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Honeypot infrastructure logs
        self.honeypot_logs = logs.LogGroup(
            self, "HoneypotInfrastructureLogs",
            log_group_name="/aws/honeypot/infrastructure",
            retention=logs.RetentionDays.THREE_MONTHS,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Security audit logs
        self.security_logs = logs.LogGroup(
            self, "SecurityAuditLogs",
            log_group_name="/aws/honeypot/security-audit",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
    
    def create_custom_metrics(self):
        """Create custom CloudWatch metrics for honeypot system"""
        
        # Metric filters for agent performance
        self.detection_agent_logs.add_metric_filter(
            "DetectionAgentErrors",
            metric_name="DetectionAgentErrors",
            metric_namespace="HoneypotSystem/Agents",
            filter_pattern=logs.FilterPattern.literal("[ERROR]"),
            metric_value="1",
            default_value=0
        )
        
        self.coordinator_agent_logs.add_metric_filter(
            "CoordinatorAgentErrors",
            metric_name="CoordinatorAgentErrors",
            metric_namespace="HoneypotSystem/Agents",
            filter_pattern=logs.FilterPattern.literal("[ERROR]"),
            metric_value="1",
            default_value=0
        )
        
        self.interaction_agent_logs.add_metric_filter(
            "InteractionAgentErrors",
            metric_name="InteractionAgentErrors",
            metric_namespace="HoneypotSystem/Agents",
            filter_pattern=logs.FilterPattern.literal("[ERROR]"),
            metric_value="1",
            default_value=0
        )
        
        # Metric filters for security events
        self.security_logs.add_metric_filter(
            "SecurityViolations",
            metric_name="SecurityViolations",
            metric_namespace="HoneypotSystem/Security",
            filter_pattern=logs.FilterPattern.literal("[SECURITY_VIOLATION]"),
            metric_value="1",
            default_value=0
        )
        
        self.security_logs.add_metric_filter(
            "RealDataDetected",
            metric_name="RealDataDetected",
            metric_namespace="HoneypotSystem/Security",
            filter_pattern=logs.FilterPattern.literal("[REAL_DATA_DETECTED]"),
            metric_value="1",
            default_value=0
        )
        
        # Metric filters for honeypot activity
        self.honeypot_logs.add_metric_filter(
            "AttackerEngagements",
            metric_name="AttackerEngagements",
            metric_namespace="HoneypotSystem/Activity",
            filter_pattern=logs.FilterPattern.literal("[ENGAGEMENT_START]"),
            metric_value="1",
            default_value=0
        )
        
        self.honeypot_logs.add_metric_filter(
            "HoneypotCreations",
            metric_name="HoneypotCreations",
            metric_namespace="HoneypotSystem/Activity",
            filter_pattern=logs.FilterPattern.literal("[HONEYPOT_CREATED]"),
            metric_value="1",
            default_value=0
        )
    
    def create_dashboard(self):
        """Create CloudWatch Dashboard for system monitoring"""
        
        self.dashboard = cloudwatch.Dashboard(
            self, "HoneypotSystemDashboard",
            dashboard_name="AI-Honeypot-System-Overview"
        )
        
        # Agent health widgets
        agent_health_widget = cloudwatch.GraphWidget(
            title="Agent Health Status",
            left=[
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Agents",
                    metric_name="DetectionAgentErrors",
                    statistic="Sum",
                    period=cdk.Duration.minutes(5)
                ),
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Agents",
                    metric_name="CoordinatorAgentErrors",
                    statistic="Sum",
                    period=cdk.Duration.minutes(5)
                ),
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Agents",
                    metric_name="InteractionAgentErrors",
                    statistic="Sum",
                    period=cdk.Duration.minutes(5)
                )
            ],
            width=12,
            height=6
        )
        
        # Database performance widget
        database_widget = cloudwatch.GraphWidget(
            title="Database Performance",
            left=[
                cloudwatch.Metric(
                    namespace="AWS/RDS",
                    metric_name="CPUUtilization",
                    dimensions_map={"DBInstanceIdentifier": self.database.instance_identifier},
                    statistic="Average",
                    period=cdk.Duration.minutes(5)
                ),
                cloudwatch.Metric(
                    namespace="AWS/RDS",
                    metric_name="DatabaseConnections",
                    dimensions_map={"DBInstanceIdentifier": self.database.instance_identifier},
                    statistic="Average",
                    period=cdk.Duration.minutes(5)
                )
            ],
            right=[
                cloudwatch.Metric(
                    namespace="AWS/RDS",
                    metric_name="ReadLatency",
                    dimensions_map={"DBInstanceIdentifier": self.database.instance_identifier},
                    statistic="Average",
                    period=cdk.Duration.minutes(5)
                ),
                cloudwatch.Metric(
                    namespace="AWS/RDS",
                    metric_name="WriteLatency",
                    dimensions_map={"DBInstanceIdentifier": self.database.instance_identifier},
                    statistic="Average",
                    period=cdk.Duration.minutes(5)
                )
            ],
            width=12,
            height=6
        )
        
        # Security monitoring widget
        security_widget = cloudwatch.GraphWidget(
            title="Security Events",
            left=[
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Security",
                    metric_name="SecurityViolations",
                    statistic="Sum",
                    period=cdk.Duration.minutes(5)
                ),
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Security",
                    metric_name="RealDataDetected",
                    statistic="Sum",
                    period=cdk.Duration.minutes(5)
                )
            ],
            width=12,
            height=6
        )
        
        # Activity monitoring widget
        activity_widget = cloudwatch.GraphWidget(
            title="Honeypot Activity",
            left=[
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Activity",
                    metric_name="AttackerEngagements",
                    statistic="Sum",
                    period=cdk.Duration.minutes(15)
                ),
                cloudwatch.Metric(
                    namespace="HoneypotSystem/Activity",
                    metric_name="HoneypotCreations",
                    statistic="Sum",
                    period=cdk.Duration.minutes(15)
                )
            ],
            width=12,
            height=6
        )
        
        # Add widgets to dashboard
        self.dashboard.add_widgets(
            agent_health_widget,
            database_widget,
            security_widget,
            activity_widget
        )
    
    def create_alarms(self):
        """Create CloudWatch alarms for system monitoring"""
        
        # High error rate alarm for Detection Agent
        detection_agent_alarm = cloudwatch.Alarm(
            self, "DetectionAgentHighErrorRate",
            alarm_name="HoneypotSystem-DetectionAgent-HighErrorRate",
            alarm_description="Detection Agent error rate is too high",
            metric=cloudwatch.Metric(
                namespace="HoneypotSystem/Agents",
                metric_name="DetectionAgentErrors",
                statistic="Sum",
                period=cdk.Duration.minutes(5)
            ),
            threshold=5,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        detection_agent_alarm.add_alarm_action(cw_actions.SnsAction(self.alerts_topic))
        
        # Database CPU utilization alarm
        database_cpu_alarm = cloudwatch.Alarm(
            self, "DatabaseHighCPU",
            alarm_name="HoneypotSystem-Database-HighCPU",
            alarm_description="Database CPU utilization is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/RDS",
                metric_name="CPUUtilization",
                dimensions_map={"DBInstanceIdentifier": self.database.instance_identifier},
                statistic="Average",
                period=cdk.Duration.minutes(5)
            ),
            threshold=80,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        database_cpu_alarm.add_alarm_action(cw_actions.SnsAction(self.alerts_topic))
        
        # Security violation alarm (critical)
        security_violation_alarm = cloudwatch.Alarm(
            self, "SecurityViolationDetected",
            alarm_name="HoneypotSystem-SecurityViolation-CRITICAL",
            alarm_description="Security violation detected in honeypot system",
            metric=cloudwatch.Metric(
                namespace="HoneypotSystem/Security",
                metric_name="SecurityViolations",
                statistic="Sum",
                period=cdk.Duration.minutes(1)
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        security_violation_alarm.add_alarm_action(cw_actions.SnsAction(self.alerts_topic))
        
        # Real data detection alarm (critical)
        real_data_alarm = cloudwatch.Alarm(
            self, "RealDataDetected",
            alarm_name="HoneypotSystem-RealDataDetected-CRITICAL",
            alarm_description="Real data detected in honeypot system - immediate action required",
            metric=cloudwatch.Metric(
                namespace="HoneypotSystem/Security",
                metric_name="RealDataDetected",
                statistic="Sum",
                period=cdk.Duration.minutes(1)
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        real_data_alarm.add_alarm_action(cw_actions.SnsAction(self.alerts_topic))
        
        # S3 bucket monitoring alarms
        for bucket_name, bucket in self.storage_buckets.items():
            bucket_size_alarm = cloudwatch.Alarm(
                self, f"{bucket_name.title()}BucketSize",
                alarm_name=f"HoneypotSystem-{bucket_name.title()}Bucket-LargeSize",
                alarm_description=f"{bucket_name} bucket size is growing too large",
                metric=cloudwatch.Metric(
                    namespace="AWS/S3",
                    metric_name="BucketSizeBytes",
                    dimensions_map={
                        "BucketName": bucket.bucket_name,
                        "StorageType": "StandardStorage"
                    },
                    statistic="Average",
                    period=cdk.Duration.days(1)
                ),
                threshold=100 * 1024 * 1024 * 1024,  # 100 GB
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
            )
            bucket_size_alarm.add_alarm_action(cw_actions.SnsAction(self.alerts_topic))