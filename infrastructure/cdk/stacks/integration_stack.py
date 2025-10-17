"""
Integration Stack for AI Honeypot AgentCore Infrastructure
Provides SNS topics, Lambda functions, and API Gateway for external integrations
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_sns as sns,
    aws_lambda as lambda_,
    aws_lambda_event_sources as lambda_event_sources,
    aws_apigateway as apigateway,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    aws_sqs as sqs,
    Stack
)
from constructs import Construct


class IntegrationStack(Stack):
    """Integration infrastructure stack for AI Honeypot external services"""
    
    def __init__(self, scope: Construct, construct_id: str, vpc, database, 
                 storage_buckets: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.vpc = vpc
        self.database = database
        self.storage_buckets = storage_buckets
        
        # Create SNS topics for notifications
        self.create_sns_topics()
        
        # Create SQS queues for message processing
        self.create_sqs_queues()
        
        # Create Lambda functions for data processing
        self.create_lambda_functions()
        
        # Create API Gateway for external integrations
        self.create_api_gateway()
        
        # Create EventBridge rules for automation
        self.create_eventbridge_rules()
        
        # Output integration resources
        cdk.CfnOutput(
            self, "AlertsTopicArn",
            value=self.alerts_topic.topic_arn,
            description="SNS topic ARN for system alerts"
        )
        
        cdk.CfnOutput(
            self, "IntelligenceTopicArn",
            value=self.intelligence_topic.topic_arn,
            description="SNS topic ARN for intelligence reports"
        )
        
        cdk.CfnOutput(
            self, "ApiGatewayUrl",
            value=self.api.url,
            description="API Gateway URL for external integrations"
        )
    
    def create_sns_topics(self):
        """Create SNS topics for different types of notifications"""
        
        # Topic for system alerts and critical notifications
        self.alerts_topic = sns.Topic(
            self, "SystemAlertsTopic",
            topic_name="ai-honeypot-system-alerts",
            display_name="AI Honeypot System Alerts",
            fifo=False
        )
        
        # Topic for intelligence reports and findings
        self.intelligence_topic = sns.Topic(
            self, "IntelligenceReportsTopic",
            topic_name="ai-honeypot-intelligence-reports",
            display_name="AI Honeypot Intelligence Reports",
            fifo=False
        )
        
        # Topic for honeypot lifecycle events
        self.lifecycle_topic = sns.Topic(
            self, "HoneypotLifecycleTopic",
            topic_name="ai-honeypot-lifecycle-events",
            display_name="AI Honeypot Lifecycle Events",
            fifo=False
        )
        
        # Topic for security events
        self.security_topic = sns.Topic(
            self, "SecurityEventsTopic",
            topic_name="ai-honeypot-security-events",
            display_name="AI Honeypot Security Events",
            fifo=False
        )
        
        # Store topics for reference
        self.topics = {
            "alerts": self.alerts_topic,
            "intelligence": self.intelligence_topic,
            "lifecycle": self.lifecycle_topic,
            "security": self.security_topic
        }
    
    def create_sqs_queues(self):
        """Create SQS queues for message processing and buffering"""
        
        # Dead letter queue for failed message processing
        self.dlq = sqs.Queue(
            self, "DeadLetterQueue",
            queue_name="ai-honeypot-dlq",
            retention_period=cdk.Duration.days(14),
            visibility_timeout=cdk.Duration.minutes(5)
        )
        
        # Queue for intelligence processing
        self.intelligence_queue = sqs.Queue(
            self, "IntelligenceProcessingQueue",
            queue_name="ai-honeypot-intelligence-processing",
            visibility_timeout=cdk.Duration.minutes(15),
            message_retention_period=cdk.Duration.days(7),
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=self.dlq
            )
        )
        
        # Queue for data archival processing
        self.archival_queue = sqs.Queue(
            self, "DataArchivalQueue",
            queue_name="ai-honeypot-data-archival",
            visibility_timeout=cdk.Duration.minutes(10),
            message_retention_period=cdk.Duration.days(3),
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=self.dlq
            )
        )
        
        # Subscribe queues to SNS topics
        self.intelligence_topic.add_subscription(
            sns.SqsSubscription(self.intelligence_queue)
        )
        
        # Store queues for reference
        self.queues = {
            "intelligence": self.intelligence_queue,
            "archival": self.archival_queue,
            "dlq": self.dlq
        }
    
    def create_lambda_functions(self):
        """Create Lambda functions for data processing and lifecycle management"""
        
        # Lambda function for intelligence report processing
        self.intelligence_processor = lambda_.Function(
            self, "IntelligenceProcessor",
            function_name="ai-honeypot-intelligence-processor",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="intelligence_processor.handler",
            code=lambda_.Code.from_asset("../lambda"),
            timeout=cdk.Duration.minutes(5),
            memory_size=512,
            environment={
                "DATABASE_ENDPOINT": self.database.instance_endpoint.hostname,
                "DATABASE_NAME": "honeypot_intelligence",
                "DATABASE_SECRET_ARN": f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:HoneypotSystem-DatabaseCredentials-*",
                "INTELLIGENCE_BUCKET": self.storage_buckets["intelligence_reports"].bucket_name,
                "ALERTS_TOPIC_ARN": f"arn:aws:sns:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:ai-honeypot-system-alerts"
            },
            vpc=self.vpc,
            vpc_subnets=cdk.aws_ec2.SubnetSelection(
                subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            )
        )
        
        # Grant permissions to Lambda function
        self.storage_buckets["intelligence_reports"].grant_read_write(self.intelligence_processor)
        
        # Connect Lambda to SQS queue
        self.intelligence_processor.add_event_source(
            lambda_event_sources.SqsEventSource(
                self.intelligence_queue,
                batch_size=10,
                max_batching_window=cdk.Duration.seconds(30)
            )
        )
        
        # Lambda function for data lifecycle management
        self.lifecycle_manager = lambda_.Function(
            self, "DataLifecycleManager",
            function_name="ai-honeypot-lifecycle-manager",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="lifecycle_manager.handler",
            code=lambda_.Code.from_asset("../lambda"),
            timeout=cdk.Duration.minutes(15),
            memory_size=1024,
            environment={
                "DATABASE_ENDPOINT": self.database.instance_endpoint.hostname,
                "DATABASE_NAME": "honeypot_intelligence",
                "DATABASE_SECRET_ARN": f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:HoneypotSystem-DatabaseCredentials-*",
                "SESSION_DATA_BUCKET": self.storage_buckets["session_data"].bucket_name,
                "INTELLIGENCE_BUCKET": self.storage_buckets["intelligence_reports"].bucket_name,
                "AUDIT_LOGS_BUCKET": self.storage_buckets["audit_logs"].bucket_name,
                "SYNTHETIC_DATA_BUCKET": self.storage_buckets["synthetic_data"].bucket_name,
                "ALERTS_TOPIC_ARN": f"arn:aws:sns:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:ai-honeypot-system-alerts"
            }
        )
        
        # Grant permissions to lifecycle manager
        for bucket in self.storage_buckets.values():
            bucket.grant_read_write(self.lifecycle_manager)
        
        # Lambda function for security event processing
        self.security_processor = lambda_.Function(
            self, "SecurityEventProcessor",
            function_name="ai-honeypot-security-processor",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="security_processor.handler",
            code=lambda_.Code.from_asset("../lambda"),
            timeout=cdk.Duration.minutes(5),
            memory_size=512,
            environment={
                "DATABASE_ENDPOINT": self.database.instance_endpoint.hostname,
                "DATABASE_NAME": "honeypot_intelligence",
                "DATABASE_SECRET_ARN": f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:HoneypotSystem-DatabaseCredentials-*",
                "ALERTS_TOPIC_ARN": f"arn:aws:sns:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:ai-honeypot-system-alerts",
                "SECURITY_TOPIC_ARN": f"arn:aws:sns:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:ai-honeypot-security-events"
            }
        )
        
        # Lambda function for API Gateway integration
        self.api_handler = lambda_.Function(
            self, "APIHandler",
            function_name="ai-honeypot-api-handler",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="api_handler.handler",
            code=lambda_.Code.from_asset("../lambda"),
            timeout=cdk.Duration.minutes(5),
            memory_size=512,
            environment={
                "DATABASE_ENDPOINT": self.database.instance_endpoint.hostname,
                "DATABASE_NAME": "honeypot_intelligence",
                "DATABASE_SECRET_ARN": f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:HoneypotSystem-DatabaseCredentials-*",
                "INTELLIGENCE_BUCKET": self.storage_buckets["intelligence_reports"].bucket_name,
                "INTELLIGENCE_TOPIC_ARN": f"arn:aws:sns:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:ai-honeypot-intelligence-reports"
            },
            vpc=self.vpc,
            vpc_subnets=cdk.aws_ec2.SubnetSelection(
                subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            )
        )
        
        # Grant permissions to API handler
        self.storage_buckets["intelligence_reports"].grant_read_write(self.api_handler)
        
        # Store functions for reference
        self.functions = {
            "intelligence_processor": self.intelligence_processor,
            "lifecycle_manager": self.lifecycle_manager,
            "security_processor": self.security_processor,
            "api_handler": self.api_handler
        }
    
    def create_api_gateway(self):
        """Create API Gateway for external SIEM and threat intelligence integrations"""
        
        # Create REST API
        self.api = apigateway.RestApi(
            self, "HoneypotIntegrationAPI",
            rest_api_name="ai-honeypot-integration-api",
            description="API for AI Honeypot external integrations",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "Authorization"]
            ),
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]
            )
        )
        
        # Create API key for authentication
        self.api_key = self.api.add_api_key(
            "HoneypotAPIKey",
            api_key_name="ai-honeypot-integration-key",
            description="API key for AI Honeypot integrations"
        )
        
        # Create usage plan
        self.usage_plan = self.api.add_usage_plan(
            "HoneypotUsagePlan",
            name="ai-honeypot-usage-plan",
            description="Usage plan for AI Honeypot API",
            throttle=apigateway.ThrottleSettings(
                rate_limit=100,
                burst_limit=200
            ),
            quota=apigateway.QuotaSettings(
                limit=10000,
                period=apigateway.Period.DAY
            )
        )
        
        self.usage_plan.add_api_key(self.api_key)
        
        # Create resources and methods
        
        # Intelligence reports endpoint
        intelligence_resource = self.api.root.add_resource("intelligence")
        
        # GET /intelligence - retrieve intelligence reports
        intelligence_resource.add_method(
            "GET",
            apigateway.LambdaIntegration(self.api_handler),
            api_key_required=True,
            authorization_type=apigateway.AuthorizationType.NONE
        )
        
        # POST /intelligence - submit external intelligence
        intelligence_resource.add_method(
            "POST",
            apigateway.LambdaIntegration(self.api_handler),
            api_key_required=True,
            authorization_type=apigateway.AuthorizationType.NONE
        )
        
        # Additional intelligence endpoints
        reports_resource = intelligence_resource.add_resource("reports")
        reports_resource.add_method(
            "GET",
            apigateway.LambdaIntegration(self.api_handler),
            api_key_required=True
        )
        
        iocs_resource = intelligence_resource.add_resource("iocs")
        iocs_resource.add_method(
            "GET",
            apigateway.LambdaIntegration(self.api_handler),
            api_key_required=True
        )
        
        mitre_resource = intelligence_resource.add_resource("mitre")
        mitre_resource.add_method(
            "GET",
            apigateway.LambdaIntegration(self.api_handler),
            api_key_required=True
        )
        
        # Webhook endpoints
        webhooks_resource = self.api.root.add_resource("webhooks")
        siem_webhook_resource = webhooks_resource.add_resource("siem")
        siem_webhook_resource.add_method(
            "POST",
            apigateway.LambdaIntegration(self.api_handler),
            api_key_required=True
        )
        
        # Health check endpoint
        health_resource = self.api.root.add_resource("health")
        health_resource.add_method(
            "GET",
            apigateway.MockIntegration(
                integration_responses=[
                    apigateway.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": '{"status": "healthy", "timestamp": "$context.requestTime"}'
                        }
                    )
                ],
                request_templates={
                    "application/json": '{"statusCode": 200}'
                }
            ),
            method_responses=[
                apigateway.MethodResponse(
                    status_code="200",
                    response_models={
                        "application/json": apigateway.Model.EMPTY_MODEL
                    }
                )
            ]
        )
        
        # Add usage plan to API stage
        self.usage_plan.add_api_stage(
            stage=self.api.deployment_stage
        )
    
    def create_eventbridge_rules(self):
        """Create EventBridge rules for automated workflows"""
        
        # Rule for daily lifecycle management
        lifecycle_rule = events.Rule(
            self, "DailyLifecycleRule",
            rule_name="ai-honeypot-daily-lifecycle",
            description="Trigger daily data lifecycle management",
            schedule=events.Schedule.cron(
                minute="0",
                hour="2",  # 2 AM UTC
                day="*",
                month="*",
                year="*"
            )
        )
        
        lifecycle_rule.add_target(
            targets.LambdaFunction(self.lifecycle_manager)
        )
        
        # Rule for S3 object creation events
        s3_rule = events.Rule(
            self, "S3ObjectCreatedRule",
            rule_name="ai-honeypot-s3-object-created",
            description="Process new objects in S3 buckets",
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["Object Created"],
                detail={
                    "bucket": {
                        "name": [bucket.bucket_name for bucket in self.storage_buckets.values()]
                    }
                }
            )
        )
        
        s3_rule.add_target(
            targets.SqsQueue(self.archival_queue)
        )