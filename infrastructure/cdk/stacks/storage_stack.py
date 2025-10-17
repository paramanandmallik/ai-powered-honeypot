"""
Storage Stack for AI Honeypot AgentCore Infrastructure
Provides S3 buckets for session data archiving and audit logs with lifecycle policies
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    aws_kms as kms,
    aws_iam as iam,
    Stack
)
from constructs import Construct


class StorageStack(Stack):
    """Storage infrastructure stack for AI Honeypot data archiving"""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create KMS key for S3 bucket encryption
        self.storage_encryption_key = kms.Key(
            self, "StorageEncryptionKey",
            description="KMS key for AI Honeypot S3 bucket encryption",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Create S3 bucket for session data archiving
        self.session_data_bucket = s3.Bucket(
            self, "SessionDataBucket",
            bucket_name=f"ai-honeypot-session-data-{cdk.Aws.ACCOUNT_ID}-{cdk.Aws.REGION}",
            
            # Security configuration
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.storage_encryption_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            
            # Lifecycle configuration for cost optimization
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="SessionDataLifecycle",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=cdk.Duration.days(30)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=cdk.Duration.days(90)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=cdk.Duration.days(365)
                        )
                    ],
                    expiration=cdk.Duration.days(2555)  # 7 years retention
                )
            ],
            
            # Notification configuration for new objects
            event_bridge_enabled=True,
            
            removal_policy=cdk.RemovalPolicy.DESTROY  # Change to RETAIN in production
        )
        
        # Create S3 bucket for audit logs
        self.audit_logs_bucket = s3.Bucket(
            self, "AuditLogsBucket",
            bucket_name=f"ai-honeypot-audit-logs-{cdk.Aws.ACCOUNT_ID}-{cdk.Aws.REGION}",
            
            # Security configuration
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.storage_encryption_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            
            # Lifecycle configuration for compliance retention
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="AuditLogsLifecycle",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=cdk.Duration.days(90)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=cdk.Duration.days(365)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.DEEP_ARCHIVE,
                            transition_after=cdk.Duration.days(1095)  # 3 years
                        )
                    ],
                    expiration=cdk.Duration.days(3650)  # 10 years retention for compliance
                )
            ],
            
            # Enable access logging to separate bucket
            server_access_logs_prefix="access-logs/",
            
            removal_policy=cdk.RemovalPolicy.DESTROY  # Change to RETAIN in production
        )
        
        # Create S3 bucket for intelligence reports
        self.intelligence_reports_bucket = s3.Bucket(
            self, "IntelligenceReportsBucket",
            bucket_name=f"ai-honeypot-intelligence-{cdk.Aws.ACCOUNT_ID}-{cdk.Aws.REGION}",
            
            # Security configuration
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.storage_encryption_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            
            # Lifecycle configuration
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="IntelligenceReportsLifecycle",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=cdk.Duration.days(60)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=cdk.Duration.days(180)
                        )
                    ],
                    expiration=cdk.Duration.days(1825)  # 5 years retention
                )
            ],
            
            # Enable cross-region replication for disaster recovery
            # (would need destination bucket in another region)
            
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Create S3 bucket for synthetic data templates
        self.synthetic_data_bucket = s3.Bucket(
            self, "SyntheticDataBucket",
            bucket_name=f"ai-honeypot-synthetic-data-{cdk.Aws.ACCOUNT_ID}-{cdk.Aws.REGION}",
            
            # Security configuration
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.storage_encryption_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            
            # Lifecycle configuration
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="SyntheticDataLifecycle",
                    enabled=True,
                    abort_incomplete_multipart_upload_after=cdk.Duration.days(1),
                    noncurrent_version_expiration=cdk.Duration.days(30)
                )
            ],
            
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Create bucket policy for cross-account access (if needed)
        self.create_bucket_policies()
        
        # Store bucket references for other stacks
        self.buckets = {
            "session_data": self.session_data_bucket,
            "audit_logs": self.audit_logs_bucket,
            "intelligence_reports": self.intelligence_reports_bucket,
            "synthetic_data": self.synthetic_data_bucket
        }
        
        # Output bucket information
        cdk.CfnOutput(
            self, "SessionDataBucketName",
            value=self.session_data_bucket.bucket_name,
            description="S3 bucket for session data archiving"
        )
        
        cdk.CfnOutput(
            self, "AuditLogsBucketName",
            value=self.audit_logs_bucket.bucket_name,
            description="S3 bucket for audit logs"
        )
        
        cdk.CfnOutput(
            self, "IntelligenceReportsBucketName",
            value=self.intelligence_reports_bucket.bucket_name,
            description="S3 bucket for intelligence reports"
        )
        
        cdk.CfnOutput(
            self, "SyntheticDataBucketName",
            value=self.synthetic_data_bucket.bucket_name,
            description="S3 bucket for synthetic data templates"
        )
        
        cdk.CfnOutput(
            self, "StorageEncryptionKeyId",
            value=self.storage_encryption_key.key_id,
            description="KMS key ID for storage encryption"
        )
    
    def create_bucket_policies(self):
        """Create bucket policies for secure access"""
        
        # Policy for session data bucket - restrict to AgentCore agents only
        session_data_policy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    sid="DenyInsecureConnections",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=["s3:*"],
                    resources=[
                        self.session_data_bucket.bucket_arn,
                        f"{self.session_data_bucket.bucket_arn}/*"
                    ],
                    conditions={
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    }
                ),
                iam.PolicyStatement(
                    sid="RequireSSEKMS",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=["s3:PutObject"],
                    resources=[f"{self.session_data_bucket.bucket_arn}/*"],
                    conditions={
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "aws:kms"
                        }
                    }
                )
            ]
        )
        
        # Apply policy to session data bucket
        s3.CfnBucketPolicy(
            self, "SessionDataBucketPolicy",
            bucket=self.session_data_bucket.bucket_name,
            policy_document=session_data_policy
        )
        
        # Similar policies for other buckets
        audit_logs_policy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    sid="DenyInsecureConnections",
                    effect=iam.Effect.DENY,
                    principals=[iam.AnyPrincipal()],
                    actions=["s3:*"],
                    resources=[
                        self.audit_logs_bucket.bucket_arn,
                        f"{self.audit_logs_bucket.bucket_arn}/*"
                    ],
                    conditions={
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    }
                )
            ]
        )
        
        s3.CfnBucketPolicy(
            self, "AuditLogsBucketPolicy",
            bucket=self.audit_logs_bucket.bucket_name,
            policy_document=audit_logs_policy
        )