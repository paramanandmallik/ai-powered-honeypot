"""
Security Stack for AI Honeypot AgentCore Infrastructure
Provides IAM roles, security groups, and access control policies
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_kms as kms,
    Stack
)
from constructs import Construct


class SecurityStack(Stack):
    """Security infrastructure stack for AI Honeypot system"""
    
    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.Vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.vpc = vpc
        
        # Create security groups
        self.create_security_groups()
        
        # Create IAM roles and policies
        self.create_iam_roles()
        
        # Create KMS keys for additional encryption needs
        self.create_kms_keys()
        
        # Output security resources
        cdk.CfnOutput(
            self, "AgentCoreExecutionRoleArn",
            value=self.agentcore_execution_role.role_arn,
            description="IAM role ARN for AgentCore Runtime execution"
        )
        
        cdk.CfnOutput(
            self, "DatabaseSecurityGroupId",
            value=self.database_security_groups["database"].security_group_id,
            description="Security group ID for database access"
        )
    
    def create_security_groups(self):
        """Create security groups for different system components"""
        
        # Security group for AgentCore Runtime agents
        self.agentcore_sg = ec2.SecurityGroup(
            self, "AgentCoreSecurityGroup",
            vpc=self.vpc,
            description="Security group for AgentCore Runtime agents",
            allow_all_outbound=True
        )
        
        # Security group for database access
        self.database_sg = ec2.SecurityGroup(
            self, "DatabaseSecurityGroup",
            vpc=self.vpc,
            description="Security group for RDS database access",
            allow_all_outbound=False
        )
        
        # Allow AgentCore agents to access database
        self.database_sg.add_ingress_rule(
            peer=self.agentcore_sg,
            connection=ec2.Port.tcp(5432),
            description="Allow AgentCore agents to access PostgreSQL database"
        )
        
        # Security group for honeypot infrastructure
        self.honeypot_sg = ec2.SecurityGroup(
            self, "HoneypotSecurityGroup",
            vpc=self.vpc,
            description="Security group for honeypot infrastructure",
            allow_all_outbound=False
        )
        
        # Allow AgentCore agents to manage honeypots
        self.honeypot_sg.add_ingress_rule(
            peer=self.agentcore_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow AgentCore agents to manage honeypots"
        )
        
        # Allow honeypots to communicate with AgentCore agents
        self.honeypot_sg.add_egress_rule(
            peer=self.agentcore_sg,
            connection=ec2.Port.all_traffic(),
            description="Allow honeypots to communicate with AgentCore agents"
        )
        
        # Security group for management dashboard
        self.dashboard_sg = ec2.SecurityGroup(
            self, "DashboardSecurityGroup",
            vpc=self.vpc,
            description="Security group for management dashboard",
            allow_all_outbound=True
        )
        
        # Allow HTTPS access to dashboard from specific IP ranges (configure as needed)
        self.dashboard_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4("10.0.0.0/8"),  # Internal networks only
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS access to management dashboard"
        )
        
        # Store security groups for other stacks
        self.database_security_groups = {
            "database": self.database_sg
        }
        
        self.security_groups = {
            "agentcore": self.agentcore_sg,
            "database": self.database_sg,
            "honeypot": self.honeypot_sg,
            "dashboard": self.dashboard_sg
        }
    
    def create_iam_roles(self):
        """Create IAM roles and policies for system components"""
        
        # IAM role for AgentCore Runtime execution
        self.agentcore_execution_role = iam.Role(
            self, "AgentCoreExecutionRole",
            role_name="HoneypotSystem-AgentCore-ExecutionRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            description="Execution role for AI Honeypot AgentCore Runtime agents",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonVPCReadOnlyAccess")
            ]
        )
        
        # Custom policy for AgentCore agents
        agentcore_policy = iam.Policy(
            self, "AgentCoreCustomPolicy",
            policy_name="HoneypotSystem-AgentCore-CustomPolicy",
            statements=[
                # S3 access for data storage
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket"
                    ],
                    resources=[
                        f"arn:aws:s3:::ai-honeypot-*",
                        f"arn:aws:s3:::ai-honeypot-*/*"
                    ]
                ),
                # RDS access for intelligence data
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "rds:DescribeDBInstances",
                        "rds:DescribeDBClusters"
                    ],
                    resources=["*"]
                ),
                # Secrets Manager access for database credentials
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret"
                    ],
                    resources=[
                        f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:HoneypotSystem-*"
                    ]
                ),
                # KMS access for encryption/decryption
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:Encrypt",
                        "kms:GenerateDataKey",
                        "kms:ReEncrypt*"
                    ],
                    resources=[
                        f"arn:aws:kms:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:key/*"
                    ],
                    conditions={
                        "StringEquals": {
                            "kms:ViaService": [
                                f"s3.{cdk.Aws.REGION}.amazonaws.com",
                                f"rds.{cdk.Aws.REGION}.amazonaws.com"
                            ]
                        }
                    }
                ),
                # SNS access for notifications
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "sns:Publish"
                    ],
                    resources=[
                        f"arn:aws:sns:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:ai-honeypot-*"
                    ]
                ),
                # CloudWatch metrics and logs
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "cloudwatch:PutMetricData",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogStreams"
                    ],
                    resources=["*"]
                )
            ]
        )
        
        self.agentcore_execution_role.attach_inline_policy(agentcore_policy)
        
        # IAM role for Lambda functions (used in integration stack)
        self.lambda_execution_role = iam.Role(
            self, "LambdaExecutionRole",
            role_name="HoneypotSystem-Lambda-ExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Execution role for AI Honeypot Lambda functions",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"),
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )
        
        # Custom policy for Lambda functions
        lambda_policy = iam.Policy(
            self, "LambdaCustomPolicy",
            policy_name="HoneypotSystem-Lambda-CustomPolicy",
            statements=[
                # S3 access for data processing
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    resources=[
                        f"arn:aws:s3:::ai-honeypot-*/*"
                    ]
                ),
                # RDS access for data queries
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "rds:DescribeDBInstances"
                    ],
                    resources=["*"]
                ),
                # Secrets Manager access
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "secretsmanager:GetSecretValue"
                    ],
                    resources=[
                        f"arn:aws:secretsmanager:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:secret:HoneypotSystem-*"
                    ]
                )
            ]
        )
        
        self.lambda_execution_role.attach_inline_policy(lambda_policy)
        
        # IAM role for API Gateway (if needed)
        self.api_gateway_role = iam.Role(
            self, "ApiGatewayRole",
            role_name="HoneypotSystem-ApiGateway-Role",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            description="Role for API Gateway to access backend services"
        )
        
        # Store roles for other stacks
        self.roles = {
            "agentcore_execution": self.agentcore_execution_role,
            "lambda_execution": self.lambda_execution_role,
            "api_gateway": self.api_gateway_role
        }
    
    def create_kms_keys(self):
        """Create additional KMS keys for encryption"""
        
        # KMS key for AgentCore Runtime encryption
        self.agentcore_encryption_key = kms.Key(
            self, "AgentCoreEncryptionKey",
            description="KMS key for AgentCore Runtime encryption",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Allow AgentCore execution role to use the key
        self.agentcore_encryption_key.grant_encrypt_decrypt(self.agentcore_execution_role)
        
        # KMS key for Lambda function encryption
        self.lambda_encryption_key = kms.Key(
            self, "LambdaEncryptionKey",
            description="KMS key for Lambda function encryption",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Allow Lambda execution role to use the key
        self.lambda_encryption_key.grant_encrypt_decrypt(self.lambda_execution_role)
        
        # Store keys for other stacks
        self.encryption_keys = {
            "agentcore": self.agentcore_encryption_key,
            "lambda": self.lambda_encryption_key
        }
        
        # Output key information
        cdk.CfnOutput(
            self, "AgentCoreEncryptionKeyId",
            value=self.agentcore_encryption_key.key_id,
            description="KMS key ID for AgentCore Runtime encryption"
        )
        
        cdk.CfnOutput(
            self, "LambdaEncryptionKeyId",
            value=self.lambda_encryption_key.key_id,
            description="KMS key ID for Lambda function encryption"
        )