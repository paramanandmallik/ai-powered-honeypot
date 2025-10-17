"""
Database Stack for AI Honeypot AgentCore Infrastructure
Provides RDS database for intelligence data storage with encryption and backup
"""

import aws_cdk as cdk
from aws_cdk import (
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_secretsmanager as secretsmanager,
    aws_kms as kms,
    aws_logs as logs,
    Stack
)
from constructs import Construct


class DatabaseStack(Stack):
    """Database infrastructure stack for AI Honeypot intelligence storage"""
    
    def __init__(self, scope: Construct, construct_id: str, vpc: ec2.Vpc, 
                 security_groups: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.vpc = vpc
        self.security_groups = security_groups
        
        # Create KMS key for database encryption
        self.db_encryption_key = kms.Key(
            self, "DatabaseEncryptionKey",
            description="KMS key for AI Honeypot database encryption",
            enable_key_rotation=True,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Create database credentials in Secrets Manager
        self.db_credentials = secretsmanager.Secret(
            self, "DatabaseCredentials",
            description="Database credentials for AI Honeypot intelligence database",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"username": "honeypot_admin"}',
                generate_string_key="password",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\"\\",
                password_length=32
            )
        )
        
        # Create DB subnet group for private subnets
        self.db_subnet_group = rds.SubnetGroup(
            self, "DatabaseSubnetGroup",
            description="Subnet group for AI Honeypot database",
            vpc=self.vpc,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Create parameter group for PostgreSQL optimization
        self.db_parameter_group = rds.ParameterGroup(
            self, "DatabaseParameterGroup",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_15_4
            ),
            description="Parameter group for AI Honeypot PostgreSQL database",
            parameters={
                "shared_preload_libraries": "pg_stat_statements",
                "log_statement": "all",
                "log_min_duration_statement": "1000",
                "log_checkpoints": "on",
                "log_connections": "on",
                "log_disconnections": "on"
            }
        )
        
        # Create RDS instance for intelligence data
        self.database = rds.DatabaseInstance(
            self, "IntelligenceDatabase",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_15_4
            ),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3,
                ec2.InstanceSize.MEDIUM
            ),
            credentials=rds.Credentials.from_secret(self.db_credentials),
            vpc=self.vpc,
            subnet_group=self.db_subnet_group,
            security_groups=[self.security_groups["database"]],
            parameter_group=self.db_parameter_group,
            
            # Storage configuration
            allocated_storage=100,
            max_allocated_storage=1000,
            storage_type=rds.StorageType.GP3,
            storage_encrypted=True,
            storage_encryption_key=self.db_encryption_key,
            
            # Backup and maintenance
            backup_retention=cdk.Duration.days(7),
            delete_automated_backups=True,
            deletion_protection=False,  # Set to True in production
            preferred_backup_window="03:00-04:00",
            preferred_maintenance_window="sun:04:00-sun:05:00",
            
            # Monitoring and logging
            monitoring_interval=cdk.Duration.seconds(60),
            enable_performance_insights=True,
            performance_insight_retention=rds.PerformanceInsightRetention.DEFAULT,
            cloudwatch_logs_exports=["postgresql"],
            
            # Multi-AZ for production (disabled for cost in dev)
            multi_az=False,  # Set to True in production
            
            database_name="honeypot_intelligence",
            removal_policy=cdk.RemovalPolicy.DESTROY  # Change to RETAIN in production
        )
        
        # Create read replica for analytics workloads
        self.read_replica = rds.DatabaseInstanceReadReplica(
            self, "IntelligenceDatabaseReadReplica",
            source_database_instance=self.database,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3,
                ec2.InstanceSize.SMALL
            ),
            vpc=self.vpc,
            subnet_group=self.db_subnet_group,
            security_groups=[self.security_groups["database"]],
            
            # Storage encryption (inherited from source)
            storage_encrypted=True,
            
            # Monitoring
            monitoring_interval=cdk.Duration.seconds(60),
            enable_performance_insights=True,
            
            deletion_protection=False,  # Set to True in production
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Create CloudWatch log groups for database logs
        self.db_log_group = logs.LogGroup(
            self, "DatabaseLogGroup",
            log_group_name=f"/aws/rds/instance/{self.database.instance_identifier}/postgresql",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        
        # Output database connection information
        cdk.CfnOutput(
            self, "DatabaseEndpoint",
            value=self.database.instance_endpoint.hostname,
            description="RDS database endpoint for intelligence data"
        )
        
        cdk.CfnOutput(
            self, "DatabasePort",
            value=str(self.database.instance_endpoint.port),
            description="RDS database port"
        )
        
        cdk.CfnOutput(
            self, "DatabaseName",
            value="honeypot_intelligence",
            description="Database name for intelligence data"
        )
        
        cdk.CfnOutput(
            self, "DatabaseCredentialsSecretArn",
            value=self.db_credentials.secret_arn,
            description="ARN of the secret containing database credentials"
        )
        
        cdk.CfnOutput(
            self, "ReadReplicaEndpoint",
            value=self.read_replica.instance_endpoint.hostname,
            description="Read replica endpoint for analytics workloads"
        )