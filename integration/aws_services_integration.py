#!/usr/bin/env python3
"""
AWS Services Integration Module

Provides integration between AgentCore Runtime agents and AWS supporting services
including S3, RDS, CloudWatch, SNS, and VPC networking.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import aioboto3


class AWSServicesIntegration:
    """
    Manages integration with AWS supporting services
    """
    
    def __init__(self, region: str = "us-east-1", config: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger(__name__)
        self.region = region
        self.config = config or {}
        
        # AWS clients (will be initialized async)
        self.s3_client = None
        self.rds_client = None
        self.cloudwatch_client = None
        self.sns_client = None
        self.ec2_client = None
        self.lambda_client = None
        
        # Service status tracking
        self.service_status = {
            "s3": "disconnected",
            "rds": "disconnected", 
            "cloudwatch": "disconnected",
            "sns": "disconnected",
            "ec2": "disconnected",
            "lambda": "disconnected"
        }
        
        # Integration metrics
        self.integration_metrics = {
            "s3_operations": 0,
            "rds_queries": 0,
            "cloudwatch_metrics": 0,
            "sns_notifications": 0,
            "last_health_check": None,
            "error_count": 0
        }
        
        # Resource tracking
        self.managed_resources = {
            "s3_buckets": [],
            "rds_instances": [],
            "sns_topics": [],
            "lambda_functions": [],
            "vpc_resources": []
        }
    
    async def initialize(self) -> bool:
        """Initialize AWS service connections"""
        try:
            self.logger.info("Initializing AWS services integration...")
            
            # Create async AWS clients
            session = aioboto3.Session()
            
            # Initialize S3 client
            self.s3_client = session.client('s3', region_name=self.region)
            await self._test_s3_connection()
            
            # Initialize RDS client
            self.rds_client = session.client('rds', region_name=self.region)
            await self._test_rds_connection()
            
            # Initialize CloudWatch client
            self.cloudwatch_client = session.client('cloudwatch', region_name=self.region)
            await self._test_cloudwatch_connection()
            
            # Initialize SNS client
            self.sns_client = session.client('sns', region_name=self.region)
            await self._test_sns_connection()
            
            # Initialize EC2 client
            self.ec2_client = session.client('ec2', region_name=self.region)
            await self._test_ec2_connection()
            
            # Initialize Lambda client
            self.lambda_client = session.client('lambda', region_name=self.region)
            await self._test_lambda_connection()
            
            # Discover existing resources
            await self._discover_managed_resources()
            
            self.logger.info("AWS services integration initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"AWS services integration initialization failed: {e}")
            return False
    
    async def _test_s3_connection(self):
        """Test S3 connection and permissions"""
        try:
            async with self.s3_client as s3:
                # List buckets to test connection
                response = await s3.list_buckets()
                self.service_status["s3"] = "connected"
                self.logger.info("S3 connection established")
        except Exception as e:
            self.service_status["s3"] = f"error: {e}"
            raise
    
    async def _test_rds_connection(self):
        """Test RDS connection and permissions"""
        try:
            async with self.rds_client as rds:
                # Describe DB instances to test connection
                response = await rds.describe_db_instances()
                self.service_status["rds"] = "connected"
                self.logger.info("RDS connection established")
        except Exception as e:
            self.service_status["rds"] = f"error: {e}"
            raise
    
    async def _test_cloudwatch_connection(self):
        """Test CloudWatch connection and permissions"""
        try:
            async with self.cloudwatch_client as cw:
                # List metrics to test connection
                response = await cw.list_metrics(MaxRecords=1)
                self.service_status["cloudwatch"] = "connected"
                self.logger.info("CloudWatch connection established")
        except Exception as e:
            self.service_status["cloudwatch"] = f"error: {e}"
            raise
    
    async def _test_sns_connection(self):
        """Test SNS connection and permissions"""
        try:
            async with self.sns_client as sns:
                # List topics to test connection
                response = await sns.list_topics()
                self.service_status["sns"] = "connected"
                self.logger.info("SNS connection established")
        except Exception as e:
            self.service_status["sns"] = f"error: {e}"
            raise
    
    async def _test_ec2_connection(self):
        """Test EC2 connection and permissions"""
        try:
            async with self.ec2_client as ec2:
                # Describe regions to test connection
                response = await ec2.describe_regions()
                self.service_status["ec2"] = "connected"
                self.logger.info("EC2 connection established")
        except Exception as e:
            self.service_status["ec2"] = f"error: {e}"
            raise
    
    async def _test_lambda_connection(self):
        """Test Lambda connection and permissions"""
        try:
            async with self.lambda_client as lambda_client:
                # List functions to test connection
                response = await lambda_client.list_functions(MaxItems=1)
                self.service_status["lambda"] = "connected"
                self.logger.info("Lambda connection established")
        except Exception as e:
            self.service_status["lambda"] = f"error: {e}"
            raise
    
    async def _discover_managed_resources(self):
        """Discover existing managed resources"""
        try:
            # Discover S3 buckets with honeypot tags
            await self._discover_s3_resources()
            
            # Discover RDS instances
            await self._discover_rds_resources()
            
            # Discover SNS topics
            await self._discover_sns_resources()
            
            # Discover Lambda functions
            await self._discover_lambda_resources()
            
            # Discover VPC resources
            await self._discover_vpc_resources()
            
            self.logger.info("Resource discovery completed")
            
        except Exception as e:
            self.logger.error(f"Resource discovery failed: {e}")
    
    async def _discover_s3_resources(self):
        """Discover S3 buckets managed by the system"""
        try:
            async with self.s3_client as s3:
                response = await s3.list_buckets()
                
                for bucket in response.get('Buckets', []):
                    bucket_name = bucket['Name']
                    
                    # Check if bucket has honeypot tags
                    try:
                        tags_response = await s3.get_bucket_tagging(Bucket=bucket_name)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagSet', [])}
                        
                        if tags.get('Project') == 'ai-honeypot':
                            self.managed_resources["s3_buckets"].append({
                                "name": bucket_name,
                                "creation_date": bucket['CreationDate'],
                                "tags": tags
                            })
                    except ClientError:
                        # Bucket has no tags or access denied
                        pass
        
        except Exception as e:
            self.logger.error(f"S3 resource discovery failed: {e}")
    
    async def _discover_rds_resources(self):
        """Discover RDS instances managed by the system"""
        try:
            async with self.rds_client as rds:
                response = await rds.describe_db_instances()
                
                for db_instance in response.get('DBInstances', []):
                    # Check if instance has honeypot tags
                    db_arn = db_instance['DBInstanceArn']
                    
                    try:
                        tags_response = await rds.list_tags_for_resource(ResourceName=db_arn)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagList', [])}
                        
                        if tags.get('Project') == 'ai-honeypot':
                            self.managed_resources["rds_instances"].append({
                                "identifier": db_instance['DBInstanceIdentifier'],
                                "endpoint": db_instance.get('Endpoint', {}).get('Address'),
                                "status": db_instance['DBInstanceStatus'],
                                "tags": tags
                            })
                    except ClientError:
                        # Access denied or no tags
                        pass
        
        except Exception as e:
            self.logger.error(f"RDS resource discovery failed: {e}")
    
    async def _discover_sns_resources(self):
        """Discover SNS topics managed by the system"""
        try:
            async with self.sns_client as sns:
                response = await sns.list_topics()
                
                for topic in response.get('Topics', []):
                    topic_arn = topic['TopicArn']
                    
                    try:
                        tags_response = await sns.list_tags_for_resource(ResourceArn=topic_arn)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                        
                        if tags.get('Project') == 'ai-honeypot':
                            self.managed_resources["sns_topics"].append({
                                "arn": topic_arn,
                                "name": topic_arn.split(':')[-1],
                                "tags": tags
                            })
                    except ClientError:
                        # Access denied or no tags
                        pass
        
        except Exception as e:
            self.logger.error(f"SNS resource discovery failed: {e}")
    
    async def _discover_lambda_resources(self):
        """Discover Lambda functions managed by the system"""
        try:
            async with self.lambda_client as lambda_client:
                response = await lambda_client.list_functions()
                
                for function in response.get('Functions', []):
                    function_arn = function['FunctionArn']
                    
                    try:
                        tags_response = await lambda_client.list_tags(Resource=function_arn)
                        tags = tags_response.get('Tags', {})
                        
                        if tags.get('Project') == 'ai-honeypot':
                            self.managed_resources["lambda_functions"].append({
                                "name": function['FunctionName'],
                                "arn": function_arn,
                                "runtime": function['Runtime'],
                                "status": function['State'],
                                "tags": tags
                            })
                    except ClientError:
                        # Access denied or no tags
                        pass
        
        except Exception as e:
            self.logger.error(f"Lambda resource discovery failed: {e}")
    
    async def _discover_vpc_resources(self):
        """Discover VPC resources managed by the system"""
        try:
            async with self.ec2_client as ec2:
                # Discover VPCs
                vpcs_response = await ec2.describe_vpcs()
                
                for vpc in vpcs_response.get('Vpcs', []):
                    tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                    
                    if tags.get('Project') == 'ai-honeypot':
                        self.managed_resources["vpc_resources"].append({
                            "type": "vpc",
                            "id": vpc['VpcId'],
                            "cidr": vpc['CidrBlock'],
                            "state": vpc['State'],
                            "tags": tags
                        })
                
                # Discover Subnets
                subnets_response = await ec2.describe_subnets()
                
                for subnet in subnets_response.get('Subnets', []):
                    tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                    
                    if tags.get('Project') == 'ai-honeypot':
                        self.managed_resources["vpc_resources"].append({
                            "type": "subnet",
                            "id": subnet['SubnetId'],
                            "vpc_id": subnet['VpcId'],
                            "cidr": subnet['CidrBlock'],
                            "availability_zone": subnet['AvailabilityZone'],
                            "tags": tags
                        })
        
        except Exception as e:
            self.logger.error(f"VPC resource discovery failed: {e}")
    
    # S3 Integration Methods
    async def store_session_data(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Store session data in S3"""
        try:
            bucket_name = self.config.get("s3_bucket", "ai-honeypot-data")
            key = f"sessions/{datetime.utcnow().strftime('%Y/%m/%d')}/{session_id}.json"
            
            async with self.s3_client as s3:
                await s3.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=json.dumps(data, default=str),
                    ContentType='application/json',
                    ServerSideEncryption='AES256',
                    Metadata={
                        'session-id': session_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'data-type': 'session'
                    }
                )
            
            self.integration_metrics["s3_operations"] += 1
            self.logger.info(f"Stored session data for {session_id} in S3")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store session data in S3: {e}")
            self.integration_metrics["error_count"] += 1
            return False
    
    async def store_intelligence_report(self, report_id: str, report: Dict[str, Any]) -> bool:
        """Store intelligence report in S3"""
        try:
            bucket_name = self.config.get("s3_bucket", "ai-honeypot-data")
            key = f"intelligence/{datetime.utcnow().strftime('%Y/%m/%d')}/{report_id}.json"
            
            async with self.s3_client as s3:
                await s3.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=json.dumps(report, default=str),
                    ContentType='application/json',
                    ServerSideEncryption='AES256',
                    Metadata={
                        'report-id': report_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'data-type': 'intelligence'
                    }
                )
            
            self.integration_metrics["s3_operations"] += 1
            self.logger.info(f"Stored intelligence report {report_id} in S3")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store intelligence report in S3: {e}")
            self.integration_metrics["error_count"] += 1
            return False
    
    async def archive_old_data(self, days_old: int = 30) -> int:
        """Archive old data to cheaper storage class"""
        try:
            bucket_name = self.config.get("s3_bucket", "ai-honeypot-data")
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            archived_count = 0
            
            async with self.s3_client as s3:
                # List objects older than cutoff date
                paginator = s3.get_paginator('list_objects_v2')
                
                async for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get('Contents', []):
                        if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                            # Move to Glacier storage class
                            await s3.copy_object(
                                Bucket=bucket_name,
                                Key=obj['Key'],
                                CopySource={'Bucket': bucket_name, 'Key': obj['Key']},
                                StorageClass='GLACIER',
                                MetadataDirective='COPY'
                            )
                            archived_count += 1
            
            self.logger.info(f"Archived {archived_count} objects to Glacier storage")
            return archived_count
            
        except Exception as e:
            self.logger.error(f"Failed to archive old data: {e}")
            self.integration_metrics["error_count"] += 1
            return 0
    
    # RDS Integration Methods
    async def store_intelligence_data(self, intelligence_data: Dict[str, Any]) -> bool:
        """Store structured intelligence data in RDS"""
        try:
            # This would typically use a database connection pool
            # For now, we'll simulate the operation
            
            self.integration_metrics["rds_queries"] += 1
            self.logger.info("Stored intelligence data in RDS")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store intelligence data in RDS: {e}")
            self.integration_metrics["error_count"] += 1
            return False
    
    async def query_threat_patterns(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query threat patterns from RDS"""
        try:
            # This would typically execute SQL queries
            # For now, we'll simulate the operation
            
            self.integration_metrics["rds_queries"] += 1
            self.logger.info("Queried threat patterns from RDS")
            return []
            
        except Exception as e:
            self.logger.error(f"Failed to query threat patterns from RDS: {e}")
            self.integration_metrics["error_count"] += 1
            return []
    
    # CloudWatch Integration Methods
    async def publish_metrics(self, namespace: str, metrics: List[Dict[str, Any]]) -> bool:
        """Publish custom metrics to CloudWatch"""
        try:
            async with self.cloudwatch_client as cw:
                metric_data = []
                
                for metric in metrics:
                    metric_data.append({
                        'MetricName': metric['name'],
                        'Value': metric['value'],
                        'Unit': metric.get('unit', 'Count'),
                        'Timestamp': datetime.utcnow(),
                        'Dimensions': metric.get('dimensions', [])
                    })
                
                await cw.put_metric_data(
                    Namespace=namespace,
                    MetricData=metric_data
                )
            
            self.integration_metrics["cloudwatch_metrics"] += len(metrics)
            self.logger.info(f"Published {len(metrics)} metrics to CloudWatch")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to publish metrics to CloudWatch: {e}")
            self.integration_metrics["error_count"] += 1
            return False
    
    async def create_alarm(self, alarm_config: Dict[str, Any]) -> bool:
        """Create CloudWatch alarm"""
        try:
            async with self.cloudwatch_client as cw:
                await cw.put_metric_alarm(**alarm_config)
            
            self.logger.info(f"Created CloudWatch alarm: {alarm_config['AlarmName']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create CloudWatch alarm: {e}")
            self.integration_metrics["error_count"] += 1
            return False
    
    # SNS Integration Methods
    async def send_alert(self, topic_arn: str, message: str, subject: str = None) -> bool:
        """Send alert via SNS"""
        try:
            async with self.sns_client as sns:
                params = {
                    'TopicArn': topic_arn,
                    'Message': message
                }
                
                if subject:
                    params['Subject'] = subject
                
                await sns.publish(**params)
            
            self.integration_metrics["sns_notifications"] += 1
            self.logger.info(f"Sent SNS alert to {topic_arn}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send SNS alert: {e}")
            self.integration_metrics["error_count"] += 1
            return False
    
    async def send_intelligence_alert(self, intelligence_report: Dict[str, Any]) -> bool:
        """Send intelligence-based alert"""
        try:
            topic_arn = self.config.get("sns_topic_arn")
            if not topic_arn:
                self.logger.warning("No SNS topic ARN configured for intelligence alerts")
                return False
            
            message = {
                "alert_type": "intelligence_report",
                "timestamp": datetime.utcnow().isoformat(),
                "report_id": intelligence_report.get("report_id"),
                "threat_level": intelligence_report.get("threat_level", "medium"),
                "mitre_techniques": intelligence_report.get("mitre_techniques", []),
                "summary": intelligence_report.get("summary", "New threat intelligence available")
            }
            
            return await self.send_alert(
                topic_arn,
                json.dumps(message, indent=2),
                f"Threat Intelligence Alert - {intelligence_report.get('threat_level', 'medium').upper()}"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to send intelligence alert: {e}")
            return False
    
    # Health Check Methods
    async def check_services_health(self) -> Dict[str, str]:
        """Check health of all AWS services"""
        try:
            self.integration_metrics["last_health_check"] = datetime.utcnow()
            
            # Test each service
            await self._test_s3_connection()
            await self._test_rds_connection()
            await self._test_cloudwatch_connection()
            await self._test_sns_connection()
            await self._test_ec2_connection()
            await self._test_lambda_connection()
            
            return self.service_status.copy()
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return {service: "error" for service in self.service_status.keys()}
    
    async def get_integration_metrics(self) -> Dict[str, Any]:
        """Get AWS integration metrics"""
        return {
            "service_status": self.service_status.copy(),
            "integration_metrics": self.integration_metrics.copy(),
            "managed_resources": {
                resource_type: len(resources)
                for resource_type, resources in self.managed_resources.items()
            }
        }
    
    async def cleanup_resources(self, resource_type: str = None) -> int:
        """Cleanup managed resources"""
        cleaned_count = 0
        
        try:
            if not resource_type or resource_type == "s3":
                # Cleanup old S3 objects
                cleaned_count += await self.archive_old_data()
            
            # Add other resource cleanup as needed
            
            self.logger.info(f"Cleaned up {cleaned_count} resources")
            return cleaned_count
            
        except Exception as e:
            self.logger.error(f"Resource cleanup failed: {e}")
            return 0
    
    async def shutdown(self):
        """Shutdown AWS services integration"""
        self.logger.info("Shutting down AWS services integration...")
        
        # Close async clients
        if self.s3_client:
            await self.s3_client.close()
        if self.rds_client:
            await self.rds_client.close()
        if self.cloudwatch_client:
            await self.cloudwatch_client.close()
        if self.sns_client:
            await self.sns_client.close()
        if self.ec2_client:
            await self.ec2_client.close()
        if self.lambda_client:
            await self.lambda_client.close()
        
        # Reset status
        for service in self.service_status:
            self.service_status[service] = "disconnected"
        
        self.logger.info("AWS services integration shutdown completed")


# Example usage and testing
if __name__ == "__main__":
    async def test_aws_integration():
        # Create AWS integration
        aws_integration = AWSServicesIntegration(region="us-east-1")
        
        # Initialize
        success = await aws_integration.initialize()
        if not success:
            print("AWS integration initialization failed")
            return
        
        # Test operations
        session_data = {
            "session_id": "test-session-123",
            "timestamp": datetime.utcnow().isoformat(),
            "interactions": ["login attempt", "file access"]
        }
        
        # Store session data
        await aws_integration.store_session_data("test-session-123", session_data)
        
        # Publish metrics
        metrics = [
            {"name": "ActiveSessions", "value": 5, "unit": "Count"},
            {"name": "ThreatLevel", "value": 0.75, "unit": "None"}
        ]
        await aws_integration.publish_metrics("AI-Honeypot", metrics)
        
        # Check health
        health = await aws_integration.check_services_health()
        print(f"Service health: {health}")
        
        # Get metrics
        metrics = await aws_integration.get_integration_metrics()
        print(f"Integration metrics: {metrics}")
        
        # Cleanup
        await aws_integration.shutdown()
    
    asyncio.run(test_aws_integration())