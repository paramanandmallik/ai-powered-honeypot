#!/usr/bin/env python3
"""
Deployment validation script for AI Honeypot Infrastructure
Validates that all components are deployed and configured correctly
"""

import boto3
import json
import sys
import time
import psycopg2
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DeploymentValidator:
    """Validates AI Honeypot infrastructure deployment"""
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        
        # AWS clients
        self.cloudformation = boto3.client('cloudformation', region_name=region)
        self.rds = boto3.client('rds', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.sns = boto3.client('sns', region_name=region)
        self.lambda_client = boto3.client('lambda', region_name=region)
        self.apigateway = boto3.client('apigateway', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.secrets = boto3.client('secretsmanager', region_name=region)
        self.ec2 = boto3.client('ec2', region_name=region)
        
        self.validation_results = {}
    
    def validate_all(self) -> bool:
        """Run all validation checks"""
        
        logger.info("Starting deployment validation...")
        
        # Validate CloudFormation stacks
        self.validate_cloudformation_stacks()
        
        # Validate VPC and networking
        self.validate_vpc_networking()
        
        # Validate RDS database
        self.validate_rds_database()
        
        # Validate S3 buckets
        self.validate_s3_buckets()
        
        # Validate Lambda functions
        self.validate_lambda_functions()
        
        # Validate API Gateway
        self.validate_api_gateway()
        
        # Validate SNS topics
        self.validate_sns_topics()
        
        # Validate CloudWatch monitoring
        self.validate_cloudwatch_monitoring()
        
        # Validate database connectivity and schema
        self.validate_database_schema()
        
        # Generate validation report
        return self.generate_validation_report()
    
    def validate_cloudformation_stacks(self):
        """Validate CloudFormation stacks are deployed successfully"""
        
        logger.info("Validating CloudFormation stacks...")
        
        expected_stacks = [
            "HoneypotNetworkStack",
            "HoneypotSecurityStack", 
            "HoneypotDatabaseStack",
            "HoneypotStorageStack",
            "HoneypotMonitoringStack",
            "HoneypotIntegrationStack"
        ]
        
        stack_results = {}
        
        for stack_name in expected_stacks:
            try:
                response = self.cloudformation.describe_stacks(StackName=stack_name)
                stack = response['Stacks'][0]
                
                stack_results[stack_name] = {
                    'status': stack['StackStatus'],
                    'creation_time': stack['CreationTime'].isoformat(),
                    'outputs': {output['OutputKey']: output['OutputValue'] 
                              for output in stack.get('Outputs', [])}
                }
                
                if stack['StackStatus'] != 'CREATE_COMPLETE':
                    logger.warning(f"Stack {stack_name} status: {stack['StackStatus']}")
                else:
                    logger.info(f"Stack {stack_name}: OK")
                    
            except Exception as e:
                logger.error(f"Error validating stack {stack_name}: {e}")
                stack_results[stack_name] = {'status': 'ERROR', 'error': str(e)}
        
        self.validation_results['cloudformation_stacks'] = stack_results
    
    def validate_vpc_networking(self):
        """Validate VPC and networking configuration"""
        
        logger.info("Validating VPC and networking...")
        
        try:
            # Find honeypot VPC
            vpcs = self.ec2.describe_vpcs(
                Filters=[{'Name': 'tag:Name', 'Values': ['*Honeypot*']}]
            )
            
            if not vpcs['Vpcs']:
                logger.error("Honeypot VPC not found")
                self.validation_results['vpc'] = {'status': 'ERROR', 'error': 'VPC not found'}
                return
            
            vpc = vpcs['Vpcs'][0]
            vpc_id = vpc['VpcId']
            
            # Validate subnets
            subnets = self.ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )
            
            subnet_types = {}
            for subnet in subnets['Subnets']:
                for tag in subnet.get('Tags', []):
                    if tag['Key'] == 'aws-cdk:subnet-type':
                        subnet_type = tag['Value']
                        if subnet_type not in subnet_types:
                            subnet_types[subnet_type] = 0
                        subnet_types[subnet_type] += 1
            
            # Validate security groups
            security_groups = self.ec2.describe_security_groups(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )
            
            # Validate VPC endpoints
            vpc_endpoints = self.ec2.describe_vpc_endpoints(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )
            
            self.validation_results['vpc'] = {
                'status': 'OK',
                'vpc_id': vpc_id,
                'cidr_block': vpc['CidrBlock'],
                'subnet_types': subnet_types,
                'security_groups_count': len(security_groups['SecurityGroups']),
                'vpc_endpoints_count': len(vpc_endpoints['VpcEndpoints'])
            }
            
            logger.info(f"VPC validation: OK (VPC ID: {vpc_id})")
            
        except Exception as e:
            logger.error(f"Error validating VPC: {e}")
            self.validation_results['vpc'] = {'status': 'ERROR', 'error': str(e)}
    
    def validate_rds_database(self):
        """Validate RDS database deployment and configuration"""
        
        logger.info("Validating RDS database...")
        
        try:
            # Find honeypot database
            databases = self.rds.describe_db_instances()
            
            honeypot_db = None
            for db in databases['DBInstances']:
                if 'honeypot' in db['DBInstanceIdentifier'].lower():
                    honeypot_db = db
                    break
            
            if not honeypot_db:
                logger.error("Honeypot database not found")
                self.validation_results['rds'] = {'status': 'ERROR', 'error': 'Database not found'}
                return
            
            # Validate database configuration
            db_status = honeypot_db['DBInstanceStatus']
            
            self.validation_results['rds'] = {
                'status': 'OK' if db_status == 'available' else 'WARNING',
                'db_instance_identifier': honeypot_db['DBInstanceIdentifier'],
                'db_instance_status': db_status,
                'engine': honeypot_db['Engine'],
                'engine_version': honeypot_db['EngineVersion'],
                'instance_class': honeypot_db['DBInstanceClass'],
                'allocated_storage': honeypot_db['AllocatedStorage'],
                'storage_encrypted': honeypot_db['StorageEncrypted'],
                'multi_az': honeypot_db['MultiAZ'],
                'endpoint': honeypot_db['Endpoint']['Address'],
                'port': honeypot_db['Endpoint']['Port']
            }
            
            if db_status == 'available':
                logger.info(f"RDS validation: OK ({honeypot_db['DBInstanceIdentifier']})")
            else:
                logger.warning(f"RDS status: {db_status}")
                
        except Exception as e:
            logger.error(f"Error validating RDS: {e}")
            self.validation_results['rds'] = {'status': 'ERROR', 'error': str(e)}
    
    def validate_s3_buckets(self):
        """Validate S3 buckets and configuration"""
        
        logger.info("Validating S3 buckets...")
        
        expected_buckets = [
            'session-data',
            'audit-logs', 
            'intelligence-reports',
            'synthetic-data'
        ]
        
        bucket_results = {}
        
        # List all buckets
        try:
            buckets = self.s3.list_buckets()
            
            for bucket_type in expected_buckets:
                bucket_name = None
                
                # Find bucket by naming pattern
                for bucket in buckets['Buckets']:
                    if bucket_type in bucket['Name'] and 'honeypot' in bucket['Name']:
                        bucket_name = bucket['Name']
                        break
                
                if bucket_name:
                    try:
                        # Check bucket encryption
                        encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                        
                        # Check bucket versioning
                        versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                        
                        # Check lifecycle configuration
                        try:
                            lifecycle = self.s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                            lifecycle_rules = len(lifecycle.get('Rules', []))
                        except:
                            lifecycle_rules = 0
                        
                        bucket_results[bucket_type] = {
                            'status': 'OK',
                            'bucket_name': bucket_name,
                            'encryption_enabled': 'ServerSideEncryptionConfiguration' in encryption,
                            'versioning_enabled': versioning.get('Status') == 'Enabled',
                            'lifecycle_rules': lifecycle_rules
                        }
                        
                        logger.info(f"S3 bucket {bucket_type}: OK ({bucket_name})")
                        
                    except Exception as e:
                        bucket_results[bucket_type] = {
                            'status': 'ERROR',
                            'bucket_name': bucket_name,
                            'error': str(e)
                        }
                        logger.error(f"Error validating bucket {bucket_name}: {e}")
                else:
                    bucket_results[bucket_type] = {
                        'status': 'ERROR',
                        'error': 'Bucket not found'
                    }
                    logger.error(f"S3 bucket for {bucket_type} not found")
            
            self.validation_results['s3_buckets'] = bucket_results
            
        except Exception as e:
            logger.error(f"Error validating S3 buckets: {e}")
            self.validation_results['s3_buckets'] = {'status': 'ERROR', 'error': str(e)}
    
    def validate_lambda_functions(self):
        """Validate Lambda functions deployment"""
        
        logger.info("Validating Lambda functions...")
        
        expected_functions = [
            'ai-honeypot-intelligence-processor',
            'ai-honeypot-lifecycle-manager',
            'ai-honeypot-security-processor',
            'ai-honeypot-api-handler'
        ]
        
        function_results = {}
        
        for function_name in expected_functions:
            try:
                response = self.lambda_client.get_function(FunctionName=function_name)
                
                function_config = response['Configuration']
                
                function_results[function_name] = {
                    'status': 'OK',
                    'function_name': function_config['FunctionName'],
                    'runtime': function_config['Runtime'],
                    'state': function_config['State'],
                    'last_modified': function_config['LastModified'],
                    'memory_size': function_config['MemorySize'],
                    'timeout': function_config['Timeout']
                }
                
                logger.info(f"Lambda function {function_name}: OK")
                
            except Exception as e:
                function_results[function_name] = {
                    'status': 'ERROR',
                    'error': str(e)
                }
                logger.error(f"Error validating Lambda function {function_name}: {e}")
        
        self.validation_results['lambda_functions'] = function_results
    
    def validate_api_gateway(self):
        """Validate API Gateway deployment"""
        
        logger.info("Validating API Gateway...")
        
        try:
            # Find honeypot API
            apis = self.apigateway.get_rest_apis()
            
            honeypot_api = None
            for api in apis['items']:
                if 'honeypot' in api['name'].lower():
                    honeypot_api = api
                    break
            
            if not honeypot_api:
                logger.error("Honeypot API Gateway not found")
                self.validation_results['api_gateway'] = {'status': 'ERROR', 'error': 'API not found'}
                return
            
            api_id = honeypot_api['id']
            
            # Get API resources
            resources = self.apigateway.get_resources(restApiId=api_id)
            
            # Get API stages
            stages = self.apigateway.get_stages(restApiId=api_id)
            
            self.validation_results['api_gateway'] = {
                'status': 'OK',
                'api_id': api_id,
                'api_name': honeypot_api['name'],
                'created_date': honeypot_api['createdDate'].isoformat(),
                'endpoint_configuration': honeypot_api['endpointConfiguration']['types'],
                'resources_count': len(resources['items']),
                'stages_count': len(stages['item'])
            }
            
            logger.info(f"API Gateway validation: OK (API ID: {api_id})")
            
        except Exception as e:
            logger.error(f"Error validating API Gateway: {e}")
            self.validation_results['api_gateway'] = {'status': 'ERROR', 'error': str(e)}
    
    def validate_sns_topics(self):
        """Validate SNS topics"""
        
        logger.info("Validating SNS topics...")
        
        expected_topics = [
            'ai-honeypot-system-alerts',
            'ai-honeypot-intelligence-reports',
            'ai-honeypot-lifecycle-events',
            'ai-honeypot-security-events'
        ]
        
        topic_results = {}
        
        try:
            # List all topics
            topics = self.sns.list_topics()
            
            for expected_topic in expected_topics:
                topic_arn = None
                
                # Find topic by name
                for topic in topics['Topics']:
                    if expected_topic in topic['TopicArn']:
                        topic_arn = topic['TopicArn']
                        break
                
                if topic_arn:
                    try:
                        # Get topic attributes
                        attributes = self.sns.get_topic_attributes(TopicArn=topic_arn)
                        
                        # Get subscriptions
                        subscriptions = self.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
                        
                        topic_results[expected_topic] = {
                            'status': 'OK',
                            'topic_arn': topic_arn,
                            'subscriptions_count': len(subscriptions['Subscriptions']),
                            'display_name': attributes['Attributes'].get('DisplayName', '')
                        }
                        
                        logger.info(f"SNS topic {expected_topic}: OK")
                        
                    except Exception as e:
                        topic_results[expected_topic] = {
                            'status': 'ERROR',
                            'topic_arn': topic_arn,
                            'error': str(e)
                        }
                        logger.error(f"Error validating topic {expected_topic}: {e}")
                else:
                    topic_results[expected_topic] = {
                        'status': 'ERROR',
                        'error': 'Topic not found'
                    }
                    logger.error(f"SNS topic {expected_topic} not found")
            
            self.validation_results['sns_topics'] = topic_results
            
        except Exception as e:
            logger.error(f"Error validating SNS topics: {e}")
            self.validation_results['sns_topics'] = {'status': 'ERROR', 'error': str(e)}
    
    def validate_cloudwatch_monitoring(self):
        """Validate CloudWatch monitoring setup"""
        
        logger.info("Validating CloudWatch monitoring...")
        
        try:
            # Check for honeypot dashboard
            dashboards = self.cloudwatch.list_dashboards()
            
            honeypot_dashboard = None
            for dashboard in dashboards['DashboardEntries']:
                if 'honeypot' in dashboard['DashboardName'].lower():
                    honeypot_dashboard = dashboard
                    break
            
            # Check for custom metrics
            metrics = self.cloudwatch.list_metrics(Namespace='HoneypotSystem/Agents')
            
            # Check for alarms
            alarms = self.cloudwatch.describe_alarms()
            honeypot_alarms = [alarm for alarm in alarms['MetricAlarms'] 
                             if 'honeypot' in alarm['AlarmName'].lower()]
            
            self.validation_results['cloudwatch'] = {
                'status': 'OK',
                'dashboard_exists': honeypot_dashboard is not None,
                'dashboard_name': honeypot_dashboard['DashboardName'] if honeypot_dashboard else None,
                'custom_metrics_count': len(metrics['Metrics']),
                'alarms_count': len(honeypot_alarms)
            }
            
            logger.info("CloudWatch monitoring validation: OK")
            
        except Exception as e:
            logger.error(f"Error validating CloudWatch: {e}")
            self.validation_results['cloudwatch'] = {'status': 'ERROR', 'error': str(e)}
    
    def validate_database_schema(self):
        """Validate database connectivity and schema"""
        
        logger.info("Validating database schema...")
        
        try:
            # Get database credentials from Secrets Manager
            db_info = self.validation_results.get('rds', {})
            if db_info.get('status') != 'OK':
                logger.error("Cannot validate database schema - RDS validation failed")
                self.validation_results['database_schema'] = {
                    'status': 'ERROR', 
                    'error': 'RDS not available'
                }
                return
            
            # Try to find database secret
            secrets = self.secrets.list_secrets()
            db_secret_arn = None
            
            for secret in secrets['SecretList']:
                if 'database' in secret['Name'].lower() and 'honeypot' in secret['Name'].lower():
                    db_secret_arn = secret['ARN']
                    break
            
            if not db_secret_arn:
                logger.error("Database credentials secret not found")
                self.validation_results['database_schema'] = {
                    'status': 'ERROR',
                    'error': 'Database credentials not found'
                }
                return
            
            # Get database credentials
            secret_response = self.secrets.get_secret_value(SecretId=db_secret_arn)
            credentials = json.loads(secret_response['SecretString'])
            
            # Connect to database
            conn = psycopg2.connect(
                host=db_info['endpoint'],
                database='honeypot_intelligence',
                user=credentials['username'],
                password=credentials['password'],
                port=db_info['port'],
                sslmode='require',
                connect_timeout=10
            )
            
            cursor = conn.cursor()
            
            # Check schemas
            cursor.execute("""
                SELECT schema_name FROM information_schema.schemata 
                WHERE schema_name IN ('honeypot', 'intelligence', 'security', 'audit')
            """)
            schemas = [row[0] for row in cursor.fetchall()]
            
            # Check tables
            cursor.execute("""
                SELECT table_schema, table_name 
                FROM information_schema.tables 
                WHERE table_schema IN ('honeypot', 'intelligence', 'security', 'audit')
            """)
            tables = cursor.fetchall()
            
            # Check views
            cursor.execute("""
                SELECT table_schema, table_name 
                FROM information_schema.views 
                WHERE table_schema IN ('honeypot', 'intelligence', 'security', 'audit')
            """)
            views = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            self.validation_results['database_schema'] = {
                'status': 'OK',
                'schemas': schemas,
                'tables_count': len(tables),
                'views_count': len(views),
                'connection_successful': True
            }
            
            logger.info(f"Database schema validation: OK ({len(schemas)} schemas, {len(tables)} tables)")
            
        except Exception as e:
            logger.error(f"Error validating database schema: {e}")
            self.validation_results['database_schema'] = {
                'status': 'ERROR',
                'error': str(e),
                'connection_successful': False
            }
    
    def generate_validation_report(self) -> bool:
        """Generate validation report and return overall success status"""
        
        logger.info("Generating validation report...")
        
        # Count successes and failures
        total_checks = 0
        successful_checks = 0
        failed_checks = []
        
        for component, result in self.validation_results.items():
            if isinstance(result, dict):
                if 'status' in result:
                    total_checks += 1
                    if result['status'] == 'OK':
                        successful_checks += 1
                    else:
                        failed_checks.append(f"{component}: {result.get('error', 'Unknown error')}")
                else:
                    # Handle nested results (like S3 buckets, Lambda functions)
                    for sub_component, sub_result in result.items():
                        if isinstance(sub_result, dict) and 'status' in sub_result:
                            total_checks += 1
                            if sub_result['status'] == 'OK':
                                successful_checks += 1
                            else:
                                failed_checks.append(f"{component}.{sub_component}: {sub_result.get('error', 'Unknown error')}")
        
        # Generate report
        report = {
            'validation_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'overall_status': 'PASS' if successful_checks == total_checks else 'FAIL',
            'summary': {
                'total_checks': total_checks,
                'successful_checks': successful_checks,
                'failed_checks': len(failed_checks),
                'success_rate': f"{(successful_checks/total_checks*100):.1f}%" if total_checks > 0 else "0%"
            },
            'failed_components': failed_checks,
            'detailed_results': self.validation_results
        }
        
        # Save report to file
        with open('deployment_validation_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "="*80)
        print("DEPLOYMENT VALIDATION REPORT")
        print("="*80)
        print(f"Timestamp: {report['validation_timestamp']}")
        print(f"Overall Status: {report['overall_status']}")
        print(f"Success Rate: {report['summary']['success_rate']}")
        print(f"Successful Checks: {successful_checks}/{total_checks}")
        
        if failed_checks:
            print(f"\nFailed Components ({len(failed_checks)}):")
            for failure in failed_checks:
                print(f"  ❌ {failure}")
        
        if successful_checks == total_checks:
            print(f"\n✅ All {total_checks} validation checks passed!")
            print("The AI Honeypot infrastructure is deployed and configured correctly.")
        else:
            print(f"\n⚠️  {len(failed_checks)} validation checks failed.")
            print("Please review the failed components and fix any issues.")
        
        print(f"\nDetailed report saved to: deployment_validation_report.json")
        print("="*80)
        
        return successful_checks == total_checks


def main():
    """Main validation script"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate AI Honeypot Infrastructure Deployment")
    parser.add_argument("--region", "-r", default="us-east-1", help="AWS region")
    
    args = parser.parse_args()
    
    try:
        validator = DeploymentValidator(args.region)
        success = validator.validate_all()
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\nValidation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Validation failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()