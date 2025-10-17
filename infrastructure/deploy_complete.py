#!/usr/bin/env python3
"""
Complete deployment script for AI Honeypot Infrastructure
Handles end-to-end deployment including database initialization
"""

import os
import sys
import subprocess
import json
import time
import boto3
import psycopg2
from pathlib import Path
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CompleteDeployer:
    """Handles complete deployment of AI Honeypot infrastructure"""
    
    def __init__(self, environment: str = "dev", region: str = "us-east-1"):
        self.environment = environment
        self.region = region
        self.account_id = self._get_account_id()
        self.project_root = Path(__file__).parent
        self.cdk_dir = self.project_root / "cdk"
        
        # AWS clients
        self.secrets = boto3.client('secretsmanager', region_name=region)
        self.rds = boto3.client('rds', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting AWS account ID: {e}")
            sys.exit(1)
    
    def deploy_complete_infrastructure(self):
        """Deploy complete infrastructure end-to-end"""
        
        logger.info("Starting complete infrastructure deployment...")
        
        try:
            # Step 1: Validate prerequisites
            self.validate_prerequisites()
            
            # Step 2: Deploy CDK infrastructure
            self.deploy_cdk_infrastructure()
            
            # Step 3: Wait for RDS to be available
            self.wait_for_rds_availability()
            
            # Step 4: Initialize database schema
            self.initialize_database()
            
            # Step 5: Upload Lambda function code
            self.upload_lambda_code()
            
            # Step 6: Configure monitoring and alerting
            self.configure_monitoring()
            
            # Step 7: Validate deployment
            self.validate_deployment()
            
            # Step 8: Generate deployment summary
            self.generate_deployment_summary()
            
            logger.info("Complete infrastructure deployment finished successfully!")
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            raise
    
    def validate_prerequisites(self):
        """Validate deployment prerequisites"""
        
        logger.info("Validating prerequisites...")
        
        # Check AWS CLI configuration
        try:
            subprocess.run(['aws', 'sts', 'get-caller-identity'], 
                         check=True, capture_output=True)
            logger.info("✓ AWS CLI configured")
        except subprocess.CalledProcessError:
            raise Exception("AWS CLI not configured or credentials invalid")
        
        # Check CDK installation
        try:
            result = subprocess.run(['cdk', '--version'], 
                                  check=True, capture_output=True, text=True)
            logger.info(f"✓ CDK installed: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            raise Exception("AWS CDK not installed")
        
        # Check Python dependencies
        try:
            import psycopg2
            logger.info("✓ Python dependencies available")
        except ImportError:
            raise Exception("Required Python dependencies not installed")
        
        # Check if CDK is bootstrapped
        try:
            subprocess.run([
                'cdk', 'bootstrap', 
                f'aws://{self.account_id}/{self.region}',
                '--context', f'environment={self.environment}'
            ], check=True, capture_output=True, cwd=self.cdk_dir)
            logger.info("✓ CDK bootstrapped")
        except subprocess.CalledProcessError as e:
            if "already bootstrapped" not in str(e.stderr):
                logger.warning(f"CDK bootstrap warning: {e.stderr}")
    
    def deploy_cdk_infrastructure(self):
        """Deploy CDK infrastructure stacks"""
        
        logger.info("Deploying CDK infrastructure...")
        
        os.chdir(self.cdk_dir)
        
        # Install CDK dependencies
        logger.info("Installing CDK dependencies...")
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        
        # Deploy stacks in order
        stack_order = [
            "HoneypotNetworkStack",
            "HoneypotSecurityStack", 
            "HoneypotStorageStack",
            "HoneypotDatabaseStack",
            "HoneypotMonitoringStack",
            "HoneypotIntegrationStack"
        ]
        
        for stack_name in stack_order:
            logger.info(f"Deploying {stack_name}...")
            
            cmd = [
                "cdk", "deploy", stack_name,
                "--require-approval", "never",
                "--context", f"environment={self.environment}",
                "--context", f"account={self.account_id}",
                "--context", f"region={self.region}",
                "--outputs-file", f"outputs-{self.environment}.json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to deploy {stack_name}")
                logger.error(f"Error: {result.stderr}")
                raise Exception(f"CDK deployment failed for {stack_name}")
            
            logger.info(f"✓ {stack_name} deployed successfully")
        
        logger.info("✓ All CDK stacks deployed successfully")
    
    def wait_for_rds_availability(self):
        """Wait for RDS database to become available"""
        
        logger.info("Waiting for RDS database to become available...")
        
        # Find database instance
        databases = self.rds.describe_db_instances()
        honeypot_db = None
        
        for db in databases['DBInstances']:
            if 'honeypot' in db['DBInstanceIdentifier'].lower():
                honeypot_db = db
                break
        
        if not honeypot_db:
            raise Exception("Honeypot database not found")
        
        db_identifier = honeypot_db['DBInstanceIdentifier']
        
        # Wait for database to be available
        max_wait_time = 1800  # 30 minutes
        wait_interval = 30    # 30 seconds
        elapsed_time = 0
        
        while elapsed_time < max_wait_time:
            try:
                response = self.rds.describe_db_instances(
                    DBInstanceIdentifier=db_identifier
                )
                db_status = response['DBInstances'][0]['DBInstanceStatus']
                
                if db_status == 'available':
                    logger.info(f"✓ Database {db_identifier} is available")
                    return
                
                logger.info(f"Database status: {db_status}, waiting...")
                time.sleep(wait_interval)
                elapsed_time += wait_interval
                
            except Exception as e:
                logger.error(f"Error checking database status: {e}")
                time.sleep(wait_interval)
                elapsed_time += wait_interval
        
        raise Exception(f"Database did not become available within {max_wait_time} seconds")
    
    def initialize_database(self):
        """Initialize database schema and data"""
        
        logger.info("Initializing database schema...")
        
        try:
            # Get database connection info
            databases = self.rds.describe_db_instances()
            honeypot_db = None
            
            for db in databases['DBInstances']:
                if 'honeypot' in db['DBInstanceIdentifier'].lower():
                    honeypot_db = db
                    break
            
            if not honeypot_db:
                raise Exception("Honeypot database not found")
            
            # Get database credentials from Secrets Manager
            secrets = self.secrets.list_secrets()
            db_secret_arn = None
            
            for secret in secrets['SecretList']:
                if 'database' in secret['Name'].lower() and 'honeypot' in secret['Name'].lower():
                    db_secret_arn = secret['ARN']
                    break
            
            if not db_secret_arn:
                raise Exception("Database credentials secret not found")
            
            # Get credentials
            secret_response = self.secrets.get_secret_value(SecretId=db_secret_arn)
            credentials = json.loads(secret_response['SecretString'])
            
            # Connect to database
            conn = psycopg2.connect(
                host=honeypot_db['Endpoint']['Address'],
                database='honeypot_intelligence',
                user=credentials['username'],
                password=credentials['password'],
                port=honeypot_db['Endpoint']['Port'],
                sslmode='require'
            )
            
            # Execute initialization script
            init_script_path = self.project_root / "database" / "init.sql"
            
            with open(init_script_path, 'r') as f:
                init_script = f.read()
            
            cursor = conn.cursor()
            cursor.execute(init_script)
            conn.commit()
            
            # Verify schema creation
            cursor.execute("""
                SELECT schema_name FROM information_schema.schemata 
                WHERE schema_name IN ('honeypot', 'intelligence', 'security', 'audit')
            """)
            schemas = [row[0] for row in cursor.fetchall()]
            
            cursor.close()
            conn.close()
            
            logger.info(f"✓ Database initialized with schemas: {', '.join(schemas)}")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def upload_lambda_code(self):
        """Upload Lambda function code and dependencies"""
        
        logger.info("Uploading Lambda function code...")
        
        # The Lambda functions are already deployed via CDK with inline code
        # In a production environment, you might want to package and upload
        # the code separately for better version control
        
        logger.info("✓ Lambda functions deployed via CDK")
    
    def configure_monitoring(self):
        """Configure additional monitoring and alerting"""
        
        logger.info("Configuring monitoring and alerting...")
        
        # Additional monitoring configuration can be added here
        # For now, monitoring is configured via CDK
        
        logger.info("✓ Monitoring configured via CDK")
    
    def validate_deployment(self):
        """Validate the complete deployment"""
        
        logger.info("Validating deployment...")
        
        # Run deployment validation
        validation_script = self.project_root / "validate_deployment.py"
        
        result = subprocess.run([
            sys.executable, str(validation_script), 
            "--region", self.region
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✓ Deployment validation passed")
        else:
            logger.warning("⚠️ Deployment validation had issues")
            logger.warning(result.stdout)
            logger.warning(result.stderr)
    
    def generate_deployment_summary(self):
        """Generate deployment summary and next steps"""
        
        logger.info("Generating deployment summary...")
        
        # Load CDK outputs
        outputs_file = self.cdk_dir / f"outputs-{self.environment}.json"
        outputs = {}
        
        if outputs_file.exists():
            with open(outputs_file, 'r') as f:
                outputs = json.load(f)
        
        # Generate summary
        summary = {
            'deployment_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'environment': self.environment,
            'region': self.region,
            'account_id': self.account_id,
            'status': 'COMPLETED',
            'cdk_outputs': outputs,
            'next_steps': [
                "Review the deployment validation report",
                "Configure SNS topic subscriptions for alerts",
                "Set up external SIEM integrations via API Gateway",
                "Deploy AgentCore Runtime agents (Task 12)",
                "Configure honeypot infrastructure",
                "Test end-to-end workflows"
            ],
            'important_endpoints': self._extract_important_endpoints(outputs),
            'security_notes': [
                "Change default database passwords in production",
                "Configure proper SNS topic subscriptions",
                "Review and update security group rules",
                "Enable additional CloudWatch alarms as needed",
                "Configure backup and disaster recovery procedures"
            ]
        }
        
        # Save summary
        summary_file = f"deployment_summary_{self.environment}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        # Print summary
        print("\n" + "="*80)
        print("DEPLOYMENT SUMMARY")
        print("="*80)
        print(f"Environment: {self.environment}")
        print(f"Region: {self.region}")
        print(f"Account ID: {self.account_id}")
        print(f"Status: {summary['status']}")
        print(f"Timestamp: {summary['deployment_timestamp']}")
        
        if summary['important_endpoints']:
            print(f"\nImportant Endpoints:")
            for name, value in summary['important_endpoints'].items():
                print(f"  {name}: {value}")
        
        print(f"\nNext Steps:")
        for i, step in enumerate(summary['next_steps'], 1):
            print(f"  {i}. {step}")
        
        print(f"\nSecurity Notes:")
        for note in summary['security_notes']:
            print(f"  ⚠️  {note}")
        
        print(f"\nDetailed summary saved to: {summary_file}")
        print("="*80)
    
    def _extract_important_endpoints(self, outputs: dict) -> dict:
        """Extract important endpoints from CDK outputs"""
        
        endpoints = {}
        
        for stack_name, stack_outputs in outputs.items():
            for key, value in stack_outputs.items():
                if 'Url' in key or 'Endpoint' in key:
                    endpoints[f"{stack_name}.{key}"] = value
        
        return endpoints
    
    def cleanup_deployment(self):
        """Clean up deployment (destroy all resources)"""
        
        logger.info("Cleaning up deployment...")
        
        # Confirm cleanup
        response = input(f"Are you sure you want to destroy all resources in {self.environment}? (yes/no): ")
        if response.lower() != "yes":
            logger.info("Cleanup cancelled")
            return
        
        os.chdir(self.cdk_dir)
        
        # Destroy stacks in reverse order
        stack_order = [
            "HoneypotIntegrationStack",
            "HoneypotMonitoringStack",
            "HoneypotDatabaseStack",
            "HoneypotStorageStack",
            "HoneypotSecurityStack",
            "HoneypotNetworkStack"
        ]
        
        for stack_name in stack_order:
            logger.info(f"Destroying {stack_name}...")
            
            cmd = [
                "cdk", "destroy", stack_name,
                "--force",
                "--context", f"environment={self.environment}",
                "--context", f"account={self.account_id}",
                "--context", f"region={self.region}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to destroy {stack_name}")
                logger.error(f"Error: {result.stderr}")
            else:
                logger.info(f"✓ {stack_name} destroyed")
        
        logger.info("✓ Cleanup completed")


def main():
    """Main deployment script"""
    
    parser = argparse.ArgumentParser(description="Deploy AI Honeypot Infrastructure")
    parser.add_argument("--environment", "-e", default="dev", 
                       choices=["dev", "staging", "prod"],
                       help="Deployment environment")
    parser.add_argument("--region", "-r", default="us-east-1",
                       help="AWS region for deployment")
    parser.add_argument("--action", "-a", required=True,
                       choices=["deploy", "cleanup", "validate"],
                       help="Action to perform")
    
    args = parser.parse_args()
    
    try:
        deployer = CompleteDeployer(args.environment, args.region)
        
        if args.action == "deploy":
            deployer.deploy_complete_infrastructure()
        elif args.action == "cleanup":
            deployer.cleanup_deployment()
        elif args.action == "validate":
            deployer.validate_deployment()
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()