# Backup and Recovery Procedures

## Overview

This runbook provides comprehensive procedures for backing up system data, configurations, and performing disaster recovery operations for the AI-Powered Honeypot System.

## Backup Strategy

### Backup Types and Schedules

#### 1. Configuration Backups (Daily)
- Agent configurations and YAML files
- System settings and parameters
- User accounts and permissions
- Alert rules and thresholds

#### 2. Database Backups (Every 6 hours)
- Intelligence data and reports
- Threat detection history
- Engagement records and sessions
- System audit logs

#### 3. Session Data Backups (Real-time)
- Attacker interaction transcripts
- Honeypot session recordings
- Network traffic logs
- Security event logs

#### 4. Infrastructure Backups (Weekly)
- CloudFormation/CDK templates
- Network configurations
- Security group rules
- IAM policies and roles

## Daily Backup Procedures

### Configuration Backup

```python
# scripts/backup_configuration.py
import asyncio
import json
import boto3
from datetime import datetime
from agentcore_runtime import AgentCoreClient

async def backup_system_configuration():
    """Backup all system configurations to S3"""
    
    backup_timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    backup_data = {
        "backup_id": f"config_backup_{backup_timestamp}",
        "timestamp": datetime.utcnow().isoformat(),
        "backup_type": "configuration",
        "components": {}
    }
    
    print(f"🔄 Starting configuration backup: {backup_data['backup_id']}")
    
    # Backup AgentCore configurations
    client = AgentCoreClient()
    agents = ["detection-agent", "coordinator-agent", "interaction-agent", "intelligence-agent"]
    
    backup_data["components"]["agents"] = {}
    
    for agent_name in agents:
        try:
            # Get agent configuration
            agent_config = await client.get_agent_configuration(agent_name)
            
            # Get agent deployment settings
            deployment_config = await client.get_agent_deployment_config(agent_name)
            
            # Get scaling configuration
            scaling_config = await client.get_agent_scaling_config(agent_name)
            
            backup_data["components"]["agents"][agent_name] = {
                "configuration": agent_config,
                "deployment": deployment_config,
                "scaling": scaling_config
            }
            
            print(f"✅ Backed up {agent_name} configuration")
            
        except Exception as e:
            print(f"❌ Failed to backup {agent_name}: {e}")
            backup_data["components"]["agents"][agent_name] = {"error": str(e)}
    
    # Backup workflow definitions
    try:
        workflows = await client.list_workflows()
        backup_data["components"]["workflows"] = {}
        
        for workflow in workflows:
            workflow_def = await client.get_workflow_definition(workflow.id)
            backup_data["components"]["workflows"][workflow.id] = workflow_def
            
        print(f"✅ Backed up {len(workflows)} workflow definitions")
        
    except Exception as e:
        print(f"❌ Failed to backup workflows: {e}")
        backup_data["components"]["workflows"] = {"error": str(e)}
    
    # Backup system settings
    try:
        system_config = await get_system_configuration()
        backup_data["components"]["system_settings"] = system_config
        print("✅ Backed up system settings")
        
    except Exception as e:
        print(f"❌ Failed to backup system settings: {e}")
        backup_data["components"]["system_settings"] = {"error": str(e)}
    
    # Backup user accounts and permissions
    try:
        user_data = await backup_user_accounts()
        backup_data["components"]["users"] = user_data
        print(f"✅ Backed up {len(user_data)} user accounts")
        
    except Exception as e:
        print(f"❌ Failed to backup user accounts: {e}")
        backup_data["components"]["users"] = {"error": str(e)}
    
    # Upload backup to S3
    s3_client = boto3.client('s3')
    backup_key = f"configuration-backups/{datetime.utcnow().strftime('%Y/%m/%d')}/{backup_data['backup_id']}.json"
    
    try:
        s3_client.put_object(
            Bucket='honeypot-system-backups',
            Key=backup_key,
            Body=json.dumps(backup_data, indent=2, default=str),
            ServerSideEncryption='AES256',
            Metadata={
                'backup-type': 'configuration',
                'backup-timestamp': backup_timestamp,
                'system': 'honeypot-system'
            }
        )
        
        print(f"✅ Configuration backup uploaded to s3://honeypot-system-backups/{backup_key}")
        
        # Update backup registry
        await update_backup_registry(backup_data['backup_id'], backup_key, 'configuration')
        
        return {
            "success": True,
            "backup_id": backup_data['backup_id'],
            "s3_location": f"s3://honeypot-system-backups/{backup_key}",
            "size_bytes": len(json.dumps(backup_data))
        }
        
    except Exception as e:
        print(f"❌ Failed to upload backup to S3: {e}")
        return {"success": False, "error": str(e)}

async def backup_user_accounts():
    """Backup user accounts and permissions"""
    
    from user_management import UserManager
    
    user_manager = UserManager()
    users = await user_manager.list_all_users()
    
    user_backup = []
    
    for user in users:
        user_data = {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "mfa_enabled": user.mfa_enabled,
            "active": user.active
            # Note: Passwords and MFA secrets are NOT backed up for security
        }
        user_backup.append(user_data)
    
    return user_backup

if __name__ == "__main__":
    result = asyncio.run(backup_system_configuration())
    if result["success"]:
        print(f"🎉 Configuration backup completed successfully")
        print(f"   Backup ID: {result['backup_id']}")
        print(f"   Location: {result['s3_location']}")
    else:
        print(f"💥 Configuration backup failed: {result['error']}")
```

### Database Backup

```python
# scripts/backup_database.py
import asyncio
import boto3
import subprocess
from datetime import datetime

async def backup_database():
    """Backup PostgreSQL database to S3"""
    
    backup_timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"honeypot_db_backup_{backup_timestamp}.sql"
    
    print(f"🔄 Starting database backup: {backup_filename}")
    
    # Database connection parameters
    db_config = {
        "host": "honeypot-db.cluster-xxx.us-west-2.rds.amazonaws.com",
        "port": "5432",
        "database": "honeypot_db",
        "username": "honeypot_user"
    }
    
    try:
        # Create database dump using pg_dump
        dump_command = [
            "pg_dump",
            f"--host={db_config['host']}",
            f"--port={db_config['port']}",
            f"--username={db_config['username']}",
            f"--dbname={db_config['database']}",
            "--verbose",
            "--clean",
            "--no-owner",
            "--no-privileges",
            f"--file=/tmp/{backup_filename}"
        ]
        
        # Set password via environment variable
        env = {"PGPASSWORD": await get_db_password()}
        
        result = subprocess.run(dump_command, env=env, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"pg_dump failed: {result.stderr}")
        
        print("✅ Database dump created successfully")
        
        # Compress the backup
        compressed_filename = f"{backup_filename}.gz"
        compress_command = ["gzip", f"/tmp/{backup_filename}"]
        
        subprocess.run(compress_command, check=True)
        print("✅ Database backup compressed")
        
        # Upload to S3
        s3_client = boto3.client('s3')
        backup_key = f"database-backups/{datetime.utcnow().strftime('%Y/%m/%d')}/{compressed_filename}"
        
        with open(f"/tmp/{compressed_filename}", 'rb') as backup_file:
            s3_client.upload_fileobj(
                backup_file,
                'honeypot-system-backups',
                backup_key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'Metadata': {
                        'backup-type': 'database',
                        'backup-timestamp': backup_timestamp,
                        'database': db_config['database']
                    }
                }
            )
        
        print(f"✅ Database backup uploaded to s3://honeypot-system-backups/{backup_key}")
        
        # Clean up local files
        subprocess.run(["rm", f"/tmp/{compressed_filename}"], check=True)
        
        # Update backup registry
        backup_info = {
            "backup_id": f"db_backup_{backup_timestamp}",
            "s3_location": f"s3://honeypot-system-backups/{backup_key}",
            "backup_type": "database",
            "timestamp": datetime.utcnow().isoformat(),
            "database": db_config['database']
        }
        
        await update_backup_registry(backup_info["backup_id"], backup_key, "database")
        
        return backup_info
        
    except Exception as e:
        print(f"❌ Database backup failed: {e}")
        return {"success": False, "error": str(e)}

async def get_db_password():
    """Retrieve database password from AWS Secrets Manager"""
    
    secrets_client = boto3.client('secretsmanager')
    
    try:
        response = secrets_client.get_secret_value(SecretId='honeypot-db-credentials')
        secret = json.loads(response['SecretString'])
        return secret['password']
    except Exception as e:
        raise Exception(f"Failed to retrieve database password: {e}")
```

## Recovery Procedures

### Configuration Recovery

```python
# scripts/restore_configuration.py
import asyncio
import json
import boto3
from agentcore_runtime import AgentCoreClient

async def restore_configuration(backup_id: str):
    """Restore system configuration from backup"""
    
    print(f"🔄 Starting configuration restore from backup: {backup_id}")
    
    # Download backup from S3
    backup_data = await download_configuration_backup(backup_id)
    
    if not backup_data:
        raise Exception(f"Failed to download backup {backup_id}")
    
    client = AgentCoreClient()
    restore_results = {
        "backup_id": backup_id,
        "timestamp": datetime.utcnow().isoformat(),
        "components_restored": [],
        "components_failed": [],
        "warnings": []
    }
    
    # Restore agent configurations
    if "agents" in backup_data["components"]:
        print("Restoring agent configurations...")
        
        for agent_name, agent_data in backup_data["components"]["agents"].items():
            try:
                if "error" in agent_data:
                    restore_results["warnings"].append(f"Skipping {agent_name} - backup contained error")
                    continue
                
                # Restore agent configuration
                await client.update_agent_configuration(
                    agent_name, 
                    agent_data["configuration"]
                )
                
                # Restore deployment configuration
                await client.update_agent_deployment_config(
                    agent_name,
                    agent_data["deployment"]
                )
                
                # Restore scaling configuration
                await client.update_agent_scaling_config(
                    agent_name,
                    agent_data["scaling"]
                )
                
                restore_results["components_restored"].append(f"agent:{agent_name}")
                print(f"✅ Restored {agent_name} configuration")
                
            except Exception as e:
                restore_results["components_failed"].append(f"agent:{agent_name} - {str(e)}")
                print(f"❌ Failed to restore {agent_name}: {e}")
    
    # Restore workflow definitions
    if "workflows" in backup_data["components"]:
        print("Restoring workflow definitions...")
        
        for workflow_id, workflow_def in backup_data["components"]["workflows"].items():
            try:
                await client.create_or_update_workflow(workflow_id, workflow_def)
                restore_results["components_restored"].append(f"workflow:{workflow_id}")
                print(f"✅ Restored workflow {workflow_id}")
                
            except Exception as e:
                restore_results["components_failed"].append(f"workflow:{workflow_id} - {str(e)}")
                print(f"❌ Failed to restore workflow {workflow_id}: {e}")
    
    # Restore system settings
    if "system_settings" in backup_data["components"]:
        print("Restoring system settings...")
        
        try:
            await restore_system_configuration(backup_data["components"]["system_settings"])
            restore_results["components_restored"].append("system_settings")
            print("✅ Restored system settings")
            
        except Exception as e:
            restore_results["components_failed"].append(f"system_settings - {str(e)}")
            print(f"❌ Failed to restore system settings: {e}")
    
    # Restore user accounts (with warnings about passwords)
    if "users" in backup_data["components"]:
        print("Restoring user accounts...")
        restore_results["warnings"].append("User passwords and MFA secrets must be reset manually")
        
        try:
            restored_users = await restore_user_accounts(backup_data["components"]["users"])
            restore_results["components_restored"].append(f"users:{len(restored_users)}")
            print(f"✅ Restored {len(restored_users)} user accounts")
            
        except Exception as e:
            restore_results["components_failed"].append(f"users - {str(e)}")
            print(f"❌ Failed to restore user accounts: {e}")
    
    # Generate restore report
    await save_restore_report(restore_results)
    
    print(f"\n🎉 Configuration restore completed")
    print(f"   Components restored: {len(restore_results['components_restored'])}")
    print(f"   Components failed: {len(restore_results['components_failed'])}")
    print(f"   Warnings: {len(restore_results['warnings'])}")
    
    return restore_results

async def download_configuration_backup(backup_id: str):
    """Download configuration backup from S3"""
    
    # Find backup in registry
    backup_info = await get_backup_info(backup_id)
    
    if not backup_info:
        raise Exception(f"Backup {backup_id} not found in registry")
    
    # Download from S3
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.get_object(
            Bucket='honeypot-system-backups',
            Key=backup_info['s3_key']
        )
        
        backup_data = json.loads(response['Body'].read().decode('utf-8'))
        return backup_data
        
    except Exception as e:
        raise Exception(f"Failed to download backup from S3: {e}")
```

### Database Recovery

```python
# scripts/restore_database.py
import asyncio
import boto3
import subprocess
from datetime import datetime

async def restore_database(backup_id: str, target_database: str = None):
    """Restore database from backup"""
    
    print(f"🔄 Starting database restore from backup: {backup_id}")
    
    # Get backup information
    backup_info = await get_backup_info(backup_id)
    
    if not backup_info or backup_info['backup_type'] != 'database':
        raise Exception(f"Database backup {backup_id} not found")
    
    # Download backup from S3
    s3_client = boto3.client('s3')
    local_backup_file = f"/tmp/restore_{backup_id}.sql.gz"
    
    try:
        s3_client.download_file(
            'honeypot-system-backups',
            backup_info['s3_key'],
            local_backup_file
        )
        print("✅ Downloaded backup from S3")
        
    except Exception as e:
        raise Exception(f"Failed to download backup: {e}")
    
    # Decompress backup
    decompressed_file = local_backup_file.replace('.gz', '')
    
    try:
        subprocess.run(["gunzip", local_backup_file], check=True)
        print("✅ Decompressed backup file")
        
    except Exception as e:
        raise Exception(f"Failed to decompress backup: {e}")
    
    # Database connection parameters
    db_config = {
        "host": "honeypot-db.cluster-xxx.us-west-2.rds.amazonaws.com",
        "port": "5432",
        "database": target_database or "honeypot_db_restore",
        "username": "honeypot_user"
    }
    
    try:
        # Create target database if it doesn't exist
        if target_database:
            await create_database_if_not_exists(target_database)
        
        # Restore database using psql
        restore_command = [
            "psql",
            f"--host={db_config['host']}",
            f"--port={db_config['port']}",
            f"--username={db_config['username']}",
            f"--dbname={db_config['database']}",
            "--file", decompressed_file,
            "--verbose"
        ]
        
        # Set password via environment variable
        env = {"PGPASSWORD": await get_db_password()}
        
        result = subprocess.run(restore_command, env=env, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Database restore failed: {result.stderr}")
        
        print("✅ Database restored successfully")
        
        # Verify restore
        verification_result = await verify_database_restore(db_config['database'])
        
        if verification_result["success"]:
            print(f"✅ Database restore verified - {verification_result['table_count']} tables restored")
        else:
            print(f"⚠️  Database restore verification failed: {verification_result['error']}")
        
        # Clean up local files
        subprocess.run(["rm", decompressed_file], check=True)
        
        restore_info = {
            "backup_id": backup_id,
            "restore_timestamp": datetime.utcnow().isoformat(),
            "target_database": db_config['database'],
            "verification": verification_result
        }
        
        await save_restore_report(restore_info, "database")
        
        return restore_info
        
    except Exception as e:
        # Clean up on failure
        if os.path.exists(decompressed_file):
            subprocess.run(["rm", decompressed_file], check=True)
        raise Exception(f"Database restore failed: {e}")

async def verify_database_restore(database_name: str):
    """Verify database restore was successful"""
    
    try:
        # Connect to restored database and check table counts
        import asyncpg
        
        conn = await asyncpg.connect(
            host="honeypot-db.cluster-xxx.us-west-2.rds.amazonaws.com",
            port=5432,
            user="honeypot_user",
            password=await get_db_password(),
            database=database_name
        )
        
        # Check table count
        table_count = await conn.fetchval("""
            SELECT COUNT(*) 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        
        # Check for critical tables
        critical_tables = ['threat_events', 'engagements', 'intelligence_reports', 'users']
        missing_tables = []
        
        for table in critical_tables:
            exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = $1
                )
            """, table)
            
            if not exists:
                missing_tables.append(table)
        
        await conn.close()
        
        if missing_tables:
            return {
                "success": False,
                "error": f"Missing critical tables: {missing_tables}",
                "table_count": table_count
            }
        
        return {
            "success": True,
            "table_count": table_count,
            "critical_tables_present": len(critical_tables)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "table_count": 0
        }
```

This backup and recovery runbook provides comprehensive procedures for protecting system data and ensuring business continuity.