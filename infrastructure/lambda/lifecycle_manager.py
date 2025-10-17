"""
Lambda function for data lifecycle management
Handles data archival, cleanup, and retention policies
"""

import json
import boto3
import logging
import os
import psycopg2
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')
sns_client = boto3.client('sns')

# Environment variables
DATABASE_ENDPOINT = os.environ['DATABASE_ENDPOINT']
DATABASE_NAME = os.environ['DATABASE_NAME']
DATABASE_SECRET_ARN = os.environ['DATABASE_SECRET_ARN']
SESSION_DATA_BUCKET = os.environ['SESSION_DATA_BUCKET']
INTELLIGENCE_BUCKET = os.environ['INTELLIGENCE_BUCKET']
AUDIT_LOGS_BUCKET = os.environ['AUDIT_LOGS_BUCKET']
SYNTHETIC_DATA_BUCKET = os.environ['SYNTHETIC_DATA_BUCKET']
ALERTS_TOPIC_ARN = os.environ['ALERTS_TOPIC_ARN']

# Retention periods (in days)
SESSION_DATA_RETENTION_DAYS = int(os.environ.get('SESSION_DATA_RETENTION_DAYS', '2555'))  # 7 years
INTELLIGENCE_RETENTION_DAYS = int(os.environ.get('INTELLIGENCE_RETENTION_DAYS', '1825'))  # 5 years
AUDIT_LOG_RETENTION_DAYS = int(os.environ.get('AUDIT_LOG_RETENTION_DAYS', '3650'))  # 10 years
SYNTHETIC_DATA_RETENTION_DAYS = int(os.environ.get('SYNTHETIC_DATA_RETENTION_DAYS', '90'))  # 3 months


def handler(event, context):
    """Main Lambda handler for lifecycle management"""
    
    try:
        results = {}
        
        # Clean up old session data
        results['session_cleanup'] = cleanup_old_sessions()
        
        # Archive intelligence reports
        results['intelligence_archive'] = archive_intelligence_reports()
        
        # Clean up synthetic data
        results['synthetic_cleanup'] = cleanup_synthetic_data()
        
        # Clean up audit logs
        results['audit_cleanup'] = cleanup_audit_logs()
        
        # Optimize database
        results['database_optimization'] = optimize_database()
        
        # Generate lifecycle report
        generate_lifecycle_report(results)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Lifecycle management completed successfully',
                'results': results
            })
        }
        
    except Exception as e:
        logger.error(f"Error in lifecycle management: {str(e)}")
        
        # Send error alert
        send_error_alert(str(e), event)
        
        # Re-raise for monitoring
        raise


def cleanup_old_sessions():
    """Clean up session data older than retention period"""
    
    logger.info("Starting session data cleanup...")
    
    try:
        credentials = get_database_credentials()
        
        # Connect to database
        conn = psycopg2.connect(
            host=DATABASE_ENDPOINT,
            database=DATABASE_NAME,
            user=credentials['username'],
            password=credentials['password'],
            port=5432,
            sslmode='require'
        )
        
        cursor = conn.cursor()
        
        # Calculate cutoff date
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=SESSION_DATA_RETENTION_DAYS)
        
        # Find old sessions
        cursor.execute("""
            SELECT session_id, s3_location 
            FROM honeypot_sessions 
            WHERE end_time < %s AND archived = false
        """, (cutoff_date,))
        
        old_sessions = cursor.fetchall()
        
        archived_count = 0
        deleted_count = 0
        
        for session_id, s3_location in old_sessions:
            try:
                # Archive session data to Glacier
                if s3_location:
                    archive_session_to_glacier(s3_location)
                
                # Mark session as archived in database
                cursor.execute("""
                    UPDATE honeypot_sessions 
                    SET archived = true, archived_date = %s 
                    WHERE session_id = %s
                """, (datetime.now(timezone.utc), session_id))
                
                archived_count += 1
                
            except Exception as e:
                logger.error(f"Error archiving session {session_id}: {e}")
        
        # Delete very old archived sessions (beyond retention period)
        very_old_cutoff = datetime.now(timezone.utc) - timedelta(days=SESSION_DATA_RETENTION_DAYS + 365)
        
        cursor.execute("""
            SELECT session_id, s3_location 
            FROM honeypot_sessions 
            WHERE archived_date < %s AND archived = true
        """, (very_old_cutoff,))
        
        very_old_sessions = cursor.fetchall()
        
        for session_id, s3_location in very_old_sessions:
            try:
                # Delete from S3
                if s3_location:
                    delete_s3_object(s3_location)
                
                # Delete from database
                cursor.execute("DELETE FROM honeypot_sessions WHERE session_id = %s", (session_id,))
                
                deleted_count += 1
                
            except Exception as e:
                logger.error(f"Error deleting session {session_id}: {e}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        result = {
            'archived_sessions': archived_count,
            'deleted_sessions': deleted_count,
            'total_processed': len(old_sessions) + len(very_old_sessions)
        }
        
        logger.info(f"Session cleanup completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in session cleanup: {e}")
        raise


def archive_intelligence_reports():
    """Archive old intelligence reports to long-term storage"""
    
    logger.info("Starting intelligence reports archival...")
    
    try:
        # Calculate cutoff date for archival (move to IA after 60 days)
        ia_cutoff_date = datetime.now(timezone.utc) - timedelta(days=60)
        
        # List objects in intelligence bucket
        paginator = s3_client.get_paginator('list_objects_v2')
        
        archived_count = 0
        
        for page in paginator.paginate(Bucket=INTELLIGENCE_BUCKET):
            if 'Contents' not in page:
                continue
            
            for obj in page['Contents']:
                # Check if object is older than cutoff and not already in IA
                if obj['LastModified'].replace(tzinfo=timezone.utc) < ia_cutoff_date:
                    
                    # Get object storage class
                    response = s3_client.head_object(
                        Bucket=INTELLIGENCE_BUCKET,
                        Key=obj['Key']
                    )
                    
                    storage_class = response.get('StorageClass', 'STANDARD')
                    
                    # Move to IA if still in STANDARD
                    if storage_class == 'STANDARD':
                        s3_client.copy_object(
                            Bucket=INTELLIGENCE_BUCKET,
                            Key=obj['Key'],
                            CopySource={'Bucket': INTELLIGENCE_BUCKET, 'Key': obj['Key']},
                            StorageClass='STANDARD_IA',
                            MetadataDirective='COPY'
                        )
                        
                        archived_count += 1
        
        result = {
            'reports_moved_to_ia': archived_count
        }
        
        logger.info(f"Intelligence archival completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in intelligence archival: {e}")
        raise


def cleanup_synthetic_data():
    """Clean up unused synthetic data"""
    
    logger.info("Starting synthetic data cleanup...")
    
    try:
        credentials = get_database_credentials()
        
        # Connect to database
        conn = psycopg2.connect(
            host=DATABASE_ENDPOINT,
            database=DATABASE_NAME,
            user=credentials['username'],
            password=credentials['password'],
            port=5432,
            sslmode='require'
        )
        
        cursor = conn.cursor()
        
        # Find unused synthetic data (not accessed in last 90 days)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=SYNTHETIC_DATA_RETENTION_DAYS)
        
        cursor.execute("""
            SELECT data_id, s3_location 
            FROM synthetic_data 
            WHERE last_accessed < %s OR last_accessed IS NULL
        """, (cutoff_date,))
        
        unused_data = cursor.fetchall()
        
        deleted_count = 0
        
        for data_id, s3_location in unused_data:
            try:
                # Delete from S3
                if s3_location:
                    delete_s3_object(s3_location)
                
                # Delete from database
                cursor.execute("DELETE FROM synthetic_data WHERE data_id = %s", (data_id,))
                
                deleted_count += 1
                
            except Exception as e:
                logger.error(f"Error deleting synthetic data {data_id}: {e}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        result = {
            'deleted_synthetic_data': deleted_count,
            'total_unused': len(unused_data)
        }
        
        logger.info(f"Synthetic data cleanup completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in synthetic data cleanup: {e}")
        raise


def cleanup_audit_logs():
    """Clean up old audit logs based on retention policy"""
    
    logger.info("Starting audit logs cleanup...")
    
    try:
        # Calculate cutoff date
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=AUDIT_LOG_RETENTION_DAYS)
        
        # List objects in audit logs bucket
        paginator = s3_client.get_paginator('list_objects_v2')
        
        deleted_count = 0
        
        for page in paginator.paginate(Bucket=AUDIT_LOGS_BUCKET):
            if 'Contents' not in page:
                continue
            
            for obj in page['Contents']:
                # Check if object is older than retention period
                if obj['LastModified'].replace(tzinfo=timezone.utc) < cutoff_date:
                    
                    # Delete object
                    s3_client.delete_object(
                        Bucket=AUDIT_LOGS_BUCKET,
                        Key=obj['Key']
                    )
                    
                    deleted_count += 1
        
        result = {
            'deleted_audit_logs': deleted_count
        }
        
        logger.info(f"Audit logs cleanup completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in audit logs cleanup: {e}")
        raise


def optimize_database():
    """Optimize database performance"""
    
    logger.info("Starting database optimization...")
    
    try:
        credentials = get_database_credentials()
        
        # Connect to database
        conn = psycopg2.connect(
            host=DATABASE_ENDPOINT,
            database=DATABASE_NAME,
            user=credentials['username'],
            password=credentials['password'],
            port=5432,
            sslmode='require'
        )
        
        cursor = conn.cursor()
        
        # Update table statistics
        cursor.execute("ANALYZE;")
        
        # Vacuum tables to reclaim space
        cursor.execute("VACUUM;")
        
        # Get database size information
        cursor.execute("""
            SELECT 
                pg_size_pretty(pg_database_size(current_database())) as database_size,
                (SELECT count(*) FROM honeypot_sessions) as session_count,
                (SELECT count(*) FROM intelligence_reports) as intelligence_count,
                (SELECT count(*) FROM synthetic_data) as synthetic_data_count
        """)
        
        stats = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        result = {
            'database_size': stats[0],
            'session_count': stats[1],
            'intelligence_count': stats[2],
            'synthetic_data_count': stats[3]
        }
        
        logger.info(f"Database optimization completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error in database optimization: {e}")
        raise


def archive_session_to_glacier(s3_location: str):
    """Archive session data to Glacier storage"""
    
    try:
        # Parse S3 location
        if s3_location.startswith('s3://'):
            s3_location = s3_location[5:]
        
        bucket, key = s3_location.split('/', 1)
        
        # Copy to Glacier storage class
        s3_client.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={'Bucket': bucket, 'Key': key},
            StorageClass='GLACIER',
            MetadataDirective='COPY'
        )
        
        logger.info(f"Archived session data to Glacier: {s3_location}")
        
    except Exception as e:
        logger.error(f"Error archiving to Glacier: {e}")
        raise


def delete_s3_object(s3_location: str):
    """Delete object from S3"""
    
    try:
        # Parse S3 location
        if s3_location.startswith('s3://'):
            s3_location = s3_location[5:]
        
        bucket, key = s3_location.split('/', 1)
        
        # Delete object
        s3_client.delete_object(Bucket=bucket, Key=key)
        
        logger.info(f"Deleted S3 object: {s3_location}")
        
    except Exception as e:
        logger.error(f"Error deleting S3 object: {e}")
        raise


def generate_lifecycle_report(results: Dict[str, Any]):
    """Generate and store lifecycle management report"""
    
    try:
        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'lifecycle_results': results,
            'summary': {
                'total_sessions_archived': results.get('session_cleanup', {}).get('archived_sessions', 0),
                'total_sessions_deleted': results.get('session_cleanup', {}).get('deleted_sessions', 0),
                'intelligence_reports_archived': results.get('intelligence_archive', {}).get('reports_moved_to_ia', 0),
                'synthetic_data_deleted': results.get('synthetic_cleanup', {}).get('deleted_synthetic_data', 0),
                'audit_logs_deleted': results.get('audit_cleanup', {}).get('deleted_audit_logs', 0)
            }
        }
        
        # Store report in S3
        report_key = f"lifecycle-reports/{datetime.now().strftime('%Y/%m/%d')}/lifecycle-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        
        s3_client.put_object(
            Bucket=AUDIT_LOGS_BUCKET,
            Key=report_key,
            Body=json.dumps(report, indent=2),
            ContentType='application/json',
            ServerSideEncryption='aws:kms'
        )
        
        logger.info(f"Generated lifecycle report: {report_key}")
        
    except Exception as e:
        logger.error(f"Error generating lifecycle report: {e}")


def get_database_credentials():
    """Retrieve database credentials from Secrets Manager"""
    
    try:
        response = secrets_client.get_secret_value(SecretId=DATABASE_SECRET_ARN)
        credentials = json.loads(response['SecretString'])
        return credentials
    except Exception as e:
        logger.error(f"Error retrieving database credentials: {e}")
        raise


def send_error_alert(error_message: str, event: Dict[str, Any]):
    """Send alert for lifecycle management errors"""
    
    try:
        message = {
            'alert_type': 'lifecycle_management_error',
            'error_message': error_message,
            'event': event,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        sns_client.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject="Lifecycle Management Error",
            Message=json.dumps(message, indent=2)
        )
        
    except Exception as e:
        logger.error(f"Error sending error alert: {e}")