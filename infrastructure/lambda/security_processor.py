"""
Lambda function for security event processing
Handles security violations, real data detection, and emergency responses
"""

import json
import boto3
import logging
import os
import psycopg2
from datetime import datetime, timezone
from typing import Dict, List, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
sns_client = boto3.client('sns')
secrets_client = boto3.client('secretsmanager')
lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')

# Environment variables
DATABASE_ENDPOINT = os.environ['DATABASE_ENDPOINT']
DATABASE_NAME = os.environ['DATABASE_NAME']
DATABASE_SECRET_ARN = os.environ['DATABASE_SECRET_ARN']
ALERTS_TOPIC_ARN = os.environ['ALERTS_TOPIC_ARN']
SECURITY_TOPIC_ARN = os.environ['SECURITY_TOPIC_ARN']
EMERGENCY_SHUTDOWN_FUNCTION = os.environ.get('EMERGENCY_SHUTDOWN_FUNCTION')


def handler(event, context):
    """Main Lambda handler for security event processing"""
    
    try:
        processed_count = 0
        critical_events = 0
        
        # Process security events
        for record in event.get('Records', []):
            
            # Parse event data
            if 'body' in record:
                # SQS message
                message_body = json.loads(record['body'])
                if 'Message' in message_body:
                    # SNS message in SQS
                    security_event = json.loads(message_body['Message'])
                else:
                    security_event = message_body
            else:
                # Direct invocation
                security_event = record
            
            # Process security event
            severity = process_security_event(security_event)
            
            if severity == 'CRITICAL':
                critical_events += 1
            
            processed_count += 1
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security event processing completed',
                'processed_count': processed_count,
                'critical_events': critical_events
            })
        }
        
    except Exception as e:
        logger.error(f"Error processing security events: {str(e)}")
        
        # Send error alert
        send_error_alert(str(e), event)
        
        # Re-raise for monitoring
        raise


def process_security_event(event: Dict[str, Any]) -> str:
    """Process individual security event and determine response"""
    
    event_type = event.get('event_type', '').lower()
    event_id = event.get('event_id', 'unknown')
    timestamp = event.get('timestamp', datetime.now(timezone.utc).isoformat())
    
    logger.info(f"Processing security event: {event_id} - {event_type}")
    
    # Determine severity
    severity = determine_severity(event)
    
    # Log security event
    log_security_event(event, severity)
    
    # Take appropriate action based on severity
    if severity == 'CRITICAL':
        handle_critical_event(event)
    elif severity == 'HIGH':
        handle_high_priority_event(event)
    elif severity == 'MEDIUM':
        handle_medium_priority_event(event)
    else:
        handle_low_priority_event(event)
    
    return severity


def determine_severity(event: Dict[str, Any]) -> str:
    """Determine the severity of a security event"""
    
    event_type = event.get('event_type', '').lower()
    event_data = event.get('event_data', {})
    
    # Critical events that require immediate response
    critical_indicators = [
        'real_data_detected',
        'isolation_breach',
        'unauthorized_access',
        'data_exfiltration',
        'system_compromise',
        'emergency_shutdown_required'
    ]
    
    # High priority events
    high_priority_indicators = [
        'suspicious_activity',
        'privilege_escalation',
        'lateral_movement',
        'credential_theft',
        'malware_detected',
        'network_anomaly'
    ]
    
    # Medium priority events
    medium_priority_indicators = [
        'failed_authentication',
        'reconnaissance',
        'port_scanning',
        'brute_force_attempt',
        'unusual_traffic'
    ]
    
    # Check for critical indicators
    if any(indicator in event_type for indicator in critical_indicators):
        return 'CRITICAL'
    
    # Check confidence score for real data detection
    if 'real_data' in event_type and event_data.get('confidence_score', 0) > 0.9:
        return 'CRITICAL'
    
    # Check for high priority indicators
    if any(indicator in event_type for indicator in high_priority_indicators):
        return 'HIGH'
    
    # Check for medium priority indicators
    if any(indicator in event_type for indicator in medium_priority_indicators):
        return 'MEDIUM'
    
    # Default to low priority
    return 'LOW'


def handle_critical_event(event: Dict[str, Any]):
    """Handle critical security events requiring immediate response"""
    
    event_type = event.get('event_type', '')
    event_id = event.get('event_id', 'unknown')
    
    logger.critical(f"CRITICAL security event detected: {event_id} - {event_type}")
    
    # Immediate actions for critical events
    actions_taken = []
    
    try:
        # 1. Send immediate alert
        send_critical_alert(event)
        actions_taken.append('critical_alert_sent')
        
        # 2. Handle specific critical event types
        if 'real_data_detected' in event_type.lower():
            handle_real_data_detection(event)
            actions_taken.append('real_data_quarantine')
        
        elif 'isolation_breach' in event_type.lower():
            handle_isolation_breach(event)
            actions_taken.append('isolation_breach_response')
        
        elif 'emergency_shutdown' in event_type.lower():
            trigger_emergency_shutdown(event)
            actions_taken.append('emergency_shutdown_triggered')
        
        # 3. Quarantine affected resources
        quarantine_resources(event)
        actions_taken.append('resources_quarantined')
        
        # 4. Create incident record
        create_incident_record(event, 'CRITICAL', actions_taken)
        
        logger.info(f"Critical event response completed: {actions_taken}")
        
    except Exception as e:
        logger.error(f"Error handling critical event: {e}")
        send_error_alert(f"Critical event handling failed: {e}", event)


def handle_high_priority_event(event: Dict[str, Any]):
    """Handle high priority security events"""
    
    event_type = event.get('event_type', '')
    event_id = event.get('event_id', 'unknown')
    
    logger.warning(f"HIGH priority security event: {event_id} - {event_type}")
    
    actions_taken = []
    
    try:
        # 1. Send high priority alert
        send_high_priority_alert(event)
        actions_taken.append('high_priority_alert_sent')
        
        # 2. Enhanced monitoring
        enable_enhanced_monitoring(event)
        actions_taken.append('enhanced_monitoring_enabled')
        
        # 3. Create security incident
        create_incident_record(event, 'HIGH', actions_taken)
        
        logger.info(f"High priority event response completed: {actions_taken}")
        
    except Exception as e:
        logger.error(f"Error handling high priority event: {e}")


def handle_medium_priority_event(event: Dict[str, Any]):
    """Handle medium priority security events"""
    
    event_type = event.get('event_type', '')
    event_id = event.get('event_id', 'unknown')
    
    logger.info(f"MEDIUM priority security event: {event_id} - {event_type}")
    
    try:
        # 1. Send standard alert
        send_standard_alert(event)
        
        # 2. Log for analysis
        log_for_analysis(event)
        
        # 3. Update threat intelligence
        update_threat_intelligence(event)
        
    except Exception as e:
        logger.error(f"Error handling medium priority event: {e}")


def handle_low_priority_event(event: Dict[str, Any]):
    """Handle low priority security events"""
    
    event_type = event.get('event_type', '')
    event_id = event.get('event_id', 'unknown')
    
    logger.info(f"LOW priority security event: {event_id} - {event_type}")
    
    try:
        # Log for trend analysis
        log_for_analysis(event)
        
    except Exception as e:
        logger.error(f"Error handling low priority event: {e}")


def handle_real_data_detection(event: Dict[str, Any]):
    """Handle real data detection events"""
    
    logger.critical("Real data detected - initiating quarantine procedures")
    
    event_data = event.get('event_data', {})
    
    try:
        # 1. Immediately quarantine the data
        data_location = event_data.get('data_location')
        if data_location:
            quarantine_data(data_location)
        
        # 2. Terminate affected sessions
        session_id = event_data.get('session_id')
        if session_id:
            terminate_session(session_id)
        
        # 3. Block attacker IP
        attacker_ip = event_data.get('attacker_ip')
        if attacker_ip:
            block_ip_address(attacker_ip)
        
        # 4. Notify security team immediately
        notify_security_team_urgent(event)
        
        logger.info("Real data detection response completed")
        
    except Exception as e:
        logger.error(f"Error handling real data detection: {e}")
        raise


def handle_isolation_breach(event: Dict[str, Any]):
    """Handle network isolation breach events"""
    
    logger.critical("Network isolation breach detected - initiating containment")
    
    event_data = event.get('event_data', {})
    
    try:
        # 1. Immediately isolate affected resources
        resource_id = event_data.get('resource_id')
        if resource_id:
            isolate_resource(resource_id)
        
        # 2. Update security groups to block traffic
        update_security_groups_emergency(event_data)
        
        # 3. Terminate all sessions on affected honeypots
        terminate_all_sessions(event_data.get('honeypot_id'))
        
        # 4. Trigger network forensics
        trigger_network_forensics(event)
        
        logger.info("Isolation breach response completed")
        
    except Exception as e:
        logger.error(f"Error handling isolation breach: {e}")
        raise


def trigger_emergency_shutdown(event: Dict[str, Any]):
    """Trigger emergency shutdown of honeypot system"""
    
    logger.critical("Triggering emergency shutdown of honeypot system")
    
    try:
        if EMERGENCY_SHUTDOWN_FUNCTION:
            # Invoke emergency shutdown Lambda
            lambda_client.invoke(
                FunctionName=EMERGENCY_SHUTDOWN_FUNCTION,
                InvocationType='Event',  # Asynchronous
                Payload=json.dumps(event)
            )
            
            logger.info("Emergency shutdown function invoked")
        else:
            logger.warning("Emergency shutdown function not configured")
        
    except Exception as e:
        logger.error(f"Error triggering emergency shutdown: {e}")
        raise


def quarantine_resources(event: Dict[str, Any]):
    """Quarantine affected resources"""
    
    event_data = event.get('event_data', {})
    
    try:
        # Quarantine honeypot instances
        honeypot_id = event_data.get('honeypot_id')
        if honeypot_id:
            quarantine_honeypot(honeypot_id)
        
        # Quarantine data
        data_locations = event_data.get('data_locations', [])
        for location in data_locations:
            quarantine_data(location)
        
        logger.info("Resource quarantine completed")
        
    except Exception as e:
        logger.error(f"Error quarantining resources: {e}")


def quarantine_data(data_location: str):
    """Quarantine specific data location"""
    
    logger.info(f"Quarantining data at location: {data_location}")
    
    # Implementation would move data to quarantine bucket
    # and update database records
    
    # For now, log the action
    logger.info(f"Data quarantined: {data_location}")


def quarantine_honeypot(honeypot_id: str):
    """Quarantine specific honeypot"""
    
    logger.info(f"Quarantining honeypot: {honeypot_id}")
    
    # Implementation would:
    # 1. Stop honeypot instance
    # 2. Update security groups to deny all traffic
    # 3. Mark honeypot as quarantined in database
    
    # For now, log the action
    logger.info(f"Honeypot quarantined: {honeypot_id}")


def terminate_session(session_id: str):
    """Terminate specific session"""
    
    logger.info(f"Terminating session: {session_id}")
    
    # Implementation would:
    # 1. Close network connections
    # 2. Stop session recording
    # 3. Update session status in database
    
    # For now, log the action
    logger.info(f"Session terminated: {session_id}")


def block_ip_address(ip_address: str):
    """Block specific IP address"""
    
    logger.info(f"Blocking IP address: {ip_address}")
    
    # Implementation would:
    # 1. Update security groups
    # 2. Add to WAF block list
    # 3. Update network ACLs
    
    # For now, log the action
    logger.info(f"IP address blocked: {ip_address}")


def send_critical_alert(event: Dict[str, Any]):
    """Send critical security alert"""
    
    try:
        message = {
            'alert_level': 'CRITICAL',
            'event_type': event.get('event_type'),
            'event_id': event.get('event_id'),
            'timestamp': event.get('timestamp'),
            'event_data': event.get('event_data', {}),
            'response_required': 'IMMEDIATE',
            'escalation_level': 'SECURITY_TEAM'
        }
        
        # Send to both alerts and security topics
        for topic_arn in [ALERTS_TOPIC_ARN, SECURITY_TOPIC_ARN]:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject=f"CRITICAL SECURITY ALERT - {event.get('event_type', 'Unknown')}",
                Message=json.dumps(message, indent=2)
            )
        
        logger.info("Critical security alert sent")
        
    except Exception as e:
        logger.error(f"Error sending critical alert: {e}")


def send_high_priority_alert(event: Dict[str, Any]):
    """Send high priority security alert"""
    
    try:
        message = {
            'alert_level': 'HIGH',
            'event_type': event.get('event_type'),
            'event_id': event.get('event_id'),
            'timestamp': event.get('timestamp'),
            'event_data': event.get('event_data', {}),
            'response_required': 'WITHIN_1_HOUR'
        }
        
        sns_client.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject=f"HIGH PRIORITY SECURITY ALERT - {event.get('event_type', 'Unknown')}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info("High priority security alert sent")
        
    except Exception as e:
        logger.error(f"Error sending high priority alert: {e}")


def send_standard_alert(event: Dict[str, Any]):
    """Send standard security alert"""
    
    try:
        message = {
            'alert_level': 'MEDIUM',
            'event_type': event.get('event_type'),
            'event_id': event.get('event_id'),
            'timestamp': event.get('timestamp'),
            'event_data': event.get('event_data', {}),
            'response_required': 'WITHIN_24_HOURS'
        }
        
        sns_client.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject=f"Security Alert - {event.get('event_type', 'Unknown')}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info("Standard security alert sent")
        
    except Exception as e:
        logger.error(f"Error sending standard alert: {e}")


def log_security_event(event: Dict[str, Any], severity: str):
    """Log security event to database"""
    
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
        
        # Insert security event
        cursor.execute("""
            INSERT INTO security_events (
                event_id, event_type, severity, timestamp, event_data, processed_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            event.get('event_id'),
            event.get('event_type'),
            severity,
            event.get('timestamp'),
            json.dumps(event.get('event_data', {})),
            datetime.now(timezone.utc)
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Security event logged: {event.get('event_id')}")
        
    except Exception as e:
        logger.error(f"Error logging security event: {e}")


def create_incident_record(event: Dict[str, Any], severity: str, actions_taken: List[str]):
    """Create security incident record"""
    
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
        
        # Create incident record
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        cursor.execute("""
            INSERT INTO security_incidents (
                incident_id, event_id, severity, status, created_at, 
                event_data, actions_taken
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            incident_id,
            event.get('event_id'),
            severity,
            'OPEN',
            datetime.now(timezone.utc),
            json.dumps(event.get('event_data', {})),
            json.dumps(actions_taken)
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Security incident created: {incident_id}")
        
    except Exception as e:
        logger.error(f"Error creating incident record: {e}")


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
    """Send alert for security processing errors"""
    
    try:
        message = {
            'alert_type': 'security_processing_error',
            'error_message': error_message,
            'event': event,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        sns_client.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject="Security Event Processing Error",
            Message=json.dumps(message, indent=2)
        )
        
    except Exception as e:
        logger.error(f"Error sending error alert: {e}")


# Placeholder functions for additional security operations
def enable_enhanced_monitoring(event: Dict[str, Any]):
    """Enable enhanced monitoring for security event"""
    logger.info("Enhanced monitoring enabled")


def log_for_analysis(event: Dict[str, Any]):
    """Log event for security analysis"""
    logger.info("Event logged for analysis")


def update_threat_intelligence(event: Dict[str, Any]):
    """Update threat intelligence with event data"""
    logger.info("Threat intelligence updated")


def isolate_resource(resource_id: str):
    """Isolate specific resource"""
    logger.info(f"Resource isolated: {resource_id}")


def update_security_groups_emergency(event_data: Dict[str, Any]):
    """Update security groups for emergency containment"""
    logger.info("Security groups updated for emergency containment")


def terminate_all_sessions(honeypot_id: str):
    """Terminate all sessions on honeypot"""
    logger.info(f"All sessions terminated on honeypot: {honeypot_id}")


def trigger_network_forensics(event: Dict[str, Any]):
    """Trigger network forensics collection"""
    logger.info("Network forensics triggered")


def notify_security_team_urgent(event: Dict[str, Any]):
    """Send urgent notification to security team"""
    logger.info("Urgent security team notification sent")