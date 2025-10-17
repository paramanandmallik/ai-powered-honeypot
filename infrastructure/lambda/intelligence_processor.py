"""
Lambda function for processing intelligence reports
Handles MITRE ATT&CK mapping, IOC extraction, and database storage
"""

import json
import boto3
import logging
import os
import psycopg2
from datetime import datetime, timezone
from typing import Dict, List, Any
import hashlib

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
INTELLIGENCE_BUCKET = os.environ['INTELLIGENCE_BUCKET']
ALERTS_TOPIC_ARN = os.environ['ALERTS_TOPIC_ARN']


def handler(event, context):
    """Main Lambda handler for intelligence processing"""
    
    try:
        processed_count = 0
        
        # Process SQS messages
        for record in event.get('Records', []):
            message_body = json.loads(record['body'])
            
            # Handle SNS message format
            if 'Message' in message_body:
                intelligence_data = json.loads(message_body['Message'])
            else:
                intelligence_data = message_body
            
            # Process intelligence report
            processed_intelligence = process_intelligence_report(intelligence_data)
            
            # Store in database
            store_intelligence_in_database(processed_intelligence)
            
            # Store report in S3
            store_report_in_s3(processed_intelligence)
            
            # Check for high-value intelligence
            if processed_intelligence.get('confidence_score', 0) > 0.8:
                send_high_value_alert(processed_intelligence)
            
            processed_count += 1
            logger.info(f"Processed intelligence report: {processed_intelligence.get('report_id')}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Intelligence processing completed successfully',
                'processed_count': processed_count
            })
        }
        
    except Exception as e:
        logger.error(f"Error processing intelligence: {str(e)}")
        
        # Send error alert
        send_error_alert(str(e), event)
        
        # Re-raise for DLQ handling
        raise


def process_intelligence_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Process and enrich intelligence data"""
    
    report_id = data.get('report_id') or generate_report_id()
    session_id = data.get('session_id')
    
    # Extract and validate MITRE techniques
    mitre_techniques = validate_mitre_techniques(data.get('mitre_techniques', []))
    
    # Extract and validate IOCs
    iocs = extract_and_validate_iocs(data.get('raw_data', ''))
    
    # Calculate confidence score
    confidence_score = calculate_confidence_score(data, mitre_techniques, iocs)
    
    # Generate threat assessment
    threat_assessment = generate_threat_assessment(mitre_techniques, iocs, confidence_score)
    
    # Create processed intelligence object
    processed_intelligence = {
        'report_id': report_id,
        'session_id': session_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'mitre_techniques': mitre_techniques,
        'iocs': iocs,
        'confidence_score': confidence_score,
        'threat_assessment': threat_assessment,
        'raw_data': data.get('raw_data', ''),
        'attacker_ip': data.get('attacker_ip'),
        'honeypot_type': data.get('honeypot_type'),
        'session_duration': data.get('session_duration'),
        'commands_executed': data.get('commands_executed', []),
        'files_accessed': data.get('files_accessed', []),
        'network_connections': data.get('network_connections', []),
        'synthetic_data_accessed': data.get('synthetic_data_accessed', [])
    }
    
    return processed_intelligence


def validate_mitre_techniques(techniques: List[str]) -> List[Dict[str, str]]:
    """Validate and enrich MITRE ATT&CK techniques"""
    
    # MITRE ATT&CK technique mapping (subset for example)
    mitre_mapping = {
        'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access'},
        'T1055': {'name': 'Process Injection', 'tactic': 'Defense Evasion'},
        'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
        'T1078': {'name': 'Valid Accounts', 'tactic': 'Defense Evasion'},
        'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery'},
        'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
        'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery'},
        'T1090': {'name': 'Proxy', 'tactic': 'Command and Control'},
        'T1105': {'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control'},
        'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
        'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
        'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'}
    }
    
    validated_techniques = []
    
    for technique_id in techniques:
        if technique_id in mitre_mapping:
            validated_techniques.append({
                'technique_id': technique_id,
                'name': mitre_mapping[technique_id]['name'],
                'tactic': mitre_mapping[technique_id]['tactic']
            })
        else:
            # Log unknown technique for review
            logger.warning(f"Unknown MITRE technique: {technique_id}")
    
    return validated_techniques


def extract_and_validate_iocs(raw_data: str) -> List[Dict[str, str]]:
    """Extract and validate Indicators of Compromise"""
    
    import re
    
    iocs = []
    
    # IP address pattern
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_matches = re.findall(ip_pattern, raw_data)
    
    for ip in ip_matches:
        # Validate IP (basic validation)
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            # Skip private/local IPs
            if not (ip.startswith('10.') or ip.startswith('192.168.') or 
                   ip.startswith('172.') or ip.startswith('127.')):
                iocs.append({
                    'type': 'ip_address',
                    'value': ip,
                    'confidence': 'medium'
                })
    
    # Domain pattern
    domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
    domain_matches = re.findall(domain_pattern, raw_data)
    
    for domain_match in domain_matches:
        domain = ''.join(domain_match)
        # Skip common legitimate domains
        if not any(legit in domain.lower() for legit in ['amazonaws.com', 'microsoft.com', 'google.com']):
            iocs.append({
                'type': 'domain',
                'value': domain,
                'confidence': 'low'
            })
    
    # File hash pattern (MD5, SHA1, SHA256)
    hash_patterns = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }
    
    for hash_type, pattern in hash_patterns.items():
        hash_matches = re.findall(pattern, raw_data)
        for hash_value in hash_matches:
            iocs.append({
                'type': f'file_hash_{hash_type}',
                'value': hash_value.lower(),
                'confidence': 'high'
            })
    
    return iocs


def calculate_confidence_score(data: Dict[str, Any], mitre_techniques: List[Dict], iocs: List[Dict]) -> float:
    """Calculate confidence score for intelligence report"""
    
    score = 0.0
    
    # Base score from session duration
    session_duration = data.get('session_duration', 0)
    if session_duration > 300:  # 5 minutes
        score += 0.2
    elif session_duration > 60:  # 1 minute
        score += 0.1
    
    # Score from MITRE techniques
    if len(mitre_techniques) > 0:
        score += min(0.3, len(mitre_techniques) * 0.1)
    
    # Score from IOCs
    high_confidence_iocs = [ioc for ioc in iocs if ioc.get('confidence') == 'high']
    if len(high_confidence_iocs) > 0:
        score += min(0.3, len(high_confidence_iocs) * 0.15)
    
    # Score from commands executed
    commands = data.get('commands_executed', [])
    suspicious_commands = ['wget', 'curl', 'nc', 'ncat', 'python', 'perl', 'bash', 'sh']
    suspicious_count = sum(1 for cmd in commands if any(sus in cmd.lower() for sus in suspicious_commands))
    if suspicious_count > 0:
        score += min(0.2, suspicious_count * 0.05)
    
    return min(1.0, score)


def generate_threat_assessment(mitre_techniques: List[Dict], iocs: List[Dict], confidence_score: float) -> str:
    """Generate human-readable threat assessment"""
    
    if confidence_score < 0.3:
        severity = "Low"
    elif confidence_score < 0.7:
        severity = "Medium"
    else:
        severity = "High"
    
    assessment = f"Threat Severity: {severity} (Confidence: {confidence_score:.2f})\n\n"
    
    if mitre_techniques:
        assessment += "MITRE ATT&CK Techniques Observed:\n"
        for technique in mitre_techniques:
            assessment += f"- {technique['technique_id']}: {technique['name']} ({technique['tactic']})\n"
        assessment += "\n"
    
    if iocs:
        assessment += "Indicators of Compromise:\n"
        for ioc in iocs:
            assessment += f"- {ioc['type'].upper()}: {ioc['value']} (Confidence: {ioc['confidence']})\n"
        assessment += "\n"
    
    # Add recommendations
    assessment += "Recommendations:\n"
    if confidence_score > 0.8:
        assessment += "- Immediate investigation recommended\n"
        assessment += "- Consider blocking identified IOCs\n"
        assessment += "- Review similar attack patterns\n"
    elif confidence_score > 0.5:
        assessment += "- Monitor for similar activity\n"
        assessment += "- Validate IOCs against threat intelligence feeds\n"
    else:
        assessment += "- Continue monitoring\n"
        assessment += "- Archive for trend analysis\n"
    
    return assessment


def get_database_credentials():
    """Retrieve database credentials from Secrets Manager"""
    
    try:
        response = secrets_client.get_secret_value(SecretId=DATABASE_SECRET_ARN)
        credentials = json.loads(response['SecretString'])
        return credentials
    except Exception as e:
        logger.error(f"Error retrieving database credentials: {e}")
        raise


def store_intelligence_in_database(intelligence: Dict[str, Any]):
    """Store processed intelligence in PostgreSQL database"""
    
    credentials = get_database_credentials()
    
    try:
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
        
        # Insert intelligence report
        insert_query = """
        INSERT INTO intelligence_reports (
            report_id, session_id, timestamp, mitre_techniques, iocs,
            confidence_score, threat_assessment, raw_data, attacker_ip,
            honeypot_type, session_duration, commands_executed,
            files_accessed, network_connections, synthetic_data_accessed
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (report_id) DO UPDATE SET
            timestamp = EXCLUDED.timestamp,
            confidence_score = EXCLUDED.confidence_score,
            threat_assessment = EXCLUDED.threat_assessment
        """
        
        cursor.execute(insert_query, (
            intelligence['report_id'],
            intelligence['session_id'],
            intelligence['timestamp'],
            json.dumps(intelligence['mitre_techniques']),
            json.dumps(intelligence['iocs']),
            intelligence['confidence_score'],
            intelligence['threat_assessment'],
            intelligence['raw_data'],
            intelligence['attacker_ip'],
            intelligence['honeypot_type'],
            intelligence['session_duration'],
            json.dumps(intelligence['commands_executed']),
            json.dumps(intelligence['files_accessed']),
            json.dumps(intelligence['network_connections']),
            json.dumps(intelligence['synthetic_data_accessed'])
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Stored intelligence report in database: {intelligence['report_id']}")
        
    except Exception as e:
        logger.error(f"Error storing intelligence in database: {e}")
        raise


def store_report_in_s3(intelligence: Dict[str, Any]):
    """Store intelligence report in S3 for long-term storage"""
    
    try:
        # Create S3 key with date partitioning
        timestamp = datetime.fromisoformat(intelligence['timestamp'].replace('Z', '+00:00'))
        s3_key = f"intelligence-reports/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/{intelligence['report_id']}.json"
        
        # Store report
        s3_client.put_object(
            Bucket=INTELLIGENCE_BUCKET,
            Key=s3_key,
            Body=json.dumps(intelligence, indent=2),
            ContentType='application/json',
            ServerSideEncryption='aws:kms'
        )
        
        logger.info(f"Stored intelligence report in S3: {s3_key}")
        
    except Exception as e:
        logger.error(f"Error storing intelligence in S3: {e}")
        raise


def send_high_value_alert(intelligence: Dict[str, Any]):
    """Send alert for high-value intelligence"""
    
    try:
        message = {
            'alert_type': 'high_value_intelligence',
            'report_id': intelligence['report_id'],
            'confidence_score': intelligence['confidence_score'],
            'mitre_techniques': intelligence['mitre_techniques'],
            'iocs': intelligence['iocs'],
            'threat_assessment': intelligence['threat_assessment'],
            'timestamp': intelligence['timestamp']
        }
        
        sns_client.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject=f"High-Value Intelligence Detected - {intelligence['report_id']}",
            Message=json.dumps(message, indent=2)
        )
        
        logger.info(f"Sent high-value intelligence alert: {intelligence['report_id']}")
        
    except Exception as e:
        logger.error(f"Error sending high-value alert: {e}")


def send_error_alert(error_message: str, event: Dict[str, Any]):
    """Send alert for processing errors"""
    
    try:
        message = {
            'alert_type': 'intelligence_processing_error',
            'error_message': error_message,
            'event': event,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        sns_client.publish(
            TopicArn=ALERTS_TOPIC_ARN,
            Subject="Intelligence Processing Error",
            Message=json.dumps(message, indent=2)
        )
        
    except Exception as e:
        logger.error(f"Error sending error alert: {e}")


def generate_report_id() -> str:
    """Generate unique report ID"""
    
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    random_suffix = hashlib.md5(os.urandom(16)).hexdigest()[:8]
    return f"INTEL-{timestamp}-{random_suffix}"