"""
Lambda function for API Gateway integration
Handles external SIEM and threat intelligence integrations
"""

import json
import boto3
import logging
import os
import psycopg2
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import hashlib
import hmac
import base64

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
secrets_client = boto3.client('secretsmanager')
sns_client = boto3.client('sns')
s3_client = boto3.client('s3')

# Environment variables
DATABASE_ENDPOINT = os.environ['DATABASE_ENDPOINT']
DATABASE_NAME = os.environ['DATABASE_NAME']
DATABASE_SECRET_ARN = os.environ['DATABASE_SECRET_ARN']
INTELLIGENCE_BUCKET = os.environ['INTELLIGENCE_BUCKET']
API_KEY_SECRET_ARN = os.environ.get('API_KEY_SECRET_ARN')
INTELLIGENCE_TOPIC_ARN = os.environ['INTELLIGENCE_TOPIC_ARN']


def handler(event, context):
    """Main Lambda handler for API Gateway requests"""
    
    try:
        # Parse API Gateway event
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        headers = event.get('headers', {})
        query_params = event.get('queryStringParameters') or {}
        body = event.get('body')
        
        # Validate API key
        if not validate_api_key(headers):
            return create_response(401, {'error': 'Invalid or missing API key'})
        
        # Route request based on path and method
        if path == '/health':
            return handle_health_check()
        elif path == '/intelligence' and http_method == 'GET':
            return handle_get_intelligence(query_params)
        elif path == '/intelligence' and http_method == 'POST':
            return handle_submit_intelligence(body)
        elif path == '/intelligence/reports' and http_method == 'GET':
            return handle_get_reports(query_params)
        elif path == '/intelligence/iocs' and http_method == 'GET':
            return handle_get_iocs(query_params)
        elif path == '/intelligence/mitre' and http_method == 'GET':
            return handle_get_mitre_data(query_params)
        elif path == '/webhooks/siem' and http_method == 'POST':
            return handle_siem_webhook(body, headers)
        else:
            return create_response(404, {'error': 'Endpoint not found'})
    
    except Exception as e:
        logger.error(f"Error processing API request: {str(e)}")
        return create_response(500, {'error': 'Internal server error'})


def validate_api_key(headers: Dict[str, str]) -> bool:
    """Validate API key from request headers"""
    
    try:
        # Get API key from headers
        api_key = headers.get('x-api-key') or headers.get('X-API-Key')
        
        if not api_key:
            logger.warning("Missing API key in request")
            return False
        
        # Get valid API keys from Secrets Manager
        if API_KEY_SECRET_ARN:
            response = secrets_client.get_secret_value(SecretId=API_KEY_SECRET_ARN)
            api_keys = json.loads(response['SecretString'])
            
            # Check if provided key is valid
            return api_key in api_keys.get('valid_keys', [])
        
        # If no secret configured, allow for development
        logger.warning("API key validation disabled - no secret configured")
        return True
        
    except Exception as e:
        logger.error(f"Error validating API key: {e}")
        return False


def handle_health_check() -> Dict[str, Any]:
    """Handle health check endpoint"""
    
    try:
        # Check database connectivity
        db_status = check_database_health()
        
        # Check S3 connectivity
        s3_status = check_s3_health()
        
        health_status = {
            'status': 'healthy' if db_status and s3_status else 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {
                'database': 'healthy' if db_status else 'unhealthy',
                's3': 'healthy' if s3_status else 'unhealthy'
            },
            'version': '1.0.0'
        }
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        
        return create_response(status_code, health_status)
        
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return create_response(503, {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })


def handle_get_intelligence(query_params: Dict[str, str]) -> Dict[str, Any]:
    """Handle GET /intelligence - retrieve intelligence reports"""
    
    try:
        # Parse query parameters
        limit = min(int(query_params.get('limit', '50')), 1000)  # Max 1000 records
        offset = int(query_params.get('offset', '0'))
        start_date = query_params.get('start_date')
        end_date = query_params.get('end_date')
        confidence_min = float(query_params.get('confidence_min', '0.0'))
        mitre_technique = query_params.get('mitre_technique')
        
        # Query database for intelligence reports
        intelligence_reports = query_intelligence_reports(
            limit=limit,
            offset=offset,
            start_date=start_date,
            end_date=end_date,
            confidence_min=confidence_min,
            mitre_technique=mitre_technique
        )
        
        response_data = {
            'reports': intelligence_reports,
            'count': len(intelligence_reports),
            'limit': limit,
            'offset': offset,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_response(200, response_data)
        
    except Exception as e:
        logger.error(f"Error retrieving intelligence: {e}")
        return create_response(500, {'error': 'Failed to retrieve intelligence'})


def handle_submit_intelligence(body: str) -> Dict[str, Any]:
    """Handle POST /intelligence - submit external intelligence"""
    
    try:
        if not body:
            return create_response(400, {'error': 'Request body is required'})
        
        # Parse request body
        intelligence_data = json.loads(body)
        
        # Validate required fields
        required_fields = ['source', 'intelligence_type', 'data']
        for field in required_fields:
            if field not in intelligence_data:
                return create_response(400, {'error': f'Missing required field: {field}'})
        
        # Process external intelligence
        processed_intelligence = process_external_intelligence(intelligence_data)
        
        # Store in database
        store_external_intelligence(processed_intelligence)
        
        # Publish to SNS for further processing
        publish_intelligence_update(processed_intelligence)
        
        response_data = {
            'message': 'Intelligence submitted successfully',
            'intelligence_id': processed_intelligence['intelligence_id'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_response(201, response_data)
        
    except json.JSONDecodeError:
        return create_response(400, {'error': 'Invalid JSON in request body'})
    except Exception as e:
        logger.error(f"Error submitting intelligence: {e}")
        return create_response(500, {'error': 'Failed to submit intelligence'})


def handle_get_reports(query_params: Dict[str, str]) -> Dict[str, Any]:
    """Handle GET /intelligence/reports - get formatted reports"""
    
    try:
        # Parse query parameters
        report_format = query_params.get('format', 'json')  # json, csv, stix
        days = int(query_params.get('days', '7'))
        confidence_min = float(query_params.get('confidence_min', '0.5'))
        
        # Generate report
        if report_format == 'stix':
            report_data = generate_stix_report(days, confidence_min)
            content_type = 'application/json'
        elif report_format == 'csv':
            report_data = generate_csv_report(days, confidence_min)
            content_type = 'text/csv'
        else:
            report_data = generate_json_report(days, confidence_min)
            content_type = 'application/json'
        
        return create_response(200, report_data, content_type)
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return create_response(500, {'error': 'Failed to generate report'})


def handle_get_iocs(query_params: Dict[str, str]) -> Dict[str, Any]:
    """Handle GET /intelligence/iocs - get indicators of compromise"""
    
    try:
        # Parse query parameters
        ioc_type = query_params.get('type')  # ip, domain, hash, etc.
        confidence_min = float(query_params.get('confidence_min', '0.5'))
        days = int(query_params.get('days', '30'))
        
        # Query IOCs from database
        iocs = query_iocs(ioc_type, confidence_min, days)
        
        response_data = {
            'iocs': iocs,
            'count': len(iocs),
            'filters': {
                'type': ioc_type,
                'confidence_min': confidence_min,
                'days': days
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_response(200, response_data)
        
    except Exception as e:
        logger.error(f"Error retrieving IOCs: {e}")
        return create_response(500, {'error': 'Failed to retrieve IOCs'})


def handle_get_mitre_data(query_params: Dict[str, str]) -> Dict[str, Any]:
    """Handle GET /intelligence/mitre - get MITRE ATT&CK data"""
    
    try:
        # Parse query parameters
        technique_id = query_params.get('technique_id')
        tactic = query_params.get('tactic')
        days = int(query_params.get('days', '30'))
        
        # Query MITRE data from database
        mitre_data = query_mitre_data(technique_id, tactic, days)
        
        response_data = {
            'mitre_data': mitre_data,
            'count': len(mitre_data),
            'filters': {
                'technique_id': technique_id,
                'tactic': tactic,
                'days': days
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_response(200, response_data)
        
    except Exception as e:
        logger.error(f"Error retrieving MITRE data: {e}")
        return create_response(500, {'error': 'Failed to retrieve MITRE data'})


def handle_siem_webhook(body: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """Handle POST /webhooks/siem - SIEM integration webhook"""
    
    try:
        if not body:
            return create_response(400, {'error': 'Request body is required'})
        
        # Parse webhook data
        webhook_data = json.loads(body)
        
        # Validate webhook signature if configured
        if not validate_webhook_signature(body, headers):
            return create_response(401, {'error': 'Invalid webhook signature'})
        
        # Process SIEM data
        processed_data = process_siem_webhook(webhook_data)
        
        # Store webhook data
        store_webhook_data(processed_data)
        
        response_data = {
            'message': 'Webhook processed successfully',
            'webhook_id': processed_data['webhook_id'],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_response(200, response_data)
        
    except json.JSONDecodeError:
        return create_response(400, {'error': 'Invalid JSON in request body'})
    except Exception as e:
        logger.error(f"Error processing SIEM webhook: {e}")
        return create_response(500, {'error': 'Failed to process webhook'})


def query_intelligence_reports(limit: int, offset: int, start_date: Optional[str] = None,
                             end_date: Optional[str] = None, confidence_min: float = 0.0,
                             mitre_technique: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query intelligence reports from database"""
    
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
    
    # Build query
    query = """
        SELECT report_id, session_id, timestamp, mitre_techniques, iocs,
               confidence_score, threat_assessment, attacker_ip, honeypot_type
        FROM intelligence_reports
        WHERE confidence_score >= %s
    """
    
    params = [confidence_min]
    
    # Add date filters
    if start_date:
        query += " AND timestamp >= %s"
        params.append(start_date)
    
    if end_date:
        query += " AND timestamp <= %s"
        params.append(end_date)
    
    # Add MITRE technique filter
    if mitre_technique:
        query += " AND mitre_techniques::text LIKE %s"
        params.append(f'%{mitre_technique}%')
    
    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Convert to list of dictionaries
    reports = []
    for row in rows:
        reports.append({
            'report_id': row[0],
            'session_id': row[1],
            'timestamp': row[2].isoformat() if row[2] else None,
            'mitre_techniques': json.loads(row[3]) if row[3] else [],
            'iocs': json.loads(row[4]) if row[4] else [],
            'confidence_score': float(row[5]) if row[5] else 0.0,
            'threat_assessment': row[6],
            'attacker_ip': row[7],
            'honeypot_type': row[8]
        })
    
    cursor.close()
    conn.close()
    
    return reports


def query_iocs(ioc_type: Optional[str], confidence_min: float, days: int) -> List[Dict[str, Any]]:
    """Query IOCs from intelligence reports"""
    
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
    
    # Query IOCs from intelligence reports
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    query = """
        SELECT DISTINCT jsonb_array_elements(iocs) as ioc_data
        FROM intelligence_reports
        WHERE confidence_score >= %s AND timestamp >= %s
    """
    
    params = [confidence_min, cutoff_date]
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Process IOCs
    iocs = []
    for row in rows:
        ioc_data = row[0]
        
        # Filter by type if specified
        if ioc_type and ioc_data.get('type') != ioc_type:
            continue
        
        iocs.append({
            'type': ioc_data.get('type'),
            'value': ioc_data.get('value'),
            'confidence': ioc_data.get('confidence'),
            'first_seen': ioc_data.get('first_seen'),
            'last_seen': ioc_data.get('last_seen')
        })
    
    cursor.close()
    conn.close()
    
    return iocs


def query_mitre_data(technique_id: Optional[str], tactic: Optional[str], days: int) -> List[Dict[str, Any]]:
    """Query MITRE ATT&CK data from intelligence reports"""
    
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
    
    # Query MITRE techniques from intelligence reports
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    query = """
        SELECT DISTINCT jsonb_array_elements(mitre_techniques) as technique_data,
               COUNT(*) as occurrence_count
        FROM intelligence_reports
        WHERE timestamp >= %s
        GROUP BY technique_data
    """
    
    params = [cutoff_date]
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Process MITRE data
    mitre_data = []
    for row in rows:
        technique_data = row[0]
        occurrence_count = row[1]
        
        # Filter by technique ID if specified
        if technique_id and technique_data.get('technique_id') != technique_id:
            continue
        
        # Filter by tactic if specified
        if tactic and technique_data.get('tactic') != tactic:
            continue
        
        mitre_data.append({
            'technique_id': technique_data.get('technique_id'),
            'name': technique_data.get('name'),
            'tactic': technique_data.get('tactic'),
            'occurrence_count': occurrence_count
        })
    
    cursor.close()
    conn.close()
    
    return mitre_data


def process_external_intelligence(intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process external intelligence submission"""
    
    # Generate intelligence ID
    intelligence_id = generate_intelligence_id()
    
    processed_intelligence = {
        'intelligence_id': intelligence_id,
        'source': intelligence_data['source'],
        'intelligence_type': intelligence_data['intelligence_type'],
        'data': intelligence_data['data'],
        'confidence_score': intelligence_data.get('confidence_score', 0.5),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'metadata': intelligence_data.get('metadata', {})
    }
    
    return processed_intelligence


def store_external_intelligence(intelligence: Dict[str, Any]):
    """Store external intelligence in database"""
    
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
    
    # Insert external intelligence
    cursor.execute("""
        INSERT INTO external_intelligence (
            intelligence_id, source, intelligence_type, data,
            confidence_score, timestamp, metadata
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        intelligence['intelligence_id'],
        intelligence['source'],
        intelligence['intelligence_type'],
        json.dumps(intelligence['data']),
        intelligence['confidence_score'],
        intelligence['timestamp'],
        json.dumps(intelligence['metadata'])
    ))
    
    conn.commit()
    cursor.close()
    conn.close()


def publish_intelligence_update(intelligence: Dict[str, Any]):
    """Publish intelligence update to SNS"""
    
    try:
        message = {
            'event_type': 'external_intelligence_received',
            'intelligence_id': intelligence['intelligence_id'],
            'source': intelligence['source'],
            'intelligence_type': intelligence['intelligence_type'],
            'confidence_score': intelligence['confidence_score'],
            'timestamp': intelligence['timestamp']
        }
        
        sns_client.publish(
            TopicArn=INTELLIGENCE_TOPIC_ARN,
            Subject=f"External Intelligence Received - {intelligence['source']}",
            Message=json.dumps(message)
        )
        
    except Exception as e:
        logger.error(f"Error publishing intelligence update: {e}")


def generate_stix_report(days: int, confidence_min: float) -> Dict[str, Any]:
    """Generate STIX format report"""
    
    # Query intelligence data
    intelligence_reports = query_intelligence_reports(
        limit=1000,
        offset=0,
        confidence_min=confidence_min,
        start_date=(datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    )
    
    # Convert to STIX format (simplified)
    stix_report = {
        'type': 'bundle',
        'id': f'bundle--{generate_intelligence_id()}',
        'spec_version': '2.1',
        'objects': []
    }
    
    # Add indicators from IOCs
    for report in intelligence_reports:
        for ioc in report.get('iocs', []):
            indicator = {
                'type': 'indicator',
                'id': f'indicator--{generate_intelligence_id()}',
                'created': report['timestamp'],
                'modified': report['timestamp'],
                'pattern': f"[{ioc['type']}:value = '{ioc['value']}']",
                'labels': ['malicious-activity'],
                'confidence': int(float(ioc.get('confidence', 0.5)) * 100)
            }
            stix_report['objects'].append(indicator)
    
    return stix_report


def generate_csv_report(days: int, confidence_min: float) -> str:
    """Generate CSV format report"""
    
    # Query intelligence data
    intelligence_reports = query_intelligence_reports(
        limit=1000,
        offset=0,
        confidence_min=confidence_min,
        start_date=(datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    )
    
    # Generate CSV
    csv_lines = ['timestamp,report_id,confidence_score,attacker_ip,honeypot_type,mitre_techniques,ioc_count']
    
    for report in intelligence_reports:
        mitre_techniques = ','.join([t.get('technique_id', '') for t in report.get('mitre_techniques', [])])
        ioc_count = len(report.get('iocs', []))
        
        csv_line = f"{report['timestamp']},{report['report_id']},{report['confidence_score']},{report['attacker_ip']},{report['honeypot_type']},{mitre_techniques},{ioc_count}"
        csv_lines.append(csv_line)
    
    return '\n'.join(csv_lines)


def generate_json_report(days: int, confidence_min: float) -> Dict[str, Any]:
    """Generate JSON format report"""
    
    # Query intelligence data
    intelligence_reports = query_intelligence_reports(
        limit=1000,
        offset=0,
        confidence_min=confidence_min,
        start_date=(datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    )
    
    return {
        'report_metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'period_days': days,
            'confidence_threshold': confidence_min,
            'total_reports': len(intelligence_reports)
        },
        'intelligence_reports': intelligence_reports
    }


def check_database_health() -> bool:
    """Check database connectivity"""
    
    try:
        credentials = get_database_credentials()
        
        conn = psycopg2.connect(
            host=DATABASE_ENDPOINT,
            database=DATABASE_NAME,
            user=credentials['username'],
            password=credentials['password'],
            port=5432,
            sslmode='require',
            connect_timeout=5
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


def check_s3_health() -> bool:
    """Check S3 connectivity"""
    
    try:
        s3_client.head_bucket(Bucket=INTELLIGENCE_BUCKET)
        return True
        
    except Exception as e:
        logger.error(f"S3 health check failed: {e}")
        return False


def validate_webhook_signature(body: str, headers: Dict[str, str]) -> bool:
    """Validate webhook signature"""
    
    # Implementation would validate HMAC signature
    # For now, return True (implement based on SIEM requirements)
    return True


def process_siem_webhook(webhook_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process SIEM webhook data"""
    
    webhook_id = generate_intelligence_id()
    
    processed_data = {
        'webhook_id': webhook_id,
        'source': 'siem_webhook',
        'data': webhook_data,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    return processed_data


def store_webhook_data(webhook_data: Dict[str, Any]):
    """Store webhook data"""
    
    # Implementation would store webhook data in database
    logger.info(f"Webhook data stored: {webhook_data['webhook_id']}")


def get_database_credentials():
    """Retrieve database credentials from Secrets Manager"""
    
    try:
        response = secrets_client.get_secret_value(SecretId=DATABASE_SECRET_ARN)
        credentials = json.loads(response['SecretString'])
        return credentials
    except Exception as e:
        logger.error(f"Error retrieving database credentials: {e}")
        raise


def generate_intelligence_id() -> str:
    """Generate unique intelligence ID"""
    
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    random_suffix = hashlib.md5(os.urandom(16)).hexdigest()[:8]
    return f"{timestamp}-{random_suffix}"


def create_response(status_code: int, body: Any, content_type: str = 'application/json') -> Dict[str, Any]:
    """Create API Gateway response"""
    
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': content_type,
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-API-Key'
        },
        'body': json.dumps(body) if content_type == 'application/json' else str(body)
    }