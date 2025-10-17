# API Specifications

## Overview

This document provides comprehensive API specifications for the AI-Powered Honeypot System, including REST APIs, GraphQL endpoints, webhook interfaces, and AgentCore Runtime integration APIs.

## REST API Specification

### Base Configuration

**Base URL**: `https://api.honeypot-system.aws.amazon.com/v1`
**Authentication**: Bearer Token (JWT)
**Content-Type**: `application/json`

### Authentication

#### Obtain Access Token
```http
POST /auth/token
Content-Type: application/json

{
  "username": "string",
  "password": "string",
  "mfa_code": "string"
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "string",
  "scope": ["read", "write", "admin"]
}
```

### Threat Detection API

#### Submit Threat Feed
```http
POST /threats/feed
Authorization: Bearer {token}
Content-Type: application/json

{
  "source": "string",
  "threat_type": "ssh_brute_force|web_attack|malware|phishing",
  "indicators": [
    {
      "type": "ip_address|domain|hash|url",
      "value": "string",
      "confidence": 0.0-1.0
    }
  ],
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "source_reliability": "A|B|C|D|E",
    "tlp": "white|green|amber|red"
  }
}
```

**Response**:
```json
{
  "threat_id": "uuid",
  "status": "accepted|rejected",
  "confidence_score": 0.85,
  "engagement_decision": true,
  "processing_time_ms": 150
}
```

#### Get Threat Analysis
```http
GET /threats/{threat_id}
Authorization: Bearer {token}
```

**Response**:
```json
{
  "threat_id": "uuid",
  "status": "analyzing|completed|failed",
  "confidence_score": 0.85,
  "threat_classification": {
    "primary_type": "ssh_brute_force",
    "mitre_techniques": ["T1110.001", "T1021.004"],
    "severity": "high|medium|low"
  },
  "engagement_decision": true,
  "decision_rationale": "High confidence SSH brute force attack with known IOCs",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:15Z"
}
```

### Honeypot Management API

#### List Active Honeypots
```http
GET /honeypots
Authorization: Bearer {token}
Query Parameters:
  - status: active|inactive|creating|destroying
  - type: web_admin|ssh|database|file_share|email
  - limit: integer (default: 50)
  - offset: integer (default: 0)
```

**Response**:
```json
{
  "honeypots": [
    {
      "honeypot_id": "uuid",
      "type": "ssh",
      "status": "active",
      "endpoint": "ssh://honeypot-001.internal:22",
      "created_at": "2024-01-15T10:30:00Z",
      "engagement_id": "uuid",
      "attacker_count": 1,
      "interaction_count": 23,
      "synthetic_data_sets": ["corporate_linux_server"]
    }
  ],
  "total_count": 5,
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": false
  }
}
```

#### Create Honeypot
```http
POST /honeypots
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "ssh|web_admin|database|file_share|email",
  "configuration": {
    "persona": "linux_admin|windows_admin|database_admin",
    "synthetic_data_set": "corporate_linux_server|financial_database|email_server",
    "interaction_level": "basic|advanced|expert"
  },
  "duration_limit": 3600,
  "auto_destroy": true
}
```

**Response**:
```json
{
  "honeypot_id": "uuid",
  "status": "creating",
  "estimated_ready_time": "2024-01-15T10:30:30Z",
  "endpoint": "ssh://honeypot-002.internal:22"
}
```

#### Destroy Honeypot
```http
DELETE /honeypots/{honeypot_id}
Authorization: Bearer {token}
```

**Response**:
```json
{
  "honeypot_id": "uuid",
  "status": "destroying",
  "estimated_completion_time": "2024-01-15T10:35:00Z"
}
```

### Engagement Management API

#### List Engagements
```http
GET /engagements
Authorization: Bearer {token}
Query Parameters:
  - status: active|completed|terminated
  - start_date: ISO 8601 date
  - end_date: ISO 8601 date
  - limit: integer (default: 50)
  - offset: integer (default: 0)
```

**Response**:
```json
{
  "engagements": [
    {
      "engagement_id": "uuid",
      "threat_id": "uuid",
      "status": "active",
      "honeypot_type": "ssh",
      "attacker_ip": "192.168.1.100",
      "start_time": "2024-01-15T10:30:00Z",
      "duration": 1847,
      "interaction_count": 23,
      "intelligence_extracted": false
    }
  ],
  "total_count": 15,
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

#### Get Engagement Details
```http
GET /engagements/{engagement_id}
Authorization: Bearer {token}
```

**Response**:
```json
{
  "engagement_id": "uuid",
  "threat_id": "uuid",
  "status": "completed",
  "honeypot_id": "uuid",
  "honeypot_type": "ssh",
  "attacker_profile": {
    "ip_address": "192.168.1.100",
    "user_agent": "ssh_client_2.0",
    "geolocation": {
      "country": "US",
      "region": "California",
      "city": "San Francisco"
    }
  },
  "timeline": {
    "start_time": "2024-01-15T10:30:00Z",
    "end_time": "2024-01-15T11:00:47Z",
    "duration": 1847
  },
  "interactions": {
    "total_count": 23,
    "command_count": 15,
    "file_access_count": 8,
    "authentication_attempts": 5
  },
  "synthetic_data_accessed": [
    {
      "data_id": "uuid",
      "data_type": "credential",
      "access_count": 3
    }
  ],
  "intelligence_status": "extracted",
  "session_transcript_url": "s3://honeypot-sessions/uuid/transcript.json"
}
```

#### Terminate Engagement
```http
POST /engagements/{engagement_id}/terminate
Authorization: Bearer {token}
Content-Type: application/json

{
  "reason": "security_concern|manual_intervention|time_limit",
  "notes": "string"
}
```

### Intelligence API

#### List Intelligence Reports
```http
GET /intelligence/reports
Authorization: Bearer {token}
Query Parameters:
  - start_date: ISO 8601 date
  - end_date: ISO 8601 date
  - confidence_min: float (0.0-1.0)
  - mitre_technique: string (e.g., "T1110")
  - limit: integer (default: 50)
  - offset: integer (default: 0)
```

**Response**:
```json
{
  "reports": [
    {
      "report_id": "uuid",
      "engagement_id": "uuid",
      "generation_time": "2024-01-15T11:05:00Z",
      "confidence_score": 0.89,
      "threat_assessment": "high",
      "mitre_techniques": ["T1110.001", "T1021.004", "T1083"],
      "ioc_count": 5,
      "summary": "SSH brute force attack with credential stuffing and system reconnaissance"
    }
  ],
  "total_count": 25,
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": false
  }
}
```

#### Get Intelligence Report
```http
GET /intelligence/reports/{report_id}
Authorization: Bearer {token}
```

**Response**:
```json
{
  "report_id": "uuid",
  "engagement_id": "uuid",
  "session_id": "uuid",
  "generation_time": "2024-01-15T11:05:00Z",
  "confidence_score": 0.89,
  "threat_assessment": {
    "severity": "high",
    "confidence": 0.89,
    "threat_actor_profile": {
      "sophistication": "intermediate",
      "motivation": "financial",
      "attribution_confidence": 0.45
    }
  },
  "mitre_attack_mapping": [
    {
      "technique_id": "T1110.001",
      "technique_name": "Password Guessing",
      "tactic": "Credential Access",
      "confidence": 0.95,
      "evidence": ["Multiple failed login attempts with common passwords"]
    }
  ],
  "indicators_of_compromise": [
    {
      "type": "ip_address",
      "value": "192.168.1.100",
      "confidence": 0.9,
      "first_seen": "2024-01-15T10:30:00Z",
      "context": "Source of brute force attack"
    }
  ],
  "recommendations": [
    "Implement account lockout policies",
    "Deploy multi-factor authentication",
    "Monitor for similar attack patterns"
  ],
  "raw_data": {
    "session_transcript_url": "s3://honeypot-sessions/uuid/transcript.json",
    "network_logs_url": "s3://honeypot-logs/uuid/network.log",
    "system_logs_url": "s3://honeypot-logs/uuid/system.log"
  }
}
```

### System Management API

#### Get System Status
```http
GET /system/status
Authorization: Bearer {token}
```

**Response**:
```json
{
  "system_status": "healthy|degraded|unhealthy",
  "timestamp": "2024-01-15T11:10:00Z",
  "agents": {
    "detection_agent": {
      "status": "healthy",
      "instance_count": 2,
      "error_rate": 0.02,
      "avg_response_time_ms": 150
    },
    "coordinator_agent": {
      "status": "healthy",
      "instance_count": 1,
      "error_rate": 0.01,
      "avg_response_time_ms": 75
    },
    "interaction_agent": {
      "status": "healthy",
      "instance_count": 5,
      "error_rate": 0.03,
      "avg_response_time_ms": 200
    },
    "intelligence_agent": {
      "status": "healthy",
      "instance_count": 2,
      "error_rate": 0.01,
      "avg_response_time_ms": 500
    }
  },
  "infrastructure": {
    "active_honeypots": 3,
    "active_engagements": 2,
    "database_status": "healthy",
    "storage_usage_percent": 45,
    "network_status": "healthy"
  }
}
```

#### Get System Metrics
```http
GET /system/metrics
Authorization: Bearer {token}
Query Parameters:
  - start_time: ISO 8601 datetime
  - end_time: ISO 8601 datetime
  - granularity: minute|hour|day
```

**Response**:
```json
{
  "time_range": {
    "start_time": "2024-01-15T10:00:00Z",
    "end_time": "2024-01-15T11:00:00Z",
    "granularity": "minute"
  },
  "metrics": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "threats_detected": 5,
      "engagements_created": 2,
      "interactions_processed": 150,
      "intelligence_reports_generated": 1,
      "system_cpu_percent": 45.2,
      "system_memory_percent": 62.8,
      "response_time_p95_ms": 180
    }
  ]
}
```

## GraphQL API

### Schema Definition

```graphql
type Query {
  threats(filter: ThreatFilter, pagination: Pagination): ThreatConnection
  threat(id: ID!): Threat
  
  honeypots(filter: HoneypotFilter, pagination: Pagination): HoneypotConnection
  honeypot(id: ID!): Honeypot
  
  engagements(filter: EngagementFilter, pagination: Pagination): EngagementConnection
  engagement(id: ID!): Engagement
  
  intelligenceReports(filter: IntelligenceFilter, pagination: Pagination): IntelligenceReportConnection
  intelligenceReport(id: ID!): IntelligenceReport
  
  systemStatus: SystemStatus
  systemMetrics(timeRange: TimeRange): [SystemMetric]
}

type Mutation {
  submitThreat(input: ThreatInput!): ThreatResult
  createHoneypot(input: HoneypotInput!): HoneypotResult
  destroyHoneypot(id: ID!): DestroyResult
  terminateEngagement(id: ID!, reason: String!): TerminateResult
}

type Subscription {
  threatDetected: Threat
  engagementStarted: Engagement
  engagementCompleted: Engagement
  intelligenceGenerated: IntelligenceReport
  systemAlert: SystemAlert
}

type Threat {
  id: ID!
  status: ThreatStatus!
  confidenceScore: Float!
  threatType: String!
  indicators: [Indicator!]!
  engagementDecision: Boolean!
  createdAt: DateTime!
  updatedAt: DateTime!
}

type Honeypot {
  id: ID!
  type: HoneypotType!
  status: HoneypotStatus!
  endpoint: String
  engagement: Engagement
  interactionCount: Int!
  createdAt: DateTime!
}

type Engagement {
  id: ID!
  threat: Threat!
  honeypot: Honeypot!
  status: EngagementStatus!
  attackerProfile: AttackerProfile!
  timeline: Timeline!
  interactions: [Interaction!]!
  intelligenceReport: IntelligenceReport
}

type IntelligenceReport {
  id: ID!
  engagement: Engagement!
  confidenceScore: Float!
  mitreAttackMapping: [MitreMapping!]!
  indicatorsOfCompromise: [IOC!]!
  recommendations: [String!]!
  generatedAt: DateTime!
}
```

### Example Queries

#### Get Recent Threats with Engagements
```graphql
query RecentThreats {
  threats(
    filter: { 
      createdAfter: "2024-01-15T00:00:00Z"
      confidenceMin: 0.7 
    }
    pagination: { limit: 10 }
  ) {
    edges {
      node {
        id
        confidenceScore
        threatType
        engagementDecision
        createdAt
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

#### Get Engagement with Intelligence
```graphql
query EngagementDetails($id: ID!) {
  engagement(id: $id) {
    id
    status
    attackerProfile {
      ipAddress
      userAgent
      geolocation {
        country
        city
      }
    }
    timeline {
      startTime
      endTime
      duration
    }
    interactions {
      timestamp
      type
      content
    }
    intelligenceReport {
      confidenceScore
      mitreAttackMapping {
        techniqueId
        techniqueName
        confidence
      }
      indicatorsOfCompromise {
        type
        value
        confidence
      }
    }
  }
}
```

## Webhook API

### Webhook Configuration

#### Register Webhook
```http
POST /webhooks
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": "https://your-system.com/webhooks/honeypot",
  "events": [
    "threat.detected",
    "engagement.started", 
    "engagement.completed",
    "intelligence.generated",
    "system.alert"
  ],
  "secret": "your-webhook-secret",
  "active": true
}
```

### Webhook Events

#### Threat Detected Event
```json
{
  "event": "threat.detected",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "threat_id": "uuid",
    "confidence_score": 0.89,
    "threat_type": "ssh_brute_force",
    "engagement_decision": true,
    "indicators": [
      {
        "type": "ip_address",
        "value": "192.168.1.100"
      }
    ]
  }
}
```

#### Intelligence Generated Event
```json
{
  "event": "intelligence.generated",
  "timestamp": "2024-01-15T11:05:00Z",
  "data": {
    "report_id": "uuid",
    "engagement_id": "uuid",
    "confidence_score": 0.89,
    "mitre_techniques": ["T1110.001", "T1021.004"],
    "ioc_count": 5,
    "threat_assessment": "high"
  }
}
```

This API specification provides comprehensive access to all honeypot system functionality through multiple interface types.